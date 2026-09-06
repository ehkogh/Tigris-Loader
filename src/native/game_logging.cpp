#include "native/game_logging.h"

#include <Windows.h>
#include <MinHook.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>

#include "core/log.h"
#include "core/runtime.h"
#include "native/native_scan.h"

namespace d2mod::native::game_logging {
namespace {

constexpr std::array<PatternByte, 27> kEnqueue{{
    {0x83}, {0xF9}, {0xFF}, {0x74}, {0, true},
    {0x48}, {0x89}, {0x5C}, {0x24}, {0, true}, {0x56},
    {0x48}, {0x83}, {0xEC}, {0x20}, {0x8B}, {0xD9}, {0x48}, {0x8B}, {0xF2},
    {0x48}, {0x8B}, {0x0D}, {0, true}, {0, true}, {0, true}, {0, true}
}};
constexpr std::array<PatternByte, 12> kCategory{{
    {0x4C}, {0x8B}, {0x05}, {0, true}, {0, true}, {0, true}, {0, true},
    {0xB8}, {0x05}, {0x00}, {0x00}, {0x00}
}};
constexpr std::size_t kTextCapacity = 320;
constexpr std::size_t kCategoryCount = 26;
constexpr std::size_t kThresholdOffset = 0x19808;
using Enqueue = void(__fastcall*)(std::int32_t, const char*);

SRWLOCK g_lock{SRWLOCK_INIT};
std::atomic_bool g_capture{false};
Enqueue g_original{};
bool g_hookInstalled{};
std::byte** g_blockSlot{};
std::byte* g_savedBlock{};
std::array<LONG, kCategoryCount> g_savedThresholds{};
LONG g_verbosity{};
ULONGLONG g_nextUpdate{};
thread_local bool g_inCapture{};

std::size_t copy_text(const char* text, char* output) noexcept {
    if (text == nullptr) {
        return 0;
    }
    __try {
        std::size_t length = 0;
        for (; length < kTextCapacity && text[length] != '\0'; ++length) {
            output[length] = text[length];
        }
        return length;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

void __fastcall observe(const std::int32_t site, const char* text) noexcept {
    // Trampoline and this DLL are retained for the process lifetime, including shutdown.
    g_original(site, text);
    if (site != -1 && g_capture.load(std::memory_order_acquire) && !g_inCapture) {
        g_inCapture = true;
        std::array<char, kTextCapacity> copy{};
        const auto length = copy_text(text, copy.data());
        if (length != 0) {
            log::write_game(site, {copy.data(), length});
        }
        g_inCapture = false;
    }
}

// Thresholds are naturally aligned 32-bit values. The gate is threshold <= site level.
// Save existing values and restore only values we still own. A late config load may rewrite them.
void thresholds(const bool restore) noexcept {
    __try {
        std::byte* const block = g_blockSlot != nullptr ? *g_blockSlot : nullptr;
        if (block == nullptr) {
            return;
        }
        auto* const levels = reinterpret_cast<volatile LONG*>(block + kThresholdOffset);
        if (restore) {
            if (block == g_savedBlock) {
                for (std::size_t i = 0; i < kCategoryCount; ++i) {
                    (void)InterlockedCompareExchange(levels + i, g_savedThresholds[i], g_verbosity);
                }
            }
            g_savedBlock = nullptr;
            return;
        }
        if (block != g_savedBlock) {
            for (std::size_t i = 0; i < kCategoryCount; ++i) {
                g_savedThresholds[i] = InterlockedCompareExchange(levels + i, 0, 0);
            }
            g_savedBlock = block;
        }
        for (std::size_t i = 0; i < kCategoryCount; ++i) {
            const LONG previous = InterlockedExchange(levels + i, g_verbosity);
            if (previous != g_verbosity) {
                g_savedThresholds[i] = previous;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_savedBlock = nullptr;
    }
}

bool install_hook() noexcept {
    const auto image = main_image();
    auto* const entry = scan_unique(image, kEnqueue);
    auto* const category = scan_unique(image, kCategory);
    if (entry == nullptr || category == nullptr) {
        log::write("Tiger/D2 capture unavailable: build-86657 logging signatures missing or ambiguous");
        return false;
    }
    std::int32_t enqueueOffset{}, categoryOffset{};
    std::memcpy(&enqueueOffset, entry + 23, sizeof(enqueueOffset));
    std::memcpy(&categoryOffset, category + 3, sizeof(categoryOffset));
    const auto enqueueSlot = reinterpret_cast<std::uintptr_t>(entry + 27) + enqueueOffset;
    const auto categorySlot = reinterpret_cast<std::uintptr_t>(category + 7) + categoryOffset;
    const auto base = reinterpret_cast<std::uintptr_t>(image.base);
    if (enqueueSlot != categorySlot || categorySlot < base
        || categorySlot - base > image.size - sizeof(void*)) {
        log::write("Tiger/D2 capture unavailable: log-block references disagree");
        return false;
    }
    const MH_STATUS initialized = MH_Initialize();
    if (initialized != MH_OK && initialized != MH_ERROR_ALREADY_INITIALIZED) {
        log::write("Tiger/D2 capture unavailable: hook library initialization failed");
        return false;
    }
    LPVOID original = nullptr;
    const MH_STATUS created = MH_CreateHook(entry, reinterpret_cast<LPVOID>(&observe), &original);
    if (created != MH_OK) {
        log::write(MH_StatusToString(created));
        return false;
    }
    g_original = reinterpret_cast<Enqueue>(original);
    g_blockSlot = reinterpret_cast<std::byte**>(categorySlot);
    HMODULE pinned{};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                            reinterpret_cast<LPCWSTR>(&observe), &pinned)) {
        (void)MH_RemoveHook(entry);
        log::write("Tiger/D2 capture unavailable: could not retain observer module");
        return false;
    }
    const MH_STATUS enabled = MH_EnableHook(entry);
    if (enabled != MH_OK) {
        (void)MH_RemoveHook(entry);
        log::write(MH_StatusToString(enabled));
        return false;
    }
    g_hookInstalled = true;
    return true;
}

} // namespace

void start() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_capture.load(std::memory_order_acquire)) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    const auto config = runtime::configuration_path();
    if (GetPrivateProfileIntW(L"logging", L"game_logs", 1, config.c_str()) == 0) {
        ReleaseSRWLockExclusive(&g_lock);
        log::write("Tiger/D2 log capture disabled by config");
        return;
    }
    const UINT verbosity = GetPrivateProfileIntW(L"logging", L"game_verbosity", 0, config.c_str());
    g_verbosity = verbosity <= 5 ? static_cast<LONG>(verbosity) : 0;
    if (!g_hookInstalled && !install_hook()) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    g_capture.store(true, std::memory_order_release);
    thresholds(false);
    g_nextUpdate = GetTickCount64() + 2000;
    ReleaseSRWLockExclusive(&g_lock);
    log::write("Tiger/D2 native retail log capture active (messages retain their engine channel names)");
}

void update() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    const ULONGLONG now = GetTickCount64();
    if (g_capture.load(std::memory_order_acquire) && now >= g_nextUpdate) {
        thresholds(false);
        g_nextUpdate = now + 2000;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void stop() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_capture.exchange(false, std::memory_order_acq_rel)) {
        thresholds(true);
    }
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace d2mod::native::game_logging
