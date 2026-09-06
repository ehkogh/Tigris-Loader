#include "mods/package_trust.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstring>

#include "core/log.h"
#include "native/native_scan.h"

namespace d2mod::packages::trust {
namespace {

constexpr std::array<native::PatternByte, 36> kHeaderValidator{{
    {0x40, false}, {0x53, false}, {0x48, false}, {0x83, false}, {0xEC, false}, {0x20, false},
    {0x80, false}, {0x7C, false}, {0x24, false}, {0x58, false}, {0x00, false},
    {0x44, false}, {0x0F, false}, {0xB7, false}, {0xDA, false}, {0x4C, false}, {0x8B, false},
    {0xD1, false}, {0xBB, false}, {0x01, false}, {0x00, false}, {0x00, false}, {0x00, false},
    {0x75, false}, {0x0D, false}, {0xBB, false}, {0xA3, false}, {0xFF, false}, {0xFF, false},
    {0xFF, false}, {0x8B, false}, {0xC3, false}, {0x48, false}, {0x83, false}, {0xC4, false},
    {0x20, false},
}};

constexpr std::array<native::PatternByte, 10> kExtendedHeaderFailure{{
    {0xB8, false}, {0xA7, false}, {0xFF, false}, {0xFF, false}, {0xFF, false},
    {0xE9, false}, {0x00, true}, {0x00, true}, {0x00, true}, {0x00, true},
}};

constexpr std::array<native::PatternByte, 18> kCachedDataHashGate{{
    {0x84, false}, {0xC0, false}, {0x0F, false}, {0x85, false},
    {0x00, true}, {0x00, true}, {0x00, true}, {0x00, true},
    {0xE9, false}, {0x00, true}, {0x00, true}, {0x00, true}, {0x00, true},
    {0x48, false}, {0x8B, false}, {0x45, false}, {0x48, false}, {0x89, false},
}};

constexpr std::size_t kHeaderTrustBranchOffset = 23;
constexpr std::size_t kExtendedHeaderResultOffset = 1;
constexpr std::size_t kCachedDataBranchOffset = 2;

std::byte* g_headerBranch{};
std::byte* g_extendedHeaderResult{};
std::byte* g_cachedDataBranch{};

std::byte g_headerBranchOriginal{};
std::array<std::byte, 4> g_extendedHeaderOriginal{};
std::array<std::byte, 2> g_cachedDataBranchOriginal{};

template <std::size_t Size>
[[nodiscard]] bool write_code(std::byte* destination,
                              const std::array<std::byte, Size>& value) noexcept {
    if (destination == nullptr) {
        return false;
    }
    DWORD protection = 0;
    if (VirtualProtect(destination, value.size(), PAGE_EXECUTE_READWRITE, &protection) == FALSE) {
        return false;
    }
    std::memcpy(destination, value.data(), value.size());
    FlushInstructionCache(GetCurrentProcess(), destination, value.size());
    DWORD ignored = 0;
    return VirtualProtect(destination, value.size(), protection, &ignored) != FALSE;
}

[[nodiscard]] bool write_byte(std::byte* destination, const std::byte value) noexcept {
    return write_code(destination, std::array<std::byte, 1>{value});
}

void clear_state() noexcept {
    g_headerBranch = nullptr;
    g_extendedHeaderResult = nullptr;
    g_cachedDataBranch = nullptr;
}

} // namespace

bool install() noexcept {
    if (is_installed()) {
        return true;
    }

    const native::ImageView image = native::main_image();
    if (image.base == nullptr) {
        log::write("package trust: main image unavailable");
        return false;
    }

    std::byte* const header = native::scan_unique(image, kHeaderValidator);
    std::byte* const extended = native::scan_unique(image, kExtendedHeaderFailure);
    std::byte* const cached = native::scan_unique(image, kCachedDataHashGate);
    if (header == nullptr || extended == nullptr || cached == nullptr) {
        log::write("package trust: required build-86657 gate did not resolve uniquely");
        return false;
    }

    g_headerBranch = header + kHeaderTrustBranchOffset;
    g_extendedHeaderResult = extended + kExtendedHeaderResultOffset;
    g_cachedDataBranch = cached + kCachedDataBranchOffset;

    g_headerBranchOriginal = *g_headerBranch;
    std::memcpy(g_extendedHeaderOriginal.data(),
                g_extendedHeaderResult,
                g_extendedHeaderOriginal.size());
    std::memcpy(g_cachedDataBranchOriginal.data(),
                g_cachedDataBranch,
                g_cachedDataBranchOriginal.size());

    if (!write_byte(g_headerBranch, std::byte{0xEB})) {
        clear_state();
        log::write("package trust: header RSA gate patch failed");
        return false;
    }

    const std::array<std::byte, 4> successResult{
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    if (!write_code(g_extendedHeaderResult, successResult)) {
        (void)write_byte(g_headerBranch, g_headerBranchOriginal);
        clear_state();
        log::write("package trust: extended-header gate patch failed");
        return false;
    }

    const std::array<std::byte, 2> alwaysSuccess{std::byte{0x90}, std::byte{0xE9}};
    if (!write_code(g_cachedDataBranch, alwaysSuccess)) {
        (void)write_code(g_extendedHeaderResult, g_extendedHeaderOriginal);
        (void)write_byte(g_headerBranch, g_headerBranchOriginal);
        clear_state();
        log::write("package trust: cached-data gate patch failed");
        return false;
    }

    log::write("package trust: build-86657 package integrity gates enabled");
    return true;
}

bool uninstall() noexcept {
    bool ok = true;
    if (g_cachedDataBranch != nullptr) {
        ok = write_code(g_cachedDataBranch, g_cachedDataBranchOriginal) && ok;
    }
    if (g_extendedHeaderResult != nullptr) {
        ok = write_code(g_extendedHeaderResult, g_extendedHeaderOriginal) && ok;
    }
    if (g_headerBranch != nullptr) {
        ok = write_byte(g_headerBranch, g_headerBranchOriginal) && ok;
    }
    if (ok) {
        clear_state();
    }
    return ok;
}

bool is_installed() noexcept {
    return g_headerBranch != nullptr && g_extendedHeaderResult != nullptr
           && g_cachedDataBranch != nullptr;
}

} // namespace d2mod::packages::trust
