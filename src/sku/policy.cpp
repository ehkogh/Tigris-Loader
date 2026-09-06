#include "sku/policy.h"

#include <Windows.h>
#include <intrin.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "core/log.h"
#include "core/runtime.h"
#include "native/native_scan.h"

namespace d2mod::sku::policy {
namespace {

constexpr std::array<native::PatternByte, 50> kVerifier{{
    {0x40}, {0x55}, {0x56}, {0x57}, {0x41}, {0x56}, {0x48}, {0x8D},
    {0xAC}, {0x24}, {0xC8}, {0xFC}, {0xFF}, {0xFF}, {0x48}, {0x81},
    {0xEC}, {0x38}, {0x04}, {0x00}, {0x00}, {0x48}, {0x8B}, {0x05},
    {0, true}, {0, true}, {0, true}, {0, true}, {0x48}, {0x33}, {0xC4},
    {0x48}, {0x89}, {0x85}, {0x20}, {0x03}, {0x00}, {0x00},
    {0x33}, {0xFF}, {0x4D}, {0x8B}, {0xF0}, {0x40}, {0x38}, {0x3D},
    {0, true}, {0, true}, {0, true}, {0, true}
}};
volatile char* g_gate{};
char g_original{};
bool g_active{};
bool g_protectionPending{};
DWORD g_restoreProtection{};

void memory_error(const char* operation, const DWORD protection, const DWORD error) noexcept {
    std::array<char, 192> message{};
    (void)std::snprintf(message.data(), message.size(),
                       "Unsigned SKU policy: %s (protection=0x%lX, error=%lu)",
                       operation, protection, error);
    log::write(message.data());
}

bool readable_gate(const void* address, MEMORY_BASIC_INFORMATION& region) noexcept {
    if (!VirtualQuery(address, &region, sizeof(region))) {
        memory_error("could not query signature gate", 0, GetLastError());
        return false;
    }
    const DWORD access = region.Protect & 0xFF;
    const bool readable = access == PAGE_READONLY || access == PAGE_READWRITE
                          || access == PAGE_WRITECOPY || access == PAGE_EXECUTE_READ
                          || access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY;
    if (region.State != MEM_COMMIT || !readable || (region.Protect & PAGE_GUARD) != 0) {
        memory_error("signature gate is not committed readable memory", region.Protect, 0);
        return false;
    }
    return true;
}

bool set_gate(const char expected, const char value) noexcept {
    auto* const address = const_cast<char*>(g_gate);
    MEMORY_BASIC_INFORMATION region{};
    if (!readable_gate(address, region)) return false;
    const DWORD access = region.Protect & 0xFF;
    const bool executable = access == PAGE_EXECUTE_READ || access == PAGE_EXECUTE_READWRITE
                            || access == PAGE_EXECUTE_WRITECOPY;
    DWORD previous{};
    if (!VirtualProtect(address, 1, executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &previous)) {
        memory_error("could not make signature gate writable", region.Protect, GetLastError());
        return false;
    }
    if (!g_protectionPending) g_restoreProtection = previous;
    g_protectionPending = true;
    (void)_InterlockedCompareExchange8(g_gate, value, expected);
    DWORD ignored{};
    if (!VirtualProtect(address, 1, g_restoreProtection, &ignored)) {
        memory_error("could not restore signature gate protection", g_restoreProtection, GetLastError());
        return false;
    }
    g_protectionPending = false;
    return true;
}

} // namespace

bool install() noexcept {
    if (g_active) return true;
    if (g_gate != nullptr && !uninstall()) return false;
    const auto config = runtime::configuration_path();
    if (GetPrivateProfileIntW(L"sku", L"allow_unsigned", 0, config.c_str()) == 0) return true;
    const auto image = native::main_image();
    auto* const verifier = native::scan_unique(image, kVerifier);
    if (verifier == nullptr) {
        log::write("Unsigned SKU policy failed: build-86657 verifier not uniquely identified");
        return false;
    }
    std::int32_t displacement{};
    std::memcpy(&displacement, verifier + 46, sizeof(displacement));
    const auto address = reinterpret_cast<std::uintptr_t>(verifier + 50) + displacement;
    const auto base = reinterpret_cast<std::uintptr_t>(image.base);
    if (address < base || address - base >= image.size) return false;
    MEMORY_BASIC_INFORMATION region{};
    if (!readable_gate(reinterpret_cast<void*>(address), region)) return false;
    auto* const gate = reinterpret_cast<volatile char*>(address);
    const char original = *gate;
    if (original != 0 && original != 1) {
        log::write("Unsigned SKU policy failed: signature gate has an unexpected value");
        return false;
    }
    g_original = original;
    g_gate = gate;
    if (!set_gate(original, 0)) {
        (void)uninstall();
        return false;
    }
    g_active = true;
    log::write("Unsigned SKU configs enabled: use plaintext or headerless tool output, not the signed retail envelope");
    return true;
}

bool uninstall() noexcept {
    if (g_gate == nullptr) return true;
    g_active = false;
    if (!set_gate(0, g_original)) return false;
    g_gate = nullptr;
    return true;
}

} // namespace d2mod::sku::policy
