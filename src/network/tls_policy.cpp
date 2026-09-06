#include "network/tls_policy.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "core/log.h"
#include "native/native_scan.h"
#include "core/runtime.h"

namespace d2mod::tls {
namespace {

constexpr std::array<native::PatternByte, 25> kPinnedCaGetter{{
    {0x48, false}, {0x8D, false}, {0x05, false},
    {0x00, true},  {0x00, true},  {0x00, true}, {0x00, true},
    {0xC3, false}, {0x83, false}, {0xC0, false}, {0x01, false}, {0xE9, false},
    {0x00, true},  {0x00, true},  {0x00, true}, {0x00, true},
    {0x48, false}, {0x8D, false}, {0x05, false},
    {0x00, true},  {0x00, true},  {0x00, true}, {0x00, true},
    {0xC3, false}, {0xCC, false},
}};

constexpr std::array<native::PatternByte, 15> kSslOptions{{
    {0x48, false}, {0x89, false}, {0x5C, false}, {0x24, false}, {0x00, true},
    {0x57, false}, {0x48, false}, {0x83, false}, {0xEC, false}, {0x20, false},
    {0xBA, false}, {0x51, false}, {0x00, false}, {0x00, false}, {0x00, false},
}};

constexpr std::size_t kPinnedCaGetterRva = 0x38F700;
constexpr std::size_t kSslOptionsRva = 0x1A862E0;

constexpr std::size_t kVerifyHostDisplacementOffset = 0x19;
constexpr std::size_t kVerifyPeerDisplacementOffset = 0x2D;
constexpr std::byte kVerifyHostStock{0xB1};
constexpr std::byte kVerifyPeerStock{0xC1};
constexpr std::byte kVerifyHostDisabled{0xAF}; // 0x51 - 0x51 = 0
constexpr std::byte kVerifyPeerDisabled{0xC0}; // 0x40 - 0x40 = 0

std::byte* g_pinnedCaGetter{};
std::byte* g_verifyHostDisplacement{};
std::byte* g_verifyPeerDisplacement{};
std::array<std::byte, 3> g_pinnedCaOriginal{};
std::byte g_verifyHostOriginal{};
std::byte g_verifyPeerOriginal{};

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

[[nodiscard]] bool matches_rva(const native::ImageView image,
                               const std::byte* address,
                               const std::size_t rva) noexcept {
    return image.base != nullptr && address != nullptr && address >= image.base
           && static_cast<std::size_t>(address - image.base) == rva;
}

[[nodiscard]] bool setting_enabled(const wchar_t* key, const bool defaultValue) noexcept {
    const std::wstring path = runtime::configuration_path();
    return GetPrivateProfileIntW(
               L"server", key, defaultValue ? 1 : 0, path.c_str())
           != 0;
}

void clear_state() noexcept {
    g_pinnedCaGetter = nullptr;
    g_verifyHostDisplacement = nullptr;
    g_verifyPeerDisplacement = nullptr;
}

} // namespace

bool install() noexcept {
    if (is_installed()) {
        return true;
    }

    const bool removePinning = setting_enabled(L"remove_pinning", true);
    const bool allowSelfSigned = setting_enabled(L"allow_self_signed", false);
    if (!removePinning && !allowSelfSigned) {
        log::write("TLS policy: stock certificate policy retained");
        return true;
    }

    const native::ImageView image = native::main_image();
    if (image.base == nullptr) {
        log::write("TLS policy: main image unavailable");
        return false;
    }

    std::byte* const pinnedCaGetter = native::scan_unique(image, kPinnedCaGetter);
    std::byte* const sslOptions = native::scan_unique(image, kSslOptions);
    if ((removePinning && !matches_rva(image, pinnedCaGetter, kPinnedCaGetterRva))
        || (allowSelfSigned && !matches_rva(image, sslOptions, kSslOptionsRva))) {
        log::write("TLS policy: required build-86657 target missing or non-unique");
        return false;
    }

    if (removePinning) {
        constexpr std::array<std::byte, 3> kReturnNull{
            std::byte{0x31}, std::byte{0xC0}, std::byte{0xC3}}; // xor eax,eax; ret
        if (pinnedCaGetter[0] != std::byte{0x48} || pinnedCaGetter[1] != std::byte{0x8D}
            || pinnedCaGetter[2] != std::byte{0x05}) {
            log::write("TLS policy: pinned-CA getter entry bytes changed");
            return false;
        }
        g_pinnedCaGetter = pinnedCaGetter;
        std::memcpy(g_pinnedCaOriginal.data(), g_pinnedCaGetter, g_pinnedCaOriginal.size());
        if (!write_code(g_pinnedCaGetter, kReturnNull)) {
            clear_state();
            log::write("TLS policy: failed to remove custom CA bundle");
            return false;
        }
        log::write("TLS policy: Bungie/Tiger CA bundle disabled; normal HTTPS verification retained");
    }

    if (allowSelfSigned) {
        g_verifyHostDisplacement = sslOptions + kVerifyHostDisplacementOffset;
        g_verifyPeerDisplacement = sslOptions + kVerifyPeerDisplacementOffset;
        if (*g_verifyHostDisplacement != kVerifyHostStock
            || *g_verifyPeerDisplacement != kVerifyPeerStock) {
            if (g_pinnedCaGetter != nullptr) {
                (void)write_code(g_pinnedCaGetter, g_pinnedCaOriginal);
            }
            clear_state();
            log::write("TLS policy: SSL verification instruction bytes changed");
            return false;
        }
        g_verifyHostOriginal = *g_verifyHostDisplacement;
        g_verifyPeerOriginal = *g_verifyPeerDisplacement;
        if (!write_byte(g_verifyHostDisplacement, kVerifyHostDisabled)
            || !write_byte(g_verifyPeerDisplacement, kVerifyPeerDisabled)) {
            (void)write_byte(g_verifyHostDisplacement, g_verifyHostOriginal);
            (void)write_byte(g_verifyPeerDisplacement, g_verifyPeerOriginal);
            if (g_pinnedCaGetter != nullptr) {
                (void)write_code(g_pinnedCaGetter, g_pinnedCaOriginal);
            }
            clear_state();
            log::write("TLS policy: failed to enable self-signed HTTPS mode");
            return false;
        }
        log::write("TLS policy: self-signed HTTPS enabled; peer and hostname verification disabled");
    }

    return true;
}

bool uninstall() noexcept {
    bool ok = true;
    if (g_verifyPeerDisplacement != nullptr) {
        ok = write_byte(g_verifyPeerDisplacement, g_verifyPeerOriginal) && ok;
    }
    if (g_verifyHostDisplacement != nullptr) {
        ok = write_byte(g_verifyHostDisplacement, g_verifyHostOriginal) && ok;
    }
    if (g_pinnedCaGetter != nullptr) {
        ok = write_code(g_pinnedCaGetter, g_pinnedCaOriginal) && ok;
    }
    if (ok) {
        clear_state();
    }
    return ok;
}

bool is_installed() noexcept {
    return g_pinnedCaGetter != nullptr || g_verifyHostDisplacement != nullptr
           || g_verifyPeerDisplacement != nullptr;
}

} // namespace d2mod::tls
