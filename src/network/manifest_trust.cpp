#include "network/manifest_trust.h"

#include <Windows.h>
#include <MinHook.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "core/log.h"
#include "core/runtime.h"
#include "native/native_scan.h"

namespace d2mod::manifest::trust {
namespace {

constexpr std::size_t kPublicKeyBytes = 270;
// Build 86657 manifest-key getter, RVA 0x3481F0. It bounds-checks the
// one-entry key table, then returns {DER pointer, DER length} for an index.
constexpr std::array<native::PatternByte, 46> kManifestKeyGetter{{
    {0x3B}, {0x0D}, {0, true}, {0, true}, {0, true}, {0, true},
    {0x72}, {0x09}, {0x33}, {0xC0}, {0x48}, {0x89}, {0x02}, {0x41}, {0x89}, {0x00}, {0xC3},
    {0x8B}, {0xC9}, {0x48}, {0x8D}, {0x05}, {0, true}, {0, true}, {0, true}, {0, true},
    {0x48}, {0xC1}, {0xE1}, {0x04}, {0x48}, {0x03}, {0xC8}, {0x48}, {0x8B}, {0x01},
    {0x48}, {0x89}, {0x02}, {0x8B}, {0x41}, {0x08}, {0x41}, {0x89}, {0x00}, {0xC3},
}};

using KeyGetter = std::uint32_t(__fastcall*)(std::uint32_t, const std::byte**, std::uint32_t*);

void* g_getterAddress{};
KeyGetter g_originalGetter{};
std::array<std::byte, kPublicKeyBytes> g_replacement{};
bool g_active{};

[[nodiscard]] bool is_pkcs1_rsa2048_public_key(const std::vector<std::byte>& der) noexcept {
    if (der.size() != kPublicKeyBytes) return false;
    constexpr std::array<std::uint8_t, 9> prefix{
        0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00};
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (static_cast<std::uint8_t>(der[i]) != prefix[i]) return false;
    }
    constexpr std::array<std::uint8_t, 5> exponent{0x02, 0x03, 0x01, 0x00, 0x01};
    for (std::size_t i = 0; i < exponent.size(); ++i) {
        if (static_cast<std::uint8_t>(der[der.size() - exponent.size() + i]) != exponent[i]) return false;
    }
    return true;
}

[[nodiscard]] bool is_pkcs1_rsa2048_public_key(const std::byte* der,
                                               const std::size_t size) noexcept {
    if (der == nullptr || size != kPublicKeyBytes) return false;
    constexpr std::array<std::uint8_t, 9> prefix{
        0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00};
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (static_cast<std::uint8_t>(der[i]) != prefix[i]) return false;
    }
    constexpr std::array<std::uint8_t, 5> exponent{0x02, 0x03, 0x01, 0x00, 0x01};
    for (std::size_t i = 0; i < exponent.size(); ++i) {
        if (static_cast<std::uint8_t>(der[size - exponent.size() + i]) != exponent[i]) return false;
    }
    return true;
}

[[nodiscard]] std::filesystem::path configured_key_path() {
    const auto config = runtime::configuration_path();
    std::array<wchar_t, 32768> value{};
    const DWORD length = GetPrivateProfileStringW(L"server", L"manifest_public_key", L"",
                                                  value.data(), static_cast<DWORD>(value.size()),
                                                  config.c_str());
    if (length == 0) return {};
    std::filesystem::path path(value.data());
    if (path.is_relative()) {
        path = std::filesystem::path(runtime::module_directory()) / path;
    }
    return path.lexically_normal();
}

[[nodiscard]] bool read_public_key(const std::filesystem::path& path,
                                   std::vector<std::byte>& der) noexcept {
    try {
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        if (!input) return false;
        const auto size = input.tellg();
        if (size != static_cast<std::streamoff>(kPublicKeyBytes)) return false;
        der.resize(kPublicKeyBytes);
        input.seekg(0, std::ios::beg);
        input.read(reinterpret_cast<char*>(der.data()), static_cast<std::streamsize>(der.size()));
        return input.good() || input.eof();
    } catch (...) {
        return false;
    }
}

[[nodiscard]] bool in_image(const native::ImageView image, const void* address,
                            const std::size_t size) noexcept {
    if (image.base == nullptr || address == nullptr || size > image.size) return false;
    const auto base = reinterpret_cast<std::uintptr_t>(image.base);
    const auto ptr = reinterpret_cast<std::uintptr_t>(address);
    return ptr >= base && ptr - base <= image.size - size;
}

std::uint32_t __fastcall hooked_key_getter(const std::uint32_t index,
                                          const std::byte** der,
                                          std::uint32_t* size) noexcept {
    if (index == 0 && der != nullptr && size != nullptr) {
        *der = g_replacement.data();
        *size = static_cast<std::uint32_t>(g_replacement.size());
        return *size;
    }
    return g_originalGetter != nullptr ? g_originalGetter(index, der, size) : 0;
}

} // namespace

bool install() noexcept {
    if (g_active) return true;

    const auto path = configured_key_path();
    if (path.empty()) return true;

    std::vector<std::byte> replacement;
    if (!read_public_key(path, replacement) || !is_pkcs1_rsa2048_public_key(replacement)) {
        log::write("manifest trust: manifest_public_key must be a 270-byte PKCS#1 RSA-2048 DER public key");
        return false;
    }

    const native::ImageView image = native::main_image();
    auto* const getter = native::scan_unique(image, kManifestKeyGetter);
    if (getter == nullptr) {
        log::write("manifest trust: build-86657 key getter did not resolve uniquely");
        return false;
    }

    auto* const stockGetter = reinterpret_cast<KeyGetter>(getter);
    const std::byte* stockKey{};
    std::uint32_t stockSize{};
    const std::uint32_t stockResult = stockGetter(0, &stockKey, &stockSize);
    const std::byte* secondKey = reinterpret_cast<const std::byte*>(1);
    std::uint32_t secondSize = 1;
    const std::uint32_t secondResult = stockGetter(1, &secondKey, &secondSize);
    if (stockResult != kPublicKeyBytes || stockSize != kPublicKeyBytes
        || !in_image(image, stockKey, kPublicKeyBytes)
        || !is_pkcs1_rsa2048_public_key(stockKey, stockSize)
        || secondResult != 0 || secondKey != nullptr || secondSize != 0) {
        log::write("manifest trust: stock key getter contract does not match build 86657");
        return false;
    }

    std::memcpy(g_replacement.data(), replacement.data(), g_replacement.size());
    LPVOID original{};
    const MH_STATUS created = MH_CreateHook(getter,
                                            reinterpret_cast<LPVOID>(&hooked_key_getter),
                                            &original);
    if (created != MH_OK) {
        log::write("manifest trust: could not hook stock manifest key getter");
        return false;
    }
    g_originalGetter = reinterpret_cast<KeyGetter>(original);
    g_getterAddress = getter;
    const MH_STATUS enabled = MH_EnableHook(getter);
    if (enabled != MH_OK) {
        (void)MH_RemoveHook(getter);
        g_originalGetter = nullptr;
        g_getterAddress = nullptr;
        log::write("manifest trust: could not enable manifest key getter hook");
        return false;
    }

    g_active = true;
    log::write("manifest trust: custom RSA public key getter installed; stock RSA-PSS verification remains enabled");
    return true;
}

bool uninstall() noexcept {
    if (g_getterAddress == nullptr) {
        g_active = false;
        return true;
    }
    const MH_STATUS disabled = MH_DisableHook(g_getterAddress);
    const MH_STATUS removed = MH_RemoveHook(g_getterAddress);
    const bool ok = (disabled == MH_OK || disabled == MH_ERROR_DISABLED)
                    && removed == MH_OK;
    if (!ok) return false;
    g_getterAddress = nullptr;
    g_originalGetter = nullptr;
    g_active = false;
    return true;
}

bool is_installed() noexcept {
    return g_active;
}

} // namespace d2mod::manifest::trust
