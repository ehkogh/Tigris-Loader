#include "steam/certificate_compat.h"

#include <Windows.h>
#include <MinHook.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "core/log.h"
#include "core/runtime.h"
#include "native/native_scan.h"

namespace d2mod::steam::certificate_compat {
namespace {

using AuthenticationStatus = int(__fastcall*)(void*, void*);
using SetCertificate = bool(__fastcall*)(void*, const void*, int, char*);

constexpr int kAvailabilityCurrent = 100;
constexpr int kAvailabilityFailed = -101;

constexpr std::array<native::PatternByte, 28> kAuthenticationStatus{{
    {0x40}, {0x57}, {0x48}, {0x83}, {0xEC}, {0, true},
    {0x48}, {0xC7}, {0x44}, {0x24}, {0, true}, {0, true}, {0, true}, {0, true}, {0, true},
    {0x48}, {0x89}, {0x5C}, {0x24}, {0, true},
    {0x48}, {0x8B}, {0xDA}, {0x48}, {0x8B}, {0xF9}, {0x33}, {0xC9},
}};

constexpr std::array<native::PatternByte, 55> kSetCertificate{{
    {0x48}, {0x8B}, {0xC4}, {0x55}, {0x41}, {0x56}, {0x41}, {0x57},
    {0x48}, {0x8D}, {0xA8}, {0, true}, {0, true}, {0, true}, {0, true},
    {0x48}, {0x81}, {0xEC}, {0, true}, {0, true}, {0, true}, {0, true},
    {0x48}, {0xC7}, {0x44}, {0x24}, {0, true}, {0xFE}, {0xFF}, {0xFF}, {0xFF},
    {0x48}, {0x89}, {0x58}, {0, true},
    {0x48}, {0x89}, {0x70}, {0, true},
    {0x48}, {0x89}, {0x78}, {0, true},
    {0x4D}, {0x8B}, {0xF1}, {0x41}, {0x8B}, {0xD8}, {0x48}, {0x8B}, {0xFA}, {0x48}, {0x8B}, {0xF1},
}};

AuthenticationStatus g_originalAuthenticationStatus{};
SetCertificate g_originalSetCertificate{};
void* g_authenticationStatusAddress{};
void* g_setCertificateAddress{};
std::atomic_bool g_active{false};
std::atomic_bool g_failed{false};
std::atomic_bool g_loggedAuthOverride{false};
std::atomic_bool g_loggedCertificateOverride{false};
bool g_configRead{};
bool g_requested{};

[[nodiscard]] native::ImageView image_for_module(HMODULE module) noexcept {
    if (module == nullptr) return {};
    auto* const base = reinterpret_cast<std::byte*>(module);
    const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return {};
    const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
        || nt->OptionalHeader.SizeOfImage == 0) {
        return {};
    }
    return {base, static_cast<std::size_t>(nt->OptionalHeader.SizeOfImage)};
}

int __fastcall hooked_authentication_status(void* self, void* details) noexcept {
    const int value = g_originalAuthenticationStatus != nullptr
                          ? g_originalAuthenticationStatus(self, details)
                          : kAvailabilityFailed;
    if (value == kAvailabilityFailed) {
        if (!g_loggedAuthOverride.exchange(true, std::memory_order_relaxed)) {
            log::write("Steam certificate compatibility: networking authentication -101 treated as current");
        }
        return kAvailabilityCurrent;
    }
    return value;
}

bool __fastcall hooked_set_certificate(void* self,
                                       const void* certificate,
                                       int certificateSize,
                                       char* error) noexcept {
    const bool accepted = g_originalSetCertificate != nullptr
                              ? g_originalSetCertificate(self, certificate, certificateSize, error)
                              : false;
    if (!accepted && !g_loggedCertificateOverride.exchange(true, std::memory_order_relaxed)) {
        log::write("Steam certificate compatibility: local BAP certificate accepted after stock parser rejection");
    }
    return true;
}

void remove_partial_hooks() noexcept {
    if (g_authenticationStatusAddress != nullptr) {
        (void)MH_DisableHook(g_authenticationStatusAddress);
        (void)MH_RemoveHook(g_authenticationStatusAddress);
    }
    if (g_setCertificateAddress != nullptr) {
        (void)MH_DisableHook(g_setCertificateAddress);
        (void)MH_RemoveHook(g_setCertificateAddress);
    }
    g_authenticationStatusAddress = nullptr;
    g_setCertificateAddress = nullptr;
    g_originalAuthenticationStatus = nullptr;
    g_originalSetCertificate = nullptr;
}

} // namespace

void update() noexcept {
    if (g_active.load(std::memory_order_acquire) || g_failed.load(std::memory_order_acquire)) return;

    if (!g_configRead) {
        const auto config = runtime::configuration_path();
        g_requested = GetPrivateProfileIntW(L"server", L"steam_certificate_compat", 0, config.c_str()) != 0;
        g_configRead = true;
    }
    if (!g_requested) return;

    HMODULE module = GetModuleHandleW(L"steamnetworkingsockets.dll");
    if (module == nullptr) return; // It may be loaded lazily; the next callback pump retries.

    const native::ImageView image = image_for_module(module);
    auto* const authenticationStatus = native::scan_unique(image, kAuthenticationStatus);
    auto* const setCertificate = native::scan_unique(image, kSetCertificate);
    if (authenticationStatus == nullptr || setCertificate == nullptr) {
        log::write("Steam certificate compatibility unavailable: SteamNetworkingSockets signatures missing or ambiguous");
        g_failed.store(true, std::memory_order_release);
        return;
    }

    const MH_STATUS initialized = MH_Initialize();
    if (initialized != MH_OK && initialized != MH_ERROR_ALREADY_INITIALIZED) {
        log::write("Steam certificate compatibility unavailable: hook library initialization failed");
        g_failed.store(true, std::memory_order_release);
        return;
    }

    LPVOID originalAuthentication{};
    LPVOID originalCertificate{};
    if (MH_CreateHook(authenticationStatus,
                      reinterpret_cast<LPVOID>(&hooked_authentication_status),
                      &originalAuthentication) != MH_OK
        || MH_CreateHook(setCertificate,
                         reinterpret_cast<LPVOID>(&hooked_set_certificate),
                         &originalCertificate) != MH_OK) {
        g_authenticationStatusAddress = authenticationStatus;
        g_setCertificateAddress = setCertificate;
        remove_partial_hooks();
        log::write("Steam certificate compatibility unavailable: could not create SteamNetworkingSockets hooks");
        g_failed.store(true, std::memory_order_release);
        return;
    }

    g_authenticationStatusAddress = authenticationStatus;
    g_setCertificateAddress = setCertificate;
    g_originalAuthenticationStatus = reinterpret_cast<AuthenticationStatus>(originalAuthentication);
    g_originalSetCertificate = reinterpret_cast<SetCertificate>(originalCertificate);
    if (MH_EnableHook(authenticationStatus) != MH_OK || MH_EnableHook(setCertificate) != MH_OK) {
        remove_partial_hooks();
        log::write("Steam certificate compatibility unavailable: could not enable SteamNetworkingSockets hooks");
        g_failed.store(true, std::memory_order_release);
        return;
    }

    g_active.store(true, std::memory_order_release);
    log::write("Steam certificate compatibility active; stock Steam networking transport/SDR selection remains unchanged");
}

bool uninstall() noexcept {
    if (!g_active.exchange(false, std::memory_order_acq_rel)) return true;
    const MH_STATUS authDisabled = MH_DisableHook(g_authenticationStatusAddress);
    const MH_STATUS certDisabled = MH_DisableHook(g_setCertificateAddress);
    const MH_STATUS authRemoved = MH_RemoveHook(g_authenticationStatusAddress);
    const MH_STATUS certRemoved = MH_RemoveHook(g_setCertificateAddress);
    const bool ok = (authDisabled == MH_OK || authDisabled == MH_ERROR_DISABLED)
                    && (certDisabled == MH_OK || certDisabled == MH_ERROR_DISABLED)
                    && authRemoved == MH_OK && certRemoved == MH_OK;
    g_authenticationStatusAddress = nullptr;
    g_setCertificateAddress = nullptr;
    g_originalAuthenticationStatus = nullptr;
    g_originalSetCertificate = nullptr;
    return ok;
}

bool is_installed() noexcept {
    return g_active.load(std::memory_order_acquire);
}

} // namespace d2mod::steam::certificate_compat
