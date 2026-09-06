#include "core/runtime.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <string>

#include "core/log.h"
#include "mods/mod_catalog.h"
#include "mods/package_runtime.h"
#include "mods/package_trust.h"
#include "network/tls_policy.h"
#include "native/game_logging.h"
#include "sku/policy.h"

namespace d2mod::runtime {
namespace {

HMODULE g_module{};
SRWLOCK g_lock{SRWLOCK_INIT};
std::atomic_bool g_initialized{false};
std::atomic_bool g_firstCallbackPump{false};

} // namespace

void set_module(const HMODULE module) noexcept { g_module = module; }

std::wstring module_directory() {
    if (g_module == nullptr) {
        return {};
    }

    std::array<wchar_t, 32768> path{};
    const DWORD length = GetModuleFileNameW(g_module, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) {
        return {};
    }

    std::wstring directory(path.data(), length);
    const std::size_t slash = directory.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return {};
    }
    directory.resize(slash);
    return directory;
}

std::wstring configuration_path() {
    std::wstring path = module_directory();
    if (!path.empty() && path.back() != L'\\') {
        path.push_back(L'\\');
    }
    path.append(L"modloader.ini");
    return path;
}

bool initialize() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_initialized.load(std::memory_order_acquire)) {
        ReleaseSRWLockExclusive(&g_lock);
        return true;
    }

    log::initialize();
    log::write("D2 mod loader initializing");
    native::game_logging::start();
    if (!sku::policy::install()) {
        log::write("D2 mod loader initialization failed: requested unsigned SKU policy unavailable");
        native::game_logging::stop();
        log::shutdown();
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    if (!packages::trust::install()) {
        log::write("D2 mod loader initialization failed: package trust gates unavailable");
        native::game_logging::stop();
        (void)sku::policy::uninstall();
        log::shutdown();
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    if (!tls::install()) {
        log::write("D2 mod loader initialization failed: TLS policy unavailable");
        (void)packages::trust::uninstall();
        native::game_logging::stop();
        (void)sku::policy::uninstall();
        log::shutdown();
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    mods::scan();

    g_initialized.store(true, std::memory_order_release);
    log::write("D2 mod loader initialized");
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

void shutdown() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (!g_initialized.exchange(false, std::memory_order_acq_rel)) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    if (!tls::uninstall()) {
        log::write("TLS policy restore failed during shutdown");
    }
    if (!packages::trust::uninstall()) {
        log::write("package trust restore failed during shutdown");
    }
    log::write("D2 mod loader shutdown");
    native::game_logging::stop();
    (void)sku::policy::uninstall();
    log::shutdown();
    ReleaseSRWLockExclusive(&g_lock);
}

void on_callback_pump() noexcept {
    native::game_logging::update();
    bool expected = false;
    if (g_firstCallbackPump.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        log::write("first Steam callback pump reached; post-unpack activation boundary is live");
        packages::activate_discovered();
    }
}

} // namespace d2mod::runtime
