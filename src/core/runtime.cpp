#include "core/runtime.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <filesystem>
#include <stdexcept>
#include <string>

#include "core/default_config.h"
#include "core/log.h"
#include "mods/mod_catalog.h"
#include "mods/package_runtime.h"
#include "mods/package_trust.h"
#include "network/tls_policy.h"
#include "native/game_logging.h"
#include "sku/policy.h"
#include "sku/file.h"

namespace d2mod::runtime {
namespace {

HMODULE g_module{};
SRWLOCK g_lock{SRWLOCK_INIT};
std::atomic_bool g_initialized{false};
std::atomic_bool g_firstCallbackPump{false};

bool create_default_configuration() {
    const auto path = configuration_path();
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_EXISTS;
    DWORD written{};
    const bool saved = WriteFile(file, kDefaultConfig.data(), static_cast<DWORD>(kDefaultConfig.size()),
                                &written, nullptr) && written == kDefaultConfig.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!saved) DeleteFileW(path.c_str());
    return saved;
}

bool prepare_sku() noexcept {
    try {
        const auto config = configuration_path();
        if (GetPrivateProfileIntW(L"sku", L"auto_decrypt", 1, config.c_str()) == 0) return true;
        if (GetPrivateProfileIntW(L"sku", L"allow_unsigned", 0, config.c_str()) == 0) {
            log::write("SKU auto-decrypt skipped: allow_unsigned=0");
            return true;
        }
        std::array<wchar_t, 32768> executable{};
        const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (length == 0 || length >= executable.size()) throw std::runtime_error("Cannot locate game executable");
        const auto path = std::filesystem::path(executable.data()).parent_path() / L"sku_config.txt";
        if (!std::filesystem::exists(path)) {
            log::write("SKU auto-decrypt skipped: no sku_config.txt beside the game executable");
            return true;
        }
        log::write(sku::decrypt_file(path)
            ? "SKU config decrypted to plaintext; original saved as sku_config.txt.encrypted.bak"
            : "SKU config already plaintext; left unchanged");
        return true;
    } catch (const std::exception& error) {
        log::write(std::string("SKU auto-decrypt failed: ") + error.what());
        return false;
    }
}

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

    const bool configReady = create_default_configuration();
    log::initialize();
    if (!configReady) {
        log::write("Cannot create modloader.ini from embedded defaults; check directory permissions");
        log::shutdown();
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
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

    if (!prepare_sku()) {
        (void)tls::uninstall();
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
