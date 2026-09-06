#include "steam/backend.h"

#include <Windows.h>

#include <array>
#include <string>

#include "core/log.h"
#include "core/runtime.h"

namespace d2mod::backend {
namespace {

using SteamInit = bool (*)() noexcept;
using SteamShutdown = void (*)() noexcept;
using SteamRunCallbacks = void (*)() noexcept;
using SteamRestartAppIfNecessary = bool (*)(DWORD) noexcept;
using SteamIsRunning = bool (*)() noexcept;
using SteamGetUser = UserHandle (*)() noexcept;
using SteamGetPipe = PipeHandle (*)() noexcept;
using SteamRegisterCallback = void (*)(void*, int) noexcept;
using SteamUnregisterCallback = void (*)(void*) noexcept;
using SteamRegisterCallResult = void (*)(void*, ApiCall) noexcept;
using SteamUnregisterCallResult = void (*)(void*, ApiCall) noexcept;
using SteamContextInit = void* (*)(void*) noexcept;
using SteamCreateInterface = void* (*)(const char*) noexcept;
using SteamFindOrCreateUserInterface = void* (*)(UserHandle, const char*) noexcept;

struct Exports {
    SteamInit init{};
    SteamShutdown shutdown{};
    SteamRunCallbacks runCallbacks{};
    SteamRestartAppIfNecessary restartAppIfNecessary{};
    SteamIsRunning isRunning{};
    SteamGetUser getUser{};
    SteamGetPipe getPipe{};
    SteamRegisterCallback registerCallback{};
    SteamUnregisterCallback unregisterCallback{};
    SteamRegisterCallResult registerCallResult{};
    SteamUnregisterCallResult unregisterCallResult{};
    SteamContextInit contextInit{};
    SteamCreateInterface createInterface{};
    SteamFindOrCreateUserInterface findOrCreateUserInterface{};
};

HMODULE g_module{};
Exports g_exports{};
SRWLOCK g_lock{SRWLOCK_INIT};
bool g_attempted{};

template <typename T>
bool bind(T& destination, const char* name) noexcept {
    destination = reinterpret_cast<T>(GetProcAddress(g_module, name));
    if (destination == nullptr) {
        std::string message = "original Steam DLL missing export: ";
        message.append(name);
        log::write(message);
        return false;
    }
    return true;
}

std::wstring configured_original_path() {
    std::array<wchar_t, 32768> value{};
    const std::wstring ini = runtime::configuration_path();
    GetPrivateProfileStringW(L"steam",
                             L"original_dll",
                             L"steam_api64_original.dll",
                             value.data(),
                             static_cast<DWORD>(value.size()),
                             ini.c_str());

    std::wstring path(value.data());
    if (path.find(L':') == std::wstring::npos && !path.starts_with(L"\\\\")) {
        std::wstring absolute = runtime::module_directory();
        if (!absolute.empty() && absolute.back() != L'\\') {
            absolute.push_back(L'\\');
        }
        absolute.append(path);
        path = std::move(absolute);
    }
    return path;
}

} // namespace

bool initialize() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_attempted) {
        const bool loaded = g_module != nullptr;
        ReleaseSRWLockExclusive(&g_lock);
        return loaded;
    }
    g_attempted = true;

    const std::wstring path = configured_original_path();
    if (path.empty()) {
        log::write("original Steam DLL path is empty");
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    g_module = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    if (g_module == nullptr) {
        log::write("could not load original Steam DLL");
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    const bool complete =
        bind(g_exports.init, "SteamAPI_Init")
        && bind(g_exports.shutdown, "SteamAPI_Shutdown")
        && bind(g_exports.runCallbacks, "SteamAPI_RunCallbacks")
        && bind(g_exports.restartAppIfNecessary, "SteamAPI_RestartAppIfNecessary")
        && bind(g_exports.isRunning, "SteamAPI_IsSteamRunning")
        && bind(g_exports.getUser, "SteamAPI_GetHSteamUser")
        && bind(g_exports.getPipe, "SteamAPI_GetHSteamPipe")
        && bind(g_exports.registerCallback, "SteamAPI_RegisterCallback")
        && bind(g_exports.unregisterCallback, "SteamAPI_UnregisterCallback")
        && bind(g_exports.registerCallResult, "SteamAPI_RegisterCallResult")
        && bind(g_exports.unregisterCallResult, "SteamAPI_UnregisterCallResult")
        && bind(g_exports.contextInit, "SteamInternal_ContextInit")
        && bind(g_exports.createInterface, "SteamInternal_CreateInterface")
        && bind(g_exports.findOrCreateUserInterface, "SteamInternal_FindOrCreateUserInterface");

    if (!complete) {
        FreeLibrary(g_module);
        g_module = nullptr;
        g_exports = {};
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    log::write("original Steam DLL loaded; Steam behavior is fully delegated");
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

bool is_loaded() noexcept { return g_module != nullptr; }

bool steam_init() noexcept { return initialize() && g_exports.init(); }
void steam_shutdown() noexcept {
    if (initialize() && g_exports.shutdown != nullptr) {
        g_exports.shutdown();
    }
}
void steam_run_callbacks() noexcept {
    if (initialize() && g_exports.runCallbacks != nullptr) {
        g_exports.runCallbacks();
    }
}
bool steam_restart_app_if_necessary(const DWORD appId) noexcept {
    return initialize() && g_exports.restartAppIfNecessary(appId);
}
bool steam_is_running() noexcept {
    return initialize() && g_exports.isRunning();
}
UserHandle steam_get_user() noexcept {
    return initialize() ? g_exports.getUser() : 0;
}
PipeHandle steam_get_pipe() noexcept {
    return initialize() ? g_exports.getPipe() : 0;
}
void steam_register_callback(void* const callback, const int callbackId) noexcept {
    if (initialize()) {
        g_exports.registerCallback(callback, callbackId);
    }
}
void steam_unregister_callback(void* const callback) noexcept {
    if (initialize()) {
        g_exports.unregisterCallback(callback);
    }
}
void steam_register_call_result(void* const callback, const ApiCall call) noexcept {
    if (initialize()) {
        g_exports.registerCallResult(callback, call);
    }
}
void steam_unregister_call_result(void* const callback, const ApiCall call) noexcept {
    if (initialize()) {
        g_exports.unregisterCallResult(callback, call);
    }
}
void* steam_context_init(void* const data) noexcept {
    return initialize() ? g_exports.contextInit(data) : nullptr;
}
void* steam_create_interface(const char* const version) noexcept {
    return initialize() ? g_exports.createInterface(version) : nullptr;
}
void* steam_find_or_create_user_interface(const UserHandle user, const char* const version) noexcept {
    return initialize() ? g_exports.findOrCreateUserInterface(user, version) : nullptr;
}

} // namespace d2mod::backend
