#include <Windows.h>

#include "steam/backend.h"
#include "core/runtime.h"

extern "C" __declspec(dllexport) bool SteamAPI_Init() noexcept {
    if (!d2mod::runtime::initialize()) {
        return false;
    }
    if (!d2mod::backend::steam_init()) {
        d2mod::runtime::shutdown();
        return false;
    }
    return true;
}

extern "C" __declspec(dllexport) void SteamAPI_Shutdown() noexcept {
    d2mod::backend::steam_shutdown();
    d2mod::runtime::shutdown();
}

extern "C" __declspec(dllexport) void SteamAPI_RunCallbacks() noexcept {
    d2mod::runtime::on_callback_pump();
    d2mod::backend::steam_run_callbacks();
}

extern "C" __declspec(dllexport) bool SteamAPI_RestartAppIfNecessary(const DWORD appId) noexcept {
    if (!d2mod::runtime::initialize()) {
        return false;
    }
    return d2mod::backend::steam_restart_app_if_necessary(appId);
}

extern "C" __declspec(dllexport) bool SteamAPI_IsSteamRunning() noexcept {
    return d2mod::backend::steam_is_running();
}

extern "C" __declspec(dllexport) d2mod::backend::UserHandle SteamAPI_GetHSteamUser() noexcept {
    return d2mod::backend::steam_get_user();
}

extern "C" __declspec(dllexport) d2mod::backend::PipeHandle SteamAPI_GetHSteamPipe() noexcept {
    return d2mod::backend::steam_get_pipe();
}

extern "C" __declspec(dllexport) void SteamAPI_RegisterCallback(void* const callback,
                                                                const int callbackId) noexcept {
    d2mod::backend::steam_register_callback(callback, callbackId);
}

extern "C" __declspec(dllexport) void SteamAPI_UnregisterCallback(void* const callback) noexcept {
    d2mod::backend::steam_unregister_callback(callback);
}

extern "C" __declspec(dllexport) void
SteamAPI_RegisterCallResult(void* const callback, const d2mod::backend::ApiCall call) noexcept {
    d2mod::backend::steam_register_call_result(callback, call);
}

extern "C" __declspec(dllexport) void
SteamAPI_UnregisterCallResult(void* const callback, const d2mod::backend::ApiCall call) noexcept {
    d2mod::backend::steam_unregister_call_result(callback, call);
}

extern "C" __declspec(dllexport) void* SteamInternal_ContextInit(void* const data) noexcept {
    return d2mod::backend::steam_context_init(data);
}

extern "C" __declspec(dllexport) void*
SteamInternal_FindOrCreateUserInterface(const d2mod::backend::UserHandle user,
                                        const char* const version) noexcept {
    return d2mod::backend::steam_find_or_create_user_interface(user, version);
}

extern "C" __declspec(dllexport) void* SteamInternal_CreateInterface(const char* const version) noexcept {
    return d2mod::backend::steam_create_interface(version);
}

BOOL WINAPI DllMain(const HINSTANCE instance, const DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        d2mod::runtime::set_module(instance);
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
