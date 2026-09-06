#pragma once

#include <Windows.h>

#include <cstdint>

namespace d2mod::backend {

using UserHandle = std::int32_t;
using PipeHandle = std::int32_t;
using ApiCall = std::uint64_t;

[[nodiscard]] bool initialize() noexcept;
[[nodiscard]] bool is_loaded() noexcept;

bool steam_init() noexcept;
void steam_shutdown() noexcept;
void steam_run_callbacks() noexcept;
bool steam_restart_app_if_necessary(DWORD appId) noexcept;
bool steam_is_running() noexcept;
UserHandle steam_get_user() noexcept;
PipeHandle steam_get_pipe() noexcept;
void steam_register_callback(void* callback, int callbackId) noexcept;
void steam_unregister_callback(void* callback) noexcept;
void steam_register_call_result(void* callback, ApiCall call) noexcept;
void steam_unregister_call_result(void* callback, ApiCall call) noexcept;
void* steam_context_init(void* data) noexcept;
void* steam_create_interface(const char* version) noexcept;
void* steam_find_or_create_user_interface(UserHandle user, const char* version) noexcept;

} // namespace d2mod::backend
