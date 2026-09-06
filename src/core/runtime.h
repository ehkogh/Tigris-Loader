#pragma once

#include <Windows.h>

#include <string>

namespace d2mod::runtime {

void set_module(HMODULE module) noexcept;
bool initialize() noexcept;
void shutdown() noexcept;
void on_callback_pump() noexcept;

std::wstring module_directory();
std::wstring configuration_path();

} // namespace d2mod::runtime

