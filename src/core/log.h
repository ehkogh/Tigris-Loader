#pragma once

#include <string_view>
#include <cstdint>

namespace d2mod::log {

void initialize() noexcept;
void shutdown() noexcept;
void write(std::string_view message) noexcept;
void write_game(std::int32_t site, std::string_view message) noexcept;

} // namespace d2mod::log
