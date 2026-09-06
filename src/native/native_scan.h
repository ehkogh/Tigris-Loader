#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <span>

namespace d2mod::native {

struct PatternByte {
    std::uint8_t value{};
    bool wildcard{};
};

struct ImageView {
    std::byte* base{};
    std::size_t size{};
};

ImageView main_image() noexcept;
std::byte* scan_unique(ImageView image, std::span<const PatternByte> pattern) noexcept;

} // namespace d2mod::native

