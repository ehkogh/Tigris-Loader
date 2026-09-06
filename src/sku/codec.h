#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace d2mod::sku {

enum class Format { plaintext, encrypted, signed_encrypted };
struct Document {
    Format format{};
    std::string text;
};

Document decode(std::span<const std::uint8_t> input);
std::vector<std::uint8_t> encode(std::string_view text);
void validate(std::string_view text);
std::string_view format_name(Format format) noexcept;

} // namespace d2mod::sku
