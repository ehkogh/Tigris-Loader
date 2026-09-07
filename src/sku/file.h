#pragma once

#include <filesystem>

namespace d2mod::sku {
// Returns false for an already plaintext file. Throws without replacing the
// input if decoding, validation, backup, or writing the replacement fails.
bool decrypt_file(const std::filesystem::path& path);
}
