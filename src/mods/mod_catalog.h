#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace d2mod::mods {

struct PackageFile {
    std::wstring path;
    std::uint16_t packageId{};
    std::uint16_t patchId{};
    std::uint32_t headerFileSize{};
};

struct ModRecord {
    std::wstring id;
    std::wstring directory;
    std::vector<PackageFile> packages;
    std::vector<std::wstring> scripts;
};

void scan() noexcept;
const std::vector<ModRecord>& catalog() noexcept;

} // namespace d2mod::mods

