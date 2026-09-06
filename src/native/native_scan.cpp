#include "native/native_scan.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>

namespace d2mod::native {

ImageView main_image() noexcept {
    const HMODULE module = GetModuleHandleW(nullptr);
    if (module == nullptr) {
        return {};
    }

    auto* const base = reinterpret_cast<std::byte*>(module);
    const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return {};
    }

    const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
        || nt->OptionalHeader.SizeOfImage == 0) {
        return {};
    }
    return {base, static_cast<std::size_t>(nt->OptionalHeader.SizeOfImage)};
}

std::byte* scan_unique(const ImageView image,
                       const std::span<const PatternByte> pattern) noexcept {
    if (image.base == nullptr || image.size == 0 || pattern.empty()
        || pattern.size() > image.size) {
        return nullptr;
    }

    std::byte* match = nullptr;
    const std::size_t last = image.size - pattern.size();
    for (std::size_t offset = 0; offset <= last; ++offset) {
        bool matches = true;
        for (std::size_t index = 0; index < pattern.size(); ++index) {
            if (!pattern[index].wildcard
                && static_cast<std::uint8_t>(image.base[offset + index]) != pattern[index].value) {
                matches = false;
                break;
            }
        }
        if (!matches) {
            continue;
        }
        if (match != nullptr) {
            return nullptr;
        }
        match = image.base + offset;
    }
    return match;
}

} // namespace d2mod::native

