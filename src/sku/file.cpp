#include "sku/file.h"

#include <Windows.h>

#include <fstream>
#include <stdexcept>
#include <vector>

#include "sku/codec.h"

namespace d2mod::sku {
namespace {
std::vector<std::uint8_t> read(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Could not open SKU file");
    const auto size = stream.tellg();
    if (size <= 0 || size > 1024 * 1024 + 264) throw std::runtime_error("SKU file is empty or too large");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(bytes.data()), size)) {
        throw std::runtime_error("Could not read complete SKU file");
    }
    return bytes;
}
}

bool decrypt_file(const std::filesystem::path& path) {
    const auto bytes = read(path);
    const auto document = decode(bytes);
    if (document.format == Format::plaintext) return false;
    validate(document.text);

    auto backup = path;
    backup += L".encrypted.bak";
    if (!CopyFileW(path.c_str(), backup.c_str(), TRUE)) {
        if (GetLastError() != ERROR_FILE_EXISTS || read(backup) != bytes) {
            throw std::runtime_error("Cannot preserve encrypted SKU backup; existing backups are never overwritten");
        }
    }

    auto temporary = path;
    temporary += L".decrypting";
    const HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Cannot create SKU temporary file; check permissions or a leftover .decrypting file");
    }
    DWORD written{};
    const bool saved = WriteFile(file, document.text.data(), static_cast<DWORD>(document.text.size()),
                                &written, nullptr) && written == document.text.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!saved) {
        DeleteFileW(temporary.c_str());
        throw std::runtime_error("Cannot write complete plaintext SKU file");
    }
    // Check that the original has not been edited while preparing its replacement.
    try {
        if (read(path) != bytes) throw std::runtime_error("SKU file changed during conversion");
        if (!ReplaceFileW(path.c_str(), temporary.c_str(), nullptr, 0, nullptr, nullptr)) {
            throw std::runtime_error("Cannot replace encrypted SKU file; encrypted backup retained");
        }
    } catch (...) {
        DeleteFileW(temporary.c_str());
        throw;
    }
    return true;
}
}
