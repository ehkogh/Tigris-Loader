#include "sku/codec.h"

#include <Windows.h>
#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> read(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Could not open input file");
    const auto size = stream.tellg();
    if (size <= 0 || size > 1024 * 1024 + 264) throw std::runtime_error("Input is empty or too large");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(bytes.data()), size)) {
        throw std::runtime_error("Could not read complete input file");
    }
    return bytes;
}

void save(const std::filesystem::path& path, const std::span<const std::uint8_t> bytes, const bool force) {
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                    force ? CREATE_ALWAYS : CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Could not create output (use --force to overwrite an existing file)");
    }
    DWORD written = 0;
    const bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr)
                    && written == bytes.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!ok) throw std::runtime_error("Could not write complete output file");
}

void usage() {
    std::cout << "SKU Config Tool - Destiny 2 build 86657\n\n"
                 "  sku_config view <file>\n"
                 "  sku_config decode <file> <text-output> [--force]\n"
                 "  sku_config encode <text-file> <encrypted-output> [--template <retail-file>] [--force]\n"
                 "  sku_config check <file>\n\n"
                 "decode also accepts plaintext or unsigned encrypted payloads.\n"
                 "encode writes a headerless AES-CBC payload for [sku] allow_unsigned=1.\n"
                 "--template preserves the retail header only when the encrypted payload is unchanged.\n"
                 "Retail signatures cannot be regenerated after editing. check validates options, not signatures.\n";
}

} // namespace

int wmain(const int argc, wchar_t** argv) {
    try {
        // Preserve existing CRLF when viewing or redirecting decoded text.
        (void)_setmode(_fileno(stdout), _O_BINARY);
        if (argc == 1 || (argc == 2 && std::wstring_view(argv[1]) == L"--help")) {
            usage();
            return 0;
        }
        if (argc < 3) throw std::runtime_error("Missing command or input; run --help");
        const std::wstring_view command(argv[1]);
        const bool writes = command == L"decode" || command == L"encode";
        if (!writes && command != L"view" && command != L"check") {
            throw std::runtime_error("Unknown command; run --help");
        }
        if (writes && argc < 4) throw std::runtime_error("Missing output filename");
        bool force = false;
        std::filesystem::path original;
        for (int i = writes ? 4 : 3; i < argc; ++i) {
            const std::wstring_view argument(argv[i]);
            if (writes && argument == L"--force") {
                force = true;
            } else if (command == L"encode" && argument == L"--template" && i + 1 < argc) {
                original = argv[++i];
            } else {
                throw std::runtime_error("Unexpected argument; run --help");
            }
        }
        const auto input = read(argv[2]);
        const auto document = d2mod::sku::decode(input);
        if (command == L"view") {
            std::cerr << "Format: " << d2mod::sku::format_name(document.format) << '\n';
            std::cout << document.text;
            if (document.text.empty() || document.text.back() != '\n') std::cout << '\n';
            return 0;
        }
        if (command == L"check") {
            d2mod::sku::validate(document.text);
            std::cout << "Valid build-86657 options; " << d2mod::sku::format_name(document.format) << '\n';
            return 0;
        }
        if (command == L"decode") {
            save(argv[3], {reinterpret_cast<const std::uint8_t*>(document.text.data()), document.text.size()}, force);
            std::cout << "Decoded text saved. Edit it, then use encode to rebuild.\n";
        } else {
            if (document.format != d2mod::sku::Format::plaintext) {
                throw std::runtime_error("encode expects plaintext; decode the input first");
            }
            auto output = d2mod::sku::encode(document.text);
            if (!original.empty()) {
                const auto retail = read(original);
                const auto retailDocument = d2mod::sku::decode(retail);
                if (retailDocument.format != d2mod::sku::Format::signed_encrypted) {
                    throw std::runtime_error("--template must be an original signed retail config");
                }
                constexpr std::size_t headerSize = 264;
                if (retail.size() != output.size() + headerSize
                    || !std::equal(output.begin(), output.end(), retail.begin() + headerSize)) {
                    throw std::runtime_error("Edited payload cannot reuse the retail signature. Omit --template and use [sku] allow_unsigned=1");
                }
                output.insert(output.begin(), retail.begin(), retail.begin() + headerSize);
            }
            save(argv[3], output, force);
            std::cout << (original.empty()
                ? "Encrypted payload saved. Set [sku] allow_unsigned=1 in modloader.ini to load it.\n"
                : "Original signed envelope preserved byte for byte (signature not verified).\n");
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "sku_config: " << error.what() << '\n';
        return 1;
    }
}
