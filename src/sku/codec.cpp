#include "sku/codec.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <map>
#include <stdexcept>

namespace d2mod::sku {
namespace {

constexpr std::size_t kBlockSize = 16;
constexpr std::size_t kSignedHeaderSize = 264;
constexpr std::size_t kMaxSize = 1024 * 1024;
constexpr std::array<std::uint8_t, 16> kKey{
    0x54, 0x00, 0x00, 0x00, 0x4D, 0x04, 0x6E, 0x79,
    0x00, 0x05, 0x03, 0x63, 0x72, 0x03, 0x74, 0x05
};
constexpr std::array<std::uint8_t, 16> kIv{
    0x04, 0x74, 0x00, 0x04, 0x6C, 0x6C, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x04, 0x02, 0x01, 0x06
};
constexpr std::array<std::uint8_t, 8> kHeader{1, 0, 0, 0, 0, 0, 0, 0};

void check(const NTSTATUS status, const char* operation) {
    if (status < 0) {
        throw std::runtime_error(std::string("Windows AES operation failed: ") + operation);
    }
}

std::vector<std::uint8_t> crypt(std::span<const std::uint8_t> input, bool encrypt) {
    struct Handles {
        BCRYPT_ALG_HANDLE algorithm{};
        BCRYPT_KEY_HANDLE key{};
        ~Handles() {
            if (key != nullptr) BCryptDestroyKey(key);
            if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    } handles;
    check(BCryptOpenAlgorithmProvider(&handles.algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0), "open");
    check(BCryptSetProperty(handles.algorithm, BCRYPT_CHAINING_MODE,
                            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                            sizeof(BCRYPT_CHAIN_MODE_CBC), 0), "CBC mode");
    auto key = kKey;
    check(BCryptGenerateSymmetricKey(handles.algorithm, &handles.key, nullptr, 0,
                                     key.data(), static_cast<ULONG>(key.size()), 0), "key setup");
    auto iv = kIv;
    std::vector<std::uint8_t> output(input.size());
    ULONG written = 0;
    const auto operation = encrypt ? BCryptEncrypt : BCryptDecrypt;
    check(operation(handles.key, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()),
                    nullptr, iv.data(), static_cast<ULONG>(iv.size()), output.data(),
                    static_cast<ULONG>(output.size()), &written, 0), "transform");
    output.resize(written);
    return output;
}

int number(const std::string& value, const char* key) {
    int output{};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), output);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
        throw std::runtime_error(std::string(key) + " must be a decimal integer");
    }
    return output;
}

} // namespace

void validate(const std::string_view text) {
    if (text.empty() || text.size() > kMaxSize) {
        throw std::runtime_error("Config must contain between 1 byte and 1 MiB of text");
    }
    if (!text.starts_with("version=2\n") && !text.starts_with("version=2\r\n")) {
        throw std::runtime_error("Config must start with version=2 on its own line, without a BOM");
    }
    for (const unsigned char c : text) {
        if ((c < 32 && c != '\r' && c != '\n' && c != '\t') || c >= 127) {
            throw std::runtime_error("Config must be ASCII text without NUL or control characters");
        }
    }
    std::map<std::string, std::string> options;
    unsigned signonCount = 0;
    for (std::size_t position = 0; position < text.size();) {
        const auto end = text.find('\n', position);
        auto line = text.substr(position, end == text.npos ? text.size() - position : end - position);
        position = end == text.npos ? text.size() : end + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
            line.remove_suffix(1);
        }
        if (line.size() >= 2047) throw std::runtime_error("Config line exceeds the client's line buffer");
        if (line.empty() || line.front() == ';') continue;
        const auto equals = line.find('=');
        if (equals == line.npos) throw std::runtime_error("Expected key=value on every non-comment line");
        std::string key(line.substr(0, equals));
        for (char& c : key) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        const std::string value(line.substr(equals + 1));
        if (value.empty()) throw std::runtime_error("Empty value for " + key);
        const std::array<std::string_view, 10> known{
            "version", "sku_type", "ui_language", "audio_language", "default_language",
            "base_content_version", "signon_url", "group_overrides", "demo_mode",
            "application_password_signature"
        };
        if (std::find(known.begin(), known.end(), key) == known.end()) {
            throw std::runtime_error("Unknown config key: " + key);
        }
        if (key == "signon_url") {
            if (++signonCount > 2 || value.size() > 124) {
                throw std::runtime_error("At most two signon_url values of 124 bytes each are supported");
            }
        } else if (options.contains(key)) {
            throw std::runtime_error("Duplicate config key: " + key);
        }
        options[key] = value;
    }
    for (const char* key : {"version", "sku_type", "ui_language", "audio_language",
                            "default_language", "base_content_version"}) {
        if (!options.contains(key)) throw std::runtime_error(std::string("Missing required key: ") + key);
    }
    if (number(options.at("version"), "version") != 2) throw std::runtime_error("version must equal 2");
    const int ui = number(options.at("ui_language"), "ui_language");
    const int audio = number(options.at("audio_language"), "audio_language");
    const int language = number(options.at("default_language"), "default_language");
    if (ui < 1 || ui > 8191 || audio < 1 || audio > 8191 || language < 0 || language > 12
        || (ui & (1 << language)) == 0 || (audio & (1 << language)) == 0) {
        throw std::runtime_error("Language masks must be 1..8191 and both include default_language (0..12)");
    }
    const std::array<std::string_view, 9> skus{
        "default", "north_america_digital", "north_america_disc", "europe_digital", "europe_disc",
        "japan_digital", "japan_disc", "asia_digital", "asia_disc"
    };
    if (std::find(skus.begin(), skus.end(), options.at("sku_type")) == skus.end()) {
        throw std::runtime_error("Unknown sku_type");
    }
    if (options.at("base_content_version").size() > 63
        || (options.contains("group_overrides") && options.at("group_overrides").size() > 255)) {
        throw std::runtime_error("Config value exceeds the client's string buffer");
    }
    if (options.contains("demo_mode") && number(options.at("demo_mode"), "demo_mode") != 1) {
        throw std::runtime_error("demo_mode, when present, must equal 1");
    }
    if (options.contains("application_password_signature")
        && options.at("application_password_signature").size() != 40) {
        throw std::runtime_error("application_password_signature must contain exactly 40 characters");
    }
}

Document decode(const std::span<const std::uint8_t> input) {
    if (input.empty() || input.size() > kMaxSize + kSignedHeaderSize) {
        throw std::runtime_error("Input is empty or larger than 1 MiB plus its header");
    }
    constexpr std::string_view prefix = "version";
    if (input.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), input.begin())) {
        return {Format::plaintext, std::string(input.begin(), input.end())};
    }
    auto payload = input;
    Format format = Format::encrypted;
    if (input.size() >= kHeader.size() && std::equal(kHeader.begin(), kHeader.end(), input.begin())) {
        if (input.size() <= kSignedHeaderSize) throw std::runtime_error("Truncated signed SKU header");
        payload = input.subspan(kSignedHeaderSize);
        format = Format::signed_encrypted;
    }
    if (payload.size() % kBlockSize != 0) {
        throw std::runtime_error("Encrypted payload length must be a multiple of 16 bytes");
    }
    auto plain = crypt(payload, false);
    while (!plain.empty() && plain.back() == 0) plain.pop_back();
    if (plain.empty() || std::find(plain.begin(), plain.end(), 0) != plain.end()
        || !std::all_of(plain.begin(), plain.end(), [](std::uint8_t c) {
               return (c >= 32 && c < 127) || c == '\r' || c == '\n' || c == '\t';
           })) {
        throw std::runtime_error("Decoded data is not SKU text (wrong format, build, or damaged ciphertext)");
    }
    return {format, std::string(plain.begin(), plain.end())};
}

std::vector<std::uint8_t> encode(const std::string_view text) {
    validate(text);
    std::vector<std::uint8_t> padded(text.begin(), text.end());
    padded.resize((padded.size() + kBlockSize - 1) / kBlockSize * kBlockSize, 0);
    return crypt(padded, true);
}

std::string_view format_name(const Format format) noexcept {
    switch (format) {
    case Format::plaintext: return "plaintext";
    case Format::encrypted: return "unsigned AES-CBC payload";
    case Format::signed_encrypted: return "retail signature header + AES-CBC payload (signature not verified)";
    }
    return "unknown";
}

} // namespace d2mod::sku
