#include "mods/package_runtime.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <set>
#include <string>
#include <utility>

#include "core/log.h"
#include "mods/mod_catalog.h"
#include "native/native_scan.h"
#include "core/runtime.h"

namespace d2mod::packages {
namespace {

constexpr std::array<native::PatternByte, 21> kPackageRegistrationPattern{{
    {0x48, false}, {0x89, false}, {0x5C, false}, {0x24, false}, {0x00, true},
    {0x48, false}, {0x89, false}, {0x6C, false}, {0x24, false}, {0x00, true},
    {0x56, false}, {0x57, false}, {0x41, false}, {0x56, false}, {0x48, false},
    {0x83, false}, {0xEC, false}, {0x20, false}, {0x49, false}, {0x8B, false},
    {0xF9, false},
}};

using PackageRegistration = void(__fastcall*)(const char* path,
                                               const std::uint32_t* validationFlags,
                                               std::uint16_t expectedPackageId,
                                               std::uint64_t manifestQword,
                                               std::uint32_t manifestRow) noexcept;

bool registration_enabled() noexcept {
    const std::wstring ini = runtime::configuration_path();
    return GetPrivateProfileIntW(L"packages", L"register_discovered", 1, ini.c_str()) != 0;
}

std::string narrow_path(const std::wstring& value) {
    BOOL usedDefault = FALSE;
    const int required = WideCharToMultiByte(CP_ACP,
                                             WC_NO_BEST_FIT_CHARS,
                                             value.c_str(),
                                             -1,
                                             nullptr,
                                             0,
                                             nullptr,
                                             &usedDefault);
    if (required <= 1 || usedDefault != FALSE) {
        return {};
    }

    std::string result(static_cast<std::size_t>(required), '\0');
    usedDefault = FALSE;
    const int written = WideCharToMultiByte(CP_ACP,
                                            WC_NO_BEST_FIT_CHARS,
                                            value.c_str(),
                                            -1,
                                            result.data(),
                                            required,
                                            nullptr,
                                            &usedDefault);
    if (written != required || usedDefault != FALSE) {
        return {};
    }
    result.resize(static_cast<std::size_t>(required - 1));
    return result;
}

PackageRegistration resolve_registration() noexcept {
    const native::ImageView image = native::main_image();
    if (image.base == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<PackageRegistration>(native::scan_unique(image, kPackageRegistrationPattern));
}

} // namespace

void activate_discovered() noexcept {
    if (!registration_enabled()) {
        log::write("discovered package registration disabled by config");
        return;
    }

    const PackageRegistration registration = resolve_registration();
    if (registration == nullptr) {
        log::write("package_registration target did not resolve uniquely for this build");
        return;
    }

    std::set<std::pair<std::uint16_t, std::uint16_t>> submitted;
    std::uint32_t validationFlags = 0x02;
    std::size_t count = 0;

    for (const mods::ModRecord& mod : mods::catalog()) {
        for (const mods::PackageFile& package : mod.packages) {
            const auto identity = std::pair{package.packageId, package.patchId};
            if (!submitted.insert(identity).second) {
                log::write("skipping duplicate mod package_id/patch_id pair");
                continue;
            }

            const std::string path = narrow_path(package.path);
            if (path.empty() || path.size() >= 256) {
                log::write("skipping package whose native path is not representable in 255 bytes");
                continue;
            }

            registration(path.c_str(),
                         &validationFlags,
                         package.packageId,
                         0,
                         0xFFFFFFFFu);
            ++count;

            std::array<char, 256> message{};
            const int length = std::snprintf(message.data(),
                                             message.size(),
                                             "submitted mod package package=0x%04X patch=%u",
                                             package.packageId,
                                             package.patchId);
            if (length > 0) {
                log::write(std::string_view(message.data(), static_cast<std::size_t>(length)));
            }
        }
    }

    std::array<char, 128> message{};
    const int length = std::snprintf(message.data(),
                                     message.size(),
                                     "submitted discovered mod packages count=%zu",
                                     count);
    if (length > 0) {
        log::write(std::string_view(message.data(), static_cast<std::size_t>(length)));
    }
}

} // namespace d2mod::packages
