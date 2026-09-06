#include "mods/mod_catalog.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <system_error>

#include "core/log.h"
#include "core/runtime.h"

namespace d2mod::mods {
namespace {

std::vector<ModRecord> g_catalog;

std::wstring configured_mod_directory() {
    std::array<wchar_t, 32768> value{};
    const std::wstring ini = runtime::configuration_path();
    GetPrivateProfileStringW(L"mods",
                             L"directory",
                             L"mods",
                             value.data(),
                             static_cast<DWORD>(value.size()),
                             ini.c_str());
    std::filesystem::path path(value.data());
    if (path.is_relative()) {
        path = std::filesystem::path(runtime::module_directory()) / path;
    }
    return path.wstring();
}

bool read_package_header(const std::filesystem::path& path, PackageFile& out) noexcept {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    std::array<std::byte, 0x168> header{};
    file.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (file.gcount() != static_cast<std::streamsize>(header.size())) {
        return false;
    }

    std::memcpy(&out.packageId, header.data() + 0x04, sizeof out.packageId);
    std::memcpy(&out.patchId, header.data() + 0x20, sizeof out.patchId);
    std::memcpy(&out.headerFileSize, header.data() + 0x164, sizeof out.headerFileSize);
    out.path = path.wstring();
    return true;
}

void log_mod(const ModRecord& mod) noexcept {
    std::array<char, 512> message{};
    const int length = std::snprintf(message.data(),
                                     message.size(),
                                     "mod discovered packages=%zu scripts=%zu",
                                     mod.packages.size(),
                                     mod.scripts.size());
    if (length > 0) {
        log::write(std::string_view(message.data(), static_cast<std::size_t>(length)));
    }

    for (const PackageFile& package : mod.packages) {
        std::array<char, 512> packageMessage{};
        const int packageLength = std::snprintf(packageMessage.data(),
                                                packageMessage.size(),
                                                "package discovered package=0x%04X patch=%u header_size=%u",
                                                package.packageId,
                                                package.patchId,
                                                package.headerFileSize);
        if (packageLength > 0) {
            log::write(std::string_view(packageMessage.data(),
                                        static_cast<std::size_t>(packageLength)));
        }
    }
}

} // namespace

void scan() noexcept {
    g_catalog.clear();

    const std::filesystem::path root(configured_mod_directory());
    std::error_code error;
    if (!std::filesystem::exists(root, error)) {
        std::filesystem::create_directories(root, error);
    }
    if (error) {
        log::write("mod catalog root unavailable");
        return;
    }

    for (std::filesystem::directory_iterator it(root, error), end; it != end && !error;
         it.increment(error)) {
        if (!it->is_directory(error) || error) {
            continue;
        }

        ModRecord mod{};
        mod.id = it->path().filename().wstring();
        mod.directory = it->path().wstring();

        const std::filesystem::path packages = it->path() / L"packages";
        if (std::filesystem::exists(packages, error) && !error) {
            for (std::filesystem::directory_iterator packageIt(packages, error), packageEnd;
                 packageIt != packageEnd && !error;
                 packageIt.increment(error)) {
                if (!packageIt->is_regular_file(error) || error
                    || packageIt->path().extension() != L".pkg") {
                    continue;
                }
                PackageFile package{};
                if (read_package_header(packageIt->path(), package)) {
                    mod.packages.push_back(std::move(package));
                } else {
                    log::write("ignored unreadable package file");
                }
            }
        }
        error.clear();

        const std::filesystem::path scripts = it->path() / L"scripts";
        if (std::filesystem::exists(scripts, error) && !error) {
            for (std::filesystem::recursive_directory_iterator scriptIt(scripts, error), scriptEnd;
                 scriptIt != scriptEnd && !error;
                 scriptIt.increment(error)) {
                if (scriptIt->is_regular_file(error) && !error
                    && scriptIt->path().extension() == L".lua") {
                    mod.scripts.push_back(scriptIt->path().wstring());
                }
            }
        }
        error.clear();

        std::sort(mod.packages.begin(),
                  mod.packages.end(),
                  [](const PackageFile& left, const PackageFile& right) {
                      if (left.packageId != right.packageId) {
                          return left.packageId < right.packageId;
                      }
                      if (left.patchId != right.patchId) {
                          return left.patchId < right.patchId;
                      }
                      return left.path < right.path;
                  });
        std::sort(mod.scripts.begin(), mod.scripts.end());
        log_mod(mod);
        g_catalog.push_back(std::move(mod));
    }

    if (error) {
        log::write("mod catalog scan ended with a filesystem error");
    }
    std::sort(g_catalog.begin(),
              g_catalog.end(),
              [](const ModRecord& left, const ModRecord& right) { return left.id < right.id; });
}

const std::vector<ModRecord>& catalog() noexcept { return g_catalog; }

} // namespace d2mod::mods
