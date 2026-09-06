#include "native/native_targets.h"

#include <Windows.h>

#include <cctype>
#include <cstring>
#include <string_view>
#include <vector>

#include "core/log.h"
#include "native/native_scan.h"

namespace d2mod::native::targets {
namespace {

constexpr std::string_view kControlledObjectPattern =
    "40 53 48 83 EC 20 48 8B D9 C7 01 FF FF FF FF 48 8D 4C 24 30 E8 ? ? ? ? "
    "8B 44 24 30 83 F8 FF 74 18 25 FF 1F 00 00 0F AF 05";
constexpr std::string_view kCameraTransformPattern =
    "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 48 8D 6C 24 E0 "
    "48 81 EC 20 01 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 10 0F 57 C0 48 63 F9";
constexpr std::string_view kBootStepPattern =
    "48 83 EC 28 E8 ? ? ? ? 48 85 C0 74 ? 8B 80 90 03 00 00 48 83 C4 28 C3 83 C8 FF";
constexpr std::string_view kNamedTagPattern =
    "48 89 5C 24 ? 4C 89 44 24 ? 48 89 54 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC";
constexpr std::string_view kFindComponentPattern =
    "48 89 5C 24 ? 57 48 81 EC 60 0C 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? "
    "49 8B F8 4C 8B D1 48 8D 4C 24 ? 41 83 C8 FF 49 8B D9 B8 40 00 00 00 66 66 0F 1F 84 00 ? ? ? ? "
    "66 44 89 01 48 8D 49 ? 48 83 E8 01 75 ? 44 89 84 24 ? ? ? ? 48 8D 4C 24 ? 44 8B C2 "
    "89 84 24 ? ? ? ? 49 8B D2 C7 44 24";
constexpr std::string_view kMarkerRefreshPattern =
    "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8D 6C 24 ? "
    "48 81 EC 90 00 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 8B 08";

constexpr std::size_t kControlledLocalDatumCall = 0x14;
constexpr std::size_t kControlledStrideLoad = 0x27;
constexpr std::size_t kControlledBaseLoad = 0x2E;
constexpr std::size_t kCameraSingletonCall = 0x72;
constexpr std::size_t kMarkerHandleTablesLoad = 0x66;
constexpr std::size_t kMarkerObjectTransformCall = 0xE3;

Table g_targets{};

[[nodiscard]] int hex_digit(const char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return 10 + value - 'a';
    if (value >= 'A' && value <= 'F') return 10 + value - 'A';
    return -1;
}

[[nodiscard]] std::vector<PatternByte> parse_pattern(const std::string_view text) {
    std::vector<PatternByte> pattern;
    std::size_t offset = 0;
    while (offset < text.size()) {
        while (offset < text.size() && std::isspace(static_cast<unsigned char>(text[offset])) != 0) {
            ++offset;
        }
        if (offset >= text.size()) break;
        if (text[offset] == '?') {
            pattern.push_back({0, true});
            while (offset < text.size() && text[offset] == '?') ++offset;
            continue;
        }
        if (offset + 1 >= text.size()) return {};
        const int high = hex_digit(text[offset]);
        const int low = hex_digit(text[offset + 1]);
        if (high < 0 || low < 0) return {};
        pattern.push_back({static_cast<std::uint8_t>((high << 4) | low), false});
        offset += 2;
    }
    return pattern;
}

[[nodiscard]] std::byte* find(const ImageView image, const std::string_view text) {
    const auto pattern = parse_pattern(text);
    return pattern.empty() ? nullptr : scan_unique(image, pattern);
}

[[nodiscard]] bool inside(const ImageView image, const void* address, const std::size_t bytes = 1) noexcept {
    if (image.base == nullptr || address == nullptr || bytes == 0) return false;
    const auto* value = static_cast<const std::byte*>(address);
    return value >= image.base && value <= image.base + image.size - bytes;
}

[[nodiscard]] std::byte* relative_call(const ImageView image,
                                       std::byte* function,
                                       const std::size_t offset) noexcept {
    std::byte* const site = function + offset;
    if (!inside(image, site, 5) || static_cast<std::uint8_t>(*site) != 0xE8) return nullptr;
    std::int32_t displacement{};
    std::memcpy(&displacement, site + 1, sizeof displacement);
    std::byte* const target = site + 5 + displacement;
    return inside(image, target) ? target : nullptr;
}

[[nodiscard]] std::byte* rip_target(const ImageView image,
                                    std::byte* instruction,
                                    const std::size_t displacementOffset,
                                    const std::size_t instructionLength) noexcept {
    if (!inside(image, instruction, instructionLength)) return nullptr;
    std::int32_t displacement{};
    std::memcpy(&displacement, instruction + displacementOffset, sizeof displacement);
    std::byte* const target = instruction + instructionLength + displacement;
    return inside(image, target, sizeof(void*)) ? target : nullptr;
}

[[nodiscard]] bool expected_bytes(const ImageView image,
                                  std::byte* address,
                                  const std::initializer_list<std::uint8_t> bytes) noexcept {
    if (!inside(image, address, bytes.size())) return false;
    std::size_t index = 0;
    for (const auto value : bytes) {
        if (static_cast<std::uint8_t>(address[index++]) != value) return false;
    }
    return true;
}

} // namespace

bool resolve() noexcept {
    if (is_resolved()) return true;

    const ImageView image = main_image();
    if (image.base == nullptr) {
        log::write("native scripting targets: main image unavailable");
        return false;
    }

    std::byte* const controlled = find(image, kControlledObjectPattern);
    std::byte* const camera = find(image, kCameraTransformPattern);
    std::byte* const bootStep = find(image, kBootStepPattern);
    std::byte* const namedTag = find(image, kNamedTagPattern);
    std::byte* const findComponent = find(image, kFindComponentPattern);
    std::byte* const markerRefresh = find(image, kMarkerRefreshPattern);
    if (controlled == nullptr || camera == nullptr || bootStep == nullptr || namedTag == nullptr
        || findComponent == nullptr || markerRefresh == nullptr) {
        log::write("native scripting targets: required build-86657 signature missing or non-unique");
        return false;
    }

    std::byte* const localDatum = relative_call(image, controlled, kControlledLocalDatumCall);
    std::byte* const cameraSingleton = relative_call(image, camera, kCameraSingletonCall);

    if (!expected_bytes(image, controlled + kControlledStrideLoad, {0x0F, 0xAF, 0x05})
        || !expected_bytes(image, controlled + kControlledBaseLoad, {0x48, 0x03, 0x05})) {
        log::write("native scripting targets: player registry derivation bytes changed");
        return false;
    }
    std::byte* const stride = rip_target(image, controlled + kControlledStrideLoad, 3, 7);
    std::byte* const rows = rip_target(image, controlled + kControlledBaseLoad, 3, 7);
    if (!expected_bytes(image, markerRefresh + kMarkerHandleTablesLoad, {0x48, 0x8B, 0x05})) {
        log::write("native scripting targets: shared handle-table derivation bytes changed");
        return false;
    }
    std::byte* const handleTables =
        rip_target(image, markerRefresh + kMarkerHandleTablesLoad, 3, 7);
    std::byte* const objectTransform =
        relative_call(image, markerRefresh, kMarkerObjectTransformCall);
    if (localDatum == nullptr || cameraSingleton == nullptr || stride == nullptr || rows == nullptr
        || handleTables == nullptr || objectTransform == nullptr) {
        log::write("native scripting targets: derived build-86657 target invalid");
        return false;
    }

    Table resolved;
    resolved.localPlayerDatum = reinterpret_cast<OutHandle>(localDatum);
    resolved.localControlledObject = reinterpret_cast<OutHandle>(controlled);
    resolved.cameraTransform = reinterpret_cast<CameraTransform>(camera);
    resolved.cameraSingleton = reinterpret_cast<CameraSingleton>(cameraSingleton);
    resolved.bootFlowGetStep = reinterpret_cast<BootFlowGetStep>(bootStep);
    resolved.lookupNamedTag = reinterpret_cast<LookupNamedTag>(namedTag);
    resolved.findFirstComponentByClass = reinterpret_cast<FindFirstComponentByClass>(findComponent);
    resolved.objectGetTransform = reinterpret_cast<ObjectGetTransform>(objectTransform);
    resolved.playerRows = reinterpret_cast<std::byte**>(rows);
    resolved.playerRowStride = reinterpret_cast<std::uint32_t*>(stride);
    resolved.handleTablesOwner = reinterpret_cast<std::byte**>(handleTables);
    g_targets = resolved;
    log::write("native scripting targets: build-86657 core resolved");
    return true;
}

bool is_resolved() noexcept {
    return g_targets.localPlayerDatum != nullptr && g_targets.localControlledObject != nullptr
           && g_targets.cameraSingleton != nullptr && g_targets.bootFlowGetStep != nullptr
           && g_targets.lookupNamedTag != nullptr && g_targets.playerRows != nullptr
           && g_targets.playerRowStride != nullptr && g_targets.findFirstComponentByClass != nullptr
           && g_targets.handleTablesOwner != nullptr && g_targets.objectGetTransform != nullptr;
}

const Table& get() noexcept { return g_targets; }

void clear() noexcept { g_targets = {}; }

} // namespace d2mod::native::targets
