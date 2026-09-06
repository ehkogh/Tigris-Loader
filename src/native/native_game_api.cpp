#include "native/native_game_api.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <string>

#include "native/native_targets.h"

namespace d2mod::native::game {
namespace {

constexpr std::uint32_t kHandleIndexMask = 0x1FFFu;

// player_registry_row fields proved/documented for 86657.
constexpr std::size_t kPlayerSlotIndex = 0x44;
constexpr std::size_t kPlayerDatumHandle = 0x48;
constexpr std::size_t kPlayerObjectHandle = 0x4C;
constexpr std::size_t kPlayerControlledObjectHandle = 0x54;

// Camera pose = singleton + slot * 0xC50 + 0x594.
constexpr std::size_t kCameraStride = 0xC50;
constexpr std::size_t kCameraPose = 0x594;
constexpr std::size_t kCameraPosition = 0x00;
constexpr std::size_t kCameraForward = 0x28;
constexpr std::size_t kCameraUp = 0x34;
constexpr std::size_t kCameraHorizontalFov = 0x40;
constexpr std::size_t kCameraAspect = 0xB8;

struct ComponentReference {
    std::array<std::byte, 24> unknown{};
    std::uint32_t nodeHandle{kInvalidHandle};
    std::uint32_t padding{};
    std::int32_t fieldOffset{};
};
static_assert(offsetof(ComponentReference, nodeHandle) == 0x18);
static_assert(offsetof(ComponentReference, fieldOffset) == 0x20);

template <typename T>
[[nodiscard]] bool safe_read(const void* address, T& output) noexcept {
    if (address == nullptr) return false;
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), address, &output, sizeof output, &copied) != FALSE
           && copied == sizeof output;
}

} // namespace

bool local_player(LocalPlayer& output) noexcept {
    output = {};
    output.datumHandle = kInvalidHandle;
    output.slotIndex = kInvalidHandle;
    output.objectHandle = kInvalidHandle;
    output.controlledObjectHandle = kInvalidHandle;

    if (!targets::is_resolved()) return false;
    const auto& target = targets::get();

    std::uint32_t datum = kInvalidHandle;
    if (target.localPlayerDatum(&datum) == nullptr || datum == kInvalidHandle) return false;

    std::byte* rows = nullptr;
    std::uint32_t stride = 0;
    if (!safe_read(target.playerRows, rows) || !safe_read(target.playerRowStride, stride)
        || rows == nullptr || stride == 0) {
        return false;
    }
    const std::size_t index = static_cast<std::size_t>(datum & kHandleIndexMask);
    if (index > (std::numeric_limits<std::size_t>::max)() / stride) return false;
    const std::byte* const row = rows + index * stride;

    std::uint32_t rowDatum = kInvalidHandle;
    LocalPlayer result;
    result.datumHandle = datum;
    if (!safe_read(row + kPlayerDatumHandle, rowDatum)
        || !safe_read(row + kPlayerSlotIndex, result.slotIndex)
        || !safe_read(row + kPlayerObjectHandle, result.objectHandle)
        || !safe_read(row + kPlayerControlledObjectHandle, result.controlledObjectHandle)) {
        return false;
    }
    // Generation-tagged identity, not merely low-13 slot equality.
    if (rowDatum != datum) return false;
    output = result;
    return true;
}

bool camera_pose(CameraPose& output) noexcept {
    output = {};
    LocalPlayer player;
    if (!local_player(player) || player.slotIndex == kInvalidHandle || !targets::is_resolved()) {
        return false;
    }
    std::byte* const cameras = targets::get().cameraSingleton();
    if (cameras == nullptr) return false;

    const std::size_t slot = static_cast<std::size_t>(player.slotIndex);
    if (slot > ((std::numeric_limits<std::size_t>::max)() - kCameraPose) / kCameraStride) {
        return false;
    }
    const std::byte* const pose = cameras + slot * kCameraStride + kCameraPose;
    CameraPose result;
    if (!safe_read(pose + kCameraPosition, result.position)
        || !safe_read(pose + kCameraForward, result.forward)
        || !safe_read(pose + kCameraUp, result.up)
        || !safe_read(pose + kCameraHorizontalFov, result.horizontalFov)
        || !safe_read(pose + kCameraAspect, result.aspect)) {
        return false;
    }
    output = result;
    return true;
}

std::int32_t world_step() noexcept {
    return targets::is_resolved() ? targets::get().bootFlowGetStep() : -1;
}

WorldPhase world_phase() noexcept {
    const std::int32_t step = world_step();
    if (step < 0) return WorldPhase::unavailable;
    if (step >= 33 && step <= 37) return WorldPhase::transitioning;
    if (step == 38) return WorldPhase::inWorld;
    return WorldPhase::idle;
}

bool lookup_named_tag(const std::string_view name, NamedTag& output) noexcept {
    output = {};
    output.tag = kInvalidHandle;
    output.classHandle = kInvalidHandle;
    if (!targets::is_resolved() || name.empty() || name.find('\0') != std::string_view::npos) {
        return false;
    }
    const std::string terminated(name);
    NamedTag result;
    result.tag = kInvalidHandle;
    result.classHandle = kInvalidHandle;
    if (targets::get().lookupNamedTag(&result.tag, terminated.c_str(), &result.classHandle) == nullptr
        || result.tag == kInvalidHandle) {
        return false;
    }
    output = result;
    return true;
}

bool resolve_handle(const std::uint32_t handle, std::byte*& output) noexcept {
    output = nullptr;
    if (!targets::is_resolved() || handle == kInvalidHandle) return false;

    // Exact selector formula emitted by the stock world-object marker refresh.
    const std::int32_t signedHandle = static_cast<std::int32_t>(handle);
    const std::int32_t shifted = signedHandle >> 13;
    std::uint64_t selectorWide = static_cast<std::uint64_t>(static_cast<std::int64_t>(shifted));
    selectorWide |= 0x0FFC0000ull;
    const std::uint64_t low16 = static_cast<std::uint16_t>(shifted);
    selectorWide >>= 18;
    const std::size_t selector = static_cast<std::size_t>(selectorWide & low16);

    std::byte* owner = nullptr;
    std::byte* descriptorBase = nullptr;
    if (!safe_read(targets::get().handleTablesOwner, owner) || owner == nullptr
        || !safe_read(owner, descriptorBase) || descriptorBase == nullptr) {
        return false;
    }
    if (selector > (std::numeric_limits<std::size_t>::max)() / 64) return false;
    const std::byte* const descriptor = descriptorBase + selector * 64;

    std::byte* records = nullptr;
    std::uint32_t stride = 0;
    std::int32_t correctionMask = 0;
    if (!safe_read(descriptor + 0x08, records) || records == nullptr
        || !safe_read(descriptor + 0x30, stride) || stride == 0
        || !safe_read(descriptor + 0x34, correctionMask)) {
        return false;
    }
    const std::size_t index = static_cast<std::size_t>(handle & kHandleIndexMask);
    if (index > (std::numeric_limits<std::size_t>::max)() / stride) return false;
    std::byte* const record = records + index * stride;
    std::uint64_t correctionSource = 0;
    if (!safe_read(record + 0x08, correctionSource)) return false;
    const std::uint64_t mask = static_cast<std::uint64_t>(static_cast<std::int64_t>(correctionMask));
    const std::uint64_t correction = correctionSource & mask;
    if (correction > static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(record))) {
        return false;
    }
    output = record - static_cast<std::size_t>(correction);
    return output != nullptr;
}

bool find_component(const std::uint32_t objectHandle,
                    const std::uint32_t classHandle,
                    Component& output) noexcept {
    output = {};
    output.nodeHandle = kInvalidHandle;
    output.componentHandle = kInvalidHandle;
    if (!targets::is_resolved() || objectHandle == kInvalidHandle || classHandle == kInvalidHandle) {
        return false;
    }
    std::byte* object = nullptr;
    if (!resolve_handle(objectHandle, object)) return false;

    ComponentReference reference;
    std::uint32_t componentHandle = kInvalidHandle;
    if (!targets::get().findFirstComponentByClass(
            object, classHandle, &reference, &componentHandle)
        || reference.nodeHandle == kInvalidHandle) {
        return false;
    }
    std::byte* node = nullptr;
    if (!resolve_handle(reference.nodeHandle, node)) return false;
    Component result;
    result.nodeHandle = reference.nodeHandle;
    result.componentHandle = componentHandle;
    result.fieldOffset = reference.fieldOffset;
    result.address = node + reference.fieldOffset;
    output = result;
    return true;
}

bool object_transform(const std::uint32_t objectHandle, ObjectTransform& output) noexcept {
    output = {};
    if (!targets::is_resolved() || objectHandle == kInvalidHandle) return false;
    std::byte* object = nullptr;
    if (!resolve_handle(objectHandle, object)) return false;

    ObjectTransform result;
    if (!targets::get().objectGetTransform(object + 0x30, &result)) return false;
    output = result;
    return true;
}

bool local_player_transform(ObjectTransform& output) noexcept {
    output = {};
    LocalPlayer player;
    if (!local_player(player)) return false;
    return object_transform(player.controlledObjectHandle, output);
}

} // namespace d2mod::native::game
