#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace d2mod::native::game {

inline constexpr std::uint32_t kInvalidHandle = 0xFFFFFFFFu;

enum class WorldPhase : std::uint8_t {
    unavailable,
    idle,
    transitioning,
    inWorld,
};

struct LocalPlayer {
    std::uint32_t datumHandle{kInvalidHandle};
    std::uint32_t slotIndex{kInvalidHandle};
    std::uint32_t objectHandle{kInvalidHandle};
    std::uint32_t controlledObjectHandle{kInvalidHandle};
};

struct CameraPose {
    std::array<float, 3> position{};
    std::array<float, 3> forward{};
    std::array<float, 3> up{};
    float horizontalFov{};
    float aspect{};
};

struct NamedTag {
    std::uint32_t tag{kInvalidHandle};
    std::uint32_t classHandle{kInvalidHandle};
};

struct Component {
    std::uint32_t nodeHandle{kInvalidHandle};
    std::uint32_t componentHandle{kInvalidHandle};
    std::int32_t fieldOffset{};
    std::byte* address{};
};

struct ObjectTransform {
    std::array<float, 4> orientation{};
    std::array<float, 4> position{};
};

[[nodiscard]] bool local_player(LocalPlayer& output) noexcept;
[[nodiscard]] bool camera_pose(CameraPose& output) noexcept;
[[nodiscard]] std::int32_t world_step() noexcept;
[[nodiscard]] WorldPhase world_phase() noexcept;
[[nodiscard]] bool lookup_named_tag(std::string_view name, NamedTag& output) noexcept;
[[nodiscard]] bool resolve_handle(std::uint32_t handle, std::byte*& output) noexcept;
[[nodiscard]] bool find_component(std::uint32_t objectHandle,
                                  std::uint32_t classHandle,
                                  Component& output) noexcept;
[[nodiscard]] bool object_transform(std::uint32_t objectHandle, ObjectTransform& output) noexcept;
[[nodiscard]] bool local_player_transform(ObjectTransform& output) noexcept;

} // namespace d2mod::native::game
