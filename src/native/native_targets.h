#pragma once

#include <cstddef>
#include <cstdint>

namespace d2mod::native::targets {

using OutHandle = std::uint32_t* (__fastcall*)(std::uint32_t* out);
using CameraTransform = std::int64_t (__fastcall*)(std::uint32_t playerIndex);
using CameraSingleton = std::byte* (__fastcall*)();
using BootFlowGetStep = std::int32_t (__fastcall*)();
using LookupNamedTag = std::uint32_t* (__fastcall*)(std::uint32_t* outTag,
                                                    const char* name,
                                                    std::uint32_t* outClass);
using FindFirstComponentByClass = bool (__fastcall*)(void* object,
                                                     std::uint32_t classHandle,
                                                     void* outReference,
                                                     std::uint32_t* outComponentHandle);
using ObjectGetTransform = bool (__fastcall*)(void* objectReference, void* outTransform);

struct Table {
    OutHandle localPlayerDatum{};
    OutHandle localControlledObject{};
    CameraTransform cameraTransform{};
    CameraSingleton cameraSingleton{};
    BootFlowGetStep bootFlowGetStep{};
    LookupNamedTag lookupNamedTag{};
    FindFirstComponentByClass findFirstComponentByClass{};
    ObjectGetTransform objectGetTransform{};

    std::byte** playerRows{};
    std::uint32_t* playerRowStride{};
    std::byte** handleTablesOwner{};
};

[[nodiscard]] bool resolve() noexcept;
[[nodiscard]] bool is_resolved() noexcept;
[[nodiscard]] const Table& get() noexcept;
void clear() noexcept;

} // namespace d2mod::native::targets
