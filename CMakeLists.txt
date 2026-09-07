cmake_minimum_required(VERSION 3.24)

project(D2ModLoader LANGUAGES C CXX)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS modloader.ini.example)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/modloader.ini.example" DEFAULT_CONFIG)
configure_file(src/core/default_config.h.in generated/core/default_config.h @ONLY)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "D2 Mod Loader requires Windows x64")
endif()

add_library(minhook STATIC
    third_party/minhook/src/buffer.c
    third_party/minhook/src/hook.c
    third_party/minhook/src/trampoline.c
    third_party/minhook/src/hde/hde64.c
)
target_include_directories(minhook PUBLIC third_party/minhook/include)
set_property(TARGET minhook PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(d2_mod_loader SHARED
    src/core/dllmain.cpp
    src/steam/backend.cpp
    src/steam/backend.h
    src/core/log.cpp
    src/core/log.h
    src/mods/mod_catalog.cpp
    src/mods/mod_catalog.h
    src/native/native_scan.cpp
    src/native/native_scan.h
    src/native/game_logging.cpp
    src/native/game_logging.h
    src/mods/package_runtime.cpp
    src/mods/package_runtime.h
    src/mods/package_trust.cpp
    src/mods/package_trust.h
    src/core/runtime.cpp
    src/core/runtime.h
    src/network/tls_policy.cpp
    src/network/tls_policy.h
    src/steam/exports.def
    src/sku/policy.cpp
    src/sku/policy.h
)

target_include_directories(d2_mod_loader PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(d2_mod_loader PRIVATE minhook user32)

target_compile_features(d2_mod_loader PRIVATE cxx_std_20)
target_compile_definitions(d2_mod_loader PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

if(MSVC)
    target_compile_options(d2_mod_loader PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/WX>
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
    )
    set_property(TARGET d2_mod_loader PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set_target_properties(d2_mod_loader PROPERTIES
    OUTPUT_NAME steam_api64
    PREFIX ""
)

add_library(sku_codec STATIC src/sku/codec.cpp src/sku/codec.h src/sku/file.cpp src/sku/file.h)
target_include_directories(sku_codec PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(sku_codec PUBLIC cxx_std_20)
target_compile_definitions(sku_codec PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(sku_codec PUBLIC bcrypt)
target_link_libraries(d2_mod_loader PRIVATE sku_codec)

add_custom_command(TARGET d2_mod_loader POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/modloader.ini.example"
        "$<TARGET_FILE_DIR:d2_mod_loader>/modloader.ini.example"
)

add_executable(sku_config src/sku/main.cpp)
target_link_libraries(sku_config PRIVATE sku_codec)
target_compile_definitions(sku_config PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

foreach(target sku_codec sku_config)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /utf-8)
        set_property(TARGET ${target} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
endforeach()
