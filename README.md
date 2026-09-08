# Tigris Loader

> **Active development:** This project is a work in progress. Expect bugs, incomplete features, and breaking changes.

A Windows x64 mod loader for Destiny 2 build 86657.

## Build

Requires CMake 3.24 or newer and Visual Studio 2022 with the C++ desktop tools.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Outputs are `build/Release/steam_api64.dll` and `build/Release/sku_config.exe`. The SKU tool uses Windows cryptography.