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

## Custom content-manifest signing

Build 86657 normally verifies the boot-time `content_manifest` with a one-entry
RSA-2048 public-key table. Tigris Loader can replace that manifest trust anchor
without disabling the game's verifier.

Put a 270-byte ASN.1 PKCS#1 `RSAPublicKey` DER file beside `steam_api64.dll`
and set:

```ini
[server]
manifest_public_key=content-manifest-public.der
```

Relative paths are resolved beside the loader DLL. Leaving the setting empty
keeps the retail Bungie manifest key. The replacement is build-86657-specific:
the loader resolves the native key getter, verifies the expected one-entry table
and RVAs, swaps only the manifest key bytes, and restores the original key on
shutdown. The stock RSA-PSS/SHA-256 verification path remains enabled.

`SignOnServer` can generate the matching RSA-2048 keypair and sign generated
manifests using the exact build-86657 envelope and RSA-PSS parameters. Copy only
its public DER artifact to the client; keep the private PEM on the server.
