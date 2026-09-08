#pragma once

namespace d2mod::manifest::trust {

[[nodiscard]] bool install() noexcept;
[[nodiscard]] bool uninstall() noexcept;
[[nodiscard]] bool is_installed() noexcept;

} // namespace d2mod::manifest::trust
