#pragma once

namespace d2mod::tls {

[[nodiscard]] bool install() noexcept;

[[nodiscard]] bool uninstall() noexcept;

[[nodiscard]] bool is_installed() noexcept;

} // namespace d2mod::tls
