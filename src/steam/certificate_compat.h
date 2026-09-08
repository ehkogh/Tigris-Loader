#pragma once

namespace d2mod::steam::certificate_compat {

void update() noexcept;

[[nodiscard]] bool uninstall() noexcept;
[[nodiscard]] bool is_installed() noexcept;

} // namespace d2mod::steam::certificate_compat
