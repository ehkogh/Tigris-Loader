#include "core/log.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>

#include "core/runtime.h"

namespace d2mod::log {
namespace {

constexpr std::size_t kLineCapacity = 2048;
constexpr std::size_t kQueueCapacity = 1024;
struct Line {
    std::array<char, kLineCapacity> text{};
    DWORD size{};
};

SRWLOCK g_lock{SRWLOCK_INIT};
CONDITION_VARIABLE g_ready{CONDITION_VARIABLE_INIT};
std::array<Line, kQueueCapacity> g_queue{};
std::size_t g_head{};
std::size_t g_count{};
unsigned long long g_dropped{};
bool g_stopping{};
bool g_ownsConsole{};
HANDLE g_file{INVALID_HANDLE_VALUE};
HANDLE g_console{INVALID_HANDLE_VALUE};
HANDLE g_thread{};

BOOL WINAPI console_control(const DWORD event) {
    return event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT;
}

void emit(const Line& line) noexcept {
    OutputDebugStringA(line.text.data());
    if (g_file != INVALID_HANDLE_VALUE) {
        DWORD offset = 0;
        while (offset < line.size) {
            DWORD written = 0;
            if (!WriteFile(g_file, line.text.data() + offset, line.size - offset, &written, nullptr)
                || written == 0) {
                break;
            }
            offset += written;
        }
    }
    if (g_console != INVALID_HANDLE_VALUE) {
        std::array<wchar_t, kLineCapacity> wide{};
        int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, line.text.data(),
                                      static_cast<int>(line.size), wide.data(),
                                      static_cast<int>(wide.size()));
        if (size == 0) {
            size = MultiByteToWideChar(CP_ACP, 0, line.text.data(), static_cast<int>(line.size),
                                      wide.data(), static_cast<int>(wide.size()));
        }
        DWORD written = 0;
        if (size > 0) {
            (void)WriteConsoleW(g_console, wide.data(), static_cast<DWORD>(size), &written, nullptr);
        }
    }
}

DWORD WINAPI drain(void*) noexcept {
    for (;;) {
        Line line{};
        unsigned long long dropped = 0;
        AcquireSRWLockExclusive(&g_lock);
        while (g_count == 0 && !g_stopping) {
            (void)SleepConditionVariableSRW(&g_ready, &g_lock, INFINITE, 0);
        }
        if (g_count == 0 && g_stopping) {
            ReleaseSRWLockExclusive(&g_lock);
            return 0;
        }
        line = g_queue[g_head];
        g_head = (g_head + 1) % kQueueCapacity;
        --g_count;
        dropped = g_dropped;
        g_dropped = 0;
        ReleaseSRWLockExclusive(&g_lock);
        emit(line);
        if (dropped != 0) {
            Line notice{};
            notice.size = static_cast<DWORD>(std::snprintf(
                notice.text.data(), notice.text.size(),
                "[Loader] Log queue full: dropped %llu messages; increase game_verbosity to reduce volume.\r\n",
                dropped));
            emit(notice);
        }
    }
}

void enqueue(const char* source, const std::string_view message) noexcept {
    Line line{};
    SYSTEMTIME now{};
    GetLocalTime(&now);
    const int prefix = std::snprintf(line.text.data(), line.text.size(),
                                     "[%02u:%02u:%02u.%03u] [%s] ",
                                     static_cast<unsigned>(now.wHour),
                                     static_cast<unsigned>(now.wMinute),
                                     static_cast<unsigned>(now.wSecond),
                                     static_cast<unsigned>(now.wMilliseconds), source);
    if (prefix <= 0 || static_cast<std::size_t>(prefix) >= line.text.size() - 3) {
        return;
    }
    std::size_t length = static_cast<std::size_t>(prefix);
    const std::size_t count = (std::min)(message.size(), line.text.size() - length - 3);
    for (std::size_t i = 0; i < count; ++i) {
        const unsigned char value = static_cast<unsigned char>(message[i]);
        // Keep each event on one line and prevent native text acting as console control input.
        line.text[length++] = value >= 32 && value != 127 ? static_cast<char>(value) : ' ';
    }
    while (length > static_cast<std::size_t>(prefix) && line.text[length - 1] == ' ') {
        --length;
    }
    line.text[length++] = '\r';
    line.text[length++] = '\n';
    line.text[length] = '\0';
    line.size = static_cast<DWORD>(length);

    AcquireSRWLockExclusive(&g_lock);
    if (g_thread != nullptr && !g_stopping) {
        if (g_count < kQueueCapacity) {
            g_queue[(g_head + g_count) % kQueueCapacity] = line;
            ++g_count;
            WakeConditionVariable(&g_ready);
        } else {
            ++g_dropped;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void close_outputs() noexcept {
    if (g_file != INVALID_HANDLE_VALUE) {
        (void)FlushFileBuffers(g_file);
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
    if (g_console != INVALID_HANDLE_VALUE) {
        CloseHandle(g_console);
        g_console = INVALID_HANDLE_VALUE;
    }
    if (g_ownsConsole) {
        (void)SetConsoleCtrlHandler(console_control, FALSE);
        (void)FreeConsole();
        g_ownsConsole = false;
    }
}

} // namespace

void initialize() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_thread != nullptr) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    std::wstring path = runtime::module_directory();
    if (!path.empty() && path.back() != L'\\') {
        path.push_back(L'\\');
    }
    path.append(L"d2_mod_loader.log");
    g_file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                         nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    const bool fileFailed = g_file == INVALID_HANDLE_VALUE;
    const auto config = runtime::configuration_path();
    const bool showConsole = GetPrivateProfileIntW(L"logging", L"console", 1, config.c_str()) != 0;
    if (showConsole) {
        g_ownsConsole = AllocConsole() != FALSE;
        // CONOUT$ also works if the process already has a console; do not take ownership of it.
        g_console = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_ownsConsole) {
            SetConsoleTitleW(L"Destiny 2 | TigrisLoader");
            (void)SetConsoleCtrlHandler(console_control, TRUE);
            if (const HWND window = GetConsoleWindow()) {
                if (const HMENU menu = GetSystemMenu(window, FALSE)) {
                    (void)DeleteMenu(menu, SC_CLOSE, MF_BYCOMMAND);
                }
            }
            DWORD mode = 0;
            if (GetConsoleMode(g_console, &mode)) {
                (void)SetConsoleMode(g_console, mode | ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);
            }
            // Selection must not pause the console writer and fill the log queue.
            const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
            if (GetConsoleMode(input, &mode)) {
                (void)SetConsoleMode(input, (mode | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE);
            }
        }
    }
    const bool consoleFailed = showConsole && g_console == INVALID_HANDLE_VALUE;
    g_head = g_count = 0;
    g_dropped = 0;
    g_stopping = false;
    g_thread = CreateThread(nullptr, 0, drain, nullptr, 0, nullptr);
    if (g_thread == nullptr) {
        OutputDebugStringA("D2 Mod Loader: could not start log writer\n");
        close_outputs();
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (fileFailed) {
        write("Could not open d2_mod_loader.log; file logging unavailable");
    }
    if (consoleFailed) {
        write("Could not open console; file/debugger logging remains available");
    }
}

void shutdown() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    const HANDLE thread = g_thread;
    g_stopping = true;
    WakeConditionVariable(&g_ready);
    ReleaseSRWLockExclusive(&g_lock);
    if (thread != nullptr) {
        (void)WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
    AcquireSRWLockExclusive(&g_lock);
    g_thread = nullptr;
    close_outputs();
    ReleaseSRWLockExclusive(&g_lock);
}

void write(const std::string_view message) noexcept { enqueue("Loader", message); }

void write_game(const std::int32_t site, const std::string_view message) noexcept {
    std::array<char, 48> source{};
    (void)std::snprintf(source.data(), source.size(), "Tiger/D2 site=%d", site);
    enqueue(source.data(), message);
}

} // namespace d2mod::log
