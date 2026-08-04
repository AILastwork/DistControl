#include "MainWindow.h"
#include "PolicyManager.h"

#include <shellapi.h>
#include <windows.h>

#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

namespace {
#ifdef DISKCONTROL_ADMIN
constexpr const wchar_t* kAppTitle = L"DiskControl Admin";
#else
constexpr const wchar_t* kAppTitle = L"DiskControl";
#endif

struct CommandLineOptions {
    std::wstring policyPath;
};

std::wstring widenAscii(const char* text) {
    std::wstring result;
    while (*text) {
        result.push_back(static_cast<unsigned char>(*text++));
    }
    return result;
}

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr) != size) {
        return {};
    }
    result.resize(static_cast<size_t>(size - 1));
    return result;
}

std::wstring timestamp() {
    SYSTEMTIME time{};
    GetLocalTime(&time);

    std::wostringstream stream;
    stream << std::setfill(L'0')
        << time.wYear << L"-"
        << std::setw(2) << time.wMonth << L"-"
        << std::setw(2) << time.wDay << L" "
        << std::setw(2) << time.wHour << L":"
        << std::setw(2) << time.wMinute << L":"
        << std::setw(2) << time.wSecond;
    return stream.str();
}

std::wstring logFileName() {
    SYSTEMTIME time{};
    GetLocalTime(&time);

    std::wostringstream stream;
    stream << std::setfill(L'0')
        << L"startup-"
        << time.wYear
        << std::setw(2) << time.wMonth
        << std::setw(2) << time.wDay
        << L".log";
    return stream.str();
}

std::wstring moduleDirectory() {
    wchar_t modulePath[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (length > 0 && length < MAX_PATH) {
        return std::filesystem::path(modulePath).parent_path().wstring();
    }
    return std::filesystem::current_path().wstring();
}

std::wstring programDataLogDirectory() {
    const DWORD needed = GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
    if (needed == 0) {
        return {};
    }

    std::wstring programData(needed, L'\0');
    const DWORD written = GetEnvironmentVariableW(L"ProgramData", programData.data(), needed);
    if (written == 0 || written >= needed) {
        return {};
    }

    programData.resize(written);
    return (std::filesystem::path(programData) / L"DiskControl" / L"logs").wstring();
}

bool tryAppendStartupLog(const std::wstring& directory, const std::wstring& message, std::wstring* writtenPath) {
    try {
        if (directory.empty()) {
            return false;
        }

        std::filesystem::create_directories(directory);
        const std::filesystem::path path = std::filesystem::path(directory) / logFileName();
        const bool newFile = !std::filesystem::exists(path) || std::filesystem::file_size(path) == 0;

        std::ofstream stream(path, std::ios::binary | std::ios::app);
        if (!stream) {
            return false;
        }

        if (newFile) {
            stream << "\xEF\xBB\xBF";
        }

        stream << wideToUtf8(L"[" + timestamp() + L"] " + message + L"\r\n");
        if (writtenPath) {
            *writtenPath = path.wstring();
        }
        return true;
    }
    catch (...) {
        return false;
    }
}

std::wstring appendStartupLog(const std::wstring& message) {
    std::wstring path;
    if (tryAppendStartupLog(programDataLogDirectory(), message, &path)) {
        return path;
    }
    tryAppendStartupLog((std::filesystem::path(moduleDirectory()) / L"logs").wstring(), message, &path);
    return path;
}

std::wstring formatHex(ULONG_PTR value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

LONG WINAPI unhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
    std::wstring message = L"Unhandled Windows exception";
    if (exceptionInfo && exceptionInfo->ExceptionRecord) {
        message += L": code=" + formatHex(exceptionInfo->ExceptionRecord->ExceptionCode);
        message += L", address=" + formatHex(reinterpret_cast<ULONG_PTR>(exceptionInfo->ExceptionRecord->ExceptionAddress));
    }
    appendStartupLog(message);
    return EXCEPTION_EXECUTE_HANDLER;
}

void showFatalError(const std::wstring& message, const std::wstring& logPath) {
    std::wstring text = message;
    if (!logPath.empty()) {
        text += L"\n\nЛог: " + logPath;
    }
    MessageBoxW(nullptr, text.c_str(), kAppTitle, MB_ICONERROR | MB_OK);
}

CommandLineOptions parseCommandLine() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        return {};
    }

    CommandLineOptions options;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        const std::wstring prefix = L"--policy=";
        if (arg == L"--policy" || arg == L"/policy") {
            if (i + 1 < argc) {
                options.policyPath = argv[++i];
            }
        }
        else if (arg.rfind(prefix, 0) == 0) {
            options.policyPath = arg.substr(prefix.size());
        }
    }

    LocalFree(argv);
    return options;
}

int runApplication(HINSTANCE instance, int showCommand) {
    const CommandLineOptions options = parseCommandLine();
    if (!options.policyPath.empty()) {
        PolicyManager::setConfigPathOverride(options.policyPath);
    }

    appendStartupLog(std::wstring(kAppTitle) + L" start. CommandLine=" + GetCommandLineW());

    MainWindow window;
    if (!window.create(instance, showCommand)) {
        const std::wstring logPath = appendStartupLog(std::wstring(kAppTitle) + L" failed to create main window. GetLastError=" + std::to_wstring(GetLastError()));
        showFatalError(L"Не удалось открыть окно DiskControl. Перезапустите приложение, а если ошибка повторится, отправьте администратору файл журнала.", logPath);
        return 1;
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(message.wParam);
}
}

int APIENTRY wWinMain(
    _In_ HINSTANCE instance,
    _In_opt_ HINSTANCE,
    _In_ PWSTR,
    _In_ int showCommand) {
    SetUnhandledExceptionFilter(unhandledExceptionFilter);

    try {
        return runApplication(instance, showCommand);
    }
    catch (const std::exception& error) {
        const std::wstring message = std::wstring(kAppTitle) + L" fatal error: " + widenAscii(error.what());
        const std::wstring logPath = appendStartupLog(message);
        showFatalError(L"DiskControl не смог запуститься. Попробуйте запустить приложение ещё раз или переустановить DiskControl.\n\nТехническая причина: " + widenAscii(error.what()), logPath);
        return 1;
    }
    catch (...) {
        const std::wstring message = std::wstring(kAppTitle) + L" fatal error: unknown exception";
        const std::wstring logPath = appendStartupLog(message);
        showFatalError(L"DiskControl не смог запуститься из-за неизвестной ошибки. Отправьте администратору файл журнала.", logPath);
        return 1;
    }
}
