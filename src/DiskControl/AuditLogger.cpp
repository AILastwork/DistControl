#include "AuditLogger.h"

#include "PolicyManager.h"

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace {
namespace fs = std::filesystem;

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

std::string csvEscape(const std::wstring& value) {
    const std::string text = wideToUtf8(value);
    bool mustQuote = false;
    for (char ch : text) {
        if (ch == '"' || ch == ',' || ch == '\n' || ch == '\r') {
            mustQuote = true;
            break;
        }
    }

    if (!mustQuote) {
        return text;
    }

    std::string escaped = "\"";
    for (char ch : text) {
        escaped += ch == '"' ? "\"\"" : std::string(1, ch);
    }
    escaped.push_back('"');
    return escaped;
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
        << L"audit-"
        << time.wYear
        << std::setw(2) << time.wMonth
        << std::setw(2) << time.wDay
        << L".csv";
    return stream.str();
}
}

void AuditLogger::log(const AuditEvent& event) {
    try {
        if (tryWrite(defaultLogDirectory(), event)) {
            return;
        }

        tryWrite(fallbackLogDirectory(), event);
    }
    catch (...) {
    }
}

void AuditLogger::logDeviceAction(
    const std::wstring& action,
    const DeviceViewModel& device,
    const std::wstring& result,
    const std::wstring& details) {
    AuditEvent event;
    event.action = action;
    event.endpoint = device.endpoint;
    event.nickname = device.nickname;
    event.product = device.product;
    event.result = result;
    event.details = details;
    log(event);
}

std::string AuditLogger::csvEscapeForTest(const std::wstring& value) {
    return csvEscape(value);
}

std::wstring AuditLogger::defaultLogDirectory() {
    const DWORD needed = GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
    if (needed == 0) {
        return fallbackLogDirectory();
    }

    std::wstring programData(needed, L'\0');
    const DWORD written = GetEnvironmentVariableW(L"ProgramData", programData.data(), needed);
    if (written == 0 || written >= needed) {
        return fallbackLogDirectory();
    }

    programData.resize(written);
    return (fs::path(programData) / L"DiskControl" / L"logs").wstring();
}

std::wstring AuditLogger::fallbackLogDirectory() {
    wchar_t modulePath[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (length > 0 && length < MAX_PATH) {
        return (fs::path(modulePath).parent_path() / L"logs").wstring();
    }

    return (fs::current_path() / L"logs").wstring();
}

bool AuditLogger::tryWrite(const std::wstring& directory, const AuditEvent& event) {
    try {
        fs::create_directories(directory);
        const fs::path filePath = fs::path(directory) / logFileName();
        const bool newFile = !fs::exists(filePath) || fs::file_size(filePath) == 0;

        std::ofstream stream(filePath, std::ios::binary | std::ios::app);
        if (!stream) {
            return false;
        }

        if (newFile) {
            stream << "\xEF\xBB\xBF";
            stream << "timestamp,user,sid,action,endpoint,nickname,product,result,details\n";
        }

        stream
            << csvEscape(timestamp()) << ','
            << csvEscape(PolicyManager::currentUserName()) << ','
            << csvEscape(PolicyManager::currentUserSid()) << ','
            << csvEscape(event.action) << ','
            << csvEscape(event.endpoint) << ','
            << csvEscape(event.nickname) << ','
            << csvEscape(event.product) << ','
            << csvEscape(event.result) << ','
            << csvEscape(event.details)
            << '\n';

        return true;
    }
    catch (...) {
        return false;
    }
}
