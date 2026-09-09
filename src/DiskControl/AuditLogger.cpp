#include "AuditLogger.h"

#include "PolicyManager.h"

#include <windows.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <vector>

namespace {
namespace fs = std::filesystem;

std::atomic<unsigned long long> gOperationSequence{0};
std::mutex gLogMutex;
std::map<std::wstring, ULONGLONG> gLastLogCleanupTicks;

constexpr std::uintmax_t kMaximumLogDirectoryBytes = 100ULL * 1024ULL * 1024ULL;
constexpr std::uintmax_t kMaximumSingleLogBytes = 20ULL * 1024ULL * 1024ULL;
constexpr auto kLogRetention = std::chrono::hours(24 * 30);
constexpr ULONGLONG kLogCleanupIntervalMs = 5ULL * 60ULL * 1000ULL;

bool isManagedLogFile(const fs::path& path) {
    const std::wstring extension = path.extension().wstring();
    return extension == L".log" || extension == L".csv";
}

void pruneLogDirectoryIfDue(const fs::path& directory) {
    const std::wstring key = directory.wstring();
    const ULONGLONG nowTick = GetTickCount64();
    const auto previous = gLastLogCleanupTicks.find(key);
    if (previous != gLastLogCleanupTicks.end() &&
        nowTick - previous->second < kLogCleanupIntervalMs) {
        return;
    }
    gLastLogCleanupTicks[key] = nowTick;

    std::error_code error;
    const auto now = fs::file_time_type::clock::now();
    for (fs::directory_iterator it(directory, error), end; !error && it != end; it.increment(error)) {
        if (!it->is_regular_file(error) || !isManagedLogFile(it->path())) {
            continue;
        }
        const auto modified = it->last_write_time(error);
        if (!error && now - modified > kLogRetention) {
            fs::remove(it->path(), error);
            error.clear();
        }
    }

    struct LogFileInfo {
        fs::path path;
        fs::file_time_type modified;
        std::uintmax_t size = 0;
    };
    std::vector<LogFileInfo> files;
    std::uintmax_t totalSize = 0;
    error.clear();
    for (fs::directory_iterator it(directory, error), end; !error && it != end; it.increment(error)) {
        if (!it->is_regular_file(error) || !isManagedLogFile(it->path())) {
            continue;
        }
        LogFileInfo info{it->path(), it->last_write_time(error), it->file_size(error)};
        if (!error) {
            totalSize += info.size;
            files.push_back(std::move(info));
        }
        error.clear();
    }
    std::sort(files.begin(), files.end(), [](const LogFileInfo& left, const LogFileInfo& right) {
        return left.modified < right.modified;
    });
    size_t remainingFiles = files.size();
    for (const LogFileInfo& file : files) {
        if (totalSize <= kMaximumLogDirectoryBytes || remainingFiles <= 2) {
            break;
        }
        error.clear();
        if (fs::remove(file.path, error)) {
            totalSize = file.size > totalSize ? 0 : totalSize - file.size;
            --remainingFiles;
        }
    }
}

void rotateOversizedLog(const fs::path& filePath) {
    std::error_code error;
    if (!fs::exists(filePath, error) || error) {
        return;
    }
    const std::uintmax_t size = fs::file_size(filePath, error);
    if (error || size < kMaximumSingleLogBytes) {
        return;
    }

    SYSTEMTIME time{};
    GetLocalTime(&time);
    std::wostringstream suffix;
    suffix << L"-" << std::setfill(L'0')
        << std::setw(2) << time.wHour
        << std::setw(2) << time.wMinute
        << std::setw(2) << time.wSecond;
    const fs::path rotated = filePath.parent_path() /
        (filePath.stem().wstring() + suffix.str() + filePath.extension().wstring());
    fs::rename(filePath, rotated, error);
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

std::wstring traceTimestamp() {
    SYSTEMTIME time{};
    GetLocalTime(&time);

    std::wostringstream stream;
    stream << std::setfill(L'0')
        << time.wYear << L"-"
        << std::setw(2) << time.wMonth << L"-"
        << std::setw(2) << time.wDay << L" "
        << std::setw(2) << time.wHour << L":"
        << std::setw(2) << time.wMinute << L":"
        << std::setw(2) << time.wSecond << L"."
        << std::setw(3) << time.wMilliseconds;
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

std::wstring traceFileName() {
    SYSTEMTIME time{};
    GetLocalTime(&time);

    std::wostringstream stream;
    stream << std::setfill(L'0')
        << L"trace-"
        << time.wYear
        << std::setw(2) << time.wMonth
        << std::setw(2) << time.wDay
        << L".log";
    return stream.str();
}
}

void AuditLogger::log(const AuditEvent& event) {
    try {
        const std::lock_guard<std::mutex> lock(gLogMutex);
        if (tryWrite(defaultLogDirectory(), event)) {
            return;
        }

        tryWrite(fallbackLogDirectory(), event);
    }
    catch (...) {
    }
}

std::wstring AuditLogger::createOperationId(const std::wstring& prefix) {
    const unsigned long long sequence = ++gOperationSequence;
    std::wostringstream stream;
    stream << prefix << L"-" << GetCurrentProcessId() << L"-"
        << std::setfill(L'0') << std::setw(6) << sequence;
    return stream.str();
}

void AuditLogger::trace(const std::wstring& operationId, const std::wstring& message) {
    try {
        const std::lock_guard<std::mutex> lock(gLogMutex);
        if (tryWriteTrace(defaultLogDirectory(), operationId, message)) {
            return;
        }
        tryWriteTrace(fallbackLogDirectory(), operationId, message);
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
        pruneLogDirectoryIfDue(directory);
        const fs::path filePath = fs::path(directory) / logFileName();
        rotateOversizedLog(filePath);
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

bool AuditLogger::tryWriteTrace(
    const std::wstring& directory,
    const std::wstring& operationId,
    const std::wstring& message) {
    try {
        fs::create_directories(directory);
        pruneLogDirectoryIfDue(directory);
        const fs::path filePath = fs::path(directory) / traceFileName();
        rotateOversizedLog(filePath);
        const bool newFile = !fs::exists(filePath) || fs::file_size(filePath) == 0;

        std::ofstream stream(filePath, std::ios::binary | std::ios::app);
        if (!stream) {
            return false;
        }
        if (newFile) {
            stream << "\xEF\xBB\xBF";
            stream << wideToUtf8(
                L"Журнал пошаговой диагностики DiskControl. Пароли и общие ключи VPN не записываются.\r\n");
        }

        const std::wstring line = L"[" + traceTimestamp() + L"] [PID " +
            std::to_wstring(GetCurrentProcessId()) + L"] [TID " +
            std::to_wstring(GetCurrentThreadId()) + L"] [" +
            (operationId.empty() ? L"БЕЗ-ОПЕРАЦИИ" : operationId) + L"] " + message + L"\r\n";
        stream << wideToUtf8(line);
        return true;
    }
    catch (...) {
        return false;
    }
}
