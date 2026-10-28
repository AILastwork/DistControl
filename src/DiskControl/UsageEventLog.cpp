#include "UsageEventLog.h"

#include "PolicyManager.h"

#include <windows.h>

#include <map>
#include <stdexcept>

namespace {
std::string wideToUtf8(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
        nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size);
    return result;
}

std::string csvField(const std::wstring& value) {
    const std::string text = wideToUtf8(value);
    if (text.find_first_of(",\"\r\n") == std::string::npos) {
        return text;
    }
    std::string quoted = "\"";
    for (char ch : text) {
        quoted += ch == '"' ? std::string("\"\"") : std::string(1, ch);
    }
    return quoted + "\"";
}

std::wstring parentOf(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring{} : path.substr(0, slash);
}

void ensureDirectory(const std::wstring& directory) {
    if (directory.empty() || GetFileAttributesW(directory.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return;
    }
    ensureDirectory(parentOf(directory));
    if (!CreateDirectoryW(directory.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        throw std::runtime_error("Cannot create usage log directory.");
    }
}

std::string readAll(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND) {
            return {};
        }
        throw std::runtime_error("Cannot read usage log queue.");
    }
    std::string bytes;
    char buffer[65536];
    DWORD read = 0;
    while (ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read != 0) {
        bytes.append(buffer, read);
    }
    CloseHandle(file);
    return bytes;
}

bool appendBytes(const std::wstring& path, const std::string& bytes, bool writeHeaderIfNew) {
    HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    std::string data;
    LARGE_INTEGER size{};
    if (writeHeaderIfNew && GetFileSizeEx(file, &size) && size.QuadPart == 0) {
        data = "\xEF\xBB\xBF" + UsageEventLog::csvHeader();
    }
    data += bytes;
    DWORD written = 0;
    const bool ok = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) &&
        written == data.size() && FlushFileBuffers(file);
    CloseHandle(file);
    return ok;
}

// Serializes queue writers of this computer (DistControl and the helper).
class QueueLock {
public:
    explicit QueueLock(const std::wstring& queueFile) {
        ensureDirectory(parentOf(queueFile));
        const std::wstring lockPath = queueFile + L".lock";
        for (int attempt = 0; attempt < 100; ++attempt) {
            handle_ = CreateFileW(lockPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle_ != INVALID_HANDLE_VALUE) {
                return;
            }
            Sleep(50);
        }
        throw std::runtime_error("Timed out waiting for usage log queue lock.");
    }
    ~QueueLock() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }
    QueueLock(const QueueLock&) = delete;
    QueueLock& operator=(const QueueLock&) = delete;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

std::vector<std::string> queueLines(const std::string& bytes) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < bytes.size()) {
        size_t end = bytes.find('\n', start);
        if (end == std::string::npos) {
            break; // an unfinished line is left for the next flush
        }
        std::string line = bytes.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
        start = end + 1;
    }
    return lines;
}

// The local time is the first field and never quoted: "YYYY-MM-DD HH:MM:SS".
std::wstring lineLocalTime(const std::string& line) {
    return utf8ToWide(line.substr(0, (std::min)(line.find(','), line.size())));
}

std::wstring safeNamePart(const std::wstring& value) {
    std::wstring result;
    for (wchar_t ch : value) {
        result.push_back(wcschr(L"\\/:*?\"<>|,", ch) || ch < 0x20 ? L'_' : ch);
    }
    return result.empty() ? L"unknown" : result;
}

std::wstring computerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    return GetComputerNameW(buffer, &size) ? std::wstring(buffer) : std::wstring{};
}

void pruneOwnFiles(const std::wstring& logDirectory, const std::wstring& prefix) {
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((logDirectory + L"\\" + prefix + L"*.csv").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER nowTicks{};
    nowTicks.LowPart = now.dwLowDateTime;
    nowTicks.HighPart = now.dwHighDateTime;
    const unsigned long long retention =
        static_cast<unsigned long long>(UsageEventLog::kRetentionDays) * 24ULL * 3600ULL * 10000000ULL;
    do {
        ULARGE_INTEGER written{};
        written.LowPart = data.ftLastWriteTime.dwLowDateTime;
        written.HighPart = data.ftLastWriteTime.dwHighDateTime;
        if (nowTicks.QuadPart > written.QuadPart && nowTicks.QuadPart - written.QuadPart > retention) {
            DeleteFileW((logDirectory + L"\\" + data.cFileName).c_str());
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);
}
}

namespace UsageEventLog {
bool isUsageEvent(const std::wstring& action, const std::wstring& result) {
    if (action == L"STOP REASON") {
        return true;
    }
    return result == L"OK" && (action == L"USE" || action == L"STOP USING OWN" ||
        action == L"AUTO STOP BEFORE VPN SWITCH" || action == L"USAGE TIMER");
}

UsageLogEvent makeEvent(const std::wstring& action, const std::wstring& endpoint,
    const std::wstring& nickname, const std::wstring& result) {
    SYSTEMTIME local{};
    SYSTEMTIME utc{};
    GetLocalTime(&local);
    GetSystemTime(&utc);
    wchar_t localText[32]{};
    wchar_t utcText[32]{};
    swprintf_s(localText, L"%04u-%02u-%02u %02u:%02u:%02u",
        local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond);
    swprintf_s(utcText, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
        utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute, utc.wSecond);
    UsageLogEvent event;
    event.localTime = localText;
    event.utcTime = utcText;
    event.computer = computerName();
    event.user = PolicyManager::currentUserName();
    event.sid = PolicyManager::currentUserSid();
    event.action = action;
    event.endpoint = endpoint;
    event.nickname = nickname;
    event.result = result;
    return event;
}

std::wstring queuePath() {
#ifdef DISKCONTROL_TESTING
    return L"usage-log-queue-test.csv";
#else
    wchar_t buffer[MAX_PATH]{};
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", buffer, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        throw std::runtime_error("LOCALAPPDATA is not available for the usage log queue.");
    }
    return std::wstring(buffer) + L"\\DistControl\\state\\usage-log-queue.csv";
#endif
}

std::wstring sharedLogDirectory(const std::wstring& usageStatePath) {
    const std::wstring parent = parentOf(usageStatePath);
    return parent.empty() ? L"usage-log" : parent + L"\\usage-log";
}

std::wstring fileNameFor(const std::wstring& computer, const std::wstring& user, const std::wstring& localTime) {
    std::wstring month = localTime.size() >= 7 ? localTime.substr(0, 4) + localTime.substr(5, 2) : L"000000";
    return safeNamePart(computer) + L"-" + safeNamePart(user) + L"-" + month + L".csv";
}

std::string csvHeader() {
    return "timestamp,utc,computer,user,sid,action,endpoint,nickname,result\n";
}

std::string csvLine(const UsageLogEvent& event) {
    return csvField(event.localTime) + "," + csvField(event.utcTime) + "," + csvField(event.computer) + "," +
        csvField(event.user) + "," + csvField(event.sid) + "," + csvField(event.action) + "," +
        csvField(event.endpoint) + "," + csvField(event.nickname) + "," + csvField(event.result) + "\n";
}

void enqueue(const std::wstring& queueFile, const UsageLogEvent& event) {
    QueueLock lock(queueFile);
    if (!appendBytes(queueFile, csvLine(event), false)) {
        throw std::runtime_error("Cannot append to the usage log queue.");
    }
}

size_t queuedCount(const std::wstring& queueFile) {
    return queueLines(readAll(queueFile)).size();
}

size_t flush(const std::wstring& queueFile, const std::wstring& logDirectory,
    const std::wstring& computer, const std::wstring& user) {
    QueueLock lock(queueFile);
    const std::string bytes = readAll(queueFile);
    const std::vector<std::string> lines = queueLines(bytes);
    if (lines.empty()) {
        return 0;
    }

    std::map<std::wstring, std::string> byFile;
    for (const std::string& line : lines) {
        byFile[fileNameFor(computer, user, lineLocalTime(line))] += line + "\n";
    }

    std::string remaining;
    size_t moved = 0;
    bool directoryReady = true;
    try {
        ensureDirectory(logDirectory);
    }
    catch (const std::exception&) {
        directoryReady = false;
    }
    for (const auto& file : byFile) {
        if (directoryReady && appendBytes(logDirectory + L"\\" + file.first, file.second, true)) {
            for (char ch : file.second) {
                moved += ch == '\n' ? 1 : 0;
            }
        }
        else {
            remaining += file.second;
        }
    }

    // Keep an unfinished trailing line, if any, for the next flush.
    const size_t lastNewline = bytes.find_last_of('\n');
    if (lastNewline != std::string::npos && lastNewline + 1 < bytes.size()) {
        remaining += bytes.substr(lastNewline + 1);
    }
    HANDLE file = CreateFileW(queueFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, remaining.data(), static_cast<DWORD>(remaining.size()), &written, nullptr);
        CloseHandle(file);
    }

    if (directoryReady && moved != 0) {
        pruneOwnFiles(logDirectory, safeNamePart(computer) + L"-" + safeNamePart(user) + L"-");
    }
    return moved;
}
}
