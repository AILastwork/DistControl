#include "UsageStateStore.h"

#include <windows.h>

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <iterator>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace {
std::wstring trim(const std::wstring& text) {
    size_t first = 0;
    while (first < text.size() && std::iswspace(text[first])) {
        ++first;
    }

    size_t last = text.size();
    while (last > first && std::iswspace(text[last - 1])) {
        --last;
    }

    return text.substr(first, last - first);
}

std::wstring lowerCopy(std::wstring text) {
    if (!text.empty()) {
        CharLowerBuffW(text.data(), static_cast<DWORD>(text.size()));
    }
    return text;
}

bool equalsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return lowerCopy(left) == lowerCopy(right);
}

std::wstring parentOf(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return {};
    }
    return path.substr(0, slash);
}

bool isDriveRoot(const std::wstring& path) {
    return (path.size() == 2 && path[1] == L':') ||
        (path.size() == 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/'));
}

void ensureDirectoryTree(const std::wstring& directory) {
    if (directory.empty() || isDriveRoot(directory)) {
        return;
    }

    const DWORD attrs = GetFileAttributesW(directory.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            return;
        }
        throw std::runtime_error("Usage state parent path is not a directory.");
    }

    const std::wstring parent = parentOf(directory);
    if (!parent.empty() && parent != directory) {
        ensureDirectoryTree(parent);
    }

    if (!CreateDirectoryW(directory.c_str(), nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            throw std::runtime_error("Cannot create usage state directory.");
        }
    }
}

std::wstring timestampForFileName() {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"%04u%02u%02u-%02u%02u%02u-%03u",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
    return buffer;
}

std::wstring timestampIso() {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"%04u-%02u-%02uT%02u:%02u:%02u",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    return buffer;
}

std::wstring utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        throw std::runtime_error("Cannot decode UTF-8 usage state.");
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw std::runtime_error("Cannot encode UTF-8 usage state.");
    }
    std::string result(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr) != size) {
        throw std::runtime_error("Cannot encode UTF-8 usage state.");
    }
    result.resize(static_cast<size_t>(size - 1));
    return result;
}

std::wstring readUtf8FileIfExists(const std::wstring& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return {};
    }

    std::string bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    if (bytes.size() >= 3 &&
        static_cast<unsigned char>(bytes[0]) == 0xEF &&
        static_cast<unsigned char>(bytes[1]) == 0xBB &&
        static_cast<unsigned char>(bytes[2]) == 0xBF) {
        bytes.erase(0, 3);
    }
    return utf8ToWide(bytes);
}

void writeUtf8File(const std::wstring& path, const std::wstring& text) {
    ensureDirectoryTree(parentOf(path));
    const std::string bytes = wideToUtf8(text);
    const std::wstring tempPath = path + L".tmp-" + timestampForFileName();

    HANDLE file = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Cannot create temp usage state file.");
    }

    DWORD written = 0;
    const BOOL ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    const DWORD writeError = ok ? ERROR_SUCCESS : GetLastError();
    const BOOL flushed = ok ? FlushFileBuffers(file) : FALSE;
    const DWORD flushError = flushed ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);

    if (!ok || written != bytes.size() || !flushed) {
        DeleteFileW(tempPath.c_str());
        throw std::runtime_error(writeError != ERROR_SUCCESS || flushError != ERROR_SUCCESS
            ? "Cannot write usage state file."
            : "Incomplete usage state write.");
    }

    if (!MoveFileExW(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tempPath.c_str());
        throw std::runtime_error("Cannot replace usage state file.");
    }
}

class UsageStateFileLock {
public:
    explicit UsageStateFileLock(const std::wstring& statePath) {
        if (statePath.empty()) {
            return;
        }

        ensureDirectoryTree(parentOf(statePath));
        const std::wstring lockPath = statePath + L".lock";
        DWORD lastError = ERROR_SUCCESS;
        for (int attempt = 0; attempt < 100; ++attempt) {
            handle_ = CreateFileW(
                lockPath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (handle_ != INVALID_HANDLE_VALUE) {
                return;
            }

            lastError = GetLastError();
            if (lastError != ERROR_SHARING_VIOLATION && lastError != ERROR_LOCK_VIOLATION) {
                throw std::runtime_error("Cannot create usage state lock file.");
            }
            Sleep(50);
        }

        throw std::runtime_error("Timed out waiting for usage state lock.");
    }

    ~UsageStateFileLock() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    UsageStateFileLock(const UsageStateFileLock&) = delete;
    UsageStateFileLock& operator=(const UsageStateFileLock&) = delete;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

std::wstring jsonEscape(const std::wstring& value) {
    std::wstring escaped = L"\"";
    for (wchar_t ch : value) {
        switch (ch) {
        case L'"': escaped += L"\\\""; break;
        case L'\\': escaped += L"\\\\"; break;
        case L'\b': escaped += L"\\b"; break;
        case L'\f': escaped += L"\\f"; break;
        case L'\n': escaped += L"\\n"; break;
        case L'\r': escaped += L"\\r"; break;
        case L'\t': escaped += L"\\t"; break;
        default:
            if (ch < 32) {
                wchar_t buffer[8]{};
                swprintf_s(buffer, L"\\u%04x", static_cast<unsigned int>(ch));
                escaped += buffer;
            }
            else {
                escaped.push_back(ch);
            }
            break;
        }
    }
    escaped.push_back(L'"');
    return escaped;
}

unsigned int hexValue(wchar_t ch) {
    if (ch >= L'0' && ch <= L'9') {
        return static_cast<unsigned int>(ch - L'0');
    }
    if (ch >= L'a' && ch <= L'f') {
        return static_cast<unsigned int>(ch - L'a' + 10);
    }
    if (ch >= L'A' && ch <= L'F') {
        return static_cast<unsigned int>(ch - L'A' + 10);
    }
    return 0;
}

std::wstring jsonUnescape(const std::wstring& value) {
    std::wstring result;
    for (size_t i = 0; i < value.size(); ++i) {
        wchar_t ch = value[i];
        if (ch != L'\\' || i + 1 >= value.size()) {
            result.push_back(ch);
            continue;
        }

        ch = value[++i];
        switch (ch) {
        case L'"': result.push_back(L'"'); break;
        case L'\\': result.push_back(L'\\'); break;
        case L'/': result.push_back(L'/'); break;
        case L'b': result.push_back(L'\b'); break;
        case L'f': result.push_back(L'\f'); break;
        case L'n': result.push_back(L'\n'); break;
        case L'r': result.push_back(L'\r'); break;
        case L't': result.push_back(L'\t'); break;
        case L'u':
            if (i + 4 < value.size()) {
                unsigned int code = 0;
                for (int n = 0; n < 4; ++n) {
                    code = (code << 4) + hexValue(value[++i]);
                }
                result.push_back(static_cast<wchar_t>(code));
            }
            break;
        default:
            result.push_back(ch);
            break;
        }
    }
    return result;
}

std::wstring fieldValue(const std::wstring& objectText, const wchar_t* fieldName) {
    const std::wregex pattern(
        L"\"" + std::wstring(fieldName) + L"\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"",
        std::regex_constants::icase);
    std::wsmatch match;
    if (!std::regex_search(objectText, match, pattern) || match.size() < 2) {
        return {};
    }
    return jsonUnescape(match[1].str());
}

bool shouldUseRecordedOwner(const ParsedDevice& device) {
    const std::wstring raw = lowerCopy(trim(device.inUseBy));
    if (raw.empty() || raw == L"no one" || raw == L"you") {
        return false;
    }

    const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, L"");
    return !usage.isFree && usage.userText.empty();
}

std::wstring usageText(const UsageStateRecord& record) {
    std::wstring text = record.user;
    if (!record.computer.empty()) {
        text += L" AT " + record.computer;
    }
    return text;
}
}

UsageStateStore::UsageStateStore(std::wstring path)
    : path_(std::move(path)) {
}

void UsageStateStore::markUsed(const ParsedDevice& device, const std::wstring& userName) const {
    if (path_.empty() || device.endpoint.empty() || userName.empty()) {
        return;
    }

    UsageStateFileLock lock(path_);
    std::vector<UsageStateRecord> records = readRecords();
    records.erase(
        std::remove_if(records.begin(), records.end(),
            [&device](const UsageStateRecord& record) {
                return equalsIgnoreCase(record.endpoint, device.endpoint);
            }),
        records.end());

    UsageStateRecord record;
    record.endpoint = device.endpoint;
    record.nickname = device.nickname;
    record.product = device.product;
    record.user = userName;
    record.computer = currentComputerName();
    record.updatedAt = timestampIso();
    records.push_back(std::move(record));

    writeRecords(records);
}

void UsageStateStore::markReleased(const ParsedDevice& device) const {
    if (path_.empty() || device.endpoint.empty()) {
        return;
    }

    UsageStateFileLock lock(path_);
    std::vector<UsageStateRecord> records = readRecords();
    records.erase(
        std::remove_if(records.begin(), records.end(),
            [&device](const UsageStateRecord& record) {
                return equalsIgnoreCase(record.endpoint, device.endpoint);
            }),
        records.end());
    writeRecords(records);
}

bool UsageStateStore::applyRecordedUsage(ParsedDevice& device) const {
    return applyRecordedUsage(device, readRecords());
}

std::vector<UsageStateRecord> UsageStateStore::snapshot() const {
    return readRecords();
}

bool UsageStateStore::applyRecordedUsage(
    ParsedDevice& device,
    const std::vector<UsageStateRecord>& records) const {
    if (path_.empty() || device.endpoint.empty() || !shouldUseRecordedOwner(device)) {
        return false;
    }

    for (const UsageStateRecord& record : records) {
        if (equalsIgnoreCase(record.endpoint, device.endpoint) && !record.user.empty()) {
            device.inUseBy = usageText(record);
            return true;
        }
    }
    return false;
}

bool UsageStateStore::tryGetRecord(const ParsedDevice& device, UsageStateRecord& record) const {
    return tryGetRecord(device, record, readRecords());
}

bool UsageStateStore::tryGetRecord(
    const ParsedDevice& device,
    UsageStateRecord& record,
    const std::vector<UsageStateRecord>& records) const {
    if (path_.empty() || device.endpoint.empty()) {
        return false;
    }

    for (const UsageStateRecord& current : records) {
        if (equalsIgnoreCase(current.endpoint, device.endpoint)) {
            record = current;
            return true;
        }
    }
    return false;
}

const std::wstring& UsageStateStore::path() const {
    return path_;
}

std::wstring UsageStateStore::currentComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (GetComputerNameW(buffer, &size)) {
        return buffer;
    }
    return {};
}

std::vector<UsageStateRecord> UsageStateStore::readRecords() const {
    std::vector<UsageStateRecord> records;
    if (path_.empty()) {
        return records;
    }

    const std::wstring text = readUtf8FileIfExists(path_);
    if (trim(text).empty()) {
        return records;
    }

    const std::wregex objectPattern(L"\\{[^{}]*\"endpoint\"\\s*:\\s*\"(?:\\\\.|[^\"])*\"[^{}]*\\}");
    for (std::wsregex_iterator it(text.begin(), text.end(), objectPattern), end; it != end; ++it) {
        const std::wstring objectText = it->str();
        UsageStateRecord record;
        record.endpoint = fieldValue(objectText, L"endpoint");
        record.nickname = fieldValue(objectText, L"nickname");
        record.product = fieldValue(objectText, L"product");
        record.user = fieldValue(objectText, L"user");
        record.computer = fieldValue(objectText, L"computer");
        record.updatedAt = fieldValue(objectText, L"updatedAt");
        if (!record.endpoint.empty()) {
            records.push_back(std::move(record));
        }
    }
    return records;
}

void UsageStateStore::writeRecords(const std::vector<UsageStateRecord>& records) const {
    if (path_.empty()) {
        return;
    }

    std::wostringstream stream;
    stream << L"{\n"
        << L"  \"active\": [\n";
    for (size_t i = 0; i < records.size(); ++i) {
        const UsageStateRecord& record = records[i];
        stream << L"    {\n"
            << L"      \"endpoint\": " << jsonEscape(record.endpoint) << L",\n"
            << L"      \"nickname\": " << jsonEscape(record.nickname) << L",\n"
            << L"      \"product\": " << jsonEscape(record.product) << L",\n"
            << L"      \"user\": " << jsonEscape(record.user) << L",\n"
            << L"      \"computer\": " << jsonEscape(record.computer) << L",\n"
            << L"      \"updatedAt\": " << jsonEscape(record.updatedAt) << L"\n"
            << L"    }" << (i + 1 < records.size() ? L"," : L"") << L"\n";
    }
    stream << L"  ]\n"
        << L"}\n";

    writeUtf8File(path_, stream.str());
}
