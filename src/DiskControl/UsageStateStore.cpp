#include "UsageStateStore.h"
#include "UsageStateSync.h"
#include "StructuredJson.h"
#include "AuditLogger.h"
#include "IpcClient.h"
#include "PolicyManager.h"
#include "UsageEventLog.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cwctype>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <set>
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
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return {};
        }
        throw std::runtime_error("Cannot read usage state file. Windows error " + std::to_string(error));
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 8 * 1024 * 1024) {
        CloseHandle(file);
        throw std::runtime_error("Usage state file size is invalid.");
    }
    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    DWORD total = 0;
    while (total < bytes.size()) {
        DWORD read = 0;
        if (!ReadFile(file, bytes.data() + total, static_cast<DWORD>(bytes.size() - total), &read, nullptr) || read == 0) {
            CloseHandle(file);
            throw std::runtime_error("Cannot read complete usage state file.");
        }
        total += read;
    }
    CloseHandle(file);
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
    static std::atomic<unsigned long> sequence{0};
    const std::wstring tempPath = path + L".tmp-" + timestampForFileName() + L"-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(++sequence);

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

    DWORD replaceError = ERROR_SUCCESS;
    // File scanners can briefly prevent an otherwise atomic replacement.
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (MoveFileExW(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            return;
        }
        replaceError = GetLastError();
        if (replaceError != ERROR_SHARING_VIOLATION && replaceError != ERROR_LOCK_VIOLATION &&
            replaceError != ERROR_ACCESS_DENIED) {
            break;
        }
        Sleep(25);
    }
    if (replaceError != ERROR_SUCCESS) {
        DeleteFileW(tempPath.c_str());
        throw std::runtime_error("Cannot replace usage state file. Windows error " + std::to_string(replaceError));
    }
}

// Paths whose usage state lock is held by the current thread.
thread_local std::set<std::wstring> tHeldUsageStateLocks;

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
                heldPath_ = lowerCopy(statePath);
                tHeldUsageStateLocks.insert(heldPath_);
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
            tHeldUsageStateLocks.erase(heldPath_);
            CloseHandle(handle_);
        }
    }

    static bool heldByThisThread(const std::wstring& statePath) {
        return tHeldUsageStateLocks.count(lowerCopy(statePath)) != 0;
    }

    UsageStateFileLock(const UsageStateFileLock&) = delete;
    UsageStateFileLock& operator=(const UsageStateFileLock&) = delete;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::wstring heldPath_;
};

using DistControlJson::JsonValue;
using DistControlJson::JsonParser;

JsonValue jsonString(const std::wstring& text) {
    JsonValue result;
    result.type = JsonValue::Type::String;
    result.stringValue = text;
    return result;
}

JsonValue jsonArray() {
    JsonValue result;
    result.type = JsonValue::Type::Array;
    return result;
}

JsonValue jsonObject() {
    JsonValue result;
    result.type = JsonValue::Type::Object;
    return result;
}

std::wstring jsonField(const JsonValue& object, const wchar_t* name) {
    const JsonValue* value = object.find(name);
    if (!value) {
        return {};
    }
    if (value->type != JsonValue::Type::String) {
        throw std::runtime_error("Usage state string field is invalid.");
    }
    return value->stringValue;
}

unsigned long long currentEventFileTime() {
    FILETIME time{};
    GetSystemTimeAsFileTime(&time);
    ULARGE_INTEGER ticks{};
    ticks.LowPart = time.dwLowDateTime;
    ticks.HighPart = time.dwHighDateTime;
    return ticks.QuadPart;
}

JsonValue recordJson(const UsageStateRecord& record) {
    JsonValue value = jsonObject();
    value.objectValue = {
        { L"endpoint", jsonString(record.endpoint) },
        { L"nickname", jsonString(record.nickname) },
        { L"product", jsonString(record.product) },
        { L"user", jsonString(record.user) },
        { L"computer", jsonString(record.computer) },
        { L"updatedAt", jsonString(record.updatedAt) }
    };
    const std::pair<const wchar_t*, const std::wstring*> optional[] = {
        { L"publicIp", &record.publicIp }, { L"vpnProfileId", &record.vpnProfileId },
        { L"vpnProfileName", &record.vpnProfileName }, { L"operationId", &record.operationId },
        { L"connectionId", &record.connectionId }
    };
    for (const auto& field : optional) {
        if (!field.second->empty()) {
            value.objectValue[field.first] = jsonString(*field.second);
        }
    }
    if (record.eventFileTime != 0) {
        value.objectValue[L"eventFileTime"] = jsonString(std::to_wstring(record.eventFileTime));
    }
    return value;
}

UsageStateRecord recordFromJson(const JsonValue& value) {
    if (value.type != JsonValue::Type::Object) {
        throw std::runtime_error("Usage state record is invalid.");
    }
    UsageStateRecord record;
    record.endpoint = jsonField(value, L"endpoint");
    record.nickname = jsonField(value, L"nickname");
    record.product = jsonField(value, L"product");
    record.user = jsonField(value, L"user");
    record.computer = jsonField(value, L"computer");
    record.updatedAt = jsonField(value, L"updatedAt");
    record.publicIp = jsonField(value, L"publicIp");
    record.vpnProfileId = jsonField(value, L"vpnProfileId");
    record.vpnProfileName = jsonField(value, L"vpnProfileName");
    record.operationId = jsonField(value, L"operationId");
    record.connectionId = jsonField(value, L"connectionId");
    const std::wstring ticks = jsonField(value, L"eventFileTime");
    if (!ticks.empty()) {
        size_t consumed = 0;
        record.eventFileTime = std::stoull(ticks, &consumed);
        if (consumed != ticks.size()) {
            throw std::runtime_error("Usage state event time is invalid.");
        }
    }
    if (record.endpoint.empty()) {
        throw std::runtime_error("Usage state endpoint is missing.");
    }
    return record;
}

std::vector<UsageStateRecord> recordsFromJson(const JsonValue* array) {
    if (!array || array->type != JsonValue::Type::Array) {
        throw std::runtime_error("Usage state records must be an array.");
    }
    std::vector<UsageStateRecord> result;
    for (const JsonValue& value : array->arrayValue) {
        result.push_back(recordFromJson(value));
    }
    return result;
}

JsonValue recordsJson(const std::vector<UsageStateRecord>& records) {
    JsonValue result = jsonArray();
    for (const UsageStateRecord& record : records) {
        result.arrayValue.push_back(recordJson(record));
    }
    return result;
}

bool recordIsNewer(const UsageStateRecord& existing, const UsageStateRecord& incoming) {
    if (existing.eventFileTime != 0 && incoming.eventFileTime != 0) {
        return existing.eventFileTime > incoming.eventFileTime;
    }
    return !existing.updatedAt.empty() && existing.updatedAt > incoming.updatedAt;
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

bool usageElapsedMs(const std::wstring& startedAtLocal, unsigned long long startedFileTime,
    unsigned long long nowFileTime, unsigned long long& elapsedMs) {
    unsigned long long startTicks = startedFileTime;
    if (startTicks == 0) {
        const std::wstring& text = startedAtLocal;
        if (text.size() < 19 || text[4] != L'-' || text[7] != L'-' || text[10] != L'T' ||
            text[13] != L':' || text[16] != L':') {
            return false;
        }
        SYSTEMTIME localTime{};
        WORD* const fields[] = { &localTime.wYear, &localTime.wMonth, &localTime.wDay,
            &localTime.wHour, &localTime.wMinute, &localTime.wSecond };
        const size_t offsets[] = { 0, 5, 8, 11, 14, 17 };
        const size_t lengths[] = { 4, 2, 2, 2, 2, 2 };
        for (size_t index = 0; index < std::size(fields); ++index) {
            unsigned int value = 0;
            for (size_t digit = 0; digit < lengths[index]; ++digit) {
                const wchar_t ch = text[offsets[index] + digit];
                if (ch < L'0' || ch > L'9') {
                    return false;
                }
                value = value * 10 + static_cast<unsigned int>(ch - L'0');
            }
            *fields[index] = static_cast<WORD>(value);
        }
        SYSTEMTIME utcTime{};
        FILETIME fileTime{};
        if (!TzSpecificLocalTimeToSystemTime(nullptr, &localTime, &utcTime) ||
            !SystemTimeToFileTime(&utcTime, &fileTime)) {
            return false;
        }
        ULARGE_INTEGER ticks{};
        ticks.LowPart = fileTime.dwLowDateTime;
        ticks.HighPart = fileTime.dwHighDateTime;
        startTicks = ticks.QuadPart;
    }
    elapsedMs = nowFileTime <= startTicks ? 0 : (nowFileTime - startTicks) / 10000ULL;
    return true;
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

void UsageStateStore::applyUsedRecord(const UsageStateRecord& record) const {
    UsageStateFileLock lock(path_);
    std::vector<UsageStateRecord> records = readRecords();
    const auto existing = std::find_if(records.begin(), records.end(), [&record](const UsageStateRecord& item) {
        return equalsIgnoreCase(item.endpoint, record.endpoint);
    });
    if (existing != records.end()) {
        if (recordIsNewer(*existing, record) ||
            (existing->connectionId == record.connectionId &&
                existing->eventFileTime != 0 && existing->eventFileTime == record.eventFileTime)) {
            return;
        }
        *existing = record;
    }
    else {
        records.push_back(record);
    }
    writeRecords(records);
}

void UsageStateStore::applyReleasedRecord(const UsageStateRecord& record) const {
    UsageStateFileLock lock(path_);
    std::vector<UsageStateRecord> records = readRecords();
    const size_t before = records.size();
    records.erase(std::remove_if(records.begin(), records.end(), [&record](const UsageStateRecord& item) {
        return equalsIgnoreCase(item.endpoint, record.endpoint) &&
            equalsIgnoreCase(item.user, record.user) &&
            equalsIgnoreCase(item.computer, record.computer) &&
            (record.connectionId.empty() || item.connectionId.empty() || item.connectionId == record.connectionId) &&
            !recordIsNewer(item, record);
    }), records.end());
    if (records.size() != before) {
        writeRecords(records);
    }
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

    const JsonValue root = JsonParser(text).parse();
    if (root.type != JsonValue::Type::Object) {
        throw std::runtime_error("Usage state document is invalid.");
    }
    return recordsFromJson(root.find(L"active"));
}

void UsageStateStore::writeRecords(const std::vector<UsageStateRecord>& records) const {
    if (path_.empty()) {
        return;
    }
    JsonValue root = jsonObject();
    root.objectValue[L"active"] = recordsJson(records);
    writeUtf8File(path_, DistControlJson::serializeJson(root));
}

namespace {
struct PendingUsageChange {
    std::wstring id;
    bool released = false;
    UsageStateRecord record;
};

struct LocalUsageState {
    std::wstring sharedPath;
    std::vector<UsageStateRecord> active;
    std::vector<UsageStateRecord> cache;
    std::vector<PendingUsageChange> pending;
};

LocalUsageState parseLocalUsageState(const std::wstring& text, const std::wstring& sharedPath) {
    LocalUsageState state;
    state.sharedPath = sharedPath;
    if (text.empty()) {
        return state;
    }
    const JsonValue root = JsonParser(text).parse();
    if (root.type != JsonValue::Type::Object || jsonField(root, L"version") != L"1" ||
        !equalsIgnoreCase(jsonField(root, L"sharedPath"), sharedPath)) {
        throw std::runtime_error("Local usage state format or synchronization target is invalid.");
    }
    state.active = recordsFromJson(root.find(L"active"));
    state.cache = recordsFromJson(root.find(L"cache"));
    const JsonValue* pending = root.find(L"pending");
    if (!pending || pending->type != JsonValue::Type::Array) {
        throw std::runtime_error("Local usage state pending changes are invalid.");
    }
    for (const JsonValue& item : pending->arrayValue) {
        const JsonValue* record = item.find(L"record");
        const std::wstring action = jsonField(item, L"action");
        const std::wstring id = jsonField(item, L"id");
        if (!record || id.empty() || (action != L"use" && action != L"release")) {
            throw std::runtime_error("Local usage state change is invalid.");
        }
        state.pending.push_back({ id, action == L"release", recordFromJson(*record) });
    }
    return state;
}

// Reads the local timer queue. A damaged file is renamed to
// "<name>.corrupt-<time>" and replaced by an empty queue, so the timer keeps
// working; read errors (sharing, access) are still reported to the caller.
LocalUsageState readLocalUsageState(const std::wstring& path, const std::wstring& sharedPath) {
    std::wstring text = readUtf8FileIfExists(path);
    try {
        return parseLocalUsageState(text, sharedPath);
    }
    catch (const std::exception& firstError) {
        std::string reason = firstError.what();
        std::unique_ptr<UsageStateFileLock> lock;
        if (!UsageStateFileLock::heldByThisThread(path)) {
            // Re-read under the lock: a writer may have replaced the file meanwhile.
            lock = std::make_unique<UsageStateFileLock>(path);
            text = readUtf8FileIfExists(path);
            try {
                return parseLocalUsageState(text, sharedPath);
            }
            catch (const std::exception& error) {
                reason = error.what();
            }
        }
        const std::wstring quarantined = path + L".corrupt-" + timestampForFileName();
        if (!MoveFileExW(path.c_str(), quarantined.c_str(), MOVEFILE_WRITE_THROUGH)) {
            throw std::runtime_error("Local usage state is invalid and could not be set aside: " + reason);
        }
        AuditLogger::trace(L"USAGE-STATE",
            L"Локальный файл таймеров повреждён и сохранён как «" + quarantined +
            L"». Начат новый файл; изменения из повреждённого файла не отправлены в общую папку. Причина: " +
            utf8ToWide(reason) + L".");
        LocalUsageState state;
        state.sharedPath = sharedPath;
        return state;
    }
}

void writeLocalUsageState(const std::wstring& path, const LocalUsageState& state) {
    JsonValue root = jsonObject();
    root.objectValue[L"version"] = jsonString(L"1");
    root.objectValue[L"sharedPath"] = jsonString(state.sharedPath);
    root.objectValue[L"active"] = recordsJson(state.active);
    root.objectValue[L"cache"] = recordsJson(state.cache);
    JsonValue pending = jsonArray();
    for (const PendingUsageChange& change : state.pending) {
        JsonValue value = jsonObject();
        value.objectValue[L"id"] = jsonString(change.id);
        value.objectValue[L"action"] = jsonString(change.released ? L"release" : L"use");
        value.objectValue[L"record"] = recordJson(change.record);
        pending.arrayValue.push_back(std::move(value));
    }
    root.objectValue[L"pending"] = std::move(pending);
    writeUtf8File(path, DistControlJson::serializeJson(root));
}

std::wstring usageChangeId() {
    static std::atomic<unsigned long> sequence{0};
    return UsageStateStore::currentComputerName() + L"-" +
        std::to_wstring(currentEventFileTime()) + L"-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(++sequence);
}

void queueUsageChange(LocalUsageState& state, const UsageStateRecord& record, bool released) {
    // Only the latest state per token is needed by the shared timer. History stays in the audit log.
    state.pending.erase(std::remove_if(state.pending.begin(), state.pending.end(),
        [&record](const PendingUsageChange& change) {
            return equalsIgnoreCase(change.record.endpoint, record.endpoint);
        }), state.pending.end());
    if (!state.sharedPath.empty()) {
        state.pending.push_back({ usageChangeId(), released, record });
    }
}

std::wstring localUsageStatePath(const std::wstring& sharedPath) {
#ifndef DISKCONTROL_TESTING
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (length == 0) {
        throw std::runtime_error("LOCALAPPDATA is not available for local usage state.");
    }
    std::wstring directory(length, L'\0');
    const DWORD copied = GetEnvironmentVariableW(L"LOCALAPPDATA", directory.data(), length);
    if (copied == 0 || copied >= length) {
        throw std::runtime_error("LOCALAPPDATA is not available for local usage state.");
    }
    directory.resize(copied);
#endif
    unsigned long long hash = 14695981039346656037ULL;
    for (wchar_t ch : lowerCopy(sharedPath)) {
        hash = (hash ^ static_cast<unsigned int>(ch)) * 1099511628211ULL;
    }
    std::wostringstream suffix;
    suffix << std::hex << hash;
#ifdef DISKCONTROL_TESTING
    return L"usage-sync-test-" + suffix.str() + L".json";
#else
    return directory + L"\\DistControl\\state\\usage-sync-" + suffix.str() + L".json";
#endif
}

std::wstring quoteProcessArgument(const std::wstring& text) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : text) {
        if (ch == L'\\') {
            ++slashes;
        }
        else {
            result.append(slashes * (ch == L'\"' ? 2 : 1), L'\\');
            slashes = 0;
            if (ch == L'\"') {
                result.push_back(L'\\');
            }
            result.push_back(ch);
        }
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

struct BackgroundSyncProcess {
    HANDLE process = nullptr;
    ULONGLONG lastStartedAt = 0;
};

struct BackgroundSyncProcesses {
    std::mutex mutex;
    std::map<std::wstring, BackgroundSyncProcess> entries;

    ~BackgroundSyncProcesses() {
        for (const auto& entry : entries) {
            if (entry.second.process) {
                CloseHandle(entry.second.process);
            }
        }
    }
};

BackgroundSyncProcesses gBackgroundSyncProcesses;
}

UsageStateSync::UsageStateSync(std::wstring sharedPath, std::wstring localPath)
    : sharedPath_(std::move(sharedPath)),
      localPath_(localPath.empty() ? localUsageStatePath(sharedPath_) : std::move(localPath)) {
    if (equalsIgnoreCase(localPath_, sharedPath_)) {
        throw std::runtime_error("Local usage state must differ from the shared timer.");
    }
}

UsageStateRecord UsageStateSync::markUsed(const ParsedDevice& device, const std::wstring& userName,
    const std::wstring& publicIp, const std::wstring& vpnProfileId,
    const std::wstring& vpnProfileName, const std::wstring& operationId, bool resetTimer) const {
    UsageStateFileLock lock(localPath_);
    LocalUsageState state = readLocalUsageState(localPath_, sharedPath_);
    UsageStateRecord record;
    record.endpoint = device.endpoint;
    record.nickname = device.nickname;
    record.product = device.product;
    record.user = userName;
    record.computer = UsageStateStore::currentComputerName();
    record.updatedAt = timestampIso();
    record.eventFileTime = currentEventFileTime();
    record.operationId = operationId;
    record.connectionId = usageChangeId();
    record.publicIp = publicIp;
    record.vpnProfileId = vpnProfileId;
    record.vpnProfileName = vpnProfileName;
    if (record.endpoint.empty() || record.user.empty()) {
        throw std::runtime_error("Local usage state endpoint and user are required.");
    }
    auto existing = std::find_if(state.active.begin(), state.active.end(), [&record](const UsageStateRecord& item) {
        return equalsIgnoreCase(item.endpoint, record.endpoint);
    });
    if (resetTimer && existing != state.active.end()) {
        record.connectionId = existing->connectionId;
        record.publicIp = existing->publicIp;
        record.vpnProfileId = existing->vpnProfileId;
        record.vpnProfileName = existing->vpnProfileName;
    }
    if (existing == state.active.end()) {
        state.active.push_back(record);
    }
    else {
        *existing = record;
    }
    queueUsageChange(state, record, false);
    writeLocalUsageState(localPath_, state);
    return record;
}

void UsageStateSync::markReleased(const ParsedDevice& device, const std::wstring& userName,
    const std::wstring& operationId) const {
    if (device.endpoint.empty()) {
        return;
    }
    UsageStateFileLock lock(localPath_);
    LocalUsageState state = readLocalUsageState(localPath_, sharedPath_);
    UsageStateRecord record;
    record.endpoint = device.endpoint;
    record.nickname = device.nickname;
    record.product = device.product;
    record.user = userName;
    record.computer = UsageStateStore::currentComputerName();
    for (const auto* records : { &state.cache, &state.active }) {
        const auto existing = std::find_if(records->begin(), records->end(), [&record](const UsageStateRecord& item) {
            return equalsIgnoreCase(item.endpoint, record.endpoint) &&
                equalsIgnoreCase(item.user, record.user) && equalsIgnoreCase(item.computer, record.computer);
        });
        if (existing != records->end()) {
            record = *existing;
        }
    }
    record.updatedAt = timestampIso();
    record.eventFileTime = currentEventFileTime();
    record.operationId = operationId;
    state.active.erase(std::remove_if(state.active.begin(), state.active.end(), [&device](const UsageStateRecord& item) {
        return equalsIgnoreCase(item.endpoint, device.endpoint);
    }), state.active.end());
    queueUsageChange(state, record, true);
    writeLocalUsageState(localPath_, state);
}

std::vector<UsageStateRecord> UsageStateSync::snapshot() const {
    const LocalUsageState state = readLocalUsageState(localPath_, sharedPath_);
    std::vector<UsageStateRecord> result = state.cache;
    for (const PendingUsageChange& change : state.pending) {
        if (change.released) {
            result.erase(std::remove_if(result.begin(), result.end(), [&change](const UsageStateRecord& item) {
                return equalsIgnoreCase(item.endpoint, change.record.endpoint) &&
                    equalsIgnoreCase(item.user, change.record.user) &&
                    equalsIgnoreCase(item.computer, change.record.computer);
            }), result.end());
        }
    }
    for (const UsageStateRecord& record : state.active) {
        const auto existing = std::find_if(result.begin(), result.end(), [&record](const UsageStateRecord& item) {
            return equalsIgnoreCase(item.endpoint, record.endpoint);
        });
        if (existing == result.end()) {
            result.push_back(record);
        }
        else if (!recordIsNewer(*existing, record)) {
            *existing = record;
        }
    }
    return result;
}

size_t UsageStateSync::pendingCount() const {
    return readLocalUsageState(localPath_, sharedPath_).pending.size();
}

const std::wstring& UsageStateSync::localPath() const {
    return localPath_;
}

bool UsageStateSync::isBackgroundSyncDue(size_t pendingChanges, unsigned long long nowMs,
    unsigned long long lastStartedMs) {
    if (lastStartedMs == 0 || nowMs < lastStartedMs) {
        return true;
    }
    const unsigned long long elapsed = nowMs - lastStartedMs;
    return elapsed >= (pendingChanges != 0 ? kPendingRetryMs : kPeriodicRefreshMs);
}

void UsageStateSync::requestBackgroundSync(const std::wstring& pipeName, bool onlyIfDue) const {
#ifdef DISKCONTROL_TESTING
    (void)pipeName;
    (void)onlyIfDue;
    return;
#else
    if (sharedPath_.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(gBackgroundSyncProcesses.mutex);
    BackgroundSyncProcess& entry = gBackgroundSyncProcesses.entries[localPath_];
    if (entry.process) {
        if (WaitForSingleObject(entry.process, 0) == WAIT_TIMEOUT) {
            return;
        }
        CloseHandle(entry.process);
        entry.process = nullptr;
    }
    const ULONGLONG now = GetTickCount64();
    if (onlyIfDue) {
        size_t pending = 1;
        try {
            pending = pendingCount();
        }
        catch (const std::exception&) {
        }
        if (!isBackgroundSyncDue(pending, now, entry.lastStartedAt)) {
            return;
        }
    }
    else if (entry.lastStartedAt != 0 && now - entry.lastStartedAt < 1000) {
        // A change requested right after another start is picked up by the
        // running helper or by the next periodic check for unsent changes.
        return;
    }
    entry.lastStartedAt = now;
    std::vector<wchar_t> executable(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0 || length >= executable.size()) {
        return;
    }
    const std::wstring path(executable.data(), length);
    std::wstring command = quoteProcessArgument(path) + L" --sync-usage --shared-usage " +
        quoteProcessArgument(sharedPath_) + L" --local-usage " + quoteProcessArgument(localPath_) +
        L" --pipe " + quoteProcessArgument(pipeName);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process)) {
        AuditLogger::trace(L"USAGE-SYNC", L"Не удалось запустить фоновую синхронизацию таймера. Код Windows: " +
            std::to_wstring(GetLastError()) + L". Локальные данные сохранены.");
        return;
    }
    CloseHandle(process.hThread);
    entry.process = process.hProcess;
#endif
}

bool UsageStateSync::synchronize(const OwnershipValidator& isOwned) const {
    if (!isOwned) {
        throw std::runtime_error("Usage synchronization requires an ownership validator.");
    }
    const std::wstring trace = AuditLogger::createOperationId(L"USAGE-SYNC");
    HANDLE syncLock = INVALID_HANDLE_VALUE;
    try {
        ensureDirectoryTree(parentOf(localPath_));
        syncLock = CreateFileW((localPath_ + L".sync.lock").c_str(), GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (syncLock == INVALID_HANDLE_VALUE) {
            return false;
        }
        LocalUsageState state = readLocalUsageState(localPath_, sharedPath_);
        // Recheck old local sessions against the service after an application restart.
        for (const UsageStateRecord& record : state.active) {
            if (isOwned(record)) {
                continue;
            }
            UsageStateFileLock lock(localPath_);
            LocalUsageState current = readLocalUsageState(localPath_, sharedPath_);
            const auto found = std::find_if(current.active.begin(), current.active.end(), [&record](const UsageStateRecord& item) {
                return item.connectionId == record.connectionId;
            });
            if (found != current.active.end()) {
                UsageStateRecord released = *found;
                released.updatedAt = timestampIso();
                released.eventFileTime = currentEventFileTime();
                current.active.erase(found);
                queueUsageChange(current, released, true);
                writeLocalUsageState(localPath_, current);
            }
        }
        state = readLocalUsageState(localPath_, sharedPath_);
        UsageStateStore shared(sharedPath_);
        for (const PendingUsageChange& change : state.pending) {
            const LocalUsageState current = readLocalUsageState(localPath_, sharedPath_);
            if (std::none_of(current.pending.begin(), current.pending.end(), [&change](const PendingUsageChange& item) {
                return item.id == change.id;
            })) {
                continue;
            }
            const bool noLongerOwned = !change.released && !isOwned(change.record);
            const LocalUsageState ready = readLocalUsageState(localPath_, sharedPath_);
            if (std::none_of(ready.pending.begin(), ready.pending.end(), [&change](const PendingUsageChange& item) {
                return item.id == change.id;
            })) {
                continue;
            }
            if (change.released) {
                shared.applyReleasedRecord(change.record);
            }
            else if (!noLongerOwned) {
                shared.applyUsedRecord(change.record);
            }
            else {
                UsageStateRecord released = change.record;
                released.updatedAt = timestampIso();
                released.eventFileTime = currentEventFileTime();
                shared.applyReleasedRecord(released);
            }
            // Acknowledge and refresh the cache together, outside all network operations.
            const std::vector<UsageStateRecord> cache = shared.snapshot();
            UsageStateFileLock lock(localPath_);
            LocalUsageState acknowledged = readLocalUsageState(localPath_, sharedPath_);
            acknowledged.cache = cache;
            if (noLongerOwned) {
                acknowledged.active.erase(std::remove_if(acknowledged.active.begin(), acknowledged.active.end(),
                    [&change](const UsageStateRecord& item) {
                        return item.connectionId == change.record.connectionId;
                    }), acknowledged.active.end());
            }
            acknowledged.pending.erase(std::remove_if(acknowledged.pending.begin(), acknowledged.pending.end(),
                [&change](const PendingUsageChange& item) { return item.id == change.id; }), acknowledged.pending.end());
            writeLocalUsageState(localPath_, acknowledged);
            AuditLogger::trace(trace, L"Изменение общего таймера обработано для токена «" + change.record.nickname +
                (change.released || noLongerOwned ? L"»: отключение" : L"»: подключение") +
                L". Исходное время события: " + change.record.updatedAt + L"; внешний IP: " +
                (change.record.publicIp.empty() ? L"не определён" : change.record.publicIp) + L"; VPN: " +
                (change.record.vpnProfileName.empty() ? L"не указан" : change.record.vpnProfileName) +
                L"; исходная операция: " + change.record.operationId + L".");
        }
        const std::vector<UsageStateRecord> cache = shared.snapshot();
        {
            UsageStateFileLock lock(localPath_);
            LocalUsageState current = readLocalUsageState(localPath_, sharedPath_);
            current.cache = cache;
            writeLocalUsageState(localPath_, current);
        }
        CloseHandle(syncLock);
        return true;
    }
    catch (const std::exception& error) {
        if (syncLock != INVALID_HANDLE_VALUE) {
            CloseHandle(syncLock);
        }
        const std::wstring details = utf8ToWide(error.what());
        AuditLogger::trace(trace, L"Фоновое обновление таймеров сейчас не завершилось. Изменения остаются на компьютере, " +
            std::wstring(L"синхронизация повторится автоматически. Причина: ") + details);
        return false;
    }
}

int UsageStateSync::runBackgroundSync(const std::wstring& sharedPath,
    const std::wstring& localPath, const std::wstring& pipeName) {
    try {
        if (sharedPath.empty() || localPath.empty() || pipeName.empty()) {
            return 1;
        }
        try {
            UsageEventLog::flush(UsageEventLog::queuePath(), UsageEventLog::sharedLogDirectory(sharedPath),
                UsageStateStore::currentComputerName(), PolicyManager::currentUserName());
        }
        catch (const std::exception&) {
            // Events stay queued and are moved on the next synchronization.
        }
        UsageStateSync sync(sharedPath, localPath);
        IpcClient ipc(pipeName);
        const OwnershipValidator isOwned = [&ipc](const UsageStateRecord& record) {
            ParsedDevice device;
            device.endpoint = record.endpoint;
            const std::wstring response = ipc.issueCommand(L"DEVICE INFO," + record.endpoint, 1500);
            if (response.empty() || response.rfind(L"ERROR", 0) == 0 || response.rfind(L"FAILED", 0) == 0) {
                throw std::runtime_error("The token service is temporarily unavailable for synchronization.");
            }
            DeviceParser::applyDeviceInfo(device, response);
            if (device.inUseBy.empty()) {
                throw std::runtime_error("The token service did not provide its current owner.");
            }
            const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, record.user);
            if (!usage.isFree && !usage.isUsedByCurrentUser && usage.userText.empty()) {
                throw std::runtime_error("The token service has not identified its current owner.");
            }
            const std::wstring location = trim(usage.locationText);
            const std::wstring computerSuffix = L"(" + record.computer + L")";
            const bool currentComputer = location.empty() || equalsIgnoreCase(location, record.computer) ||
                (location.size() >= computerSuffix.size() &&
                    equalsIgnoreCase(location.substr(location.size() - computerSuffix.size()), computerSuffix));
            return usage.isUsedByCurrentUser &&
                currentComputer;
        };
        // Drain changes created while an earlier network operation was waiting.
        for (int batch = 0; batch < 8; ++batch) {
            if (!sync.synchronize(isOwned)) {
                return 1;
            }
            if (sync.pendingCount() == 0) {
                return 0;
            }
        }
        return 1;
    }
    catch (...) {
        return 1;
    }
}
