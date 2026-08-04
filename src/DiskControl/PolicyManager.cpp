#include "PolicyManager.h"

#define SECURITY_WIN32
#include <windows.h>
#include <sddl.h>
#include <security.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
std::wstring g_configPathOverride;

struct JsonValue {
    enum class Type { Null, String, Number, Object, Array };

    Type type = Type::Null;
    std::wstring stringValue;
    double numberValue = 0;
    std::map<std::wstring, JsonValue> objectValue;
    std::vector<JsonValue> arrayValue;

    const JsonValue* find(const std::wstring& key) const {
        const auto it = objectValue.find(key);
        return it == objectValue.end() ? nullptr : &it->second;
    }
};

class JsonParser {
public:
    explicit JsonParser(std::wstring text) : text_(std::move(text)) {}

    JsonValue parse() {
        skipWs();
        JsonValue value = parseValue();
        skipWs();
        if (pos_ != text_.size()) {
            throw std::runtime_error("Unexpected JSON content.");
        }
        return value;
    }

private:
    JsonValue parseValue() {
        skipWs();
        if (peek() == L'{') {
            return parseObject();
        }
        if (peek() == L'[') {
            return parseArray();
        }
        if (peek() == L'"') {
            JsonValue value;
            value.type = JsonValue::Type::String;
            value.stringValue = parseString();
            return value;
        }
        if (std::iswdigit(peek()) || peek() == L'-') {
            return parseNumber();
        }

        if (matchLiteral(L"true") || matchLiteral(L"false") || matchLiteral(L"null")) {
            return {};
        }

        throw std::runtime_error("Invalid JSON value.");
    }

    JsonValue parseObject() {
        consume(L'{');
        JsonValue value;
        value.type = JsonValue::Type::Object;
        skipWs();
        if (peek() == L'}') {
            ++pos_;
            return value;
        }

        while (true) {
            const std::wstring key = parseString();
            skipWs();
            consume(L':');
            value.objectValue[key] = parseValue();
            skipWs();
            if (peek() == L'}') {
                ++pos_;
                break;
            }
            consume(L',');
        }
        return value;
    }

    JsonValue parseArray() {
        consume(L'[');
        JsonValue value;
        value.type = JsonValue::Type::Array;
        skipWs();
        if (peek() == L']') {
            ++pos_;
            return value;
        }

        while (true) {
            value.arrayValue.push_back(parseValue());
            skipWs();
            if (peek() == L']') {
                ++pos_;
                break;
            }
            consume(L',');
        }
        return value;
    }

    JsonValue parseNumber() {
        const size_t start = pos_;
        if (peek() == L'-') {
            ++pos_;
        }
        while (std::iswdigit(peek())) {
            ++pos_;
        }
        if (peek() == L'.') {
            ++pos_;
            while (std::iswdigit(peek())) {
                ++pos_;
            }
        }

        JsonValue value;
        value.type = JsonValue::Type::Number;
        value.numberValue = std::wcstod(text_.substr(start, pos_ - start).c_str(), nullptr);
        return value;
    }

    std::wstring parseString() {
        consume(L'"');
        std::wstring result;
        while (pos_ < text_.size()) {
            wchar_t ch = text_[pos_++];
            if (ch == L'"') {
                return result;
            }
            if (ch != L'\\') {
                result.push_back(ch);
                continue;
            }

            if (pos_ >= text_.size()) {
                throw std::runtime_error("Invalid JSON escape.");
            }
            ch = text_[pos_++];
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
                result.push_back(parseUnicodeEscape());
                break;
            default:
                throw std::runtime_error("Unsupported JSON escape.");
            }
        }
        throw std::runtime_error("Unterminated JSON string.");
    }

    wchar_t parseUnicodeEscape() {
        if (pos_ + 4 > text_.size()) {
            throw std::runtime_error("Invalid unicode escape.");
        }
        unsigned int value = 0;
        for (int i = 0; i < 4; ++i) {
            const wchar_t ch = text_[pos_++];
            value <<= 4;
            if (ch >= L'0' && ch <= L'9') {
                value += ch - L'0';
            }
            else if (ch >= L'a' && ch <= L'f') {
                value += ch - L'a' + 10;
            }
            else if (ch >= L'A' && ch <= L'F') {
                value += ch - L'A' + 10;
            }
            else {
                throw std::runtime_error("Invalid unicode escape.");
            }
        }
        return static_cast<wchar_t>(value);
    }

    bool matchLiteral(const wchar_t* literal) {
        const std::wstring value(literal);
        if (text_.compare(pos_, value.size(), value) == 0) {
            pos_ += value.size();
            return true;
        }
        return false;
    }

    void consume(wchar_t expected) {
        skipWs();
        if (peek() != expected) {
            throw std::runtime_error("Unexpected JSON token.");
        }
        ++pos_;
    }

    wchar_t peek() const {
        return pos_ < text_.size() ? text_[pos_] : L'\0';
    }

    void skipWs() {
        while (pos_ < text_.size() && std::iswspace(text_[pos_])) {
            ++pos_;
        }
    }

    std::wstring text_;
    size_t pos_ = 0;
};

std::wstring utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        throw std::runtime_error("Cannot decode UTF-8 config.");
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::wstring readUtf8File(const std::wstring& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("Cannot open config file.");
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

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw std::runtime_error("Cannot encode UTF-8 config.");
    }
    std::string result(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr) != size) {
        throw std::runtime_error("Cannot encode UTF-8 config.");
    }
    result.resize(static_cast<size_t>(size - 1));
    return result;
}

std::string diagnosticPath(const std::wstring& path) {
    std::string result;
    for (wchar_t ch : path) {
        result.push_back(ch >= 32 && ch <= 126 ? static_cast<char>(ch) : '?');
    }
    return result;
}

std::string win32ErrorDetails(DWORD error) {
    switch (error) {
    case ERROR_ACCESS_DENIED:
        return "Access denied. Run DiskControl Admin as administrator or check allow.json permissions.";
    case ERROR_SHARING_VIOLATION:
        return "File is in use by another process.";
    case ERROR_PATH_NOT_FOUND:
        return "Path not found.";
    case ERROR_FILE_NOT_FOUND:
        return "File not found.";
    default:
        return "Win32 error " + std::to_string(error) + ".";
    }
}

std::runtime_error fileError(const char* action, const std::wstring& path, DWORD error) {
    return std::runtime_error(std::string(action) + ". " + win32ErrorDetails(error) + " Path=" + diagnosticPath(path));
}

std::wstring timestampForFileName();

void writeUtf8File(const std::wstring& path, const std::wstring& text) {
    const std::string bytes = wideToUtf8(text);
    const std::wstring tempPath = path + L".tmp-" + timestampForFileName();

    HANDLE file = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw fileError("Cannot create temp config file", tempPath, GetLastError());
    }

    bool ok = true;
    DWORD error = ERROR_SUCCESS;
    size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(bytes.size() - offset, 1024 * 1024));
        DWORD written = 0;
        if (!WriteFile(file, bytes.data() + offset, chunk, &written, nullptr)) {
            ok = false;
            error = GetLastError();
            break;
        }
        offset += written;
        if (written == 0) {
            ok = false;
            error = ERROR_WRITE_FAULT;
            break;
        }
    }

    if (ok && !FlushFileBuffers(file)) {
        ok = false;
        error = GetLastError();
    }

    CloseHandle(file);

    if (!ok) {
        DeleteFileW(tempPath.c_str());
        throw fileError("Cannot write temp config file", tempPath, error);
    }

    if (!MoveFileExW(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = GetLastError();
        DeleteFileW(tempPath.c_str());
        throw fileError("Cannot replace config file", path, error);
    }
}

std::wstring emptyPolicyJson() {
    return L"{\n"
        L"  \"pipeName\": \"dkclient\",\n"
        L"  \"refreshSeconds\": 5,\n"
        L"  \"userAssignments\": []\n"
        L"}\n";
}

bool fileExists(const std::wstring& path) {
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring programDataDiskControlPath(const wchar_t* fileName) {
    wchar_t buffer[MAX_PATH]{};
    const DWORD needed = GetEnvironmentVariableW(L"ProgramData", buffer, MAX_PATH);
    if (needed == 0 || needed >= MAX_PATH) {
        return {};
    }
    return std::wstring(buffer) + L"\\DiskControl\\" + fileName;
}

std::wstring programDataPolicyPath() {
    return programDataDiskControlPath(L"allow.json");
}

std::wstring programDataUsageStatePath() {
    return programDataDiskControlPath(L"usage.json");
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
        throw std::runtime_error("Config parent path is not a directory.");
    }

    const std::wstring parent = parentOf(directory);
    if (!parent.empty() && parent != directory) {
        ensureDirectoryTree(parent);
    }

    if (!CreateDirectoryW(directory.c_str(), nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            throw std::runtime_error("Cannot create config directory.");
        }
    }
}

void ensureParentDirectoryForFile(const std::wstring& path) {
    ensureDirectoryTree(parentOf(path));
}

std::wstring timestampForFileName() {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"%04u%02u%02u-%02u%02u%02u",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    return buffer;
}

JsonValue readPolicyRoot(const std::wstring& path) {
    JsonValue root = JsonParser(readUtf8File(path)).parse();
    if (root.type != JsonValue::Type::Object) {
        throw std::runtime_error("Config root must be an object.");
    }

    const JsonValue* assignments = root.find(L"userAssignments");
    if (!assignments || assignments->type != JsonValue::Type::Array) {
        throw std::runtime_error("Config must contain userAssignments array.");
    }

    return root;
}

void replaceWithEmptyPolicy(const std::wstring& path) {
    ensureParentDirectoryForFile(path);

    if (fileExists(path)) {
        const std::wstring backupPath = path + L".invalid-" + timestampForFileName() + L".bak";
        if (!CopyFileW(path.c_str(), backupPath.c_str(), TRUE)) {
            throw std::runtime_error("Cannot back up invalid config file.");
        }
    }

    writeUtf8File(path, emptyPolicyJson());
}

std::wstring findConfigPath() {
    if (!g_configPathOverride.empty()) {
        return g_configPathOverride;
    }

    const std::wstring programDataPath = programDataPolicyPath();
    if (!programDataPath.empty()) {
        return programDataPath;
    }

    return L"allow.json";
}

std::wstring lower(std::wstring value) {
    if (!value.empty()) {
        CharLowerBuffW(value.data(), static_cast<DWORD>(value.size()));
    }
    return value;
}

bool equalsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return lower(left) == lower(right);
}

std::wstring shortAccountName(const std::wstring& value) {
    const size_t slash = value.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return value;
    }
    return value.substr(slash + 1);
}

bool configuredUserMatchesTarget(const std::wstring& configured, const std::wstring& target) {
    if (target.empty()) {
        return false;
    }
    return equalsIgnoreCase(configured, target) ||
        equalsIgnoreCase(shortAccountName(configured), shortAccountName(target));
}

std::wstring getShortUserName() {
    wchar_t buffer[256]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (GetUserNameW(buffer, &size)) {
        return buffer;
    }
    return {};
}

std::wstring getSamUserName() {
    wchar_t buffer[512]{};
    ULONG size = static_cast<ULONG>(std::size(buffer));
    if (GetUserNameExW(NameSamCompatible, buffer, &size)) {
        return buffer;
    }
    return getShortUserName();
}

std::wstring getCurrentUserSid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return {};
    }

    DWORD length = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &length);
    std::vector<unsigned char> buffer(length);
    std::wstring sid;
    if (GetTokenInformation(token, TokenUser, buffer.data(), length, &length)) {
        auto* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
        LPWSTR sidText = nullptr;
        if (ConvertSidToStringSidW(tokenUser->User.Sid, &sidText)) {
            sid = sidText;
            LocalFree(sidText);
        }
    }
    CloseHandle(token);
    return sid;
}

bool userMatches(const std::wstring& configured) {
    return equalsIgnoreCase(configured, getSamUserName()) ||
        equalsIgnoreCase(configured, getShortUserName()) ||
        equalsIgnoreCase(configured, getCurrentUserSid());
}

bool lookupAccountSid(const std::wstring& account, std::vector<unsigned char>& sidBuffer) {
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE use{};
    LookupAccountNameW(nullptr, account.c_str(), nullptr, &sidSize, nullptr, &domainSize, &use);
    if (sidSize == 0) {
        return false;
    }

    sidBuffer.resize(sidSize);
    std::wstring domain(domainSize, L'\0');
    if (!LookupAccountNameW(nullptr, account.c_str(), sidBuffer.data(), &sidSize, domain.data(), &domainSize, &use)) {
        return false;
    }
    return true;
}

bool groupMatches(const std::wstring& configured) {
    PSID sid = nullptr;
    std::vector<unsigned char> sidBuffer;

    if (configured.rfind(L"S-", 0) == 0) {
        if (!ConvertStringSidToSidW(configured.c_str(), &sid)) {
            return false;
        }
    }
    else {
        if (!lookupAccountSid(configured, sidBuffer)) {
            return false;
        }
        sid = sidBuffer.data();
    }

    BOOL isMember = FALSE;
    const BOOL ok = CheckTokenMembership(nullptr, sid, &isMember);
    if (configured.rfind(L"S-", 0) == 0 && sid) {
        LocalFree(sid);
    }
    return ok && isMember;
}

std::vector<std::wstring> stringArray(const JsonValue* value) {
    std::vector<std::wstring> result;
    if (!value || value->type != JsonValue::Type::Array) {
        return result;
    }
    for (const JsonValue& item : value->arrayValue) {
        if (item.type == JsonValue::Type::String) {
            result.push_back(item.stringValue);
        }
    }
    return result;
}

std::wstring stringValue(const JsonValue* value) {
    if (!value || value->type != JsonValue::Type::String) {
        return {};
    }
    return value->stringValue;
}

JsonValue makeString(const std::wstring& value) {
    JsonValue json;
    json.type = JsonValue::Type::String;
    json.stringValue = value;
    return json;
}

JsonValue makeArray(std::vector<JsonValue> values = {}) {
    JsonValue json;
    json.type = JsonValue::Type::Array;
    json.arrayValue = std::move(values);
    return json;
}

JsonValue makeObject(std::map<std::wstring, JsonValue> values = {}) {
    JsonValue json;
    json.type = JsonValue::Type::Object;
    json.objectValue = std::move(values);
    return json;
}

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
            escaped.push_back(ch);
            break;
        }
    }
    escaped.push_back(L'"');
    return escaped;
}

void writeIndent(std::wostringstream& stream, int indent) {
    for (int i = 0; i < indent; ++i) {
        stream << L"  ";
    }
}

void serializeJson(const JsonValue& value, std::wostringstream& stream, int indent) {
    switch (value.type) {
    case JsonValue::Type::String:
        stream << jsonEscape(value.stringValue);
        break;
    case JsonValue::Type::Number:
        stream << value.numberValue;
        break;
    case JsonValue::Type::Array:
        stream << L"[\n";
        for (size_t i = 0; i < value.arrayValue.size(); ++i) {
            writeIndent(stream, indent + 1);
            serializeJson(value.arrayValue[i], stream, indent + 1);
            stream << (i + 1 < value.arrayValue.size() ? L"," : L"") << L"\n";
        }
        writeIndent(stream, indent);
        stream << L"]";
        break;
    case JsonValue::Type::Object:
        stream << L"{\n";
        for (auto it = value.objectValue.begin(); it != value.objectValue.end(); ++it) {
            writeIndent(stream, indent + 1);
            stream << jsonEscape(it->first) << L": ";
            serializeJson(it->second, stream, indent + 1);
            stream << (std::next(it) != value.objectValue.end() ? L"," : L"") << L"\n";
        }
        writeIndent(stream, indent);
        stream << L"}";
        break;
    case JsonValue::Type::Null:
    default:
        stream << L"null";
        break;
    }
}

std::wstring serializeJson(const JsonValue& value) {
    std::wostringstream stream;
    serializeJson(value, stream, 0);
    stream << L"\n";
    return stream.str();
}

bool ruleMatchesDevice(const JsonValue& ruleValue, const ParsedDevice& device) {
    if (ruleValue.type != JsonValue::Type::Object) {
        return false;
    }
    return equalsIgnoreCase(stringValue(ruleValue.find(L"endpoint")), device.endpoint) &&
        equalsIgnoreCase(stringValue(ruleValue.find(L"nickname")), device.nickname) &&
        equalsIgnoreCase(stringValue(ruleValue.find(L"product")), device.product);
}

JsonValue makeDeviceRule(const ParsedDevice& device) {
    return makeObject({
        { L"endpoint", makeString(device.endpoint) },
        { L"nickname", makeString(device.nickname) },
        { L"product", makeString(device.product) }
    });
}

std::vector<DeviceRule> rulesFromJsonArray(const JsonValue* devices) {
    std::vector<DeviceRule> rules;
    if (!devices || devices->type != JsonValue::Type::Array) {
        return rules;
    }

    for (const JsonValue& device : devices->arrayValue) {
        if (device.type != JsonValue::Type::Object) {
            continue;
        }
        DeviceRule rule;
        rule.endpoint = stringValue(device.find(L"endpoint"));
        rule.nickname = stringValue(device.find(L"nickname"));
        rule.product = stringValue(device.find(L"product"));
        if (!rule.endpoint.empty()) {
            rules.push_back(rule);
        }
    }
    return rules;
}

JsonValue makeDeviceRulesArray(const std::vector<ParsedDevice>& devices) {
    JsonValue rules = makeArray();
    for (const ParsedDevice& device : devices) {
        if (device.endpoint.empty()) {
            continue;
        }

        bool exists = false;
        for (const JsonValue& existing : rules.arrayValue) {
            if (ruleMatchesDevice(existing, device)) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            rules.arrayValue.push_back(makeDeviceRule(device));
        }
    }
    return rules;
}
}

PolicyManager::PolicyManager()
    : configPath_(findConfigPath()),
    usageStatePath_(programDataUsageStatePath()) {
    load();
}

PolicyManager::PolicyManager(std::wstring configPath)
    : configPath_(std::move(configPath)),
    usageStatePath_(programDataUsageStatePath()) {
    load();
}

bool PolicyManager::isAllowed(const ParsedDevice& device) const {
    return isAllowedByRules(device, effectiveRules_);
}

bool PolicyManager::isAllowedForUser(const ParsedDevice& device, const std::wstring& userName) const {
    return isAllowedByRules(device, rulesForUser(userName));
}

void PolicyManager::assignDeviceToCurrentUser(const ParsedDevice& device) const {
    assignDeviceToUser(device, getSamUserName());
}

void PolicyManager::assignDeviceToUser(const ParsedDevice& device, const std::wstring& userName) const {
    if (userName.empty()) {
        throw std::runtime_error("User name is required.");
    }

    JsonValue root = JsonParser(readUtf8File(configPath_)).parse();
    if (root.type != JsonValue::Type::Object) {
        throw std::runtime_error("Config root must be an object.");
    }

    JsonValue& assignments = root.objectValue[L"userAssignments"];
    if (assignments.type == JsonValue::Type::Null) {
        assignments = makeArray();
    }
    if (assignments.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config userAssignments must be an array.");
    }

    for (JsonValue& assignment : assignments.arrayValue) {
        if (assignment.type != JsonValue::Type::Object) {
            continue;
        }

        bool matchesTargetUser = false;
        for (const std::wstring& user : stringArray(assignment.find(L"users"))) {
            if (configuredUserMatchesTarget(user, userName)) {
                matchesTargetUser = true;
                break;
            }
        }
        if (!matchesTargetUser) {
            continue;
        }

        JsonValue& devices = assignment.objectValue[L"allowedDevices"];
        if (devices.type == JsonValue::Type::Null) {
            devices = makeArray();
        }
        if (devices.type != JsonValue::Type::Array) {
            throw std::runtime_error("Config allowedDevices must be an array.");
        }

        for (const JsonValue& existingRule : devices.arrayValue) {
            if (ruleMatchesDevice(existingRule, device)) {
                writeUtf8File(configPath_, serializeJson(root));
                return;
            }
        }

        devices.arrayValue.push_back(makeDeviceRule(device));
        writeUtf8File(configPath_, serializeJson(root));
        return;
    }

    assignments.arrayValue.push_back(makeObject({
        { L"users", makeArray({ makeString(userName) }) },
        { L"groups", makeArray() },
        { L"allowedDevices", makeArray({ makeDeviceRule(device) }) }
    }));
    writeUtf8File(configPath_, serializeJson(root));
}

void PolicyManager::removeDeviceFromUser(const ParsedDevice& device, const std::wstring& userName) const {
    if (userName.empty()) {
        throw std::runtime_error("User name is required.");
    }

    JsonValue root = JsonParser(readUtf8File(configPath_)).parse();
    if (root.type != JsonValue::Type::Object) {
        throw std::runtime_error("Config root must be an object.");
    }

    JsonValue& assignments = root.objectValue[L"userAssignments"];
    if (assignments.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config userAssignments must be an array.");
    }

    for (JsonValue& assignment : assignments.arrayValue) {
        if (assignment.type != JsonValue::Type::Object) {
            continue;
        }

        bool matchesTargetUser = false;
        for (const std::wstring& user : stringArray(assignment.find(L"users"))) {
            if (configuredUserMatchesTarget(user, userName)) {
                matchesTargetUser = true;
                break;
            }
        }
        if (!matchesTargetUser) {
            continue;
        }

        JsonValue& devices = assignment.objectValue[L"allowedDevices"];
        if (devices.type != JsonValue::Type::Array) {
            return;
        }

        devices.arrayValue.erase(
            std::remove_if(devices.arrayValue.begin(), devices.arrayValue.end(),
                [&device](const JsonValue& rule) {
                    return ruleMatchesDevice(rule, device);
                }),
            devices.arrayValue.end());

        writeUtf8File(configPath_, serializeJson(root));
        return;
    }

    writeUtf8File(configPath_, serializeJson(root));
}

void PolicyManager::setDevicesForUser(const std::vector<ParsedDevice>& devices, const std::wstring& userName) const {
    if (userName.empty()) {
        throw std::runtime_error("User name is required.");
    }

    JsonValue root = JsonParser(readUtf8File(configPath_)).parse();
    if (root.type != JsonValue::Type::Object) {
        throw std::runtime_error("Config root must be an object.");
    }

    JsonValue& assignments = root.objectValue[L"userAssignments"];
    if (assignments.type == JsonValue::Type::Null) {
        assignments = makeArray();
    }
    if (assignments.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config userAssignments must be an array.");
    }

    for (JsonValue& assignment : assignments.arrayValue) {
        if (assignment.type != JsonValue::Type::Object) {
            continue;
        }

        bool matchesTargetUser = false;
        for (const std::wstring& user : stringArray(assignment.find(L"users"))) {
            if (configuredUserMatchesTarget(user, userName)) {
                matchesTargetUser = true;
                break;
            }
        }
        if (!matchesTargetUser) {
            continue;
        }

        assignment.objectValue[L"allowedDevices"] = makeDeviceRulesArray(devices);
        writeUtf8File(configPath_, serializeJson(root));
        return;
    }

    assignments.arrayValue.push_back(makeObject({
        { L"users", makeArray({ makeString(userName) }) },
        { L"groups", makeArray() },
        { L"allowedDevices", makeDeviceRulesArray(devices) }
    }));
    writeUtf8File(configPath_, serializeJson(root));
}

bool PolicyManager::isAllowedByRules(const ParsedDevice& device, const std::vector<DeviceRule>& rules) {
    for (const DeviceRule& rule : rules) {
        if (!equalsIgnoreCase(rule.endpoint, device.endpoint)) {
            continue;
        }
        if (!rule.nickname.empty() && !equalsIgnoreCase(rule.nickname, device.nickname)) {
            continue;
        }
        if (!rule.product.empty() && !equalsIgnoreCase(rule.product, device.product)) {
            continue;
        }
        return true;
    }
    return false;
}

void PolicyManager::setConfigPathOverride(std::wstring configPath) {
    g_configPathOverride = std::move(configPath);
}

bool PolicyManager::ensureEditableConfig(std::wstring configPath) {
    try {
        readPolicyRoot(configPath);
        return false;
    }
    catch (...) {
        replaceWithEmptyPolicy(configPath);
        return true;
    }
}

std::wstring PolicyManager::currentUserName() {
    return getSamUserName();
}

std::wstring PolicyManager::currentUserSid() {
    return getCurrentUserSid();
}

std::vector<DeviceRule> PolicyManager::rulesForUser(const std::wstring& userName) const {
    std::vector<DeviceRule> rules;
    if (userName.empty()) {
        return rules;
    }

    const JsonValue root = JsonParser(readUtf8File(configPath_)).parse();
    if (root.type != JsonValue::Type::Object) {
        throw std::runtime_error("Config root must be an object.");
    }

    const JsonValue* assignments = root.find(L"userAssignments");
    if (!assignments || assignments->type != JsonValue::Type::Array) {
        throw std::runtime_error("Config must contain userAssignments array.");
    }

    for (const JsonValue& assignment : assignments->arrayValue) {
        if (assignment.type != JsonValue::Type::Object) {
            continue;
        }

        bool matchesTargetUser = false;
        for (const std::wstring& user : stringArray(assignment.find(L"users"))) {
            if (configuredUserMatchesTarget(user, userName)) {
                matchesTargetUser = true;
                break;
            }
        }
        if (!matchesTargetUser) {
            continue;
        }

        std::vector<DeviceRule> assignmentRules = rulesFromJsonArray(assignment.find(L"allowedDevices"));
        rules.insert(rules.end(), assignmentRules.begin(), assignmentRules.end());
    }

    return rules;
}

const std::vector<DeviceRule>& PolicyManager::effectiveRules() const {
    return effectiveRules_;
}

const std::wstring& PolicyManager::pipeName() const {
    return pipeName_;
}

const std::wstring& PolicyManager::usageStatePath() const {
    return usageStatePath_;
}

const std::wstring& PolicyManager::configPath() const {
    return configPath_;
}

void PolicyManager::load() {
    JsonValue root;
    try {
        root = readPolicyRoot(configPath_);
    }
    catch (...) {
#ifdef DISKCONTROL_ADMIN
        replaceWithEmptyPolicy(configPath_);
        root = readPolicyRoot(configPath_);
#else
        throw;
#endif
    }

    const std::wstring pipe = stringValue(root.find(L"pipeName"));
    if (!pipe.empty()) {
        pipeName_ = pipe;
    }

    const std::wstring usageStatePath = stringValue(root.find(L"usageStatePath"));
    if (!usageStatePath.empty()) {
        usageStatePath_ = usageStatePath;
    }

    const JsonValue* assignments = root.find(L"userAssignments");

    for (const JsonValue& assignment : assignments->arrayValue) {
        if (assignment.type != JsonValue::Type::Object) {
            continue;
        }

        bool matches = false;
        for (const std::wstring& user : stringArray(assignment.find(L"users"))) {
            if (userMatches(user)) {
                matches = true;
                break;
            }
        }

        if (!matches) {
            for (const std::wstring& group : stringArray(assignment.find(L"groups"))) {
                if (groupMatches(group)) {
                    matches = true;
                    break;
                }
            }
        }

        if (!matches) {
            continue;
        }

        std::vector<DeviceRule> rules = rulesFromJsonArray(assignment.find(L"allowedDevices"));
        effectiveRules_.insert(effectiveRules_.end(), rules.begin(), rules.end());
    }
}
