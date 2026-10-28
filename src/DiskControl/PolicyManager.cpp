#include "PolicyManager.h"
#include "StructuredJson.h"

#define SECURITY_WIN32
#include <windows.h>
#include <sddl.h>
#include <security.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
using DistControlJson::JsonValue;
using DistControlJson::JsonParser;
using DistControlJson::serializeJson;
std::wstring g_configPathOverride;


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
        return "Access denied. Run DistControl Admin as administrator or check allow.json permissions.";
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

class ConfigWriteLock {
public:
    explicit ConfigWriteLock(const std::wstring& configPath)
        : lockPath_(configPath + L".lock") {
        const ULONGLONG deadline = GetTickCount64() + 5000;
        do {
            handle_ = CreateFileW(
                lockPath_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
            if (handle_ != INVALID_HANDLE_VALUE) {
                return;
            }

            const DWORD error = GetLastError();
            if (error != ERROR_SHARING_VIOLATION && error != ERROR_LOCK_VIOLATION) {
                throw fileError("Cannot lock config file", configPath, error);
            }
            Sleep(50);
        } while (GetTickCount64() < deadline);

        throw std::runtime_error("Timed out waiting for policy write lock.");
    }

    ~ConfigWriteLock() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            DeleteFileW(lockPath_.c_str());
        }
    }

    ConfigWriteLock(const ConfigWriteLock&) = delete;
    ConfigWriteLock& operator=(const ConfigWriteLock&) = delete;

private:
    std::wstring lockPath_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

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
        L"  \"vpnProfiles\": [],\n"
        L"  \"userAssignments\": []\n"
        L"}\n";
}

bool fileExists(const std::wstring& path) {
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring localAppDataDistControlPath(const wchar_t* fileName) {
    wchar_t buffer[32768]{};
    const DWORD needed = GetEnvironmentVariableW(
        L"LOCALAPPDATA", buffer, static_cast<DWORD>(std::size(buffer)));
    if (needed == 0 || needed >= std::size(buffer)) {
        return {};
    }
    return std::wstring(buffer) + L"\\DistControl\\" + fileName;
}

std::wstring localAppDataPolicyPath() {
    return localAppDataDistControlPath(L"allow.json");
}

std::wstring localAppDataUsageStatePath() {
    return localAppDataDistControlPath(L"state\\usage.json");
}

std::wstring policyRevisionForText(const std::wstring& text) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const wchar_t character : text) {
        hash ^= static_cast<std::uint16_t>(character);
        hash *= 1099511628211ULL;
    }

    std::wostringstream stream;
    stream << text.size() << L":" << std::hex << std::setfill(L'0') << std::setw(16) << hash;
    return stream.str();
}

std::wstring widenDiagnostic(const char* text) {
    std::wstring result;
    if (!text) {
        return result;
    }
    while (*text) {
        result.push_back(static_cast<unsigned char>(*text++));
    }
    return result;
}

std::wstring localAppDataNetworkStatePath() {
    return localAppDataDistControlPath(L"state\\network-state.json");
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

JsonValue parsePolicyRoot(const std::wstring& text) {
    JsonValue root = JsonParser(text).parse();
    if (root.type != JsonValue::Type::Object) {
        throw std::runtime_error("Config root must be an object.");
    }

    const JsonValue* assignments = root.find(L"userAssignments");
    if (!assignments || assignments->type != JsonValue::Type::Array) {
        throw std::runtime_error("Config must contain userAssignments array.");
    }

    return root;
}

JsonValue readPolicyRoot(const std::wstring& path, std::wstring* revision = nullptr) {
    const std::wstring text = readUtf8File(path);
    if (revision) {
        *revision = policyRevisionForText(text);
    }
    return parsePolicyRoot(text);
}

void verifyPolicyRevision(const std::wstring& current, const std::wstring& expected) {
    if (!expected.empty() && current != expected) {
        throw std::runtime_error("Policy changed since it was loaded.");
    }
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

    const std::wstring localAppDataPath = localAppDataPolicyPath();
    if (!localAppDataPath.empty()) {
        return localAppDataPath;
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

bool boolValue(const JsonValue* value, bool defaultValue) {
    return value && value->type == JsonValue::Type::Boolean
        ? value->booleanValue
        : defaultValue;
}

JsonValue makeString(const std::wstring& value) {
    JsonValue json;
    json.type = JsonValue::Type::String;
    json.stringValue = value;
    return json;
}

JsonValue makeBool(bool value) {
    JsonValue json;
    json.type = JsonValue::Type::Boolean;
    json.booleanValue = value;
    return json;
}

JsonValue makeNumber(double value) {
    JsonValue json;
    json.type = JsonValue::Type::Number;
    json.numberValue = value;
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


bool ruleMatchesDevice(const JsonValue& ruleValue, const ParsedDevice& device) {
    if (ruleValue.type != JsonValue::Type::Object) {
        return false;
    }
    return equalsIgnoreCase(stringValue(ruleValue.find(L"endpoint")), device.endpoint) &&
        equalsIgnoreCase(stringValue(ruleValue.find(L"nickname")), device.nickname) &&
        equalsIgnoreCase(stringValue(ruleValue.find(L"product")), device.product);
}

JsonValue makeDeviceRule(const ParsedDevice& device, const std::wstring& vpnProfileId = {}) {
    JsonValue rule = makeObject({
        { L"endpoint", makeString(device.endpoint) },
        { L"nickname", makeString(device.nickname) },
        { L"product", makeString(device.product) }
    });
    if (!vpnProfileId.empty()) {
        rule.objectValue[L"vpnProfile"] = makeString(vpnProfileId);
    }
    return rule;
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
        rule.vpnProfileId = stringValue(device.find(L"vpnProfile"));
        if (!rule.endpoint.empty()) {
            rules.push_back(rule);
        }
    }
    return rules;
}

std::wstring existingVpnProfileForDevice(const JsonValue* existingRules, const ParsedDevice& device) {
    if (!existingRules || existingRules->type != JsonValue::Type::Array) {
        return {};
    }
    for (const JsonValue& existing : existingRules->arrayValue) {
        if (existing.type == JsonValue::Type::Object &&
            equalsIgnoreCase(stringValue(existing.find(L"endpoint")), device.endpoint)) {
            return stringValue(existing.find(L"vpnProfile"));
        }
    }
    return {};
}

JsonValue makeDeviceRulesArray(const std::vector<ParsedDevice>& devices, const JsonValue* existingRules = nullptr) {
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
            rules.arrayValue.push_back(makeDeviceRule(
                device,
                existingVpnProfileForDevice(existingRules, device)));
        }
    }
    return rules;
}

VpnProfile vpnProfileFromJson(const JsonValue& value) {
    VpnProfile profile;
    if (value.type != JsonValue::Type::Object) {
        return profile;
    }
    profile.id = stringValue(value.find(L"id"));
    profile.name = stringValue(value.find(L"name"));
    profile.serverAddress = stringValue(value.find(L"serverAddress"));
    profile.tunnelType = stringValue(value.find(L"tunnelType"));
    if (profile.tunnelType.empty()) {
        profile.tunnelType = L"L2TP";
    }
    const std::wstring mode = stringValue(value.find(L"mode"));
    profile.mode = equalsIgnoreCase(mode, L"direct")
        ? VpnProfileMode::Direct
        : VpnProfileMode::WindowsVpn;
    const std::wstring phonebookScope = stringValue(value.find(L"phonebookScope"));
    profile.phonebookScope = equalsIgnoreCase(phonebookScope, L"allUsers")
        ? VpnPhonebookScope::AllUsers
        : VpnPhonebookScope::CurrentUser;
    profile.ipCheckUrl = stringValue(value.find(L"ipCheckUrl"));
    if (profile.ipCheckUrl.empty()) {
        profile.ipCheckUrl = L"https://api.ipify.org";
    }
    profile.enabled = boolValue(value.find(L"enabled"), true);
    return profile;
}

std::vector<VpnProfile> vpnProfilesFromJson(const JsonValue* value) {
    std::vector<VpnProfile> profiles;
    if (!value || value->type != JsonValue::Type::Array) {
        return profiles;
    }
    for (const JsonValue& item : value->arrayValue) {
        VpnProfile profile = vpnProfileFromJson(item);
        const bool validWindowsProfile = profile.mode == VpnProfileMode::WindowsVpn && !profile.name.empty();
        const bool validDirectProfile = profile.mode == VpnProfileMode::Direct;
        if (!profile.id.empty() && (validWindowsProfile || validDirectProfile)) {
            profiles.push_back(std::move(profile));
        }
    }
    return profiles;
}

JsonValue makeVpnProfile(const VpnProfile& profile) {
    return makeObject({
        { L"id", makeString(profile.id) },
        { L"name", makeString(profile.name) },
        { L"serverAddress", makeString(profile.serverAddress) },
        { L"tunnelType", makeString(profile.tunnelType.empty() ? L"L2TP" : profile.tunnelType) },
        { L"mode", makeString(profile.mode == VpnProfileMode::Direct ? L"direct" : L"windowsVpn") },
        { L"phonebookScope", makeString(profile.phonebookScope == VpnPhonebookScope::AllUsers
            ? L"allUsers" : L"currentUser") },
        { L"enabled", makeBool(profile.enabled) },
        { L"ipCheckUrl", makeString(profile.ipCheckUrl.empty() ? L"https://api.ipify.org" : profile.ipCheckUrl) }
    });
}

// Returns the id of an enabled "direct" (no VPN) profile in the policy root,
// adding one when the policy has none. New token assignments use it by default.
std::wstring ensureDirectProfileId(JsonValue& root) {
    JsonValue& profiles = root.objectValue[L"vpnProfiles"];
    if (profiles.type == JsonValue::Type::Null) {
        profiles = makeArray();
    }
    if (profiles.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config vpnProfiles must be an array.");
    }
    for (const JsonValue& item : profiles.arrayValue) {
        const VpnProfile profile = vpnProfileFromJson(item);
        if (!profile.id.empty() && profile.mode == VpnProfileMode::Direct && profile.enabled) {
            return profile.id;
        }
    }

    VpnProfile direct;
    direct.mode = VpnProfileMode::Direct;
    direct.name = L"Без VPN";
    direct.id = L"direct";
    for (unsigned int suffix = 2;; ++suffix) {
        const bool occupied = std::any_of(profiles.arrayValue.begin(), profiles.arrayValue.end(),
            [&direct](const JsonValue& item) {
                return equalsIgnoreCase(stringValue(item.find(L"id")), direct.id);
            });
        if (!occupied) {
            break;
        }
        direct.id = L"direct-" + std::to_wstring(suffix);
    }
    profiles.arrayValue.push_back(makeVpnProfile(direct));
    return direct.id;
}
}

PolicyManager::PolicyManager()
    : configPath_(findConfigPath()),
    usageStatePath_(localAppDataUsageStatePath()) {
    load();
}

PolicyManager::PolicyManager(std::wstring configPath)
    : configPath_(std::move(configPath)),
    usageStatePath_(localAppDataUsageStatePath()) {
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

    ConfigWriteLock writeLock(configPath_);
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

    ConfigWriteLock writeLock(configPath_);
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

    ConfigWriteLock writeLock(configPath_);
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

        const JsonValue existingRules = assignment.objectValue[L"allowedDevices"];
        assignment.objectValue[L"allowedDevices"] = makeDeviceRulesArray(devices, &existingRules);
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

std::wstring PolicyManager::applyDeviceAccessChanges(
    const std::vector<ParsedDevice>& addedDevices,
    const std::vector<ParsedDevice>& removedDevices,
    const std::wstring& userName,
    const std::wstring& expectedRevision) const {
    if (userName.empty()) {
        throw std::runtime_error("User name is required.");
    }

    ConfigWriteLock writeLock(configPath_);
    std::wstring currentRevision;
    JsonValue root = readPolicyRoot(configPath_, &currentRevision);
    verifyPolicyRevision(currentRevision, expectedRevision);

    JsonValue& assignments = root.objectValue[L"userAssignments"];
    JsonValue* targetAssignment = nullptr;
    for (JsonValue& assignment : assignments.arrayValue) {
        if (assignment.type != JsonValue::Type::Object) {
            continue;
        }
        for (const std::wstring& user : stringArray(assignment.find(L"users"))) {
            if (configuredUserMatchesTarget(user, userName)) {
                targetAssignment = &assignment;
                break;
            }
        }
        if (targetAssignment) {
            break;
        }
    }

    if (!targetAssignment) {
        if (addedDevices.empty()) {
            return currentRevision;
        }
        assignments.arrayValue.push_back(makeObject({
            { L"users", makeArray({ makeString(userName) }) },
            { L"groups", makeArray() },
            { L"allowedDevices", makeArray() }
        }));
        targetAssignment = &assignments.arrayValue.back();
    }

    JsonValue& rules = targetAssignment->objectValue[L"allowedDevices"];
    if (rules.type == JsonValue::Type::Null) {
        rules = makeArray();
    }
    if (rules.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config allowedDevices must be an array.");
    }

    for (const ParsedDevice& removed : removedDevices) {
        rules.arrayValue.erase(
            std::remove_if(rules.arrayValue.begin(), rules.arrayValue.end(),
                [&removed](const JsonValue& rule) {
                    return rule.type == JsonValue::Type::Object &&
                        equalsIgnoreCase(stringValue(rule.find(L"endpoint")), removed.endpoint);
                }),
            rules.arrayValue.end());
    }

    // Newly allowed tokens start with "Без VPN" instead of "сеть не настроена";
    // existing VPN assignments are kept.
    std::wstring directProfileId;
    const auto defaultVpnProfile = [&root, &directProfileId]() {
        if (directProfileId.empty()) {
            directProfileId = ensureDirectProfileId(root);
        }
        return directProfileId;
    };
    for (const ParsedDevice& added : addedDevices) {
        if (added.endpoint.empty()) {
            continue;
        }
        JsonValue* existingRule = nullptr;
        for (JsonValue& rule : rules.arrayValue) {
            if (rule.type == JsonValue::Type::Object &&
                equalsIgnoreCase(stringValue(rule.find(L"endpoint")), added.endpoint)) {
                existingRule = &rule;
                break;
            }
        }
        if (existingRule) {
            existingRule->objectValue[L"endpoint"] = makeString(added.endpoint);
            existingRule->objectValue[L"nickname"] = makeString(added.nickname);
            existingRule->objectValue[L"product"] = makeString(added.product);
            if (stringValue(existingRule->find(L"vpnProfile")).empty()) {
                existingRule->objectValue[L"vpnProfile"] = makeString(defaultVpnProfile());
            }
        }
        else {
            rules.arrayValue.push_back(makeDeviceRule(added, defaultVpnProfile()));
        }
    }

    const std::wstring serialized = serializeJson(root);
    writeUtf8File(configPath_, serialized);
    return policyRevisionForText(serialized);
}

void PolicyManager::setVpnProfileForDevice(
    const ParsedDevice& device,
    const std::wstring& userName,
    const std::wstring& vpnProfileId) const {
    if (userName.empty()) {
        throw std::runtime_error("User name is required.");
    }

    ConfigWriteLock writeLock(configPath_);
    JsonValue root = readPolicyRoot(configPath_);
    JsonValue& assignments = root.objectValue[L"userAssignments"];
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
            break;
        }
        for (JsonValue& rule : devices.arrayValue) {
            if (rule.type != JsonValue::Type::Object ||
                !equalsIgnoreCase(stringValue(rule.find(L"endpoint")), device.endpoint)) {
                continue;
            }
            if (vpnProfileId.empty()) {
                rule.objectValue.erase(L"vpnProfile");
            }
            else {
                rule.objectValue[L"vpnProfile"] = makeString(vpnProfileId);
            }
            writeUtf8File(configPath_, serializeJson(root));
            return;
        }
    }

    throw std::runtime_error("Device must be assigned to the user before selecting a VPN profile.");
}

std::wstring PolicyManager::saveVpnProfileForDevices(
    const VpnProfile& profile,
    const std::vector<ParsedDevice>& devices,
    const std::wstring& userName,
    const std::wstring& expectedRevision) const {
    if (profile.id.empty() ||
        (profile.mode == VpnProfileMode::WindowsVpn && profile.name.empty())) {
        throw std::runtime_error("Network profile id and Windows profile are required.");
    }
    if (userName.empty()) {
        throw std::runtime_error("User name is required.");
    }
    if (devices.empty()) {
        throw std::runtime_error("At least one device is required.");
    }

    ConfigWriteLock writeLock(configPath_);
    std::wstring currentRevision;
    JsonValue root = readPolicyRoot(configPath_, &currentRevision);
    verifyPolicyRevision(currentRevision, expectedRevision);

    JsonValue& profiles = root.objectValue[L"vpnProfiles"];
    if (profiles.type == JsonValue::Type::Null) {
        profiles = makeArray();
    }
    if (profiles.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config vpnProfiles must be an array.");
    }

    bool profileUpdated = false;
    for (JsonValue& existing : profiles.arrayValue) {
        if (existing.type == JsonValue::Type::Object &&
            equalsIgnoreCase(stringValue(existing.find(L"id")), profile.id)) {
            existing = makeVpnProfile(profile);
            profileUpdated = true;
            break;
        }
    }
    if (!profileUpdated) {
        profiles.arrayValue.push_back(makeVpnProfile(profile));
    }

    JsonValue* targetAssignment = nullptr;
    JsonValue& assignments = root.objectValue[L"userAssignments"];
    for (JsonValue& assignment : assignments.arrayValue) {
        if (assignment.type != JsonValue::Type::Object) {
            continue;
        }
        for (const std::wstring& user : stringArray(assignment.find(L"users"))) {
            if (configuredUserMatchesTarget(user, userName)) {
                targetAssignment = &assignment;
                break;
            }
        }
        if (targetAssignment) {
            break;
        }
    }
    if (!targetAssignment) {
        throw std::runtime_error("Device must be assigned to the user before selecting a VPN profile.");
    }

    JsonValue& rules = targetAssignment->objectValue[L"allowedDevices"];
    if (rules.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config allowedDevices must be an array.");
    }

    for (const ParsedDevice& device : devices) {
        JsonValue* matchedRule = nullptr;
        for (JsonValue& rule : rules.arrayValue) {
            if (rule.type == JsonValue::Type::Object &&
                equalsIgnoreCase(stringValue(rule.find(L"endpoint")), device.endpoint)) {
                matchedRule = &rule;
                break;
            }
        }
        if (!matchedRule) {
            throw std::runtime_error("Device must be assigned to the user before selecting a VPN profile.");
        }
        matchedRule->objectValue[L"vpnProfile"] = makeString(profile.id);
    }

    const std::wstring serialized = serializeJson(root);
    writeUtf8File(configPath_, serialized);
    return policyRevisionForText(serialized);
}

std::wstring PolicyManager::clearVpnProfileForDevices(
    const std::vector<ParsedDevice>& devices,
    const std::wstring& userName,
    const std::wstring& expectedRevision) const {
    if (userName.empty()) {
        throw std::runtime_error("User name is required.");
    }

    ConfigWriteLock writeLock(configPath_);
    std::wstring currentRevision;
    JsonValue root = readPolicyRoot(configPath_, &currentRevision);
    verifyPolicyRevision(currentRevision, expectedRevision);

    JsonValue& assignments = root.objectValue[L"userAssignments"];
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

        JsonValue& rules = assignment.objectValue[L"allowedDevices"];
        if (rules.type != JsonValue::Type::Array) {
            break;
        }
        for (const ParsedDevice& device : devices) {
            bool matched = false;
            for (JsonValue& rule : rules.arrayValue) {
                if (rule.type == JsonValue::Type::Object &&
                    equalsIgnoreCase(stringValue(rule.find(L"endpoint")), device.endpoint)) {
                    rule.objectValue.erase(L"vpnProfile");
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                throw std::runtime_error("Device must be assigned to the user before selecting a VPN profile.");
            }
        }

        const std::wstring serialized = serializeJson(root);
        writeUtf8File(configPath_, serialized);
        return policyRevisionForText(serialized);
    }

    throw std::runtime_error("Device must be assigned to the user before selecting a VPN profile.");
}

std::wstring PolicyManager::saveVpnAssignmentsForDevices(
    const std::vector<VpnProfile>& profilesToSave,
    const std::vector<DeviceRule>& deviceAssignments,
    const std::wstring& userName,
    const std::wstring& expectedRevision) const {
    if (userName.empty()) {
        throw std::runtime_error("User name is required.");
    }

    ConfigWriteLock writeLock(configPath_);
    std::wstring currentRevision;
    JsonValue root = readPolicyRoot(configPath_, &currentRevision);
    verifyPolicyRevision(currentRevision, expectedRevision);

    JsonValue& profiles = root.objectValue[L"vpnProfiles"];
    if (profiles.type == JsonValue::Type::Null) {
        profiles = makeArray();
    }
    if (profiles.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config vpnProfiles must be an array.");
    }
    for (const VpnProfile& profile : profilesToSave) {
        if (profile.id.empty() ||
            (profile.mode == VpnProfileMode::WindowsVpn && profile.name.empty())) {
            throw std::runtime_error("Network profile id and Windows profile are required.");
        }
        bool updated = false;
        for (JsonValue& existing : profiles.arrayValue) {
            if (existing.type == JsonValue::Type::Object &&
                equalsIgnoreCase(stringValue(existing.find(L"id")), profile.id)) {
                existing = makeVpnProfile(profile);
                updated = true;
                break;
            }
        }
        if (!updated) {
            profiles.arrayValue.push_back(makeVpnProfile(profile));
        }
    }

    JsonValue* targetAssignment = nullptr;
    JsonValue& assignments = root.objectValue[L"userAssignments"];
    for (JsonValue& assignment : assignments.arrayValue) {
        if (assignment.type != JsonValue::Type::Object) {
            continue;
        }
        for (const std::wstring& configuredUser : stringArray(assignment.find(L"users"))) {
            if (configuredUserMatchesTarget(configuredUser, userName)) {
                targetAssignment = &assignment;
                break;
            }
        }
        if (targetAssignment) {
            break;
        }
    }
    if (!targetAssignment) {
        throw std::runtime_error("Device must be assigned to the user before selecting a VPN profile.");
    }

    JsonValue& rules = targetAssignment->objectValue[L"allowedDevices"];
    if (rules.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config allowedDevices must be an array.");
    }
    for (const DeviceRule& deviceAssignment : deviceAssignments) {
        JsonValue* matchedRule = nullptr;
        for (JsonValue& rule : rules.arrayValue) {
            if (rule.type == JsonValue::Type::Object &&
                equalsIgnoreCase(stringValue(rule.find(L"endpoint")), deviceAssignment.endpoint)) {
                matchedRule = &rule;
                break;
            }
        }
        if (!matchedRule) {
            throw std::runtime_error("Device must be assigned to the user before selecting a VPN profile.");
        }
        if (deviceAssignment.vpnProfileId.empty()) {
            matchedRule->objectValue.erase(L"vpnProfile");
        }
        else {
            const bool knownProfile = std::any_of(profilesToSave.begin(), profilesToSave.end(),
                [&deviceAssignment](const VpnProfile& profile) {
                    return equalsIgnoreCase(profile.id, deviceAssignment.vpnProfileId);
                });
            if (!knownProfile) {
                throw std::runtime_error("VPN profile mapping references an unknown profile.");
            }
            matchedRule->objectValue[L"vpnProfile"] = makeString(deviceAssignment.vpnProfileId);
        }
    }

    const std::wstring serialized = serializeJson(root);
    writeUtf8File(configPath_, serialized);
    return policyRevisionForText(serialized);
}

void PolicyManager::upsertVpnProfile(const VpnProfile& profile) const {
    if (profile.id.empty() ||
        (profile.mode == VpnProfileMode::WindowsVpn && profile.name.empty())) {
        throw std::runtime_error("Network profile id and Windows profile are required.");
    }

    ConfigWriteLock writeLock(configPath_);
    JsonValue root = readPolicyRoot(configPath_);
    JsonValue& profiles = root.objectValue[L"vpnProfiles"];
    if (profiles.type == JsonValue::Type::Null) {
        profiles = makeArray();
    }
    if (profiles.type != JsonValue::Type::Array) {
        throw std::runtime_error("Config vpnProfiles must be an array.");
    }

    for (JsonValue& existing : profiles.arrayValue) {
        if (existing.type == JsonValue::Type::Object &&
            equalsIgnoreCase(stringValue(existing.find(L"id")), profile.id)) {
            existing = makeVpnProfile(profile);
            writeUtf8File(configPath_, serializeJson(root));
            return;
        }
    }

    profiles.arrayValue.push_back(makeVpnProfile(profile));
    writeUtf8File(configPath_, serializeJson(root));
}

void PolicyManager::removeVpnProfile(const std::wstring& profileId) const {
    if (profileId.empty()) {
        return;
    }

    ConfigWriteLock writeLock(configPath_);
    JsonValue root = readPolicyRoot(configPath_);
    JsonValue& profiles = root.objectValue[L"vpnProfiles"];
    if (profiles.type == JsonValue::Type::Array) {
        profiles.arrayValue.erase(
            std::remove_if(profiles.arrayValue.begin(), profiles.arrayValue.end(),
                [&profileId](const JsonValue& item) {
                    return item.type == JsonValue::Type::Object &&
                        equalsIgnoreCase(stringValue(item.find(L"id")), profileId);
                }),
            profiles.arrayValue.end());
    }

    JsonValue& assignments = root.objectValue[L"userAssignments"];
    if (assignments.type == JsonValue::Type::Array) {
        for (JsonValue& assignment : assignments.arrayValue) {
            JsonValue& devices = assignment.objectValue[L"allowedDevices"];
            if (devices.type != JsonValue::Type::Array) {
                continue;
            }
            for (JsonValue& rule : devices.arrayValue) {
                if (rule.type == JsonValue::Type::Object &&
                    equalsIgnoreCase(stringValue(rule.find(L"vpnProfile")), profileId)) {
                    rule.objectValue.erase(L"vpnProfile");
                }
            }
        }
    }

    writeUtf8File(configPath_, serializeJson(root));
}

std::wstring PolicyManager::removeVpnProfileChecked(
    const std::wstring& profileId,
    const std::wstring& expectedRevision) const {
    if (profileId.empty()) {
        return expectedRevision;
    }

    ConfigWriteLock writeLock(configPath_);
    std::wstring currentRevision;
    JsonValue root = readPolicyRoot(configPath_, &currentRevision);
    verifyPolicyRevision(currentRevision, expectedRevision);

    JsonValue& profiles = root.objectValue[L"vpnProfiles"];
    if (profiles.type == JsonValue::Type::Array) {
        profiles.arrayValue.erase(
            std::remove_if(profiles.arrayValue.begin(), profiles.arrayValue.end(),
                [&profileId](const JsonValue& item) {
                    return item.type == JsonValue::Type::Object &&
                        equalsIgnoreCase(stringValue(item.find(L"id")), profileId);
                }),
            profiles.arrayValue.end());
    }

    JsonValue& assignments = root.objectValue[L"userAssignments"];
    if (assignments.type == JsonValue::Type::Array) {
        for (JsonValue& assignment : assignments.arrayValue) {
            JsonValue& rules = assignment.objectValue[L"allowedDevices"];
            if (rules.type != JsonValue::Type::Array) {
                continue;
            }
            for (JsonValue& rule : rules.arrayValue) {
                if (rule.type == JsonValue::Type::Object &&
                    equalsIgnoreCase(stringValue(rule.find(L"vpnProfile")), profileId)) {
                    rule.objectValue.erase(L"vpnProfile");
                }
            }
        }
    }

    const std::wstring serialized = serializeJson(root);
    writeUtf8File(configPath_, serialized);
    return policyRevisionForText(serialized);
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
    if (!fileExists(configPath)) {
        replaceWithEmptyPolicy(configPath);
        return true;
    }
    readPolicyRoot(configPath);
    return false;
}

std::wstring PolicyManager::currentUserName() {
    return getSamUserName();
}

std::wstring PolicyManager::currentUserSid() {
    return getCurrentUserSid();
}

std::wstring PolicyManager::currentNetworkStatePath() {
    return localAppDataNetworkStatePath();
}

void PolicyManager::writeNetworkState(const NetworkStateSnapshot& state) {
    const std::wstring path = currentNetworkStatePath();
    if (path.empty()) {
        throw std::runtime_error("Cannot locate the current user's local application data folder.");
    }

    JsonValue activeVpnNames = makeArray();
    for (const std::wstring& name : state.activeVpnNames) {
        if (!name.empty()) {
            activeVpnNames.arrayValue.push_back(makeString(name));
        }
    }
    JsonValue root = makeObject({
        { L"schemaVersion", makeNumber(1) },
        { L"computerName", makeString(state.computerName) },
        { L"userName", makeString(state.userName) },
        { L"publicIp", makeString(state.publicIp) },
        { L"activeVpnNames", std::move(activeVpnNames) },
        { L"updatedAtFileTime", makeString(std::to_wstring(state.updatedAtFileTime)) }
    });
    ensureParentDirectoryForFile(path);
    writeUtf8File(path, serializeJson(root));
}

bool PolicyManager::tryReadNetworkState(
    const std::wstring& path,
    NetworkStateSnapshot& state,
    std::wstring* errorMessage) {
    try {
        const JsonValue root = JsonParser(readUtf8File(path)).parse();
        if (root.type != JsonValue::Type::Object) {
            throw std::runtime_error("Network state root must be an object.");
        }

        NetworkStateSnapshot loaded;
        loaded.computerName = stringValue(root.find(L"computerName"));
        loaded.userName = stringValue(root.find(L"userName"));
        loaded.publicIp = stringValue(root.find(L"publicIp"));
        loaded.activeVpnNames = stringArray(root.find(L"activeVpnNames"));
        const std::wstring ticks = stringValue(root.find(L"updatedAtFileTime"));
        if (ticks.empty()) {
            throw std::runtime_error("Network state timestamp is missing.");
        }
        loaded.updatedAtFileTime = std::stoull(ticks);
        state = std::move(loaded);
        if (errorMessage) {
            errorMessage->clear();
        }
        return true;
    }
    catch (const std::exception& error) {
        if (errorMessage) {
            *errorMessage = widenDiagnostic(error.what());
        }
        return false;
    }
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

bool PolicyManager::tryGetVpnProfileForDevice(const ParsedDevice& device, VpnProfile& profile) const {
    for (const DeviceRule& rule : effectiveRules_) {
        if (!isAllowedByRules(device, { rule }) || rule.vpnProfileId.empty()) {
            continue;
        }
        for (const VpnProfile& candidate : vpnProfiles_) {
            if (equalsIgnoreCase(candidate.id, rule.vpnProfileId)) {
                profile = candidate;
                return true;
            }
        }
        throw std::runtime_error("VPN profile mapping references an unknown profile.");
    }
    return false;
}

const std::vector<DeviceRule>& PolicyManager::effectiveRules() const {
    return effectiveRules_;
}

const std::vector<VpnProfile>& PolicyManager::vpnProfiles() const {
    return vpnProfiles_;
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

unsigned int PolicyManager::refreshSeconds() const {
    return refreshSeconds_;
}

const std::wstring& PolicyManager::revision() const {
    return revision_;
}

void PolicyManager::load() {
    JsonValue root = readPolicyRoot(configPath_, &revision_);

    const std::wstring pipe = stringValue(root.find(L"pipeName"));
    if (!pipe.empty()) {
        pipeName_ = pipe;
    }

    const std::wstring usageStatePath = stringValue(root.find(L"usageStatePath"));
    if (!usageStatePath.empty()) {
        usageStatePath_ = usageStatePath;
    }

    const JsonValue* refresh = root.find(L"refreshSeconds");
    if (refresh && refresh->type == JsonValue::Type::Number) {
        const double seconds = refresh->numberValue;
        refreshSeconds_ = seconds < 2 ? 2u : (seconds > 300 ? 300u : static_cast<unsigned int>(seconds));
    }

    vpnProfiles_ = vpnProfilesFromJson(root.find(L"vpnProfiles"));

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
