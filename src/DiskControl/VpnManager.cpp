#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#ifndef WINVER
#define WINVER 0x0601
#endif

#include "VpnManager.h"

#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ras.h>
#include <raserror.h>
#include <shlobj.h>
#include <winhttp.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr DWORD kHttpConnectTimeoutMs = 5000;
constexpr DWORD kHttpOperationTimeoutMs = 8000;
constexpr size_t kMaximumPublicIpResponseBytes = 256;
constexpr int kPublicIpAttempts = 3;

std::mutex gLocalRouteMutex;
std::map<std::wstring, std::set<std::wstring>> gLocalRouteBaselines;

#ifdef DISKCONTROL_TESTING
bool gNetworkOperationsStubbedForTests = false;
#endif

bool equalsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return CompareStringOrdinal(
        left.c_str(), static_cast<int>(left.size()),
        right.c_str(), static_cast<int>(right.size()),
        TRUE) == CSTR_EQUAL;
}

std::wstring trim(const std::wstring& text) {
    const size_t first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) {
        return {};
    }
    const size_t last = text.find_last_not_of(L" \t\r\n");
    return text.substr(first, last - first + 1);
}

std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) {
        throw std::runtime_error("VPN public IP service returned invalid UTF-8.");
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size);
    return result;
}

std::string narrowAscii(const std::wstring& text) {
    std::string result;
    result.reserve(text.size());
    for (wchar_t ch : text) {
        result.push_back(ch >= 32 && ch <= 126 ? static_cast<char>(ch) : '?');
    }
    return result;
}

std::wstring widenError(const char* text) {
    std::wstring result;
    if (!text) {
        return result;
    }
    while (*text) {
        result.push_back(static_cast<unsigned char>(*text++));
    }
    return result;
}

void reportProgress(const VpnProgressCallback& progress, const std::wstring& message) {
    if (progress) {
        progress(message);
    }
}

std::runtime_error rasError(const char* operation, DWORD error) {
    wchar_t message[512]{};
    if (RasGetErrorStringW(error, message, static_cast<DWORD>(std::size(message))) != ERROR_SUCCESS) {
        return std::runtime_error(std::string(operation) + " failed. RAS error " + std::to_string(error) + ".");
    }
    return std::runtime_error(
        std::string(operation) + " failed. RAS error " + std::to_string(error) + ": " + narrowAscii(message));
}

void copyRasText(wchar_t* destination, size_t capacity, const std::wstring& source) {
    if (source.size() >= capacity) {
        throw std::runtime_error("VPN profile or credential value is too long for Windows RAS.");
    }
    wcscpy_s(destination, capacity, source.c_str());
}

std::wstring allUsersPhonebookPath() {
    wchar_t commonAppData[MAX_PATH]{};
    const HRESULT result = SHGetFolderPathW(
        nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, commonAppData);
    if (FAILED(result)) {
        throw std::runtime_error("Cannot locate the all-users Windows VPN phonebook.");
    }
    return std::wstring(commonAppData) + L"\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk";
}

std::vector<RASCONNW> rasActiveConnections() {
    DWORD bytes = sizeof(RASCONNW);
    DWORD count = 0;
    std::vector<RASCONNW> connections(1);
    connections[0].dwSize = sizeof(RASCONNW);

    DWORD error = RasEnumConnectionsW(connections.data(), &bytes, &count);
    if (error == ERROR_BUFFER_TOO_SMALL) {
        connections.resize((bytes + sizeof(RASCONNW) - 1) / sizeof(RASCONNW));
        connections[0].dwSize = sizeof(RASCONNW);
        error = RasEnumConnectionsW(connections.data(), &bytes, &count);
    }
    if (error != ERROR_SUCCESS) {
        throw rasError("VPN connection enumeration", error);
    }
    connections.resize(count);
    return connections;
}

DWORD hangUpProfileConnections(const std::wstring& profileName) {
    DWORD firstError = ERROR_SUCCESS;
    for (const RASCONNW& connection : rasActiveConnections()) {
        if (!equalsIgnoreCase(connection.szEntryName, profileName)) {
            continue;
        }
        const DWORD error = RasHangUpW(connection.hrasconn);
        if (firstError == ERROR_SUCCESS && error != ERROR_SUCCESS) {
            firstError = error;
        }
    }
    return firstError;
}

const wchar_t* phonebookArgument(const std::wstring& phonebookPath) {
    return phonebookPath.empty() ? nullptr : phonebookPath.c_str();
}

std::wstring phonebookForProfile(const VpnProfile& profile) {
    return profile.phonebookScope == VpnPhonebookScope::AllUsers
        ? allUsersPhonebookPath()
        : std::wstring();
}

bool pathsEqual(const std::wstring& left, const std::wstring& right) {
    if (left.empty() || right.empty()) {
        return left.empty() && right.empty();
    }
    return equalsIgnoreCase(left, right);
}

bool connectionMatchesProfile(const RASCONNW& connection, const VpnProfile& profile) {
    if (!equalsIgnoreCase(connection.szEntryName, profile.name)) {
        return false;
    }
    const std::wstring allUsers = allUsersPhonebookPath();
    const std::wstring connectionPhonebook = connection.szPhonebook;
    if (profile.phonebookScope == VpnPhonebookScope::AllUsers) {
        return pathsEqual(connectionPhonebook, allUsers);
    }
    return !pathsEqual(connectionPhonebook, allUsers);
}

std::vector<WindowsVpnProfileInfo> enumeratePhonebookProfiles(
    const std::wstring& phonebookPath,
    VpnPhonebookScope scope) {
    DWORD bytes = sizeof(RASENTRYNAMEW);
    DWORD count = 0;
    std::vector<RASENTRYNAMEW> entries(1);
    entries[0].dwSize = sizeof(RASENTRYNAMEW);
    DWORD error = RasEnumEntriesW(
        nullptr, phonebookArgument(phonebookPath), entries.data(), &bytes, &count);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
        error == ERROR_CANNOT_FIND_PHONEBOOK_ENTRY || error == ERROR_CANNOT_OPEN_PHONEBOOK) {
        return {};
    }
    if (error == ERROR_BUFFER_TOO_SMALL) {
        entries.resize((bytes + sizeof(RASENTRYNAMEW) - 1) / sizeof(RASENTRYNAMEW));
        entries[0].dwSize = sizeof(RASENTRYNAMEW);
        error = RasEnumEntriesW(
            nullptr, phonebookArgument(phonebookPath), entries.data(), &bytes, &count);
    }
    if (error != ERROR_SUCCESS) {
        throw rasError("VPN profile enumeration", error);
    }

    std::vector<WindowsVpnProfileInfo> result;
    result.reserve(count);
    for (DWORD index = 0; index < count; ++index) {
        WindowsVpnProfileInfo profile;
        profile.name = entries[index].szEntryName;
        profile.phonebookScope = scope;

        RASENTRYW entry{};
        entry.dwSize = sizeof(entry);
        DWORD entrySize = sizeof(entry);
        DWORD deviceInfoSize = 0;
        const DWORD readError = RasGetEntryPropertiesW(
            phonebookArgument(phonebookPath), profile.name.c_str(),
            &entry, &entrySize, nullptr, &deviceInfoSize);
        if (readError == ERROR_SUCCESS) {
            profile.serverAddress = entry.szLocalPhoneNumber;
            profile.tunnelType = entry.szDeviceName;
        }
        result.push_back(std::move(profile));
    }
    return result;
}

bool isValidIpAddressValue(const std::wstring& value) {
    IN_ADDR ipv4{};
    if (InetPtonW(AF_INET, value.c_str(), &ipv4) == 1) {
        return true;
    }
    IN6_ADDR ipv6{};
    return InetPtonW(AF_INET6, value.c_str(), &ipv6) == 1;
}

bool isExpectedPublicIp(const std::wstring& actual, const std::vector<std::wstring>& expected) {
    for (const std::wstring& candidate : expected) {
        if (equalsIgnoreCase(trim(candidate), actual)) {
            return true;
        }
    }
    return false;
}

bool isLocalIpv4Address(const IN_ADDR& address) {
    const ULONG value = ntohl(address.S_un.S_addr);
    return (value & 0xFF000000UL) == 0x0A000000UL ||
        (value & 0xFFF00000UL) == 0xAC100000UL ||
        (value & 0xFFFF0000UL) == 0xC0A80000UL ||
        (value & 0xFFFF0000UL) == 0xA9FE0000UL;
}

std::wstring ipv4Text(const IN_ADDR& address) {
    wchar_t text[INET_ADDRSTRLEN]{};
    if (!InetNtopW(AF_INET, &address, text, static_cast<DWORD>(std::size(text)))) {
        throw std::runtime_error("VPN local network route address could not be formatted.");
    }
    return text;
}

std::set<std::wstring> captureLocalPhysicalRoutes() {
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    const DWORD error = GetIpForwardTable2(AF_INET, &table);
    if (error != NO_ERROR) {
        throw std::runtime_error(
            "VPN local network route enumeration failed. Windows error " + std::to_string(error) + ".");
    }

    std::set<std::wstring> routes;
    try {
        for (ULONG index = 0; index < table->NumEntries; ++index) {
            const MIB_IPFORWARD_ROW2& route = table->Table[index];
            if (route.DestinationPrefix.Prefix.si_family != AF_INET ||
                route.DestinationPrefix.PrefixLength == 0 ||
                !isLocalIpv4Address(route.DestinationPrefix.Prefix.Ipv4.sin_addr)) {
                continue;
            }

            MIB_IF_ROW2 interfaceRow{};
            interfaceRow.InterfaceLuid = route.InterfaceLuid;
            if (GetIfEntry2(&interfaceRow) != NO_ERROR ||
                !interfaceRow.InterfaceAndOperStatusFlags.HardwareInterface ||
                interfaceRow.OperStatus != IfOperStatusUp) {
                continue;
            }

            routes.insert(
                ipv4Text(route.DestinationPrefix.Prefix.Ipv4.sin_addr) + L"/" +
                std::to_wstring(route.DestinationPrefix.PrefixLength) + L"@" +
                std::to_wstring(route.InterfaceLuid.Value));
        }
    }
    catch (...) {
        FreeMibTable(table);
        throw;
    }
    FreeMibTable(table);
    return routes;
}

void rememberLocalRouteBaseline(
    const std::wstring& profileName,
    const std::set<std::wstring>& routes,
    bool replaceExisting) {
    std::lock_guard<std::mutex> lock(gLocalRouteMutex);
    auto found = gLocalRouteBaselines.find(profileName);
    if (found == gLocalRouteBaselines.end() || replaceExisting) {
        gLocalRouteBaselines[profileName] = routes;
    }
}

size_t verifyLocalRoutePreservation(const std::wstring& profileName) {
    const std::set<std::wstring> currentRoutes = captureLocalPhysicalRoutes();
    std::set<std::wstring> baseline;
    {
        std::lock_guard<std::mutex> lock(gLocalRouteMutex);
        auto found = gLocalRouteBaselines.find(profileName);
        if (found == gLocalRouteBaselines.end()) {
            gLocalRouteBaselines.emplace(profileName, currentRoutes);
            baseline = currentRoutes;
        }
        else {
            baseline = found->second;
        }
    }

    std::vector<std::wstring> missing;
    for (const std::wstring& route : baseline) {
        if (currentRoutes.find(route) == currentRoutes.end()) {
            missing.push_back(route);
        }
    }
    if (!missing.empty()) {
        std::wstring details;
        for (const std::wstring& route : missing) {
            if (!details.empty()) {
                details += L", ";
            }
            details += route;
        }
        const DWORD disconnectError = hangUpProfileConnections(profileName);
        if (disconnectError != ERROR_SUCCESS) {
            details += L"; disconnectError=" + std::to_wstring(disconnectError);
        }
        throw std::runtime_error(
            "VPN local network routes were replaced. Missing=" + narrowAscii(details) + ".");
    }
    return baseline.size();
}

std::wstring expectedIpsText(const std::vector<std::wstring>& values) {
    std::wstring result;
    for (const std::wstring& value : values) {
        if (!result.empty()) {
            result += L", ";
        }
        result += value;
    }
    return result;
}

class InternetHandle {
public:
    explicit InternetHandle(HINTERNET handle = nullptr) : handle_(handle) {}
    ~InternetHandle() {
        if (handle_) {
            WinHttpCloseHandle(handle_);
        }
    }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
    HINTERNET get() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr; }

private:
    HINTERNET handle_ = nullptr;
};
}

bool VpnManager::profileExists(const VpnProfile& profile) {
    if (profile.mode == VpnProfileMode::Direct) {
        return true;
    }
    const std::wstring phonebook = phonebookForProfile(profile);
    for (const WindowsVpnProfileInfo& installed : enumeratePhonebookProfiles(
        phonebook, profile.phonebookScope)) {
        if (equalsIgnoreCase(installed.name, profile.name)) {
            return true;
        }
    }
    return false;
}

bool VpnManager::hasStoredCredentials(const VpnProfile& profile) {
    if (profile.mode == VpnProfileMode::Direct) {
        return true;
    }
    const std::wstring phonebook = phonebookForProfile(profile);
    RASCREDENTIALSW credentials{};
    credentials.dwSize = sizeof(credentials);
    credentials.dwMask = RASCM_UserName | RASCM_Password;
    const DWORD error = RasGetCredentialsW(
        phonebookArgument(phonebook), profile.name.c_str(), &credentials);
    if (error == ERROR_CANNOT_FIND_PHONEBOOK_ENTRY) {
        return false;
    }
    if (error != ERROR_SUCCESS) {
        throw rasError("VPN credential check", error);
    }
    return (credentials.dwMask & RASCM_UserName) != 0 &&
        (credentials.dwMask & RASCM_Password) != 0 &&
        credentials.szUserName[0] != L'\0';
}

void VpnManager::saveCredentials(
    const VpnProfile& profile,
    const std::wstring& userName,
    const std::wstring& password) {
    if (profile.mode == VpnProfileMode::Direct) {
        return;
    }
    if (profile.name.empty() || userName.empty() || password.empty()) {
        throw std::runtime_error("VPN profile, user name and password are required.");
    }

    const std::wstring phonebook = phonebookForProfile(profile);
    RASCREDENTIALSW credentials{};
    credentials.dwSize = sizeof(credentials);
    credentials.dwMask = RASCM_UserName | RASCM_Password;
    copyRasText(credentials.szUserName, std::size(credentials.szUserName), userName);
    copyRasText(credentials.szPassword, std::size(credentials.szPassword), password);
    const DWORD error = RasSetCredentialsW(
        phonebookArgument(phonebook), profile.name.c_str(), &credentials, FALSE);
    SecureZeroMemory(credentials.szPassword, sizeof(credentials.szPassword));
    if (error != ERROR_SUCCESS) {
        throw rasError("VPN credential save", error);
    }
}

bool VpnManager::isConnected(const VpnProfile& profile) {
    if (profile.mode == VpnProfileMode::Direct) {
        return rasActiveConnections().empty();
    }
    for (const RASCONNW& connection : rasActiveConnections()) {
        if (connectionMatchesProfile(connection, profile)) {
            return true;
        }
    }
    return false;
}

std::vector<WindowsVpnProfileInfo> VpnManager::installedProfiles() {
    return installedProfiles({}, allUsersPhonebookPath());
}

std::vector<WindowsVpnProfileInfo> VpnManager::installedProfiles(
    const std::wstring& currentUserPhonebookPath,
    const std::wstring& allUsersPhonebookPathValue) {
    std::vector<WindowsVpnProfileInfo> result = enumeratePhonebookProfiles(
        currentUserPhonebookPath, VpnPhonebookScope::CurrentUser);
    std::vector<WindowsVpnProfileInfo> allUsers = enumeratePhonebookProfiles(
        allUsersPhonebookPathValue, VpnPhonebookScope::AllUsers);
    result.insert(result.end(), allUsers.begin(), allUsers.end());

    const bool localEnumeration = currentUserPhonebookPath.empty() &&
        pathsEqual(allUsersPhonebookPathValue, allUsersPhonebookPath());
    if (localEnumeration) {
        for (WindowsVpnProfileInfo& profile : result) {
            VpnProfile configured;
            configured.name = profile.name;
            configured.phonebookScope = profile.phonebookScope;
            profile.connected = isConnected(configured);
        }
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        const int nameOrder = CompareStringOrdinal(
            left.name.c_str(), static_cast<int>(left.name.size()),
            right.name.c_str(), static_cast<int>(right.name.size()), TRUE);
        if (nameOrder != CSTR_EQUAL) {
            return nameOrder == CSTR_LESS_THAN;
        }
        return left.phonebookScope == VpnPhonebookScope::CurrentUser &&
            right.phonebookScope == VpnPhonebookScope::AllUsers;
    });
    result.erase(std::unique(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return equalsIgnoreCase(left.name, right.name) &&
            left.phonebookScope == right.phonebookScope;
    }), result.end());
    return result;
}

std::vector<ActiveVpnConnectionInfo> VpnManager::activeConnections() {
#ifdef DISKCONTROL_TESTING
    if (gNetworkOperationsStubbedForTests) {
        return {};
    }
#endif
    std::vector<ActiveVpnConnectionInfo> result;
    for (const RASCONNW& connection : rasActiveConnections()) {
        result.push_back({ connection.szEntryName, connection.szPhonebook });
    }
    return result;
}

void VpnManager::disconnectAll(const VpnProgressCallback& progress) {
#ifdef DISKCONTROL_TESTING
    if (gNetworkOperationsStubbedForTests) {
        reportProgress(progress, L"Тестовый режим: активных VPN Windows нет.");
        return;
    }
#endif
    std::vector<RASCONNW> connections = rasActiveConnections();
    if (connections.empty()) {
        reportProgress(progress, L"Активных VPN-подключений Windows нет.");
        return;
    }

    DWORD firstError = ERROR_SUCCESS;
    for (const RASCONNW& connection : connections) {
        reportProgress(progress, L"Отключаем VPN-профиль «" +
            std::wstring(connection.szEntryName) + L"».");
        const DWORD error = RasHangUpW(connection.hrasconn);
        if (firstError == ERROR_SUCCESS && error != ERROR_SUCCESS) {
            firstError = error;
        }
    }
    if (firstError != ERROR_SUCCESS) {
        throw rasError("VPN disconnect all", firstError);
    }

    constexpr int maximumChecks = 75;
    for (int check = 0; check < maximumChecks; ++check) {
        if (rasActiveConnections().empty()) {
            reportProgress(progress, L"Все VPN-подключения Windows отключены.");
            return;
        }
        Sleep(200);
    }
    throw std::runtime_error("VPN disconnect all timed out.");
}

void VpnManager::disconnect(
    const VpnProfile& profile,
    const VpnProgressCallback& progress) {
    if (profile.mode == VpnProfileMode::Direct || profile.name.empty()) {
        return;
    }
    if (!isConnected(profile)) {
        reportProgress(progress, L"VPN-профиль «" + profile.name + L"» уже отключён.");
        return;
    }

    reportProgress(progress, L"Отключаем VPN-профиль «" + profile.name + L"».");
    DWORD error = ERROR_SUCCESS;
    for (const RASCONNW& connection : rasActiveConnections()) {
        if (!connectionMatchesProfile(connection, profile)) {
            continue;
        }
        const DWORD currentError = RasHangUpW(connection.hrasconn);
        if (error == ERROR_SUCCESS && currentError != ERROR_SUCCESS) {
            error = currentError;
        }
    }
    if (error != ERROR_SUCCESS) {
        throw rasError("VPN disconnect", error);
    }

    constexpr int maximumChecks = 50;
    for (int check = 0; check < maximumChecks; ++check) {
        if (!isConnected(profile)) {
            reportProgress(progress, L"VPN-профиль «" + profile.name + L"» отключён.");
            return;
        }
        Sleep(200);
    }
    throw std::runtime_error("VPN disconnect timed out.");
}

size_t VpnManager::localPhysicalRouteCount() {
    return captureLocalPhysicalRoutes().size();
}

VpnVerificationResult VpnManager::connectAndVerify(
    const VpnProfile& profile,
    const VpnProgressCallback& progress) {
#ifdef DISKCONTROL_TESTING
    if (gNetworkOperationsStubbedForTests) {
        if (!profile.enabled || profile.expectedPublicIps.empty()) {
            throw std::runtime_error("Test network profile is incomplete.");
        }
        reportProgress(progress, L"Тестовый режим: сетевой профиль проверен.");
        return {
            profile.mode == VpnProfileMode::Direct ? L"Без VPN" : profile.name,
            profile.expectedPublicIps.front(),
            false,
            0
        };
    }
#endif
    if (profile.mode == VpnProfileMode::Direct) {
        return verifyDirect(profile, progress);
    }
    reportProgress(progress, L"Начинаем проверку VPN-профиля «" + profile.name + L"».");
    if (!profile.enabled) {
        throw std::runtime_error("VPN profile is disabled by policy.");
    }
    if (profile.name.empty()) {
        throw std::runtime_error("VPN profile name is not configured.");
    }
    if (profile.expectedPublicIps.empty()) {
        throw std::runtime_error("VPN expected public IP is not configured.");
    }
    if (!profileExists(profile)) {
        throw std::runtime_error("VPN Windows profile is not installed: " + narrowAscii(profile.name));
    }

    VpnVerificationResult result;
    result.profileName = profile.name;
    result.alreadyConnected = isConnected(profile);
    reportProgress(progress, result.alreadyConnected
        ? L"VPN-профиль уже подключён. Повторное соединение не требуется."
        : L"VPN-профиль пока не подключён. Готовим соединение Windows RAS.");
    const std::set<std::wstring> localRoutesBefore = captureLocalPhysicalRoutes();
    rememberLocalRouteBaseline(profile.name, localRoutesBefore, !result.alreadyConnected);
    reportProgress(progress, L"Сохранено локальных маршрутов перед VPN: " +
        std::to_wstring(localRoutesBefore.size()) + L".");

    HRASCONN openedConnection = nullptr;
    if (!result.alreadyConnected) {
        reportProgress(progress, L"Читаем сохранённые в Windows логин и пароль VPN.");
        RASCREDENTIALSW credentials{};
        credentials.dwSize = sizeof(credentials);
        credentials.dwMask = RASCM_UserName | RASCM_Password | RASCM_Domain;
        const std::wstring phonebook = phonebookForProfile(profile);
        DWORD error = RasGetCredentialsW(
            phonebookArgument(phonebook), profile.name.c_str(), &credentials);
        if (error != ERROR_SUCCESS) {
            throw rasError("VPN credential read", error);
        }
        if ((credentials.dwMask & RASCM_UserName) == 0 ||
            (credentials.dwMask & RASCM_Password) == 0 ||
            credentials.szUserName[0] == L'\0') {
            SecureZeroMemory(credentials.szPassword, sizeof(credentials.szPassword));
            throw std::runtime_error("VPN credentials are not configured.");
        }

        RASDIALPARAMSW parameters{};
        parameters.dwSize = sizeof(parameters);
        copyRasText(parameters.szEntryName, std::size(parameters.szEntryName), profile.name);
        copyRasText(parameters.szUserName, std::size(parameters.szUserName), credentials.szUserName);
        copyRasText(parameters.szPassword, std::size(parameters.szPassword), credentials.szPassword);
        if ((credentials.dwMask & RASCM_Domain) != 0) {
            copyRasText(parameters.szDomain, std::size(parameters.szDomain), credentials.szDomain);
        }
        SecureZeroMemory(credentials.szPassword, sizeof(credentials.szPassword));

        reportProgress(progress, L"Передаём Windows команду подключения VPN.");
        error = RasDialW(
            nullptr, phonebookArgument(phonebook), &parameters, 0, nullptr, &openedConnection);
        SecureZeroMemory(parameters.szPassword, sizeof(parameters.szPassword));
        if (error != ERROR_SUCCESS) {
            if (openedConnection) {
                RasHangUpW(openedConnection);
            }
            throw rasError("VPN connection", error);
        }
        reportProgress(progress, L"Windows сообщила об успешном подключении VPN.");
    }

    try {
        VpnVerificationResult verified = verifyConnected(profile, progress);
        verified.alreadyConnected = result.alreadyConnected;
        reportProgress(progress, L"VPN полностью проверен и готов для подключения токена.");
        return verified;
    }
    catch (...) {
        if (openedConnection) {
            reportProgress(progress, L"Проверка VPN не пройдена. Отключаем созданное этой операцией VPN-соединение.");
            RasHangUpW(openedConnection);
        }
        throw;
    }
}

VpnVerificationResult VpnManager::verifyConnected(
    const VpnProfile& profile,
    const VpnProgressCallback& progress) {
    if (profile.mode == VpnProfileMode::Direct) {
        return verifyDirect(profile, progress);
    }
    if (!profile.enabled) {
        throw std::runtime_error("VPN profile is disabled by policy.");
    }
    if (profile.name.empty()) {
        throw std::runtime_error("VPN profile name is not configured.");
    }
    if (profile.expectedPublicIps.empty()) {
        throw std::runtime_error("VPN expected public IP is not configured.");
    }
    if (!profileExists(profile)) {
        throw std::runtime_error("VPN Windows profile is not installed: " + narrowAscii(profile.name));
    }
    if (!isConnected(profile)) {
        throw std::runtime_error("VPN connection is not active: " + narrowAscii(profile.name));
    }

    const std::vector<ActiveVpnConnectionInfo> connections = activeConnections();
    if (connections.size() != 1) {
        throw std::runtime_error("Unexpected additional Windows VPN connection is active.");
    }

    VpnVerificationResult result;
    result.profileName = profile.name;
    result.alreadyConnected = true;
    reportProgress(progress, L"Проверяем, что VPN не нарушил маршруты локальной сети.");
    result.preservedLocalRouteCount = verifyLocalRoutePreservation(profile.name);
    reportProgress(progress, L"Локальная сеть доступна. Проверено маршрутов: " +
        std::to_wstring(result.preservedLocalRouteCount) + L".");
    std::runtime_error lastError("VPN public IP check failed.");
    for (int attempt = 0; attempt < kPublicIpAttempts; ++attempt) {
        try {
            reportProgress(progress, L"Запрашиваем фактический внешний IP. Попытка " +
                std::to_wstring(attempt + 1) + L" из " + std::to_wstring(kPublicIpAttempts) + L".");
            result.publicIp = queryPublicIp(profile.ipCheckUrl);
            if (!isExpectedPublicIp(result.publicIp, profile.expectedPublicIps)) {
                throw std::runtime_error(
                    "VPN public IP mismatch. Actual=" + narrowAscii(result.publicIp) +
                    "; expected=" + narrowAscii(expectedIpsText(profile.expectedPublicIps)) + ".");
            }
            reportProgress(progress, L"Внешний IP подтверждён: " + result.publicIp + L".");
            return result;
        }
        catch (const std::runtime_error& error) {
            lastError = error;
            reportProgress(progress, L"Проверка внешнего IP не удалась. Техническая причина: " +
                widenError(error.what()));
            if (attempt + 1 < kPublicIpAttempts) {
                Sleep(1200);
            }
        }
    }
    throw lastError;
}

VpnVerificationResult VpnManager::verifyDirect(
    const VpnProfile& profile,
    const VpnProgressCallback& progress) {
    if (!profile.enabled) {
        throw std::runtime_error("VPN profile is disabled by policy.");
    }
    if (profile.expectedPublicIps.empty()) {
        throw std::runtime_error("VPN expected public IP is not configured.");
    }
    if (!rasActiveConnections().empty()) {
        throw std::runtime_error("Direct network mode requires all Windows VPN connections to be disconnected.");
    }

    VpnVerificationResult result;
    result.profileName = profile.name.empty() ? L"Без VPN" : profile.name;
    std::runtime_error lastError("VPN public IP check failed.");
    for (int attempt = 0; attempt < kPublicIpAttempts; ++attempt) {
        try {
            reportProgress(progress, L"Проверяем внешний IP без VPN. Попытка " +
                std::to_wstring(attempt + 1) + L" из " + std::to_wstring(kPublicIpAttempts) + L".");
            result.publicIp = queryPublicIp(profile.ipCheckUrl);
            if (!isExpectedPublicIp(result.publicIp, profile.expectedPublicIps)) {
                throw std::runtime_error(
                    "VPN public IP mismatch. Actual=" + narrowAscii(result.publicIp) +
                    "; expected=" + narrowAscii(expectedIpsText(profile.expectedPublicIps)) + ".");
            }
            reportProgress(progress, L"Внешний IP без VPN подтверждён: " + result.publicIp + L".");
            return result;
        }
        catch (const std::runtime_error& error) {
            lastError = error;
            if (attempt + 1 < kPublicIpAttempts) {
                Sleep(1200);
            }
        }
    }
    throw lastError;
}

std::wstring VpnManager::currentPublicIp(const std::wstring& url) {
    return queryPublicIp(url.empty() ? L"https://api.ipify.org" : url);
}

bool VpnManager::isValidPublicIp(const std::wstring& value) {
    return isValidIpAddressValue(trim(value));
}

std::wstring VpnManager::allUsersPhonebook() {
    return allUsersPhonebookPath();
}

#ifdef DISKCONTROL_TESTING
void VpnManager::setNetworkOperationsStubbedForTests(bool enabled) {
    gNetworkOperationsStubbedForTests = enabled;
}
#endif

std::wstring VpnManager::queryPublicIp(const std::wstring& url) {
    URL_COMPONENTSW components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &components)) {
        throw std::runtime_error("VPN public IP check URL is invalid.");
    }

    const std::wstring host(components.lpszHostName, components.dwHostNameLength);
    std::wstring path;
    if (components.lpszUrlPath && components.dwUrlPathLength > 0) {
        path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    }
    if (components.lpszExtraInfo && components.dwExtraInfoLength > 0) {
        path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    if (path.empty()) {
        path = L"/";
    }

    InternetHandle session(WinHttpOpen(
        L"DiskControl/0.2", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) {
        throw std::runtime_error("VPN public IP check could not initialize WinHTTP.");
    }
    WinHttpSetTimeouts(
        session.get(), kHttpConnectTimeoutMs, kHttpConnectTimeoutMs,
        kHttpOperationTimeoutMs, kHttpOperationTimeoutMs);

    InternetHandle connection(WinHttpConnect(session.get(), host.c_str(), components.nPort, 0));
    if (!connection) {
        throw std::runtime_error("VPN public IP check could not connect to the verification service.");
    }

    const DWORD flags = components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    InternetHandle request(WinHttpOpenRequest(
        connection.get(), L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!request) {
        throw std::runtime_error("VPN public IP check could not create an HTTP request.");
    }
    if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request.get(), nullptr)) {
        throw std::runtime_error("VPN public IP verification service did not respond.");
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    if (!WinHttpQueryHeaders(
        request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX) || status != 200) {
        throw std::runtime_error("VPN public IP verification service returned an unexpected HTTP status.");
    }

    std::string response;
    while (response.size() < kMaximumPublicIpResponseBytes) {
        std::array<char, 128> buffer{};
        DWORD bytesRead = 0;
        if (!WinHttpReadData(request.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead)) {
            throw std::runtime_error("VPN public IP verification response could not be read.");
        }
        if (bytesRead == 0) {
            break;
        }
        response.append(buffer.data(), bytesRead);
    }
    if (response.size() >= kMaximumPublicIpResponseBytes) {
        throw std::runtime_error("VPN public IP verification response is too large.");
    }

    const std::wstring publicIp = trim(utf8ToWide(response));
    if (!isValidIpAddressValue(publicIp)) {
        throw std::runtime_error("VPN public IP verification service returned an invalid IP address.");
    }
    return publicIp;
}
