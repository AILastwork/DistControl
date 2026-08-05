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

std::wstring l2tpDeviceName() {
    DWORD bytes = sizeof(RASDEVINFOW);
    DWORD count = 0;
    std::vector<RASDEVINFOW> devices(1);
    devices[0].dwSize = sizeof(RASDEVINFOW);
    DWORD error = RasEnumDevicesW(devices.data(), &bytes, &count);
    if (error == ERROR_BUFFER_TOO_SMALL) {
        devices.resize((bytes + sizeof(RASDEVINFOW) - 1) / sizeof(RASDEVINFOW));
        devices[0].dwSize = sizeof(RASDEVINFOW);
        error = RasEnumDevicesW(devices.data(), &bytes, &count);
    }
    if (error != ERROR_SUCCESS) {
        throw rasError("VPN device enumeration", error);
    }

    std::wstring fallback;
    for (DWORD index = 0; index < count; ++index) {
        if (!equalsIgnoreCase(devices[index].szDeviceType, RASDT_Vpn)) {
            continue;
        }
        if (fallback.empty()) {
            fallback = devices[index].szDeviceName;
        }
        if (FindStringOrdinal(FIND_FROMSTART, devices[index].szDeviceName, -1, L"L2TP", -1, TRUE) >= 0) {
            return devices[index].szDeviceName;
        }
    }
    if (!fallback.empty()) {
        return fallback;
    }
    throw std::runtime_error("Windows L2TP VPN device was not found.");
}

std::vector<RASCONNW> activeConnections() {
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
    for (const RASCONNW& connection : activeConnections()) {
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

bool isValidIpAddress(const std::wstring& value) {
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

bool VpnManager::profileExists(const std::wstring& profileName) {
    if (profileName.empty()) {
        return false;
    }

    DWORD bytes = 0;
    DWORD count = 0;
    DWORD error = RasEnumEntriesW(nullptr, nullptr, nullptr, &bytes, &count);
    if (error != ERROR_BUFFER_TOO_SMALL && error != ERROR_SUCCESS) {
        throw rasError("VPN profile enumeration", error);
    }
    if (bytes == 0) {
        return false;
    }

    std::vector<unsigned char> buffer(bytes);
    auto* entries = reinterpret_cast<RASENTRYNAMEW*>(buffer.data());
    entries[0].dwSize = sizeof(RASENTRYNAMEW);
    error = RasEnumEntriesW(nullptr, nullptr, entries, &bytes, &count);
    if (error != ERROR_SUCCESS) {
        throw rasError("VPN profile enumeration", error);
    }
    for (DWORD index = 0; index < count; ++index) {
        if (equalsIgnoreCase(entries[index].szEntryName, profileName)) {
            return true;
        }
    }
    return false;
}

bool VpnManager::hasStoredCredentials(const std::wstring& profileName) {
    RASCREDENTIALSW credentials{};
    credentials.dwSize = sizeof(credentials);
    credentials.dwMask = RASCM_UserName | RASCM_Password;
    const DWORD error = RasGetCredentialsW(nullptr, profileName.c_str(), &credentials);
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
    const std::wstring& profileName,
    const std::wstring& userName,
    const std::wstring& password) {
    if (profileName.empty() || userName.empty() || password.empty()) {
        throw std::runtime_error("VPN profile, user name and password are required.");
    }

    RASCREDENTIALSW credentials{};
    credentials.dwSize = sizeof(credentials);
    credentials.dwMask = RASCM_UserName | RASCM_Password;
    copyRasText(credentials.szUserName, std::size(credentials.szUserName), userName);
    copyRasText(credentials.szPassword, std::size(credentials.szPassword), password);
    const DWORD error = RasSetCredentialsW(nullptr, profileName.c_str(), &credentials, FALSE);
    SecureZeroMemory(credentials.szPassword, sizeof(credentials.szPassword));
    if (error != ERROR_SUCCESS) {
        throw rasError("VPN credential save", error);
    }
}

void VpnManager::installOrUpdateProfile(
    const VpnProfile& profile,
    const std::wstring& preSharedKey) {
    if (profile.name.empty() || profile.serverAddress.empty()) {
        throw std::runtime_error("VPN profile name and server address are required.");
    }
    if (!profile.tunnelType.empty() && !equalsIgnoreCase(profile.tunnelType, L"L2TP")) {
        throw std::runtime_error("Only L2TP VPN profiles can be installed by DiskControl.");
    }

    const std::wstring phonebook = allUsersPhonebookPath();
    RASENTRYW entry{};
    entry.dwSize = sizeof(entry);
    DWORD entrySize = sizeof(entry);
    DWORD deviceInfoSize = 0;
    const DWORD readError = RasGetEntryPropertiesW(
        phonebook.c_str(), profile.name.c_str(), &entry, &entrySize, nullptr, &deviceInfoSize);
    const bool exists = readError == ERROR_SUCCESS;
    if (!exists && readError != ERROR_CANNOT_FIND_PHONEBOOK_ENTRY && readError != ERROR_FILE_NOT_FOUND) {
        throw rasError("VPN profile read", readError);
    }
    if (!exists) {
        if (preSharedKey.empty()) {
            throw std::runtime_error("VPN pre-shared key is required for a new Windows profile.");
        }
        entry = {};
        entry.dwSize = sizeof(entry);
        entry.dwfOptions = RASEO_RequireMsCHAP2 | RASEO_RequireDataEncryption;
        entry.dwfNetProtocols = RASNP_Ip;
        entry.dwFramingProtocol = RASFP_Ppp;
    }

    if (profile.fullTunnel) {
        entry.dwfOptions |= RASEO_RemoteDefaultGateway;
    }
    else {
        entry.dwfOptions &= ~RASEO_RemoteDefaultGateway;
    }
    entry.dwfOptions &= ~(RASEO_RequireEAP | RASEO_RequirePAP | RASEO_RequireSPAP |
        RASEO_RequireCHAP | RASEO_RequireMsEncryptedPw);
    entry.dwfOptions |= RASEO_RequireMsCHAP2 | RASEO_RequireDataEncryption;
    entry.dwfOptions2 |= RASEO2_UsePreSharedKey | RASEO2_ReconnectIfDropped;
    entry.dwType = RASET_Vpn;
    entry.dwVpnStrategy = VS_L2tpOnly;
    entry.dwfNetProtocols = RASNP_Ip;
    entry.dwFramingProtocol = RASFP_Ppp;
    copyRasText(entry.szLocalPhoneNumber, std::size(entry.szLocalPhoneNumber), profile.serverAddress);
    copyRasText(entry.szDeviceType, std::size(entry.szDeviceType), RASDT_Vpn);
    copyRasText(entry.szDeviceName, std::size(entry.szDeviceName), l2tpDeviceName());

    if (!exists) {
        const DWORD validationError = RasValidateEntryNameW(phonebook.c_str(), profile.name.c_str());
        if (validationError != ERROR_SUCCESS && validationError != ERROR_ALREADY_EXISTS) {
            throw rasError("VPN profile name validation", validationError);
        }
    }

    const DWORD writeError = RasSetEntryPropertiesW(
        phonebook.c_str(), profile.name.c_str(), &entry, sizeof(entry), nullptr, 0);
    if (writeError != ERROR_SUCCESS) {
        throw rasError("VPN profile save", writeError);
    }

    if (!preSharedKey.empty()) {
        RASCREDENTIALSW credentials{};
        credentials.dwSize = sizeof(credentials);
        credentials.dwMask = RASCM_PreSharedKey;
        copyRasText(credentials.szPassword, std::size(credentials.szPassword), preSharedKey);
        const DWORD credentialError = RasSetCredentialsW(
            phonebook.c_str(), profile.name.c_str(), &credentials, FALSE);
        SecureZeroMemory(credentials.szPassword, sizeof(credentials.szPassword));
        if (credentialError != ERROR_SUCCESS) {
            throw rasError("VPN pre-shared key save", credentialError);
        }
    }
}

bool VpnManager::isConnected(const std::wstring& profileName) {
    for (const RASCONNW& connection : activeConnections()) {
        if (equalsIgnoreCase(connection.szEntryName, profileName)) {
            return true;
        }
    }
    return false;
}

size_t VpnManager::localPhysicalRouteCount() {
    return captureLocalPhysicalRoutes().size();
}

VpnVerificationResult VpnManager::connectAndVerify(const VpnProfile& profile) {
    if (!profile.enabled) {
        throw std::runtime_error("VPN profile is disabled by policy.");
    }
    if (profile.name.empty()) {
        throw std::runtime_error("VPN profile name is not configured.");
    }
    if (profile.expectedPublicIps.empty()) {
        throw std::runtime_error("VPN expected public IP is not configured.");
    }
    if (!profileExists(profile.name)) {
        throw std::runtime_error("VPN Windows profile is not installed: " + narrowAscii(profile.name));
    }

    VpnVerificationResult result;
    result.profileName = profile.name;
    result.alreadyConnected = isConnected(profile.name);
    const std::set<std::wstring> localRoutesBefore = captureLocalPhysicalRoutes();
    rememberLocalRouteBaseline(profile.name, localRoutesBefore, !result.alreadyConnected);

    HRASCONN openedConnection = nullptr;
    if (!result.alreadyConnected) {
        RASCREDENTIALSW credentials{};
        credentials.dwSize = sizeof(credentials);
        credentials.dwMask = RASCM_UserName | RASCM_Password | RASCM_Domain;
        DWORD error = RasGetCredentialsW(nullptr, profile.name.c_str(), &credentials);
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

        error = RasDialW(nullptr, nullptr, &parameters, 0, nullptr, &openedConnection);
        SecureZeroMemory(parameters.szPassword, sizeof(parameters.szPassword));
        if (error != ERROR_SUCCESS) {
            if (openedConnection) {
                RasHangUpW(openedConnection);
            }
            throw rasError("VPN connection", error);
        }
    }

    try {
        VpnVerificationResult verified = verifyConnected(profile);
        verified.alreadyConnected = result.alreadyConnected;
        return verified;
    }
    catch (...) {
        if (openedConnection) {
            RasHangUpW(openedConnection);
        }
        throw;
    }
}

VpnVerificationResult VpnManager::verifyConnected(const VpnProfile& profile) {
    if (!profile.enabled) {
        throw std::runtime_error("VPN profile is disabled by policy.");
    }
    if (profile.name.empty()) {
        throw std::runtime_error("VPN profile name is not configured.");
    }
    if (profile.expectedPublicIps.empty()) {
        throw std::runtime_error("VPN expected public IP is not configured.");
    }
    if (!profileExists(profile.name)) {
        throw std::runtime_error("VPN Windows profile is not installed: " + narrowAscii(profile.name));
    }
    if (!isConnected(profile.name)) {
        throw std::runtime_error("VPN connection is not active: " + narrowAscii(profile.name));
    }

    VpnVerificationResult result;
    result.profileName = profile.name;
    result.alreadyConnected = true;
    result.preservedLocalRouteCount = verifyLocalRoutePreservation(profile.name);
    std::runtime_error lastError("VPN public IP check failed.");
    for (int attempt = 0; attempt < kPublicIpAttempts; ++attempt) {
        try {
            result.publicIp = queryPublicIp(profile.ipCheckUrl);
            if (!isExpectedPublicIp(result.publicIp, profile.expectedPublicIps)) {
                throw std::runtime_error(
                    "VPN public IP mismatch. Actual=" + narrowAscii(result.publicIp) +
                    "; expected=" + narrowAscii(expectedIpsText(profile.expectedPublicIps)) + ".");
            }
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
    if (!isValidIpAddress(publicIp)) {
        throw std::runtime_error("VPN public IP verification service returned an invalid IP address.");
    }
    return publicIp;
}
