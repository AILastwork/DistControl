#pragma once

#include "PolicyManager.h"

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

using VpnProgressCallback = std::function<void(const std::wstring& message)>;

struct VpnVerificationResult {
    std::wstring profileName;
    std::wstring publicIp;
    bool alreadyConnected = false;
    size_t preservedLocalRouteCount = 0;
};

struct WindowsVpnProfileInfo {
    std::wstring name;
    std::wstring serverAddress;
    std::wstring tunnelType;
    VpnPhonebookScope phonebookScope = VpnPhonebookScope::CurrentUser;
    bool connected = false;
};

enum class VpnNameMatchKind {
    None,
    Exact,
    Unique,
    Ambiguous
};

struct VpnNameMatch {
    VpnNameMatchKind kind = VpnNameMatchKind::None;
    size_t index = 0;
    std::vector<size_t> candidates;
};

// Matches text typed or pasted by an administrator against VPN choice names.
// Case, repeated whitespace, quotes and a trailing " [пользователь]" or
// " [все пользователи]" scope suffix are ignored. An exact match wins; otherwise
// a single name containing the text is a unique match.
std::wstring normalizeVpnChoiceText(const std::wstring& text);
VpnNameMatch matchVpnChoiceName(const std::vector<std::wstring>& names, const std::wstring& entered);

struct ActiveVpnConnectionInfo {
    std::wstring name;
    std::wstring phonebookPath;
};

class VpnManager {
public:
    static bool profileExists(const VpnProfile& profile);
    static bool hasStoredCredentials(const VpnProfile& profile);
    static void saveCredentials(
        const VpnProfile& profile,
        const std::wstring& userName,
        const std::wstring& password);
    static bool isConnected(const VpnProfile& profile);
    static std::vector<WindowsVpnProfileInfo> installedProfiles();
    static std::vector<WindowsVpnProfileInfo> installedProfiles(
        const std::wstring& currentUserPhonebookPath,
        const std::wstring& allUsersPhonebookPath);
    static std::vector<ActiveVpnConnectionInfo> activeConnections();
    static void disconnectAll(const VpnProgressCallback& progress = {});
    static void disconnect(
        const VpnProfile& profile,
        const VpnProgressCallback& progress = {});
    static size_t localPhysicalRouteCount();
    static VpnVerificationResult connectAndVerify(
        const VpnProfile& profile,
        const VpnProgressCallback& progress = {});
    static VpnVerificationResult verifyConnected(
        const VpnProfile& profile,
        const VpnProgressCallback& progress = {});
    static VpnVerificationResult verifyDirect(
        const VpnProfile& profile,
        const VpnProgressCallback& progress = {});
    static std::wstring currentPublicIp(
        const std::wstring& url = L"https://api.ipify.org");
    static bool isValidPublicIp(const std::wstring& value);
    static std::wstring allUsersPhonebook();

#ifdef DISKCONTROL_TESTING
    static void setNetworkOperationsStubbedForTests(bool enabled);
#endif

private:
    static std::wstring queryPublicIp(const std::wstring& url);
};
