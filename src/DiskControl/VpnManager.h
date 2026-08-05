#pragma once

#include "PolicyManager.h"

#include <cstddef>
#include <string>

struct VpnVerificationResult {
    std::wstring profileName;
    std::wstring publicIp;
    bool alreadyConnected = false;
    size_t preservedLocalRouteCount = 0;
};

class VpnManager {
public:
    static bool profileExists(const std::wstring& profileName);
    static bool hasStoredCredentials(const std::wstring& profileName);
    static void saveCredentials(
        const std::wstring& profileName,
        const std::wstring& userName,
        const std::wstring& password);
    static void installOrUpdateProfile(
        const VpnProfile& profile,
        const std::wstring& preSharedKey);
    static bool isConnected(const std::wstring& profileName);
    static size_t localPhysicalRouteCount();
    static VpnVerificationResult connectAndVerify(const VpnProfile& profile);
    static VpnVerificationResult verifyConnected(const VpnProfile& profile);

private:
    static std::wstring queryPublicIp(const std::wstring& url);
};
