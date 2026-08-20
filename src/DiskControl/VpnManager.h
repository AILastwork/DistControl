#pragma once

#include "PolicyManager.h"

#include <cstddef>
#include <functional>
#include <string>

using VpnProgressCallback = std::function<void(const std::wstring& message)>;

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
    static void disconnect(
        const std::wstring& profileName,
        const VpnProgressCallback& progress = {});
    static size_t localPhysicalRouteCount();
    static VpnVerificationResult connectAndVerify(
        const VpnProfile& profile,
        const VpnProgressCallback& progress = {});
    static VpnVerificationResult verifyConnected(
        const VpnProfile& profile,
        const VpnProgressCallback& progress = {});

private:
    static std::wstring queryPublicIp(const std::wstring& url);
};
