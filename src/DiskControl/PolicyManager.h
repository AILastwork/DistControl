#pragma once

#include "DeviceParser.h"

#include <string>
#include <vector>

struct DeviceRule {
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring product;
    std::wstring vpnProfileId;
};

struct VpnProfile {
    std::wstring id;
    std::wstring name;
    std::wstring serverAddress;
    std::wstring tunnelType = L"L2TP";
    std::vector<std::wstring> expectedPublicIps;
    std::wstring ipCheckUrl = L"https://api.ipify.org";
    bool fullTunnel = true;
    bool enabled = true;
};

class PolicyManager {
public:
    PolicyManager();
    explicit PolicyManager(std::wstring configPath);

    bool isAllowed(const ParsedDevice& device) const;
    bool isAllowedForUser(const ParsedDevice& device, const std::wstring& userName) const;
    void assignDeviceToCurrentUser(const ParsedDevice& device) const;
    void assignDeviceToUser(const ParsedDevice& device, const std::wstring& userName) const;
    void removeDeviceFromUser(const ParsedDevice& device, const std::wstring& userName) const;
    void setDevicesForUser(const std::vector<ParsedDevice>& devices, const std::wstring& userName) const;
    void setVpnProfileForDevice(
        const ParsedDevice& device,
        const std::wstring& userName,
        const std::wstring& vpnProfileId) const;
    void upsertVpnProfile(const VpnProfile& profile) const;
    void removeVpnProfile(const std::wstring& profileId) const;
    static bool isAllowedByRules(const ParsedDevice& device, const std::vector<DeviceRule>& rules);
    static void setConfigPathOverride(std::wstring configPath);
    static bool ensureEditableConfig(std::wstring configPath);
    static std::wstring currentUserName();
    static std::wstring currentUserSid();
    std::vector<DeviceRule> rulesForUser(const std::wstring& userName) const;
    bool tryGetVpnProfileForDevice(const ParsedDevice& device, VpnProfile& profile) const;
    const std::vector<DeviceRule>& effectiveRules() const;
    const std::vector<VpnProfile>& vpnProfiles() const;
    const std::wstring& pipeName() const;
    const std::wstring& usageStatePath() const;
    const std::wstring& configPath() const;

private:
    void load();

    std::wstring configPath_;
    std::wstring pipeName_ = L"dkclient";
    std::wstring usageStatePath_;
    std::vector<DeviceRule> effectiveRules_;
    std::vector<VpnProfile> vpnProfiles_;
};
