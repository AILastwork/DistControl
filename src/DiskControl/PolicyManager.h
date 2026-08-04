#pragma once

#include "DeviceParser.h"

#include <string>
#include <vector>

struct DeviceRule {
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring product;
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
    static bool isAllowedByRules(const ParsedDevice& device, const std::vector<DeviceRule>& rules);
    static void setConfigPathOverride(std::wstring configPath);
    static bool ensureEditableConfig(std::wstring configPath);
    static std::wstring currentUserName();
    static std::wstring currentUserSid();
    std::vector<DeviceRule> rulesForUser(const std::wstring& userName) const;
    const std::vector<DeviceRule>& effectiveRules() const;
    const std::wstring& pipeName() const;
    const std::wstring& usageStatePath() const;
    const std::wstring& configPath() const;

private:
    void load();

    std::wstring configPath_;
    std::wstring pipeName_ = L"dkclient";
    std::wstring usageStatePath_;
    std::vector<DeviceRule> effectiveRules_;
};
