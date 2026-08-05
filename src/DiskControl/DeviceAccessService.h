#pragma once

#include "PolicyManager.h"

#include <string>
#include <vector>

struct DeviceViewModel {
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring product;
    std::wstring inUseBy;
    std::wstring statusText;
    std::wstring usedBy;
    std::wstring usedAt;
    std::wstring usageStartedAt;
    std::wstring vpnProfileId;
    bool allowed = false;
};

class DeviceAccessService {
public:
    std::vector<DeviceViewModel> listVisibleDevices() const;
    std::vector<DeviceViewModel> listAllDevices() const;
    std::vector<DeviceViewModel> listAllDevicesForUser(const std::wstring& userName) const;
    std::wstring useDevice(const DeviceViewModel& device) const;
    std::wstring stopUsingDevice(const DeviceViewModel& device) const;
    std::wstring stopUsingOwnedDevice(const DeviceViewModel& device) const;
    void refreshUsageTimer(const DeviceViewModel& device) const;
    std::wstring verifyVpnForDevice(const DeviceViewModel& device) const;
    std::wstring assignDeviceToCurrentUser(const DeviceViewModel& device) const;
    std::wstring assignDeviceToUser(const DeviceViewModel& device, const std::wstring& userName) const;
    std::wstring removeDeviceFromUser(const DeviceViewModel& device, const std::wstring& userName) const;
    std::wstring setDevicesForUser(const std::vector<DeviceViewModel>& devices, const std::wstring& userName) const;
    std::wstring setVpnProfileForDevice(
        const DeviceViewModel& device,
        const std::wstring& userName,
        const std::wstring& vpnProfileId) const;
    std::vector<VpnProfile> vpnProfiles() const;
    void upsertVpnProfile(const VpnProfile& profile) const;
    void removeVpnProfile(const std::wstring& profileId) const;
    void updateAccessForUser(std::vector<DeviceViewModel>& devices, const std::wstring& userName) const;
    std::wstring currentUserSummary() const;
    std::wstring currentPolicyPath() const;

private:
    std::vector<DeviceViewModel> listDevices(bool includeDenied, const std::wstring& policyUser) const;
    DeviceViewModel enrichAndVerify(const DeviceViewModel& device) const;
};
