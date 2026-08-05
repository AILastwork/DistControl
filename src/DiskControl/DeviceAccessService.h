#pragma once

#include "PolicyManager.h"

#include <functional>
#include <string>
#include <vector>

using DeviceListProgressCallback = std::function<void(size_t processed, size_t total)>;

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
    std::vector<DeviceViewModel> listVisibleDevices(const DeviceListProgressCallback& progress = {}) const;
    std::vector<DeviceViewModel> listAllDevices(const DeviceListProgressCallback& progress = {}) const;
    std::vector<DeviceViewModel> listAllDevicesForUser(
        const std::wstring& userName,
        const DeviceListProgressCallback& progress = {}) const;
    std::wstring useDevice(
        const DeviceViewModel& device,
        const std::wstring& operationId = {}) const;
    std::wstring stopUsingDevice(const DeviceViewModel& device) const;
    std::wstring stopUsingOwnedDevice(
        const DeviceViewModel& device,
        const std::wstring& operationId = {}) const;
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
    void installOrUpdateWindowsVpnProfile(
        const VpnProfile& profile,
        const std::wstring& preSharedKey) const;
    void removeVpnProfile(const std::wstring& profileId) const;
    void updateAccessForUser(std::vector<DeviceViewModel>& devices, const std::wstring& userName) const;
    std::wstring currentUserSummary() const;
    std::wstring currentPolicyPath() const;

private:
    std::vector<DeviceViewModel> listDevices(
        bool includeDenied,
        const std::wstring& policyUser,
        const DeviceListProgressCallback& progress) const;
    DeviceViewModel enrichAndVerify(const DeviceViewModel& device) const;
};
