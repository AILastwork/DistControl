#pragma once

#include "PolicyManager.h"

#include <functional>
#include <string>
#include <vector>

using DeviceListProgressCallback = std::function<void(size_t processed, size_t total)>;
using TokenActionProgressCallback =
    std::function<void(size_t step, size_t total, const std::wstring& message)>;

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
    std::wstring vpnProfileDisplay;
    bool allowed = false;
};

class DeviceAccessService {
public:
    std::vector<DeviceViewModel> listVisibleDevices(const DeviceListProgressCallback& progress = {}) const;
    std::vector<DeviceViewModel> listAllDevices(const DeviceListProgressCallback& progress = {}) const;
    std::vector<DeviceViewModel> listAllDevicesForUser(
        const std::wstring& userName,
        const DeviceListProgressCallback& progress = {},
        std::wstring* policyRevision = nullptr) const;
    std::wstring useDevice(
        const DeviceViewModel& device,
        const std::wstring& operationId = {},
        const TokenActionProgressCallback& progress = {}) const;
    std::wstring stopUsingDevice(const DeviceViewModel& device) const;
    std::wstring stopUsingOwnedDevice(
        const DeviceViewModel& device,
        const std::wstring& operationId = {},
        const TokenActionProgressCallback& progress = {}) const;
    void refreshUsageTimer(const DeviceViewModel& device) const;
    std::wstring verifyVpnForDevice(const DeviceViewModel& device) const;
    std::wstring assignDeviceToCurrentUser(const DeviceViewModel& device) const;
    std::wstring assignDeviceToUser(const DeviceViewModel& device, const std::wstring& userName) const;
    std::wstring removeDeviceFromUser(const DeviceViewModel& device, const std::wstring& userName) const;
    std::wstring setDevicesForUser(const std::vector<DeviceViewModel>& devices, const std::wstring& userName) const;
    std::wstring applyDeviceAccessChanges(
        const std::vector<DeviceViewModel>& addedDevices,
        const std::vector<DeviceViewModel>& removedDevices,
        const std::wstring& userName,
        const std::wstring& expectedRevision) const;
    std::wstring setVpnProfileForDevice(
        const DeviceViewModel& device,
        const std::wstring& userName,
        const std::wstring& vpnProfileId) const;
    std::vector<VpnProfile> vpnProfiles() const;
    std::wstring saveVpnProfileForDevices(
        const VpnProfile& profile,
        const std::vector<DeviceViewModel>& devices,
        const std::wstring& userName,
        const std::wstring& expectedRevision) const;
    std::wstring clearVpnProfileForDevices(
        const std::vector<DeviceViewModel>& devices,
        const std::wstring& userName,
        const std::wstring& expectedRevision) const;
    void upsertVpnProfile(const VpnProfile& profile) const;
    void removeVpnProfile(const std::wstring& profileId) const;
    std::wstring removeVpnProfileChecked(
        const std::wstring& profileId,
        const std::wstring& expectedRevision) const;
    std::wstring updateAccessForUser(std::vector<DeviceViewModel>& devices, const std::wstring& userName) const;
    std::wstring currentUserSummary() const;
    std::wstring currentPolicyPath() const;

private:
    std::vector<DeviceViewModel> listDevices(
        bool includeDenied,
        const std::wstring& policyUser,
        const DeviceListProgressCallback& progress,
        std::wstring* policyRevision = nullptr) const;
    DeviceViewModel enrichAndVerify(const DeviceViewModel& device) const;
};
