#pragma once

#include "UsageStateStore.h"

#include <functional>

class UsageStateSync {
public:
    using OwnershipValidator = std::function<bool(const UsageStateRecord&)>;

    explicit UsageStateSync(std::wstring sharedPath, std::wstring localPath = {});

    UsageStateRecord markUsed(const ParsedDevice& device, const std::wstring& userName,
        const std::wstring& publicIp = {}, const std::wstring& vpnProfileId = {},
        const std::wstring& vpnProfileName = {}, const std::wstring& operationId = {},
        bool resetTimer = false) const;
    void markReleased(const ParsedDevice& device, const std::wstring& userName,
        const std::wstring& operationId = {}) const;
    std::vector<UsageStateRecord> snapshot() const;
    size_t pendingCount() const;
    const std::wstring& localPath() const;

    void requestBackgroundSync(const std::wstring& pipeName) const;
    bool synchronize(const OwnershipValidator& isOwned) const;
    static int runBackgroundSync(const std::wstring& sharedPath,
        const std::wstring& localPath, const std::wstring& pipeName);

private:
    std::wstring sharedPath_;
    std::wstring localPath_;
};
