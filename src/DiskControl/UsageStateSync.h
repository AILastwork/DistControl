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

    // Starts the hidden helper. With onlyIfDue the request is skipped unless
    // there are unsent changes or the periodic refresh interval has passed.
    void requestBackgroundSync(const std::wstring& pipeName, bool onlyIfDue = false) const;
    static bool isBackgroundSyncDue(size_t pendingChanges, unsigned long long nowMs,
        unsigned long long lastStartedMs);
    static constexpr unsigned long long kPendingRetryMs = 5000;
    static constexpr unsigned long long kPeriodicRefreshMs = 30000;
    bool synchronize(const OwnershipValidator& isOwned) const;
    static int runBackgroundSync(const std::wstring& sharedPath,
        const std::wstring& localPath, const std::wstring& pipeName);

private:
    std::wstring sharedPath_;
    std::wstring localPath_;
};
