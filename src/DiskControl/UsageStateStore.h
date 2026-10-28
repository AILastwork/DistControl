#pragma once

#include "DeviceParser.h"

#include <string>
#include <vector>

struct UsageStateRecord {
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring product;
    std::wstring user;
    std::wstring computer;
    std::wstring updatedAt;
    std::wstring publicIp;
    std::wstring vpnProfileId;
    std::wstring vpnProfileName;
    std::wstring operationId;
    std::wstring connectionId;
    unsigned long long eventFileTime = 0;
};

// Elapsed milliseconds of a usage period. The UTC event time is used when it
// is known; records from older versions only have local "updatedAt" text.
bool usageElapsedMs(const std::wstring& startedAtLocal, unsigned long long startedFileTime,
    unsigned long long nowFileTime, unsigned long long& elapsedMs);

class UsageStateStore {
public:
    explicit UsageStateStore(std::wstring path);

    void markUsed(const ParsedDevice& device, const std::wstring& userName) const;
    void markReleased(const ParsedDevice& device) const;
    void applyUsedRecord(const UsageStateRecord& record) const;
    void applyReleasedRecord(const UsageStateRecord& record) const;
    std::vector<UsageStateRecord> snapshot() const;
    bool applyRecordedUsage(ParsedDevice& device) const;
    bool applyRecordedUsage(ParsedDevice& device, const std::vector<UsageStateRecord>& records) const;
    bool tryGetRecord(const ParsedDevice& device, UsageStateRecord& record) const;
    bool tryGetRecord(const ParsedDevice& device, UsageStateRecord& record,
        const std::vector<UsageStateRecord>& records) const;

    const std::wstring& path() const;
    static std::wstring currentComputerName();

private:
    std::vector<UsageStateRecord> readRecords() const;
    void writeRecords(const std::vector<UsageStateRecord>& records) const;

    std::wstring path_;
};
