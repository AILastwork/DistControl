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
};

class UsageStateStore {
public:
    explicit UsageStateStore(std::wstring path);

    void markUsed(const ParsedDevice& device, const std::wstring& userName) const;
    void markReleased(const ParsedDevice& device) const;
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
