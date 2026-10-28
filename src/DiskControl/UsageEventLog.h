#pragma once

#include <string>
#include <vector>

// Shared copy of token usage events for the summary usage report.
// DistControl appends USE / release / timer / release-reason events to a local
// queue; the hidden synchronization helper moves them to
// <usage folder>\usage-log\<computer>-<user>-YYYYMM.csv. Each computer and user
// writes only its own files, appending, so no file is shared between writers.

struct UsageLogEvent {
    std::wstring localTime;   // "YYYY-MM-DD HH:MM:SS"
    std::wstring utcTime;     // "YYYY-MM-DDTHH:MM:SSZ"
    std::wstring computer;
    std::wstring user;
    std::wstring sid;
    std::wstring action;
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring result;
};

namespace UsageEventLog {
constexpr unsigned int kRetentionDays = 30;

bool isUsageEvent(const std::wstring& action, const std::wstring& result);
UsageLogEvent makeEvent(const std::wstring& action, const std::wstring& endpoint,
    const std::wstring& nickname, const std::wstring& result);

std::wstring queuePath();
std::wstring sharedLogDirectory(const std::wstring& usageStatePath);
std::wstring fileNameFor(const std::wstring& computer, const std::wstring& user, const std::wstring& localTime);
std::string csvHeader();
std::string csvLine(const UsageLogEvent& event);

// Appends one event to the local queue.
void enqueue(const std::wstring& queueFile, const UsageLogEvent& event);
// Moves queued events into this computer's and user's files in logDirectory.
// Events whose file cannot be written stay queued. Own files not written for
// kRetentionDays are removed. Returns the number of moved events.
size_t flush(const std::wstring& queueFile, const std::wstring& logDirectory,
    const std::wstring& computer, const std::wstring& user);
size_t queuedCount(const std::wstring& queueFile);
}
