#pragma once

#include <string>
#include <vector>

// Builds token usage sessions from DistControl audit logs (audit-YYYYMMDD.csv)
// and renders them as a self-contained HTML report.

struct AuditRecord {
    long long time = 0;          // local time, seconds (see parseAuditTime)
    std::wstring timestamp;
    std::wstring user;
    std::wstring computer;       // empty in local audit logs
    std::wstring action;
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring result;
    std::wstring details;
};

enum class SessionEnd {
    Manual,       // STOP USING OWN without an automatic reason
    Timer,        // released after the 20-minute question
    VpnCheck,     // released because the VPN check failed
    WindowClosed, // released when DistControl was closed
    SignOut,      // released on Windows sign-out or shutdown
    VpnSwitch,    // released to connect a token with another VPN
    Open          // no release recorded
};

struct UsageSession {
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring user;
    std::wstring computer;
    long long start = 0;
    long long end = 0;           // 0 while open
    SessionEnd endReason = SessionEnd::Open;
    unsigned int extensions = 0; // "continue" answers to the timer question
};

struct UsageReportSource {
    std::wstring computer;
    std::wstring user;
    std::wstring folder;
    size_t files = 0;
    size_t records = 0;
};

struct UsageReportInput {
    std::vector<UsageReportSource> sources;
    std::vector<UsageSession> sessions;
    long long periodStart = 0;
    long long periodEnd = 0;
    long long generatedAt = 0;
    std::wstring periodTitle;
    std::wstring sourceNote;     // shown prominently, e.g. when the shared folder is unavailable
};

// "YYYY-MM-DD HH:MM:SS" -> seconds since 1970-01-01 in the same local time;
// returns false for anything else.
bool parseAuditTime(const std::wstring& text, long long& seconds);
std::wstring formatAuditTime(long long seconds);
// "1 ч 05 мин", "12 мин", "менее 1 мин"
std::wstring formatUsageDuration(long long seconds);

// Parses one audit CSV file (UTF-8, optional BOM, header line, quoted fields).
std::vector<AuditRecord> parseAuditCsv(const std::string& utf8);

// Pairs USE with the following release of the same token by the same user on
// the same computer; records without a computer use the given one.
// Sessions that do not overlap [periodStart, periodEnd) are dropped.
std::vector<UsageSession> buildUsageSessions(std::vector<AuditRecord> records,
    const std::wstring& computer, long long periodStart, long long periodEnd);

// Seconds of the session inside the period; open sessions count as 0.
long long sessionSecondsInPeriod(const UsageSession& session, long long periodStart, long long periodEnd);

std::wstring sessionEndText(SessionEnd reason);
std::wstring escapeHtml(const std::wstring& text);
std::string renderUsageReportHtml(const UsageReportInput& input);
