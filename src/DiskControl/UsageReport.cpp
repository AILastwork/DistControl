#include "UsageReport.h"

#include <windows.h>

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace {
std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size);
    return result;
}

std::string wideToUtf8(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
        nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
        result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring lower(std::wstring text) {
    if (!text.empty()) {
        CharLowerBuffW(text.data(), static_cast<DWORD>(text.size()));
    }
    return text;
}

long long daysFromCivil(long long year, unsigned month, unsigned day) {
    year -= month <= 2 ? 1 : 0;
    const long long era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(year - era * 400);
    const unsigned doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<long long>(doe) - 719468;
}

SessionEnd reasonFromMarker(const std::wstring& result) {
    if (result == L"TIMER") {
        return SessionEnd::Timer;
    }
    if (result == L"VPN CHECK") {
        return SessionEnd::VpnCheck;
    }
    if (result == L"CLOSE") {
        return SessionEnd::WindowClosed;
    }
    if (result == L"SIGNOUT") {
        return SessionEnd::SignOut;
    }
    return SessionEnd::Manual;
}

std::wstring number(long long value) {
    return std::to_wstring(value);
}
}

bool parseAuditTime(const std::wstring& text, long long& seconds) {
    if (text.size() != 19 || text[4] != L'-' || text[7] != L'-' || text[10] != L' ' ||
        text[13] != L':' || text[16] != L':') {
        return false;
    }
    const auto field = [&text](size_t offset, size_t length, int& value) {
        value = 0;
        for (size_t index = offset; index < offset + length; ++index) {
            if (text[index] < L'0' || text[index] > L'9') {
                return false;
            }
            value = value * 10 + (text[index] - L'0');
        }
        return true;
    };
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (!field(0, 4, year) || !field(5, 2, month) || !field(8, 2, day) ||
        !field(11, 2, hour) || !field(14, 2, minute) || !field(17, 2, second) ||
        month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
        return false;
    }
    seconds = daysFromCivil(year, static_cast<unsigned>(month), static_cast<unsigned>(day)) * 86400LL +
        hour * 3600LL + minute * 60LL + second;
    return true;
}

std::wstring formatAuditTime(long long seconds) {
    long long days = seconds / 86400;
    long long rest = seconds % 86400;
    if (rest < 0) {
        rest += 86400;
        --days;
    }
    // civil_from_days
    days += 719468;
    const long long era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(days - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long long year = static_cast<long long>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned day = doy - (153 * mp + 2) / 5 + 1;
    const unsigned month = mp < 10 ? mp + 3 : mp - 9;
    year += month <= 2 ? 1 : 0;
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"%02u.%02u.%04lld %02lld:%02lld", day, month, year, rest / 3600, (rest % 3600) / 60);
    return buffer;
}

std::wstring formatUsageDuration(long long seconds) {
    if (seconds < 60) {
        return L"менее 1 мин";
    }
    const long long minutes = seconds / 60;
    const long long hours = minutes / 60;
    if (hours == 0) {
        return number(minutes) + L" мин";
    }
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"%lld ч %02lld мин", hours, minutes % 60);
    return buffer;
}

std::vector<AuditRecord> parseAuditCsv(const std::string& utf8) {
    std::wstring text = utf8ToWide(utf8);
    if (!text.empty() && text.front() == 0xFEFF) {
        text.erase(0, 1);
    }

    std::vector<std::vector<std::wstring>> rows;
    std::vector<std::wstring> row;
    std::wstring field;
    bool quoted = false;
    bool fieldStarted = false;
    for (size_t index = 0; index < text.size(); ++index) {
        const wchar_t ch = text[index];
        if (quoted) {
            if (ch == L'"') {
                if (index + 1 < text.size() && text[index + 1] == L'"') {
                    field.push_back(L'"');
                    ++index;
                }
                else {
                    quoted = false;
                }
            }
            else {
                field.push_back(ch);
            }
            continue;
        }
        if (ch == L'"' && !fieldStarted) {
            quoted = true;
            fieldStarted = true;
        }
        else if (ch == L',') {
            row.push_back(field);
            field.clear();
            fieldStarted = false;
        }
        else if (ch == L'\n' || ch == L'\r') {
            if (ch == L'\r' && index + 1 < text.size() && text[index + 1] == L'\n') {
                ++index;
            }
            row.push_back(field);
            field.clear();
            fieldStarted = false;
            rows.push_back(std::move(row));
            row.clear();
        }
        else {
            field.push_back(ch);
            fieldStarted = true;
        }
    }
    if (fieldStarted || !row.empty()) {
        row.push_back(field);
        rows.push_back(std::move(row));
    }

    std::vector<AuditRecord> records;
    if (rows.empty()) {
        return records;
    }
    std::map<std::wstring, size_t> columns;
    for (size_t index = 0; index < rows.front().size(); ++index) {
        columns[lower(rows.front()[index])] = index;
    }
    const auto column = [&columns](const std::vector<std::wstring>& values, const wchar_t* name) -> std::wstring {
        const auto found = columns.find(name);
        return found != columns.end() && found->second < values.size() ? values[found->second] : std::wstring{};
    };
    for (size_t index = 1; index < rows.size(); ++index) {
        const std::vector<std::wstring>& values = rows[index];
        AuditRecord record;
        record.timestamp = column(values, L"timestamp");
        if (!parseAuditTime(record.timestamp, record.time)) {
            continue;
        }
        record.user = column(values, L"user");
        record.computer = column(values, L"computer");
        record.action = column(values, L"action");
        record.endpoint = column(values, L"endpoint");
        record.nickname = column(values, L"nickname");
        record.result = column(values, L"result");
        record.details = column(values, L"details");
        records.push_back(std::move(record));
    }
    return records;
}

std::vector<UsageSession> buildUsageSessions(std::vector<AuditRecord> records,
    const std::wstring& computer, long long periodStart, long long periodEnd) {
    std::stable_sort(records.begin(), records.end(),
        [](const AuditRecord& left, const AuditRecord& right) { return left.time < right.time; });

    std::vector<UsageSession> sessions;
    std::map<std::wstring, size_t> open;
    std::map<std::wstring, std::pair<SessionEnd, long long>> reasons;
    for (const AuditRecord& record : records) {
        if (record.endpoint.empty()) {
            continue;
        }
        const std::wstring recordComputer = record.computer.empty() ? computer : record.computer;
        const std::wstring key = lower(record.endpoint) + L"|" + lower(record.user) + L"|" + lower(recordComputer);
        const auto current = open.find(key);
        if (record.action == L"STOP REASON") {
            reasons[key] = { reasonFromMarker(record.result), record.time };
        }
        else if (record.action == L"USE" && record.result == L"OK") {
            // A repeated USE while the session is open does not start a new one.
            if (current == open.end()) {
                UsageSession session;
                session.endpoint = record.endpoint;
                session.nickname = record.nickname;
                session.user = record.user;
                session.computer = recordComputer;
                session.start = record.time;
                open[key] = sessions.size();
                sessions.push_back(std::move(session));
                reasons.erase(key);
            }
        }
        else if (record.action == L"USAGE TIMER" && record.result == L"OK") {
            if (current != open.end()) {
                ++sessions[current->second].extensions;
            }
        }
        else if (record.result == L"OK" &&
            (record.action == L"STOP USING OWN" || record.action == L"AUTO STOP BEFORE VPN SWITCH")) {
            // A release without a recorded start began before the available log.
            if (current == open.end()) {
                continue;
            }
            UsageSession& session = sessions[current->second];
            session.end = record.time;
            session.endReason = SessionEnd::Manual;
            if (record.action == L"AUTO STOP BEFORE VPN SWITCH") {
                session.endReason = SessionEnd::VpnSwitch;
            }
            else {
                const auto reason = reasons.find(key);
                if (reason != reasons.end() && reason->second.second >= session.start) {
                    session.endReason = reason->second.first;
                }
            }
            if (session.nickname.empty()) {
                session.nickname = record.nickname;
            }
            open.erase(current);
            reasons.erase(key);
        }
    }

    std::vector<UsageSession> inPeriod;
    for (UsageSession& session : sessions) {
        const bool startsBeforeEnd = session.start < periodEnd;
        const bool endsAfterStart = session.end == 0 || session.end > periodStart;
        if (startsBeforeEnd && endsAfterStart) {
            inPeriod.push_back(std::move(session));
        }
    }
    return inPeriod;
}

long long sessionSecondsInPeriod(const UsageSession& session, long long periodStart, long long periodEnd) {
    if (session.end == 0) {
        return 0;
    }
    const long long start = (std::max)(session.start, periodStart);
    const long long end = (std::min)(session.end, periodEnd);
    return end > start ? end - start : 0;
}

std::wstring sessionEndText(SessionEnd reason) {
    switch (reason) {
    case SessionEnd::Manual: return L"вручную";
    case SessionEnd::Timer: return L"по таймеру";
    case SessionEnd::VpnCheck: return L"сбой проверки VPN";
    case SessionEnd::WindowClosed: return L"закрытие программы";
    case SessionEnd::SignOut: return L"выход из Windows";
    case SessionEnd::VpnSwitch: return L"смена VPN";
    default: return L"нет записи об отключении";
    }
}

std::wstring escapeHtml(const std::wstring& text) {
    std::wstring result;
    result.reserve(text.size());
    for (wchar_t ch : text) {
        switch (ch) {
        case L'&': result += L"&amp;"; break;
        case L'<': result += L"&lt;"; break;
        case L'>': result += L"&gt;"; break;
        case L'"': result += L"&quot;"; break;
        case L'\'': result += L"&#39;"; break;
        default:
            if (ch < 0x20 && ch != L'\t') {
                result.push_back(L' ');
            }
            else {
                result.push_back(ch);
            }
        }
    }
    return result;
}

namespace {
// JSON string for embedding in <script type="application/json">: '<', '>' and
// '&' are escaped too, so data can never close the script element.
std::wstring jsonString(const std::wstring& text) {
    std::wstring result = L"\"";
    for (wchar_t ch : text) {
        switch (ch) {
        case L'"': result += L"\\\""; break;
        case L'\\': result += L"\\\\"; break;
        case L'<': result += L"\\u003c"; break;
        case L'>': result += L"\\u003e"; break;
        case L'&': result += L"\\u0026"; break;
        case L' ': result += L"\\u2028"; break;
        case L' ': result += L"\\u2029"; break;
        default:
            if (ch < 0x20) {
                wchar_t buffer[8]{};
                swprintf_s(buffer, L"\\u%04x", static_cast<unsigned int>(ch));
                result += buffer;
            }
            else {
                result.push_back(ch);
            }
        }
    }
    return result + L"\"";
}
}

std::string renderUsageReportHtml(const UsageReportInput& input) {
    std::wostringstream data;
    data << L"{\"periodStart\":" << input.periodStart << L",\"periodEnd\":" << input.periodEnd << L",\"sessions\":[";
    bool first = true;
    for (const UsageSession& session : input.sessions) {
        data << (first ? L"" : L",") << L"{\"t\":" << jsonString(session.nickname.empty() ? session.endpoint : session.nickname)
            << L",\"a\":" << jsonString(session.endpoint) << L",\"u\":" << jsonString(session.user)
            << L",\"c\":" << jsonString(session.computer) << L",\"s\":" << session.start << L",\"e\":" << session.end
            << L",\"r\":" << jsonString(sessionEndText(session.endReason)) << L",\"x\":" << session.extensions << L"}";
        first = false;
    }
    data << L"]}";

    std::wostringstream html;
    html << LR"HTML(<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DistControl — отчёт по использованию токенов</title>
<style>
:root { --bg:#f6f7f9; --card:#ffffff; --text:#1f2328; --muted:#5d6670; --line:#e3e6ea; --accent:#2563eb; --accent-soft:#dbe7ff; --warn:#b45309; --warn-bg:#fff4e5; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16181c; --card:#1f2228; --text:#e7e9ec; --muted:#9aa3ad; --line:#30343b; --accent:#6ea0ff; --accent-soft:#233458; --warn:#f0a35c; --warn-bg:#3a2a16; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI", system-ui, sans-serif; }
main { max-width:1180px; margin:0 auto; padding:28px 20px 48px; }
h1 { font-size:24px; font-weight:600; margin:0 0 4px; }
h2 { font-size:17px; font-weight:600; margin:32px 0 10px; }
.muted { color:var(--muted); }
.note { margin-top:12px; padding:10px 14px; border-radius:8px; background:var(--warn-bg); color:var(--warn); font-weight:600; }
.sources { margin:10px 0 0; padding:0; list-style:none; color:var(--muted); font-size:13px; }
.toolbar { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:20px; }
.toolbar label { color:var(--muted); font-size:13px; }
select, input[type=search] { padding:7px 10px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--text); font:inherit; }
input[type=search] { flex:1; min-width:220px; max-width:420px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-top:18px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
.tile .value { font-size:24px; font-weight:600; }
.tile .label { color:var(--muted); font-size:13px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:6px 0; overflow-x:auto; }
.bars { padding:12px 16px; }
.bar { display:grid; grid-template-columns:minmax(120px, 260px) 1fr 90px; gap:10px; align-items:center; margin:6px 0; }
.bar .name { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.bar .track { background:var(--accent-soft); border-radius:4px; height:12px; }
.bar .fill { background:var(--accent); border-radius:4px; height:12px; }
.bar .time { text-align:right; color:var(--muted); font-variant-numeric:tabular-nums; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:8px 14px; border-bottom:1px solid var(--line); white-space:nowrap; }
th { font-weight:600; color:var(--muted); font-size:13px; cursor:pointer; user-select:none; }
th:hover { color:var(--text); }
th.asc::after { content:" \25B2"; } th.desc::after { content:" \25BC"; }
td.num { text-align:right; font-variant-numeric:tabular-nums; }
tr:last-child td { border-bottom:none; }
.open { color:var(--warn); }
.empty { padding:18px 16px; color:var(--muted); }
footer { margin-top:28px; color:var(--muted); font-size:12px; }
</style>
</head>
<body>
<main>
<h1>Отчёт по использованию токенов</h1>
)HTML";
    html << L"<div class=\"muted\">" << escapeHtml(input.periodTitle) << L": " << escapeHtml(formatAuditTime(input.periodStart))
        << L" — " << escapeHtml(formatAuditTime(input.periodEnd)) << L" · сформирован "
        << escapeHtml(formatAuditTime(input.generatedAt)) << L"</div>\n";
    if (!input.sourceNote.empty()) {
        html << L"<div class=\"note\">" << escapeHtml(input.sourceNote) << L"</div>\n";
    }
    html << L"<ul class=\"sources\">";
    for (const UsageReportSource& source : input.sources) {
        html << L"<li>" << escapeHtml(source.computer.empty() ? L"—" : source.computer) << L" · "
            << escapeHtml(source.user.empty() ? L"—" : source.user) << L" — файлов: " << source.files
            << L", записей: " << source.records << L"</li>";
    }
    html << L"</ul>\n";
    html << LR"HTML(<div class="toolbar">
<label>Компьютер <select id="fComputer"><option value="">все</option></select></label>
<label>Пользователь <select id="fUser"><option value="">все</option></select></label>
<input type="search" id="fText" placeholder="Поиск по токену, пользователю, компьютеру…" autocomplete="off">
</div>
<section class="tiles" id="tiles"></section>
<h2>Топ-15 токенов по времени</h2><div class="card bars" id="bars"></div>
<h2>По токенам</h2><div class="card"><table id="tTokens"><thead><tr>
<th data-k="name">Токен</th><th data-k="addr">Адрес</th><th data-k="sec" data-num="1">Время</th><th data-k="count" data-num="1">Сессий</th><th data-k="top">Чаще всего</th><th data-k="last" data-num="1">Последнее использование</th>
</tr></thead><tbody></tbody></table></div>
<h2>По пользователям</h2><div class="card"><table id="tUsers"><thead><tr>
<th data-k="name">Пользователь</th><th data-k="sec" data-num="1">Время</th><th data-k="count" data-num="1">Сессий</th><th data-k="tokens" data-num="1">Токенов</th><th data-k="last" data-num="1">Последнее использование</th>
</tr></thead><tbody></tbody></table></div>
<h2>Сессии</h2><div class="card"><table id="tSessions"><thead><tr>
<th data-k="t">Токен</th><th data-k="u">Пользователь</th><th data-k="c">Компьютер</th><th data-k="s" data-num="1">Начало</th><th data-k="e" data-num="1">Конец</th><th data-k="sec" data-num="1">Длительность</th><th data-k="r">Как завершилась</th>
</tr></thead><tbody></tbody></table></div>
<footer>Время сессий, начавшихся или закончившихся за границами периода, учтено только внутри периода.
Сессии без записи об отключении (например, после сбоя программы) показаны, но в суммарное время не входят.
Сформировано DistControl Admin.</footer>
</main>
<script type="application/json" id="report-data">)HTML";
    html << data.str();
    html << LR"HTML(</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById('report-data').textContent);
  var ps = data.periodStart, pe = data.periodEnd;
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmtTime(sec) { var d = new Date(sec * 1000); return pad(d.getUTCDate()) + '.' + pad(d.getUTCMonth() + 1) + '.' + d.getUTCFullYear() + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()); }
  function fmtDur(sec) { if (sec < 60) return 'менее 1 мин'; var m = Math.floor(sec / 60), h = Math.floor(m / 60); return h ? h + ' ч ' + pad(m % 60) + ' мин' : m + ' мин'; }
  function inPeriod(s) { if (!s.e) return 0; var a = Math.max(s.s, ps), b = Math.min(s.e, pe); return b > a ? b - a : 0; }
  function el(tag, text, cls) { var n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
  function fill(select, values) { values.sort(function (a, b) { return a.localeCompare(b, 'ru'); }).forEach(function (v) { var o = el('option', v); o.value = v; select.appendChild(o); }); }
  var fComputer = document.getElementById('fComputer'), fUser = document.getElementById('fUser'), fText = document.getElementById('fText');
  fill(fComputer, Object.keys(data.sessions.reduce(function (m, s) { m[s.c] = 1; return m; }, {})));
  fill(fUser, Object.keys(data.sessions.reduce(function (m, s) { m[s.u] = 1; return m; }, {})));
  var sortState = {};
  function sorted(id, rows) {
    var st = sortState[id]; if (!st) return rows;
    return rows.slice().sort(function (a, b) { var x = a[st.k], y = b[st.k]; var r = st.num ? x - y : String(x).localeCompare(String(y), 'ru'); return st.asc ? r : -r; });
  }
  function fillTable(id, rows, cells, columns) {
    var body = document.querySelector('#' + id + ' tbody'); body.textContent = '';
    sorted(id, rows).forEach(function (row) { var tr = el('tr'); cells(row).forEach(function (c) { tr.appendChild(c); }); body.appendChild(tr); });
    if (!rows.length) { var tr = el('tr'), td = el('td', 'Нет данных за выбранный период.', 'empty'); td.colSpan = columns; tr.appendChild(td); body.appendChild(tr); }
  }
  function render() {
    var c = fComputer.value, u = fUser.value, q = fText.value.trim().toLowerCase();
    var list = data.sessions.filter(function (s) {
      return (!c || s.c === c) && (!u || s.u === u) && (!q || (s.t + ' ' + s.a + ' ' + s.u + ' ' + s.c).toLowerCase().indexOf(q) >= 0);
    });
    var total = 0, open = 0, tokens = {}, users = {};
    list.forEach(function (s) {
      var sec = inPeriod(s), last = s.e || s.s; total += sec; if (!s.e) open++;
      var t = tokens[s.a] || (tokens[s.a] = { name: s.t, addr: s.a, sec: 0, count: 0, last: 0, by: {} });
      t.sec += sec; t.count++; t.last = Math.max(t.last, last); t.by[s.u] = (t.by[s.u] || 0) + sec;
      var p = users[s.u] || (users[s.u] = { name: s.u, sec: 0, count: 0, last: 0, set: {} });
      p.sec += sec; p.count++; p.last = Math.max(p.last, last); p.set[s.a] = 1;
    });
    var tokenRows = Object.keys(tokens).map(function (k) { var t = tokens[k]; t.top = Object.keys(t.by).sort(function (a, b) { return t.by[b] - t.by[a]; })[0] || ''; return t; });
    var userRows = Object.keys(users).map(function (k) { var p = users[k]; p.tokens = Object.keys(p.set).length; return p; });
    tokenRows.sort(function (a, b) { return b.sec - a.sec; }); userRows.sort(function (a, b) { return b.sec - a.sec; });

    var tiles = document.getElementById('tiles'); tiles.textContent = '';
    [[String(list.length), 'сессий' + (open ? ', без записи об отключении: ' + open : '')], [fmtDur(total), 'суммарное время'],
     [String(userRows.length), 'пользователей'], [String(tokenRows.length), 'токенов']].forEach(function (x) {
      var d = el('div', undefined, 'tile'); d.appendChild(el('div', x[0], 'value')); d.appendChild(el('div', x[1], 'label')); tiles.appendChild(d);
    });

    var bars = document.getElementById('bars'); bars.textContent = '';
    var max = tokenRows.length ? tokenRows[0].sec : 0;
    tokenRows.slice(0, 15).forEach(function (t) {
      var row = el('div', undefined, 'bar'), name = el('div', t.name, 'name'); name.title = t.addr;
      var track = el('div', undefined, 'track'), fillBar = el('div', undefined, 'fill');
      fillBar.style.width = (max ? Math.max(1, Math.round(t.sec * 100 / max)) : 0) + '%'; track.appendChild(fillBar);
      row.appendChild(name); row.appendChild(track); row.appendChild(el('div', fmtDur(t.sec), 'time')); bars.appendChild(row);
    });
    if (!tokenRows.length) bars.appendChild(el('div', 'За выбранный период подключений не найдено.', 'empty'));

    fillTable('tTokens', tokenRows, function (t) { return [el('td', t.name), el('td', t.addr, 'muted'), el('td', fmtDur(t.sec), 'num'), el('td', String(t.count), 'num'), el('td', t.top), el('td', fmtTime(t.last), 'num')]; }, 6);
    fillTable('tUsers', userRows, function (p) { return [el('td', p.name), el('td', fmtDur(p.sec), 'num'), el('td', String(p.count), 'num'), el('td', String(p.tokens), 'num'), el('td', fmtTime(p.last), 'num')]; }, 5);
    var sessionRows = list.map(function (s) { return { t: s.t, u: s.u, c: s.c, s: s.s, e: s.e, sec: inPeriod(s), r: s.r + (s.x ? ', продлений: ' + s.x : ''), open: !s.e }; });
    if (!sortState.tSessions) sessionRows.sort(function (a, b) { return b.s - a.s; });
    fillTable('tSessions', sessionRows, function (s) {
      return [el('td', s.t), el('td', s.u), el('td', s.c), el('td', fmtTime(s.s), 'num'), el('td', s.open ? '—' : fmtTime(s.e), 'num'),
        el('td', s.open ? '—' : fmtDur(s.sec), 'num'), el('td', s.r, s.open ? 'open' : '')];
    }, 7);
  }
  document.querySelectorAll('table').forEach(function (table) {
    var heads = table.tHead.rows[0].cells;
    Array.prototype.forEach.call(heads, function (th) {
      th.addEventListener('click', function () {
        var st = sortState[table.id], k = th.getAttribute('data-k');
        var asc = !(st && st.k === k && st.asc);
        sortState[table.id] = { k: k, num: th.getAttribute('data-num') === '1', asc: asc };
        Array.prototype.forEach.call(heads, function (h) { h.classList.remove('asc', 'desc'); });
        th.classList.add(asc ? 'asc' : 'desc');
        render();
      });
    });
  });
  [fComputer, fUser].forEach(function (s) { s.addEventListener('change', render); });
  fText.addEventListener('input', render);
  render();
})();
</script>
</body>
</html>
)HTML";
    return wideToUtf8(html.str());
}
