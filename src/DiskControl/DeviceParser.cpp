#include "DeviceParser.h"

#include <cwctype>
#include <regex>
#include <set>

namespace {
std::wstring trim(const std::wstring& text) {
    size_t first = 0;
    while (first < text.size() && std::iswspace(text[first])) {
        ++first;
    }

    size_t last = text.size();
    while (last > first && std::iswspace(text[last - 1])) {
        --last;
    }

    return text.substr(first, last - first);
}

std::wstring lowerCopy(std::wstring text) {
    for (wchar_t& ch : text) {
        if (ch >= L'A' && ch <= L'Z') {
            ch = static_cast<wchar_t>(ch - L'A' + L'a');
        }
        else if (ch >= L'А' && ch <= L'Я') {
            ch = static_cast<wchar_t>(ch - L'А' + L'а');
        }
        else if (ch == L'Ё') {
            ch = L'ё';
        }
        else {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }
    }
    return text;
}

std::wstring shortUserName(const std::wstring& userName) {
    const size_t slash = userName.find_last_of(L"\\/");
    if (slash == std::wstring::npos || slash + 1 >= userName.size()) {
        return userName;
    }
    return userName.substr(slash + 1);
}

bool hasAccountQualifier(const std::wstring& userName) {
    return userName.find_first_of(L"\\/") != std::wstring::npos;
}

bool equalsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return lowerCopy(left) == lowerCopy(right);
}

std::pair<std::wstring, std::wstring> splitUsageUserAndLocation(const std::wstring& raw) {
    std::wstring user = trim(raw);
    std::wstring location;
    const std::wstring lowered = lowerCopy(user);

    size_t delimiter = lowered.find(L" at ");
    size_t delimiterLength = 4;
    const size_t russianDelimiter = lowered.find(L" на ");
    if (russianDelimiter != std::wstring::npos &&
        (delimiter == std::wstring::npos || russianDelimiter < delimiter)) {
        delimiter = russianDelimiter;
        delimiterLength = 4;
    }

    if (delimiter != std::wstring::npos) {
        location = trim(user.substr(delimiter + delimiterLength));
        user = trim(user.substr(0, delimiter));
    }
    return { user, location };
}

std::wstring cleanUserText(const std::wstring& user) {
    std::wstring result = trim(user);
    const size_t open = result.rfind(L'(');
    if (open == std::wstring::npos || result.empty() || result.back() != L')') {
        return result;
    }

    const std::wstring prefix = trim(result.substr(0, open));
    const std::wstring inside = trim(result.substr(open + 1, result.size() - open - 2));
    if (inside.empty()) {
        return prefix;
    }

    if (equalsIgnoreCase(prefix, inside) || equalsIgnoreCase(shortUserName(prefix), inside)) {
        return prefix;
    }

    return result;
}

bool isSystemUserText(const std::wstring& user) {
    const std::wstring lowered = lowerCopy(cleanUserText(user));
    return lowered == L"system" ||
        lowered == L"nt authority\\system" ||
        lowered == L"система" ||
        lowered == L"локальная система";
}

bool isSystemUsage(const std::wstring& inUseBy) {
    const auto [user, location] = splitUsageUserAndLocation(inUseBy);
    (void)location;
    return isSystemUserText(user);
}

std::wstring readListUsage(const std::wstring& line) {
    const std::wregex inUsePattern(LR"(\(\s*In-use\s+by\s*:\s*(.*)\)\s*$)", std::regex_constants::icase);
    std::wsmatch match;
    if (std::regex_search(line, match, inUsePattern) && match.size() >= 2) {
        return trim(match[1].str());
    }
    return {};
}
}

std::vector<ParsedDevice> DeviceParser::parseList(const std::wstring& text) {
    std::vector<ParsedDevice> devices;
    std::set<std::wstring> seen;
    const std::wregex endpointPattern(LR"(\(([^()\s]+-Gr-\d+\.\d+)\))");

    size_t lineStart = 0;
    while (lineStart <= text.size()) {
        const size_t lineEnd = text.find_first_of(L"\r\n", lineStart);
        const std::wstring line = text.substr(lineStart,
            lineEnd == std::wstring::npos ? std::wstring::npos : lineEnd - lineStart);
        lineStart = lineEnd == std::wstring::npos ? text.size() + 1 : lineEnd + 1;

        std::wsmatch endpointMatch;
        if (!std::regex_search(line, endpointMatch, endpointPattern) || endpointMatch.size() < 2) {
            continue;
        }

        const std::wstring endpoint = endpointMatch[1].str();
        if (!seen.insert(endpoint).second) {
            continue;
        }

        ParsedDevice device;
        device.endpoint = endpoint;
        std::wstring nickname = trim(line.substr(0, static_cast<size_t>(endpointMatch.position())));
        bool removedMarker = true;
        while (removedMarker && !nickname.empty()) {
            removedMarker = false;
            if (nickname.rfind(L"-->", 0) == 0) {
                nickname = trim(nickname.substr(3));
                removedMarker = true;
            }
            if (!nickname.empty() && nickname.front() == L'*') {
                nickname = trim(nickname.substr(1));
                removedMarker = true;
            }
        }
        device.nickname = nickname;
        device.inUseBy = readListUsage(line);
        devices.push_back(device);
    }

    return devices;
}

void DeviceParser::applyDeviceInfo(ParsedDevice& device, const std::wstring& text) {
    const auto readField = [&text](const wchar_t* field) -> std::wstring {
        const std::wregex pattern(std::wstring(LR"((^|\n|\r)\s*)") + field + LR"(\s*:\s*([^\r\n]+))",
            std::regex_constants::icase);
        std::wsmatch match;
        if (std::regex_search(text, match, pattern) && match.size() >= 3) {
            return match[2].str();
        }
        return L"";
    };

    const std::wstring nickname = readField(L"NICKNAME");
    const std::wstring product = readField(L"PRODUCT");
    if (!nickname.empty()) {
        device.nickname = nickname;
    }
    if (!product.empty()) {
        device.product = product;
    }
    const std::wstring infoUsage = readField(L"IN USE BY");
    if (!infoUsage.empty()) {
        if (!device.inUseBy.empty() && isSystemUsage(infoUsage) && !isSystemUsage(device.inUseBy)) {
            return;
        }
        device.inUseBy = infoUsage;
    }
}

DeviceUsageInfo DeviceParser::parseUsage(const std::wstring& inUseBy, const std::wstring& currentUserName) {
    const std::wstring raw = trim(inUseBy);
    const std::wstring lowered = lowerCopy(raw);
    DeviceUsageInfo usage;

    if (raw.empty() || lowered == L"no one") {
        usage.statusText = L"Свободен";
        usage.userText = L"";
        usage.locationText = L"";
        usage.isFree = true;
        return usage;
    }

    if (lowered == L"you") {
        usage.statusText = L"Подключён вами";
        usage.userText = currentUserName;
        usage.locationText = L"";
        usage.isUsedByCurrentUser = true;
        return usage;
    }

    auto [user, location] = splitUsageUserAndLocation(raw);
    const bool systemUser = isSystemUserText(user);
    const std::wstring displayUser = systemUser ? L"" : cleanUserText(user);

    const std::wstring currentLower = lowerCopy(currentUserName);
    const std::wstring shortCurrentLower = lowerCopy(shortUserName(currentUserName));
    const std::wstring normalizedUser = displayUser.empty() ? user : displayUser;
    const std::wstring userLower = lowerCopy(normalizedUser);
    usage.isUsedByCurrentUser = !currentLower.empty() &&
        (userLower == currentLower ||
            ((!hasAccountQualifier(normalizedUser) || !hasAccountQualifier(currentUserName)) &&
                !shortCurrentLower.empty() &&
                equalsIgnoreCase(shortUserName(normalizedUser), shortCurrentLower)));

    usage.statusText = usage.isUsedByCurrentUser ? L"Подключён вами" : L"Занят";
    usage.userText = displayUser;
    usage.locationText = location;
    return usage;
}
