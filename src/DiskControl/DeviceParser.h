#pragma once

#include <string>
#include <vector>

struct ParsedDevice {
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring product;
    std::wstring inUseBy;
};

struct DeviceUsageInfo {
    std::wstring statusText;
    std::wstring userText;
    std::wstring locationText;
    bool isFree = false;
    bool isUsedByCurrentUser = false;
};

class DeviceParser {
public:
    static std::vector<ParsedDevice> parseList(const std::wstring& text);
    static void applyDeviceInfo(ParsedDevice& device, const std::wstring& text);
    static DeviceUsageInfo parseUsage(const std::wstring& inUseBy, const std::wstring& currentUserName);
};
