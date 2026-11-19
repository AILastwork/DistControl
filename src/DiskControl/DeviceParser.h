#pragma once

#include <string>
#include <vector>

struct ParsedDevice {
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring product;
    std::wstring inUseBy;
    // Trimmed LIST line, including usage markers; empty when not read from LIST.
    std::wstring listLine;
    // DistKontrol server name without the device suffix.
    std::wstring serverName;
    // IPv4 address reported by dkclient for the USB server owning this endpoint.
    std::wstring serverAddress;
    // Per-device serial, never USB vendor/product IDs or the port address.
    std::wstring serial;
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
    static std::wstring parseServerAddress(const std::wstring& text);
    static void applyDeviceInfo(ParsedDevice& device, const std::wstring& text);
    static DeviceUsageInfo parseUsage(const std::wstring& inUseBy, const std::wstring& currentUserName);
};
