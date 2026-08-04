#pragma once

#include "DeviceAccessService.h"

#include <string>

struct AuditEvent {
    std::wstring action;
    std::wstring endpoint;
    std::wstring nickname;
    std::wstring product;
    std::wstring result;
    std::wstring details;
};

class AuditLogger {
public:
    static void log(const AuditEvent& event);
    static void logDeviceAction(
        const std::wstring& action,
        const DeviceViewModel& device,
        const std::wstring& result,
        const std::wstring& details);

    static std::string csvEscapeForTest(const std::wstring& value);

private:
    static std::wstring defaultLogDirectory();
    static std::wstring fallbackLogDirectory();
    static bool tryWrite(const std::wstring& directory, const AuditEvent& event);
};
