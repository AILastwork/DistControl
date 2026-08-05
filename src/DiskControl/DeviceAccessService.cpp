#include "DeviceAccessService.h"

#include "AuditLogger.h"
#include "DeviceParser.h"
#include "IpcClient.h"
#include "PolicyManager.h"
#include "UsageStateStore.h"
#include "VpnManager.h"

#include <windows.h>

#include <stdexcept>
#include <utility>

namespace {
constexpr unsigned long kUseCommandTimeoutMs = 120UL * 1000UL;

std::wstring widenAscii(const char* text) {
    std::wstring result;
    while (*text) {
        result.push_back(static_cast<unsigned char>(*text++));
    }
    return result;
}

std::wstring trimResponse(const std::wstring& text) {
    const size_t first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) {
        return {};
    }
    const size_t last = text.find_last_not_of(L" \t\r\n");
    return text.substr(first, last - first + 1);
}

bool startsWithIgnoreCase(const std::wstring& value, const wchar_t* prefix) {
    const std::wstring prefixValue(prefix);
    if (value.size() < prefixValue.size()) {
        return false;
    }
    return CompareStringOrdinal(
        value.c_str(), static_cast<int>(prefixValue.size()),
        prefixValue.c_str(), static_cast<int>(prefixValue.size()),
        TRUE) == CSTR_EQUAL;
}

std::string narrowAsciiForError(const std::wstring& text) {
    std::string result;
    result.reserve(text.size());
    for (wchar_t ch : text) {
        result.push_back(ch >= 32 && ch <= 126 ? static_cast<char>(ch) : '?');
    }
    return result;
}

bool isCommandFailureResponse(const std::wstring& response) {
    const std::wstring trimmed = trimResponse(response);
    return !trimmed.empty() &&
        (startsWithIgnoreCase(trimmed, L"FAILED") || startsWithIgnoreCase(trimmed, L"ERROR"));
}

std::wstring responseDetails(const std::wstring& response) {
    const std::wstring trimmed = trimResponse(response);
    return trimmed.empty() ? L"Response: <empty>" : L"Response: " + trimmed;
}

std::wstring stateDetails(const DeviceViewModel& device) {
    std::wstring details = L"User=" + PolicyManager::currentUserName() +
        L"; state=" + device.statusText;
    if (!device.usedBy.empty()) {
        details += L"; usedBy=" + device.usedBy;
    }
    if (!device.usedAt.empty()) {
        details += L"; location=" + device.usedAt;
    }
    if (!device.inUseBy.empty()) {
        details += L"; rawInUseBy=" + device.inUseBy;
    }
    if (!device.vpnProfileId.empty()) {
        details += L"; vpnProfile=" + device.vpnProfileId;
    }
    return details;
}

void throwIfCommandFailed(const std::wstring& response, const char* action) {
    const std::wstring trimmed = trimResponse(response);
    if (!isCommandFailureResponse(response)) {
        return;
    }
    throw std::runtime_error(
        std::string("DistKontrol returned ") + narrowAsciiForError(trimmed) + " for " + action + ".");
}

DeviceViewModel toViewModel(const ParsedDevice& device, bool allowed, std::wstring usageStartedAt = {}) {
    const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
    return {
        device.endpoint,
        device.nickname,
        device.product,
        device.inUseBy,
        usage.statusText,
        usage.userText,
        usage.locationText,
        std::move(usageStartedAt),
        L"",
        allowed
    };
}

ParsedDevice toParsedDevice(const DeviceViewModel& device) {
    return {
        device.endpoint,
        device.nickname,
        device.product,
        device.inUseBy
    };
}

void logUsageStateWarning(const char* details) {
    AuditEvent event;
    event.action = L"USAGE STATE";
    event.result = L"WARNING";
    event.details = widenAscii(details);
    AuditLogger::log(event);
}

void markDeviceUsedBestEffort(const PolicyManager& policy, const DeviceViewModel& device) {
    try {
        UsageStateStore(policy.usageStatePath()).markUsed(toParsedDevice(device), PolicyManager::currentUserName());
    }
    catch (const std::exception& error) {
        logUsageStateWarning(error.what());
    }
}

void markDeviceReleasedBestEffort(const PolicyManager& policy, const DeviceViewModel& device) {
    try {
        UsageStateStore(policy.usageStatePath()).markReleased(toParsedDevice(device));
    }
    catch (const std::exception& error) {
        logUsageStateWarning(error.what());
    }
}

bool equalsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return CompareStringOrdinal(
        left.c_str(), static_cast<int>(left.size()),
        right.c_str(), static_cast<int>(right.size()),
        TRUE) == CSTR_EQUAL;
}

bool isPotentiallyAllowedByRules(const ParsedDevice& device, const std::vector<DeviceRule>& rules) {
    for (const DeviceRule& rule : rules) {
        if (!equalsIgnoreCase(rule.endpoint, device.endpoint)) {
            continue;
        }
        if (!rule.nickname.empty() && !device.nickname.empty() &&
            !equalsIgnoreCase(rule.nickname, device.nickname)) {
            continue;
        }
        if (!rule.product.empty() && !device.product.empty() &&
            !equalsIgnoreCase(rule.product, device.product)) {
            continue;
        }
        return true;
    }
    return false;
}

std::wstring vpnProfileIdForDevice(const ParsedDevice& device, const std::vector<DeviceRule>& rules) {
    for (const DeviceRule& rule : rules) {
        if (!equalsIgnoreCase(rule.endpoint, device.endpoint)) {
            continue;
        }
        if (!rule.nickname.empty() && !device.nickname.empty() &&
            !equalsIgnoreCase(rule.nickname, device.nickname)) {
            continue;
        }
        if (!rule.product.empty() && !device.product.empty() &&
            !equalsIgnoreCase(rule.product, device.product)) {
            continue;
        }
        return rule.vpnProfileId;
    }
    return {};
}
}

std::vector<DeviceViewModel> DeviceAccessService::listVisibleDevices() const {
    return listDevices(false, L"");
}

std::vector<DeviceViewModel> DeviceAccessService::listAllDevices() const {
    return listDevices(true, L"");
}

std::vector<DeviceViewModel> DeviceAccessService::listAllDevicesForUser(const std::wstring& userName) const {
    return listDevices(true, userName);
}

std::wstring DeviceAccessService::useDevice(const DeviceViewModel& device) const {
    try {
        AuditLogger::logDeviceAction(
            L"USE REQUEST",
            device,
            L"START",
            L"User requested token connection. " + stateDetails(device));
        const DeviceViewModel verified = enrichAndVerify(device);
        AuditLogger::logDeviceAction(
            L"USE VERIFY",
            verified,
            L"OK",
            L"Policy and device check passed. " + stateDetails(verified));
        PolicyManager policy;
        VpnProfile vpnProfile;
        if (policy.tryGetVpnProfileForDevice(toParsedDevice(verified), vpnProfile)) {
            AuditLogger::logDeviceAction(
                L"VPN VERIFY",
                verified,
                L"START",
                L"profileId=" + vpnProfile.id + L"; profileName=" + vpnProfile.name +
                    L"; server=" + vpnProfile.serverAddress);
            try {
                const VpnVerificationResult vpn = VpnManager::connectAndVerify(vpnProfile);
                AuditLogger::logDeviceAction(
                    L"VPN VERIFY",
                    verified,
                    L"OK",
                    L"profileId=" + vpnProfile.id + L"; profileName=" + vpn.profileName +
                        L"; publicIp=" + vpn.publicIp +
                        L"; preservedLocalRoutes=" + std::to_wstring(vpn.preservedLocalRouteCount) +
                        L"; alreadyConnected=" + (vpn.alreadyConnected ? L"true" : L"false"));
            }
            catch (const std::exception& error) {
                AuditLogger::logDeviceAction(
                    L"VPN VERIFY", verified, L"ERROR",
                    L"profileId=" + vpnProfile.id + L"; profileName=" + vpnProfile.name +
                        L"; technical=" + widenAscii(error.what()));
                throw;
            }
        }
        IpcClient ipc(policy.pipeName());
        AuditLogger::logDeviceAction(
            L"USE COMMAND",
            verified,
            L"START",
            L"Sending USE command to pipe " + policy.pipeName() + L".");
        const std::wstring response = ipc.issueCommand(L"USE," + verified.endpoint, kUseCommandTimeoutMs);
        AuditLogger::logDeviceAction(
            L"USE COMMAND",
            verified,
            isCommandFailureResponse(response) ? L"ERROR" : L"OK",
            responseDetails(response));
        throwIfCommandFailed(response, "USE");
        markDeviceUsedBestEffort(policy, verified);
        const std::wstring message = response.empty() ? L"Команда USE отправлена: " + verified.endpoint : response;
        AuditLogger::logDeviceAction(L"USE", verified, L"OK", message);
        return message;
    }
    catch (const std::exception& error) {
        AuditLogger::logDeviceAction(L"USE", device, L"ERROR", widenAscii(error.what()));
        throw;
    }
}

std::wstring DeviceAccessService::stopUsingDevice(const DeviceViewModel& device) const {
    try {
        AuditLogger::logDeviceAction(
            L"STOP REQUEST",
            device,
            L"START",
            L"User requested token release. " + stateDetails(device));
        const DeviceViewModel verified = enrichAndVerify(device);
        AuditLogger::logDeviceAction(
            L"STOP VERIFY",
            verified,
            L"OK",
            L"Policy and device check passed. " + stateDetails(verified));
        PolicyManager policy;
        IpcClient ipc(policy.pipeName());
        AuditLogger::logDeviceAction(
            L"STOP COMMAND",
            verified,
            L"START",
            L"Sending STOP USING command to pipe " + policy.pipeName() + L".");
        const std::wstring response = ipc.issueCommand(L"STOP USING," + verified.endpoint);
        AuditLogger::logDeviceAction(
            L"STOP COMMAND",
            verified,
            isCommandFailureResponse(response) ? L"ERROR" : L"OK",
            responseDetails(response));
        throwIfCommandFailed(response, "STOP USING");
        markDeviceReleasedBestEffort(policy, verified);
        const std::wstring message = response.empty() ? L"Команда STOP USING отправлена: " + verified.endpoint : response;
        AuditLogger::logDeviceAction(L"STOP USING", verified, L"OK", message);
        return message;
    }
    catch (const std::exception& error) {
        AuditLogger::logDeviceAction(L"STOP USING", device, L"ERROR", widenAscii(error.what()));
        throw;
    }
}

std::wstring DeviceAccessService::stopUsingOwnedDevice(const DeviceViewModel& device) const {
    try {
        PolicyManager policy;
        IpcClient ipc(policy.pipeName());
        ParsedDevice current = toParsedDevice(device);
        AuditLogger::logDeviceAction(
            L"STOP OWN VERIFY",
            device,
            L"START",
            L"Checking current token owner before release. " + stateDetails(device));
        DeviceParser::applyDeviceInfo(current, ipc.issueCommand(L"DEVICE INFO," + current.endpoint));
        const DeviceUsageInfo usage = DeviceParser::parseUsage(current.inUseBy, PolicyManager::currentUserName());
        DeviceViewModel currentView = toViewModel(current, device.allowed);
        currentView.vpnProfileId = device.vpnProfileId;
        AuditLogger::logDeviceAction(
            L"STOP OWN VERIFY",
            currentView,
            usage.isUsedByCurrentUser ? L"OK" : L"DENIED",
            L"Owner check result. " + stateDetails(currentView));
        if (!usage.isUsedByCurrentUser) {
            throw std::runtime_error("The token is not connected by the current user.");
        }

        const DeviceViewModel verified = currentView;
        AuditLogger::logDeviceAction(
            L"STOP OWN COMMAND",
            verified,
            L"START",
            L"Sending STOP USING command to pipe " + policy.pipeName() + L".");
        const std::wstring response = ipc.issueCommand(L"STOP USING," + verified.endpoint);
        AuditLogger::logDeviceAction(
            L"STOP OWN COMMAND",
            verified,
            isCommandFailureResponse(response) ? L"ERROR" : L"OK",
            responseDetails(response));
        throwIfCommandFailed(response, "STOP USING");
        markDeviceReleasedBestEffort(policy, verified);
        const std::wstring message = response.empty()
            ? L"Команда STOP USING отправлена: " + verified.endpoint
            : response;
        AuditLogger::logDeviceAction(L"STOP USING OWN", verified, L"OK", message);
        return message;
    }
    catch (const std::exception& error) {
        AuditLogger::logDeviceAction(L"STOP USING OWN", device, L"ERROR", widenAscii(error.what()));
        throw;
    }
}

void DeviceAccessService::refreshUsageTimer(const DeviceViewModel& device) const {
    try {
        PolicyManager policy;
        UsageStateStore(policy.usageStatePath()).markUsed(toParsedDevice(device), PolicyManager::currentUserName());
        AuditLogger::logDeviceAction(L"USAGE TIMER", device, L"OK", L"Usage timer refreshed.");
    }
    catch (const std::exception& error) {
        AuditLogger::logDeviceAction(L"USAGE TIMER", device, L"ERROR", widenAscii(error.what()));
        throw;
    }
}

std::wstring DeviceAccessService::assignDeviceToCurrentUser(const DeviceViewModel& device) const {
    ParsedDevice parsed = toParsedDevice(device);
    PolicyManager policy;
    policy.assignDeviceToCurrentUser(parsed);
    const std::wstring message = L"Устройство назначено текущему пользователю: " + parsed.endpoint;
    AuditLogger::logDeviceAction(L"ASSIGN", device, L"OK", message);
    return message;
}

std::wstring DeviceAccessService::assignDeviceToUser(const DeviceViewModel& device, const std::wstring& userName) const {
    try {
        ParsedDevice parsed = toParsedDevice(device);
        PolicyManager policy;
        policy.assignDeviceToUser(parsed, userName);
        const std::wstring message = L"Устройство назначено пользователю " + userName + L": " + parsed.endpoint;
        AuditLogger::logDeviceAction(L"ASSIGN USER", device, L"OK", message);
        return message;
    }
    catch (const std::exception& error) {
        AuditLogger::logDeviceAction(L"ASSIGN USER", device, L"ERROR", widenAscii(error.what()));
        throw;
    }
}

std::wstring DeviceAccessService::removeDeviceFromUser(const DeviceViewModel& device, const std::wstring& userName) const {
    try {
        ParsedDevice parsed = toParsedDevice(device);
        PolicyManager policy;
        policy.removeDeviceFromUser(parsed, userName);
        const std::wstring message = L"Доступ пользователю " + userName + L" снят: " + parsed.endpoint;
        AuditLogger::logDeviceAction(L"REVOKE USER", device, L"OK", message);
        return message;
    }
    catch (const std::exception& error) {
        AuditLogger::logDeviceAction(L"REVOKE USER", device, L"ERROR", widenAscii(error.what()));
        throw;
    }
}

std::wstring DeviceAccessService::setDevicesForUser(const std::vector<DeviceViewModel>& devices, const std::wstring& userName) const {
    try {
        std::vector<ParsedDevice> parsedDevices;
        parsedDevices.reserve(devices.size());
        for (const DeviceViewModel& device : devices) {
            parsedDevices.push_back(toParsedDevice(device));
        }

        PolicyManager policy;
        policy.setDevicesForUser(parsedDevices, userName);
        const std::wstring message = L"Сохранён доступ пользователя " + userName +
            L": токенов " + std::to_wstring(parsedDevices.size());
        AuditEvent event;
        event.action = L"SAVE USER POLICY";
        event.result = L"OK";
        event.details = message;
        AuditLogger::log(event);
        return message;
    }
    catch (const std::exception& error) {
        AuditEvent event;
        event.action = L"SAVE USER POLICY";
        event.result = L"ERROR";
        event.details = widenAscii(error.what());
        AuditLogger::log(event);
        throw;
    }
}

std::wstring DeviceAccessService::verifyVpnForDevice(const DeviceViewModel& device) const {
    try {
        PolicyManager policy;
        VpnProfile profile;
        if (!policy.tryGetVpnProfileForDevice(toParsedDevice(device), profile)) {
            return {};
        }
        const VpnVerificationResult result = VpnManager::verifyConnected(profile);
        AuditLogger::logDeviceAction(
            L"VPN WATCHDOG", device, L"OK",
            L"profileId=" + profile.id + L"; profileName=" + profile.name +
                L"; publicIp=" + result.publicIp +
                L"; preservedLocalRoutes=" + std::to_wstring(result.preservedLocalRouteCount));
        return result.publicIp;
    }
    catch (const std::exception& error) {
        AuditLogger::logDeviceAction(
            L"VPN WATCHDOG", device, L"ERROR", L"technical=" + widenAscii(error.what()));
        throw;
    }
}

std::wstring DeviceAccessService::setVpnProfileForDevice(
    const DeviceViewModel& device,
    const std::wstring& userName,
    const std::wstring& vpnProfileId) const {
    try {
        PolicyManager policy;
        policy.setVpnProfileForDevice(toParsedDevice(device), userName, vpnProfileId);
        const std::wstring message = vpnProfileId.empty()
            ? L"VPN-профиль снят с токена " + device.endpoint
            : L"Токен " + device.endpoint + L" назначен VPN-профилю " + vpnProfileId;
        AuditLogger::logDeviceAction(L"SET VPN PROFILE", device, L"OK", message + L"; user=" + userName);
        return message;
    }
    catch (const std::exception& error) {
        AuditLogger::logDeviceAction(L"SET VPN PROFILE", device, L"ERROR", widenAscii(error.what()));
        throw;
    }
}

std::vector<VpnProfile> DeviceAccessService::vpnProfiles() const {
    PolicyManager policy;
    return policy.vpnProfiles();
}

void DeviceAccessService::upsertVpnProfile(const VpnProfile& profile) const {
    PolicyManager policy;
    policy.upsertVpnProfile(profile);
    AuditEvent event;
    event.action = L"SAVE VPN PROFILE";
    event.result = L"OK";
    event.details = L"id=" + profile.id + L"; name=" + profile.name + L"; server=" + profile.serverAddress;
    AuditLogger::log(event);
}

void DeviceAccessService::removeVpnProfile(const std::wstring& profileId) const {
    PolicyManager policy;
    policy.removeVpnProfile(profileId);
    AuditEvent event;
    event.action = L"REMOVE VPN PROFILE";
    event.result = L"OK";
    event.details = L"id=" + profileId;
    AuditLogger::log(event);
}

void DeviceAccessService::updateAccessForUser(std::vector<DeviceViewModel>& devices, const std::wstring& userName) const {
    PolicyManager policy;
    const std::vector<DeviceRule> rules = policy.rulesForUser(userName);
    for (DeviceViewModel& device : devices) {
        const ParsedDevice parsed = toParsedDevice(device);
        device.allowed = PolicyManager::isAllowedByRules(parsed, rules);
        device.vpnProfileId = vpnProfileIdForDevice(parsed, rules);
    }
}

std::wstring DeviceAccessService::currentUserSummary() const {
    return L"Пользователь: " + PolicyManager::currentUserName();
}

std::wstring DeviceAccessService::currentPolicyPath() const {
    PolicyManager policy;
    return policy.configPath();
}

std::vector<DeviceViewModel> DeviceAccessService::listDevices(bool includeDenied, const std::wstring& policyUser) const {
    try {
        PolicyManager policy;
        IpcClient ipc(policy.pipeName());
        UsageStateStore usageState(policy.usageStatePath());
        std::vector<ParsedDevice> devices = DeviceParser::parseList(ipc.issueCommand(L"LIST"));
        std::vector<DeviceViewModel> result;
        const std::vector<DeviceRule> policyUserRules = policyUser.empty()
            ? std::vector<DeviceRule>{}
            : policy.rulesForUser(policyUser);
        const std::vector<DeviceRule>& activeRules = policyUser.empty()
            ? policy.effectiveRules()
            : policyUserRules;
        std::vector<UsageStateRecord> usageRecords;
        try {
            usageRecords = usageState.snapshot();
        }
        catch (const std::exception& error) {
            logUsageStateWarning(error.what());
        }

        constexpr DWORD deviceInfoTimeoutMs = 750;
        constexpr ULONGLONG enrichmentBudgetMs = 15ULL * 1000ULL;
        const ULONGLONG enrichmentStartedAt = GetTickCount64();
        bool enrichmentBudgetWarningLogged = false;

        for (ParsedDevice& device : devices) {
            bool deviceInfoLoaded = false;
            if (GetTickCount64() - enrichmentStartedAt < enrichmentBudgetMs) {
                try {
                    DeviceParser::applyDeviceInfo(
                        device,
                        ipc.issueCommand(L"DEVICE INFO," + device.endpoint, deviceInfoTimeoutMs));
                    deviceInfoLoaded = true;
                }
                catch (const std::exception& error) {
                    AuditLogger::logDeviceAction(L"DEVICE INFO", toViewModel(device, true), L"WARNING", widenAscii(error.what()));
                }
            }
            else if (!enrichmentBudgetWarningLogged) {
                AuditEvent event;
                event.action = L"DEVICE INFO";
                event.result = L"WARNING";
                event.details = L"Device enrichment time budget was reached; LIST data is used for remaining devices.";
                AuditLogger::log(event);
                enrichmentBudgetWarningLogged = true;
            }

            UsageStateRecord usageRecord;
            std::wstring usageStartedAt;
            try {
                usageState.applyRecordedUsage(device, usageRecords);
                if (usageState.tryGetRecord(device, usageRecord, usageRecords)) {
                    usageStartedAt = usageRecord.updatedAt;
                }
            }
            catch (const std::exception& error) {
                logUsageStateWarning(error.what());
            }
            const bool allowed = deviceInfoLoaded
                ? PolicyManager::isAllowedByRules(device, activeRules)
                : isPotentiallyAllowedByRules(device, activeRules);
            const bool connectedByCurrentUser =
                DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName()).isUsedByCurrentUser;
            if (allowed || includeDenied || connectedByCurrentUser) {
                DeviceViewModel view = toViewModel(device, allowed, usageStartedAt);
                view.vpnProfileId = vpnProfileIdForDevice(device, activeRules);
                result.push_back(std::move(view));
            }
        }

        AuditEvent event;
        event.action = includeDenied ? L"LIST DIAGNOSTICS" : L"LIST";
        event.result = L"OK";
        event.details = L"visible=" + std::to_wstring(result.size()) + L", total=" + std::to_wstring(devices.size());
        AuditLogger::log(event);
        return result;
    }
    catch (const std::exception& error) {
        AuditEvent event;
        event.action = includeDenied ? L"LIST DIAGNOSTICS" : L"LIST";
        event.result = L"ERROR";
        event.details = widenAscii(error.what());
        AuditLogger::log(event);
        throw;
    }
}

DeviceViewModel DeviceAccessService::enrichAndVerify(const DeviceViewModel& device) const {
    PolicyManager policy;
    IpcClient ipc(policy.pipeName());

    ParsedDevice current = toParsedDevice(device);
    DeviceParser::applyDeviceInfo(current, ipc.issueCommand(L"DEVICE INFO," + current.endpoint));
    if (!policy.isAllowed(current)) {
        AuditLogger::logDeviceAction(L"DENY", toViewModel(current, false), L"DENIED", L"Device is not allowed by policy.");
        throw std::runtime_error("Device is not allowed by policy.");
    }

    DeviceViewModel verified = toViewModel(current, true);
    verified.vpnProfileId = vpnProfileIdForDevice(current, policy.effectiveRules());
    return verified;
}
