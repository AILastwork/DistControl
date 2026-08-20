#include "DeviceAccessService.h"

#include "AuditLogger.h"
#include "DeviceParser.h"
#include "IpcClient.h"
#include "PolicyManager.h"
#include "UsageStateStore.h"
#include "VpnManager.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace {
constexpr unsigned long kUseCommandTimeoutMs = 120UL * 1000UL;
constexpr unsigned long kStopCommandTimeoutMs = 30UL * 1000UL;
constexpr ULONGLONG kCommandConfirmationTimeoutMs = 15ULL * 1000ULL;
constexpr unsigned long kVpnRecoveryCommandTimeoutMs = 5000UL;
constexpr ULONGLONG kVpnDeviceRecoveryTimeoutMs = 60ULL * 1000ULL;
constexpr DWORD kVpnDeviceRecoveryPollMs = 1000;
constexpr int kVpnUseAttempts = 4;

std::wstring widenAscii(const char* text) {
    if (!text || *text == '\0') {
        return {};
    }
    const int length = static_cast<int>(std::strlen(text));
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, length, nullptr, 0);
    UINT codePage = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (size <= 0) {
        codePage = CP_ACP;
        flags = 0;
        size = MultiByteToWideChar(codePage, flags, text, length, nullptr, 0);
    }
    if (size <= 0) {
        return L"Не удалось преобразовать технический текст ошибки.";
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(codePage, flags, text, length, result.data(), size);
    return result;
}

bool containsTechnicalText(const char* text, const char* needle) {
    return text && needle && std::strstr(text, needle) != nullptr;
}

std::wstring humanErrorDescription(const char* error) {
    const std::wstring technical = widenAscii(error);
    std::wstring explanation;
    if (containsTechnicalText(error, "device catalog is temporarily empty")) {
        explanation = L"Служба DistKontrolUSB временно вернула пустой список устройств";
    }
    else if (containsTechnicalText(error, "device catalog did not recover after VPN connection")) {
        explanation = L"После подключения VPN служба DistKontrolUSB не успела восстановить список устройств";
    }
    else if (containsTechnicalText(error, "Invalid address")) {
        explanation = L"Служба DistKontrolUSB пока не принимает адрес токена после изменения сети";
    }
    else if (containsTechnicalText(error, "DistKontrol returned FAILED") ||
             containsTechnicalText(error, "DistKontrol returned ERROR")) {
        explanation = L"Служба DistKontrolUSB отказала в выполнении команды";
    }
    else if (containsTechnicalText(error, "pipe read timed out") ||
             containsTechnicalText(error, "pipe write timed out")) {
        explanation = L"Служба DistKontrolUSB не ответила за отведённое время";
    }
    else if (containsTechnicalText(error, "pipe is not available") ||
             containsTechnicalText(error, "Cannot open DistKontrol pipe")) {
        explanation = L"Приложение не смогло связаться со службой dkclient";
    }
    else if (containsTechnicalText(error, "VPN public IP mismatch")) {
        explanation = L"VPN подключён, но фактический внешний IP не совпал с разрешённым";
    }
    else if (containsTechnicalText(error, "VPN public IP") ||
             containsTechnicalText(error, "verification service")) {
        explanation = L"Не удалось проверить внешний IP VPN";
    }
    else if (containsTechnicalText(error, "VPN local network routes were replaced")) {
        explanation = L"VPN изменил маршруты локальной сети, поэтому подключение токена остановлено";
    }
    else if (containsTechnicalText(error, "VPN credentials are not configured")) {
        explanation = L"Для VPN не сохранены логин и пароль";
    }
    else if (containsTechnicalText(error, "RAS error 691")) {
        explanation = L"VPN-сервер отклонил логин или пароль";
    }
    else if (containsTechnicalText(error, "VPN Windows profile is not installed")) {
        explanation = L"На компьютере отсутствует требуемый профиль VPN Windows";
    }
    else if (containsTechnicalText(error, "Device is not allowed by policy")) {
        explanation = L"Токен не разрешён текущему пользователю в allow.json";
    }
    else if (containsTechnicalText(error, "The token is not connected by the current user")) {
        explanation = L"Токен сейчас не подключён текущим пользователем";
    }
    else if (containsTechnicalText(error, "The token is occupied by another user")) {
        explanation = L"Токен уже занят другим пользователем";
    }
    else if (containsTechnicalText(error, "Another active token requires a different VPN profile")) {
        explanation = L"Другой подключённый токен требует иной VPN-профиль";
    }
    else if (containsTechnicalText(error, "DistKontrol did not confirm token connection")) {
        explanation = L"Служба ответила на подключение, но не подтвердила нового владельца токена";
    }
    else if (containsTechnicalText(error, "DistKontrol did not confirm token release")) {
        explanation = L"Служба ответила на отключение, но токен всё ещё числится подключённым";
    }
    else if (containsTechnicalText(error, "usage state") ||
             containsTechnicalText(error, "Usage state")) {
        explanation = L"Не удалось прочитать или обновить общий файл таймеров";
    }
    else {
        explanation = L"Получена техническая ошибка";
    }

    return technical.empty() ? explanation : explanation + L" (технически: " + technical + L")";
}

class HumanOperationTrace {
public:
    explicit HumanOperationTrace(const wchar_t* prefix, const std::wstring& operationId = {})
        : id_(operationId.empty() ? AuditLogger::createOperationId(prefix) : operationId),
          startedAt_(GetTickCount64()) {
    }

    void step(const std::wstring& message) const {
        AuditLogger::trace(id_, message + L" Прошло с начала операции: " +
            std::to_wstring(elapsedMs()) + L" мс.");
    }

    ULONGLONG elapsedMs() const {
        return GetTickCount64() - startedAt_;
    }

    const std::wstring& id() const {
        return id_;
    }

private:
    std::wstring id_;
    ULONGLONG startedAt_ = 0;
};

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

bool containsIgnoreCase(const std::wstring& value, const wchar_t* needle) {
    return FindStringOrdinal(
        FIND_FROMSTART,
        value.c_str(), static_cast<int>(value.size()),
        needle, -1,
        TRUE) >= 0;
}

bool isTransientUseFailureResponse(const std::wstring& response) {
    const std::wstring trimmed = trimResponse(response);
    return startsWithIgnoreCase(trimmed, L"FAILED") ||
        containsIgnoreCase(trimmed, L"Invalid address");
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

bool equalsIgnoreCase(const std::wstring& left, const std::wstring& right);

DeviceViewModel loadCurrentDevice(
    const IpcClient& ipc,
    const DeviceViewModel& device,
    unsigned long timeoutMs) {
    ParsedDevice current = toParsedDevice(device);
    const std::wstring response = ipc.issueCommand(L"DEVICE INFO," + current.endpoint, timeoutMs);
    throwIfCommandFailed(response, "DEVICE INFO");
    DeviceParser::applyDeviceInfo(current, response);
    DeviceViewModel result = toViewModel(current, device.allowed, device.usageStartedAt);
    result.vpnProfileId = device.vpnProfileId;
    return result;
}

DeviceViewModel waitForDeviceAfterVpn(
    const PolicyManager& policy,
    const DeviceViewModel& device,
    const HumanOperationTrace& trace) {
    IpcClient ipc(policy.pipeName());
    const ULONGLONG startedAt = GetTickCount64();
    std::string lastError = "Device was not present in the DistKontrol catalog.";
    const size_t separator = device.endpoint.rfind(L'.');
    const std::wstring serverName = separator == std::wstring::npos
        ? std::wstring{}
        : device.endpoint.substr(0, separator);

    int attempt = 0;
    while (GetTickCount64() - startedAt < kVpnDeviceRecoveryTimeoutMs) {
        ++attempt;
        try {
            trace.step(L"Проверяем, восстановился ли каталог DistKontrolUSB после изменения сети. Попытка " +
                std::to_wstring(attempt) + L".");
            const std::wstring listResponse = ipc.issueCommand(L"LIST", kVpnRecoveryCommandTimeoutMs);
            throwIfCommandFailed(listResponse, "LIST");
            const std::vector<ParsedDevice> devices = DeviceParser::parseList(listResponse);
            const auto found = std::find_if(devices.begin(), devices.end(), [&device](const ParsedDevice& current) {
                return equalsIgnoreCase(current.endpoint, device.endpoint);
            });
            if (found == devices.end()) {
                lastError = "Device was not present in the DistKontrol catalog.";
                trace.step(L"Каталог получен: устройств " + std::to_wstring(devices.size()) +
                    L", но нужный endpoint пока отсутствует.");
            }
            else {
                trace.step(L"Каталог получен: устройств " + std::to_wstring(devices.size()) +
                    L", нужный endpoint найден.");
                if (!serverName.empty()) {
                    const std::wstring serverResponse =
                        ipc.issueCommand(L"SERVER INFO," + serverName, kVpnRecoveryCommandTimeoutMs);
                    throwIfCommandFailed(serverResponse, "SERVER INFO");
                    if (!containsIgnoreCase(serverResponse, L"STATE: Logged in")) {
                        throw std::runtime_error(
                            "DistKontrol hub is not logged in after VPN connection. Response: " +
                            narrowAsciiForError(trimResponse(serverResponse)));
                    }
                    trace.step(L"USB-концентратор снова авторизован в DistKontrolUSB.");
                }
                DeviceViewModel current = loadCurrentDevice(ipc, device, kVpnRecoveryCommandTimeoutMs);
                if (!policy.isAllowed(toParsedDevice(current))) {
                    throw std::runtime_error("Device is no longer allowed by policy after VPN connection.");
                }
                trace.step(L"DEVICE INFO получен, доступ по политике подтверждён.");
                return current;
            }
        }
        catch (const std::exception& error) {
            lastError = error.what();
            trace.step(L"Каталог ещё не готов. " + humanErrorDescription(error.what()) + L".");
        }
        Sleep(kVpnDeviceRecoveryPollMs);
    }

    throw std::runtime_error(
        "DistKontrol device catalog did not recover after VPN connection. Last error: " + lastError);
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

DeviceViewModel confirmDeviceStateAfterCommand(
    const PolicyManager& policy,
    const DeviceViewModel& device,
    bool expectOwned,
    bool waitForTransition,
    const HumanOperationTrace& trace) {
    IpcClient ipc(policy.pipeName());
    const ULONGLONG startedAt = GetTickCount64();
    int attempt = 0;
    while (true) {
        ++attempt;
        try {
            DeviceViewModel current = loadCurrentDevice(ipc, device, 3000);
            const DeviceUsageInfo usage =
                DeviceParser::parseUsage(current.inUseBy, PolicyManager::currentUserName());
            trace.step(L"Контроль DEVICE INFO после команды, попытка " + std::to_wstring(attempt) +
                L": состояние «" + current.statusText + L"».");
            if (expectOwned && usage.isUsedByCurrentUser) {
                return current;
            }
            if (!expectOwned && !usage.isUsedByCurrentUser) {
                return current;
            }
            if (expectOwned && !usage.isFree) {
                throw std::runtime_error("The token is occupied by another user.");
            }
        }
        catch (const std::runtime_error& error) {
            if (containsTechnicalText(error.what(), "occupied by another user")) {
                throw;
            }
            trace.step(L"Контрольное чтение DEVICE INFO пока не удалось. " +
                humanErrorDescription(error.what()) + L".");
        }

        if (!waitForTransition || GetTickCount64() - startedAt >= kCommandConfirmationTimeoutMs) {
            break;
        }
        Sleep(500);
    }

    throw std::runtime_error(expectOwned
        ? "DistKontrol did not confirm token connection."
        : "DistKontrol did not confirm token release.");
}

void prepareVpnForTokenConnection(
    const PolicyManager& policy,
    IpcClient& ipc,
    const DeviceViewModel& target,
    const VpnProfile& targetProfile,
    const HumanOperationTrace& trace) {
    trace.step(L"Проверяем, нет ли у текущего пользователя токена, работающего через другой VPN-профиль.");
    const std::wstring listResponse = ipc.issueCommand(L"LIST", kVpnRecoveryCommandTimeoutMs);
    throwIfCommandFailed(listResponse, "LIST");
    const std::vector<ParsedDevice> devices = DeviceParser::parseList(listResponse);
    if (devices.empty()) {
        throw std::runtime_error("DistKontrol device catalog is temporarily empty.");
    }

    const std::vector<DeviceRule>& rules = policy.effectiveRules();
    for (const ParsedDevice& device : devices) {
        if (equalsIgnoreCase(device.endpoint, target.endpoint)) {
            continue;
        }
        const DeviceUsageInfo usage =
            DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
        if (!usage.isUsedByCurrentUser) {
            continue;
        }
        const std::wstring activeProfileId = vpnProfileIdForDevice(device, rules);
        if (!equalsIgnoreCase(activeProfileId, targetProfile.id)) {
            trace.step(L"Переключение VPN остановлено: токен «" + device.nickname +
                L"» уже подключён и использует другой сетевой режим.");
            throw std::runtime_error("Another active token requires a different VPN profile.");
        }
    }

    trace.step(L"Конфликтующих активных токенов не найдено. Проверяем ранее подключённые профили DiskControl.");
    for (const VpnProfile& profile : policy.vpnProfiles()) {
        if (equalsIgnoreCase(profile.name, targetProfile.name) || !VpnManager::isConnected(profile.name)) {
            continue;
        }
        trace.step(L"Найден неиспользуемый VPN-профиль «" + profile.name +
            L"». Отключаем его перед выбором требуемого канала.");
        VpnManager::disconnect(
            profile.name,
            [&trace](const std::wstring& message) { trace.step(message); });
    }
}

std::wstring disconnectReleasedTokenVpnBestEffort(
    const PolicyManager& policy,
    IpcClient& ipc,
    const DeviceViewModel& released,
    const HumanOperationTrace& trace) {
    if (released.vpnProfileId.empty()) {
        return {};
    }

    const auto profile = std::find_if(
        policy.vpnProfiles().begin(), policy.vpnProfiles().end(),
        [&released](const VpnProfile& candidate) {
            return equalsIgnoreCase(candidate.id, released.vpnProfileId);
        });
    if (profile == policy.vpnProfiles().end()) {
        trace.step(L"VPN после отключения токена не изменяем: назначенный профиль отсутствует в конфигурации.");
        return L" VPN оставлен включённым: назначенный профиль отсутствует в конфигурации.";
    }

    try {
        trace.step(L"Проверяем, нужен ли VPN-профиль «" + profile->name + L"» другим подключённым токенам.");
        const std::wstring listResponse = ipc.issueCommand(L"LIST", kVpnRecoveryCommandTimeoutMs);
        throwIfCommandFailed(listResponse, "LIST");
        const std::vector<ParsedDevice> devices = DeviceParser::parseList(listResponse);
        if (devices.empty()) {
            throw std::runtime_error("DistKontrol device catalog is temporarily empty.");
        }

        const std::vector<DeviceRule>& rules = policy.effectiveRules();
        for (const ParsedDevice& device : devices) {
            if (equalsIgnoreCase(device.endpoint, released.endpoint)) {
                continue;
            }
            const DeviceUsageInfo usage =
                DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
            if (usage.isUsedByCurrentUser &&
                equalsIgnoreCase(vpnProfileIdForDevice(device, rules), released.vpnProfileId)) {
                trace.step(L"VPN остаётся подключённым: токен «" + device.nickname +
                    L"» продолжает использовать этот профиль.");
                return {};
            }
        }

        VpnManager::disconnect(
            profile->name,
            [&trace](const std::wstring& message) { trace.step(message); });
        AuditLogger::logDeviceAction(
            L"VPN DISCONNECT", released, L"OK", L"profileId=" + profile->id + L"; profileName=" + profile->name);
        return L" VPN-профиль «" + profile->name + L"» отключён.";
    }
    catch (const std::exception& error) {
        trace.step(L"Токен уже освобождён, но VPN оставлен включённым. " +
            humanErrorDescription(error.what()) + L".");
        AuditLogger::logDeviceAction(
            L"VPN DISCONNECT", released, L"WARNING",
            L"profileId=" + profile->id + L"; technical=" + widenAscii(error.what()));
        return L" Токен освобождён, но VPN не удалось безопасно отключить; подробности записаны в журнал.";
    }
}
}

std::vector<DeviceViewModel> DeviceAccessService::listVisibleDevices(
    const DeviceListProgressCallback& progress) const {
    return listDevices(false, L"", progress);
}

std::vector<DeviceViewModel> DeviceAccessService::listAllDevices(
    const DeviceListProgressCallback& progress) const {
    return listDevices(true, L"", progress);
}

std::vector<DeviceViewModel> DeviceAccessService::listAllDevicesForUser(
    const std::wstring& userName,
    const DeviceListProgressCallback& progress) const {
    return listDevices(true, userName, progress);
}

std::wstring DeviceAccessService::useDevice(
    const DeviceViewModel& device,
    const std::wstring& operationId) const {
    HumanOperationTrace trace(L"CONNECT", operationId);
    trace.step(L"Пользователь запросил подключение токена «" + device.nickname +
        L"», endpoint=" + device.endpoint + L".");
    try {
        AuditLogger::logDeviceAction(
            L"USE REQUEST",
            device,
            L"START",
            L"operationId=" + trace.id() + L"; User requested token connection. " + stateDetails(device));
        trace.step(L"Повторно запрашиваем DEVICE INFO и проверяем разрешение в allow.json.");
        DeviceViewModel verified = enrichAndVerify(device);
        trace.step(L"Токен найден и разрешён текущему пользователю. Состояние: " +
            verified.statusText + L".");
        const DeviceUsageInfo verifiedUsage =
            DeviceParser::parseUsage(verified.inUseBy, PolicyManager::currentUserName());
        if (verifiedUsage.isUsedByCurrentUser) {
            trace.step(L"Токен уже подключён текущим пользователем. Повторная команда USE не требуется.");
            return L"Токен уже подключён вами.";
        }
        if (!verifiedUsage.isFree) {
            throw std::runtime_error("The token is occupied by another user.");
        }
        AuditLogger::logDeviceAction(
            L"USE VERIFY",
            verified,
            L"OK",
            L"Policy and device check passed. " + stateDetails(verified));
        PolicyManager policy;
        VpnProfile vpnProfile;
        const bool vpnRequired = policy.tryGetVpnProfileForDevice(toParsedDevice(verified), vpnProfile);
        if (vpnRequired) {
            IpcClient preparationIpc(policy.pipeName());
            prepareVpnForTokenConnection(policy, preparationIpc, verified, vpnProfile, trace);
            trace.step(L"Токену назначен VPN-профиль «" + vpnProfile.id + L"» (Windows: «" +
                vpnProfile.name + L"»). Начинаем VPN-проверку.");
            AuditLogger::logDeviceAction(
                L"VPN VERIFY",
                verified,
                L"START",
                L"profileId=" + vpnProfile.id + L"; profileName=" + vpnProfile.name +
                    L"; server=" + vpnProfile.serverAddress);
            try {
                const VpnVerificationResult vpn = VpnManager::connectAndVerify(
                    vpnProfile,
                    [&trace](const std::wstring& message) { trace.step(message); });
                AuditLogger::logDeviceAction(
                    L"VPN VERIFY",
                    verified,
                    L"OK",
                    L"profileId=" + vpnProfile.id + L"; profileName=" + vpn.profileName +
                        L"; publicIp=" + vpn.publicIp +
                        L"; preservedLocalRoutes=" + std::to_wstring(vpn.preservedLocalRouteCount) +
                        L"; alreadyConnected=" + (vpn.alreadyConnected ? L"true" : L"false"));
                AuditLogger::logDeviceAction(
                    L"VPN DEVICE RECOVERY",
                    verified,
                    L"START",
                    L"Waiting for dkclient to expose the token after the network route change.");
                verified = waitForDeviceAfterVpn(policy, verified, trace);
                AuditLogger::logDeviceAction(
                    L"VPN DEVICE RECOVERY",
                    verified,
                    L"OK",
                    L"Token address is present in LIST and DEVICE INFO.");
            }
            catch (const std::exception& error) {
                trace.step(L"Подключение остановлено на этапе VPN. " + humanErrorDescription(error.what()) + L".");
                AuditLogger::logDeviceAction(
                    L"VPN VERIFY", verified, L"ERROR",
                    L"profileId=" + vpnProfile.id + L"; profileName=" + vpnProfile.name +
                        L"; technical=" + widenAscii(error.what()));
                throw;
            }
        }
        else {
            trace.step(L"Для токена VPN-профиль не назначен. Переходим сразу к DistKontrolUSB.");
        }
        IpcClient ipc(policy.pipeName());
        std::wstring response;
        const int maximumAttempts = vpnRequired ? kVpnUseAttempts : 1;
        for (int attempt = 1; attempt <= maximumAttempts; ++attempt) {
            if (vpnRequired && attempt > 1) {
                trace.step(L"Перед повторной командой USE ещё раз проверяем готовность каталога DistKontrolUSB.");
                verified = waitForDeviceAfterVpn(policy, verified, trace);
                const DeviceUsageInfo usage =
                    DeviceParser::parseUsage(verified.inUseBy, PolicyManager::currentUserName());
                if (usage.isUsedByCurrentUser) {
                    response = L"OK";
                    AuditLogger::logDeviceAction(
                        L"USE RECOVERY",
                        verified,
                        L"OK",
                        L"The previous USE attempt connected the token despite its failure response.");
                    trace.step(L"Предыдущая команда USE фактически сработала: токен уже подключён текущим пользователем.");
                    break;
                }
                if (!usage.isFree) {
                    throw std::runtime_error("The token became occupied while dkclient was recovering after VPN connection.");
                }
            }

            AuditLogger::logDeviceAction(
                L"USE COMMAND",
                verified,
                L"START",
                L"Sending USE command to pipe " + policy.pipeName() +
                    L"; attempt=" + std::to_wstring(attempt) + L"/" + std::to_wstring(maximumAttempts) + L".");
            trace.step(L"Отправляем команду USE в службу dkclient. Попытка " +
                std::to_wstring(attempt) + L" из " + std::to_wstring(maximumAttempts) + L".");
            const ULONGLONG commandStartedAt = GetTickCount64();
            response = ipc.issueCommand(L"USE," + verified.endpoint, kUseCommandTimeoutMs);
            trace.step(L"Служба dkclient ответила на USE за " +
                std::to_wstring(GetTickCount64() - commandStartedAt) + L" мс: " +
                (trimResponse(response).empty() ? L"пустой ответ" : trimResponse(response)) + L".");
            const bool retry = vpnRequired && attempt < maximumAttempts && isTransientUseFailureResponse(response);
            AuditLogger::logDeviceAction(
                L"USE COMMAND",
                verified,
                isCommandFailureResponse(response) ? (retry ? L"WARNING" : L"ERROR") : L"OK",
                responseDetails(response) + L"; attempt=" + std::to_wstring(attempt) +
                    L"/" + std::to_wstring(maximumAttempts));
            if (!isCommandFailureResponse(response)) {
                break;
            }
            if (!retry) {
                break;
            }
            trace.step(L"Ответ временный; приложение повторит подключение автоматически без нового двойного клика.");
            Sleep(kVpnDeviceRecoveryPollMs);
        }
        const bool useReportedFailure = isCommandFailureResponse(response);
        try {
            verified = confirmDeviceStateAfterCommand(
                policy, verified, true, !useReportedFailure, trace);
        }
        catch (...) {
            if (useReportedFailure) {
                throwIfCommandFailed(response, "USE");
            }
            throw;
        }
        if (useReportedFailure) {
            trace.step(L"Несмотря на ошибочный ответ USE, DEVICE INFO подтвердил подключение токена.");
            response = L"OK";
        }
        markDeviceUsedBestEffort(policy, verified);
        trace.step(L"Токен подключён. Таймер использования записан, операция завершена успешно.");
        const std::wstring message = response.empty() ? L"Команда USE отправлена: " + verified.endpoint : response;
        AuditLogger::logDeviceAction(L"USE", verified, L"OK",
            L"operationId=" + trace.id() + L"; elapsedMs=" + std::to_wstring(trace.elapsedMs()) + L"; " + message);
        return message;
    }
    catch (const std::exception& error) {
        trace.step(L"Подключение токена завершилось ошибкой. " + humanErrorDescription(error.what()) + L".");
        AuditLogger::logDeviceAction(L"USE", device, L"ERROR",
            L"operationId=" + trace.id() + L"; elapsedMs=" + std::to_wstring(trace.elapsedMs()) +
                L"; technical=" + widenAscii(error.what()));
        throw;
    }
}

std::wstring DeviceAccessService::stopUsingDevice(const DeviceViewModel& device) const {
    return stopUsingOwnedDevice(device);
}

std::wstring DeviceAccessService::stopUsingOwnedDevice(
    const DeviceViewModel& device,
    const std::wstring& operationId) const {
    HumanOperationTrace trace(L"DISCONNECT", operationId);
    trace.step(L"Пользователь запросил отключение токена «" + device.nickname +
        L"», endpoint=" + device.endpoint + L".");
    try {
        PolicyManager policy;
        IpcClient ipc(policy.pipeName());
        ParsedDevice current = toParsedDevice(device);
        AuditLogger::logDeviceAction(
            L"STOP OWN VERIFY",
            device,
            L"START",
            L"operationId=" + trace.id() + L"; Checking current token owner before release. " + stateDetails(device));
        trace.step(L"Запрашиваем DEVICE INFO и проверяем, что токен подключён именно текущим пользователем.");
        const ULONGLONG verifyStartedAt = GetTickCount64();
        const std::wstring infoResponse = ipc.issueCommand(L"DEVICE INFO," + current.endpoint);
        throwIfCommandFailed(infoResponse, "DEVICE INFO");
        DeviceParser::applyDeviceInfo(current, infoResponse);
        const DeviceUsageInfo usage = DeviceParser::parseUsage(current.inUseBy, PolicyManager::currentUserName());
        DeviceViewModel currentView = toViewModel(current, device.allowed);
        currentView.vpnProfileId = device.vpnProfileId;
        trace.step(L"Владелец токена проверен за " +
            std::to_wstring(GetTickCount64() - verifyStartedAt) + L" мс. Текущее состояние: " +
            currentView.statusText + L".");
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
        trace.step(L"Отправляем команду STOP USING в службу dkclient.");
        const ULONGLONG commandStartedAt = GetTickCount64();
        std::wstring response = ipc.issueCommand(
            L"STOP USING," + verified.endpoint, kStopCommandTimeoutMs);
        trace.step(L"Служба dkclient ответила на STOP USING за " +
            std::to_wstring(GetTickCount64() - commandStartedAt) + L" мс: " +
            (trimResponse(response).empty() ? L"пустой ответ" : trimResponse(response)) + L".");
        AuditLogger::logDeviceAction(
            L"STOP OWN COMMAND",
            verified,
            isCommandFailureResponse(response) ? L"ERROR" : L"OK",
            responseDetails(response));
        const bool stopReportedFailure = isCommandFailureResponse(response);
        try {
            confirmDeviceStateAfterCommand(policy, verified, false, !stopReportedFailure, trace);
        }
        catch (...) {
            if (stopReportedFailure) {
                throwIfCommandFailed(response, "STOP USING");
            }
            throw;
        }
        if (stopReportedFailure) {
            trace.step(L"Несмотря на ошибочный ответ STOP USING, DEVICE INFO подтвердил освобождение токена.");
            response = L"OK";
        }
        markDeviceReleasedBestEffort(policy, verified);
        trace.step(L"Токен освобождён, запись общего таймера удалена. Операция завершена успешно.");
        const std::wstring vpnStatus = disconnectReleasedTokenVpnBestEffort(policy, ipc, verified, trace);
        const std::wstring message = response.empty()
            ? L"Команда STOP USING отправлена: " + verified.endpoint
            : response;
        AuditLogger::logDeviceAction(L"STOP USING OWN", verified, L"OK",
            L"operationId=" + trace.id() + L"; elapsedMs=" + std::to_wstring(trace.elapsedMs()) + L"; " + message + vpnStatus);
        return message + vpnStatus;
    }
    catch (const std::exception& error) {
        trace.step(L"Отключение токена завершилось ошибкой. " + humanErrorDescription(error.what()) + L".");
        AuditLogger::logDeviceAction(L"STOP USING OWN", device, L"ERROR",
            L"operationId=" + trace.id() + L"; elapsedMs=" + std::to_wstring(trace.elapsedMs()) +
                L"; technical=" + widenAscii(error.what()));
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

void DeviceAccessService::installOrUpdateWindowsVpnProfile(
    const VpnProfile& profile,
    const std::wstring& preSharedKey) const {
    VpnManager::installOrUpdateProfile(profile, preSharedKey);
    AuditEvent event;
    event.action = L"INSTALL VPN PROFILE";
    event.result = L"OK";
    event.details = L"id=" + profile.id + L"; name=" + profile.name +
        L"; server=" + profile.serverAddress + L"; psk=<not logged>";
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

std::vector<DeviceViewModel> DeviceAccessService::listDevices(
    bool includeDenied,
    const std::wstring& policyUser,
    const DeviceListProgressCallback& progress) const {
    HumanOperationTrace trace(L"REFRESH");
    trace.step(includeDenied
        ? L"Начато обновление полного списка токенов для админской утилиты."
        : L"Начато обновление разрешённого списка токенов пользователя.");
    try {
        PolicyManager policy;
        IpcClient ipc(policy.pipeName());
        UsageStateStore usageState(policy.usageStatePath());
        trace.step(L"Конфигурация прочитана. Pipe=" + policy.pipeName() +
            L", файл таймеров=" + policy.usageStatePath() + L".");
        const ULONGLONG listStartedAt = GetTickCount64();
        trace.step(L"Отправляем команду LIST в службу dkclient.");
        const std::wstring listResponse = ipc.issueCommand(L"LIST");
        throwIfCommandFailed(listResponse, "LIST");
        std::vector<ParsedDevice> devices = DeviceParser::parseList(listResponse);
        trace.step(L"LIST получен за " + std::to_wstring(GetTickCount64() - listStartedAt) +
            L" мс. Распознано устройств: " + std::to_wstring(devices.size()) + L".");
        if (devices.empty()) {
            throw std::runtime_error("DistKontrol device catalog is temporarily empty.");
        }
        if (progress) {
            progress(0, devices.size());
        }
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
            trace.step(L"Общий файл таймеров прочитан. Активных записей: " +
                std::to_wstring(usageRecords.size()) + L".");
        }
        catch (const std::exception& error) {
            logUsageStateWarning(error.what());
            trace.step(L"Не удалось прочитать общий файл таймеров. Список продолжит загружаться. " +
                humanErrorDescription(error.what()) + L".");
        }

        constexpr DWORD deviceInfoTimeoutMs = 750;
        constexpr ULONGLONG enrichmentBudgetMs = 15ULL * 1000ULL;
        const ULONGLONG enrichmentStartedAt = GetTickCount64();
        bool enrichmentBudgetWarningLogged = false;
        size_t deviceInfoWarnings = 0;

        size_t processed = 0;
        for (ParsedDevice& device : devices) {
            bool deviceInfoLoaded = false;
            if (GetTickCount64() - enrichmentStartedAt < enrichmentBudgetMs) {
                try {
                    const std::wstring infoResponse =
                        ipc.issueCommand(L"DEVICE INFO," + device.endpoint, deviceInfoTimeoutMs);
                    throwIfCommandFailed(infoResponse, "DEVICE INFO");
                    DeviceParser::applyDeviceInfo(device, infoResponse);
                    deviceInfoLoaded = true;
                }
                catch (const std::exception& error) {
                    ++deviceInfoWarnings;
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
            ++processed;
            if (processed == devices.size() || processed % 10 == 0) {
                trace.step(L"Обработано DEVICE INFO: " + std::to_wstring(processed) + L" из " +
                    std::to_wstring(devices.size()) + L"; предупреждений: " +
                    std::to_wstring(deviceInfoWarnings) + L".");
            }
            if (progress) {
                progress(processed, devices.size());
            }
        }

        AuditEvent event;
        event.action = includeDenied ? L"LIST DIAGNOSTICS" : L"LIST";
        event.result = L"OK";
        event.details = L"operationId=" + trace.id() + L"; elapsedMs=" + std::to_wstring(trace.elapsedMs()) +
            L"; visible=" + std::to_wstring(result.size()) + L", total=" + std::to_wstring(devices.size());
        AuditLogger::log(event);
        trace.step(L"Обновление списка завершено успешно. Показано токенов: " +
            std::to_wstring(result.size()) + L" из " + std::to_wstring(devices.size()) + L".");
        return result;
    }
    catch (const std::exception& error) {
        AuditEvent event;
        event.action = includeDenied ? L"LIST DIAGNOSTICS" : L"LIST";
        event.result = L"ERROR";
        event.details = L"operationId=" + trace.id() + L"; elapsedMs=" + std::to_wstring(trace.elapsedMs()) +
            L"; technical=" + widenAscii(error.what());
        AuditLogger::log(event);
        trace.step(L"Обновление списка завершилось ошибкой. " + humanErrorDescription(error.what()) + L".");
        throw;
    }
}

DeviceViewModel DeviceAccessService::enrichAndVerify(const DeviceViewModel& device) const {
    PolicyManager policy;
    IpcClient ipc(policy.pipeName());

    const DeviceViewModel loaded = loadCurrentDevice(ipc, device, 3000);
    ParsedDevice current = toParsedDevice(loaded);
    if (!policy.isAllowed(current)) {
        AuditLogger::logDeviceAction(L"DENY", toViewModel(current, false), L"DENIED", L"Device is not allowed by policy.");
        throw std::runtime_error("Device is not allowed by policy.");
    }

    DeviceViewModel verified = toViewModel(current, true);
    verified.vpnProfileId = vpnProfileIdForDevice(current, policy.effectiveRules());
    return verified;
}
