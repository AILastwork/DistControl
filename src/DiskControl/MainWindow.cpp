#include "MainWindow.h"

#include "AuditLogger.h"
#include "DeviceParser.h"
#include "PolicyManager.h"
#include "UsageStateStore.h"
#include "VpnManager.h"
#include "resource.h"

#include <algorithm>
#include <commdlg.h>
#include <commctrl.h>
#include <sddl.h>
#include <windows.h>
#include <windowsx.h>

#include <cstdint>
#include <cwctype>
#include <exception>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>

namespace {
constexpr int IDC_DEVICE_LIST = 1001;
constexpr int IDC_REFRESH = 1002;
constexpr int IDC_USE = 1003;
constexpr int IDC_STOP = 1004;
constexpr int IDC_DIAGNOSTICS = 1005;
constexpr int IDC_EXPORT = 1007;
constexpr int IDC_EXPORT_JSON = 1008;
constexpr int IDC_STATUS = 1009;
constexpr int IDC_ASSIGN_USER = 1010;
constexpr int IDC_REMOVE_USER = 1011;
constexpr int IDC_SEARCH = 1012;
constexpr int IDC_CLEAR_SEARCH = 1013;
constexpr int IDC_OPEN_POLICY = 1014;
constexpr int IDC_SAVE_POLICY = 1015;
constexpr int IDC_COMPUTER = 1018;
constexpr int IDC_LOAD_COMPUTER = 1019;
constexpr int IDC_AVAILABLE_LIST = 1020;
constexpr int IDC_VPN_MAPPINGS = 1022;
constexpr UINT_PTR IDT_DELAYED_REFRESH = 2001;
constexpr UINT_PTR IDT_USAGE_WATCHDOG = 2002;
constexpr UINT_PTR IDT_USAGE_SYNC = 2003;
constexpr UINT_PTR IDT_AUTO_REFRESH = 2004;
constexpr UINT kRefreshRetryDelayMs = 3000;
constexpr unsigned int kMaximumAutomaticRefreshRetries = 10;
constexpr UINT WM_REFRESH_COMPLETE = WM_APP + 1;
constexpr UINT WM_COMPUTER_LOAD_COMPLETE = WM_APP + 2;
constexpr UINT WM_TOKEN_ACTION_COMPLETE = WM_APP + 3;
constexpr UINT WM_VPN_WATCHDOG_COMPLETE = WM_APP + 4;
constexpr UINT WM_REFRESH_PROGRESS = WM_APP + 5;
constexpr UINT WM_NETWORK_STATE_COMPLETE = WM_APP + 6;
constexpr UINT WM_TOKEN_ACTION_PROGRESS = WM_APP + 7;
constexpr LPARAM kTreeGroupParam = -1;
constexpr ULONGLONG kTokenSessionLimitMs = 20ULL * 60ULL * 1000ULL;
constexpr ULONGLONG kAutoReleaseRetryMs = 15ULL * 1000ULL;
constexpr ULONGLONG kTokenActionFailureCooldownMs = 60ULL * 1000ULL;
constexpr DWORD kTokenPromptTimeoutMs = 60 * 1000;
constexpr ULONGLONG kVpnWatchdogIntervalMs = 30ULL * 1000ULL;
constexpr int kMessageBoxTimeout = 32000;

#ifdef DISKCONTROL_ADMIN
constexpr bool kAdminBuild = true;
constexpr const wchar_t* kWindowTitle = L"DistControl Admin";
#else
constexpr bool kAdminBuild = false;
constexpr const wchar_t* kWindowTitle = L"DistControl";
#endif

HMENU controlId(int id) {
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

std::wstring widenAscii(const char* text) {
    std::wstring result;
    while (*text) {
        result.push_back(static_cast<unsigned char>(*text++));
    }
    return result;
}

bool containsAscii(const char* text, const char* needle) {
    return std::string(text).find(needle) != std::string::npos;
}

std::wstring userFriendlyErrorMessage(const char* error) {
    if (containsAscii(error, "VPN profile is disabled")) {
        return L"VPN-профиль для этого токена отключён администратором. Токен не подключён.";
    }
    if (containsAscii(error, "Network profile is not assigned to the token")) {
        return L"Для токена не выбран VPN Windows или режим «Без VPN». Обратитесь к администратору DistControl.";
    }
    if (containsAscii(error, "VPN profile mapping references an unknown profile")) {
        return L"Токену назначен VPN-профиль, которого нет в конфигурации. Токен не подключён; исправьте назначение в админке.";
    }
    if (containsAscii(error, "VPN Windows profile is not installed")) {
        return L"На компьютере не найден нужный профиль VPN Windows. Создайте его в параметрах Windows или обратитесь к администратору.";
    }
    if (containsAscii(error, "VPN credentials are not configured")) {
        return L"Не сохранены логин и пароль VPN. Обратитесь к администратору для настройки подключения в Windows.";
    }
    if (containsAscii(error, "RAS error 691")) {
        return L"VPN отклонил сохранённый логин или пароль. Обратитесь к администратору для проверки подключения в Windows.";
    }
    if (containsAscii(error, "RAS error 789")) {
        return L"Не удалось согласовать L2TP/IPsec. Проверьте общий ключ и параметры безопасности VPN в Windows.";
    }
    if (containsAscii(error, "RAS error 809")) {
        return L"VPN-сервер не отвечает. Проверьте интернет, адрес сервера и разрешение VPN в межсетевом экране.";
    }
    if (containsAscii(error, "RAS error 868")) {
        return L"Windows не смогла найти VPN-сервер. Проверьте имя или адрес сервера в свойствах подключения.";
    }
    if (containsAscii(error, "RAS error 812")) {
        return L"VPN-сервер отклонил подключение по своей политике. Обратитесь к администратору VPN.";
    }
    if (containsAscii(error, "RAS error 5") || containsAscii(error, "VPN profile enumeration")) {
        return L"Не удалось прочитать VPN-профили Windows. Проверьте права администратора и доступ к профилю пользователя или общей папке C$.";
    }
    if (containsAscii(error, "VPN local network routes were replaced")) {
        return L"VPN изменил маршруты локальной сети. Токен не подключён, VPN-сеанс остановлен, чтобы сохранить доступ к локальным ресурсам.";
    }
    if (containsAscii(error, "Direct network mode requires all Windows VPN connections")) {
        return L"Для этого токена требуется подключение без VPN, но в Windows осталось активное VPN-соединение. Токен не подключён.";
    }
    if (containsAscii(error, "Unexpected additional Windows VPN connection")) {
        return L"Одновременно активно лишнее VPN-подключение Windows. Токен не подключён.";
    }
    if (containsAscii(error, "VPN disconnect all timed out")) {
        return L"Windows не успела отключить все VPN-соединения. Токен не подключён; отключите VPN вручную и повторите попытку.";
    }
    if (containsAscii(error, "device catalog did not recover after VPN connection")) {
        return L"После подключения VPN служба DistKontrolUSB ещё не восстановила список устройств. Токен не подключён; подождите немного и повторите попытку.";
    }
    if (containsAscii(error, "device catalog is temporarily empty")) {
        return L"Служба DistKontrolUSB временно перестраивает список после изменения сети. Предыдущий список сохранён, обновление повторится автоматически.";
    }
    if (containsAscii(error, "VPN connection") || containsAscii(error, "VPN credential")) {
        return L"Не удалось подключить VPN. Проверьте профиль Windows, логин, пароль и доступность VPN-сервера.";
    }
    if (containsAscii(error, "Device is not allowed by policy")) {
        return L"Этот токен не разрешён текущему пользователю. Обратитесь к администратору DistControl.";
    }
    if (containsAscii(error, "The token is not connected by the current user")) {
        return L"Токен нельзя отключить из DistControl: сейчас он не закреплён за вашим пользователем.";
    }
    if (containsAscii(error, "The token is occupied by another user")) {
        return L"Токен уже занят другим пользователем. Обновите список, чтобы увидеть актуального владельца.";
    }
    if (containsAscii(error, "Another active token requires a different VPN profile")) {
        return L"Сначала отключите другой активный токен: он использует иной VPN-профиль.";
    }
    if (containsAscii(error, "Invalid address")) {
        return L"Служба DistKontrolUSB видит токен в списке, но пока не принимает его адрес после изменения сети. DistControl уже выполнил повторные попытки; проверьте доступность концентратора и повторите подключение.";
    }
    if (containsAscii(error, "DistKontrol returned FAILED") || containsAscii(error, "DistKontrol returned ERROR")) {
        return L"DistKontrolUSB отказал в операции. Обычно это значит, что токен уже занят, концентратор недоступен или служба dkclient работает с ошибкой.";
    }
    if (containsAscii(error, "pipe read timed out") || containsAscii(error, "pipe write timed out")) {
        return L"DistKontrolUSB слишком долго не отвечает. Подождите минуту, нажмите «Обновить» и проверьте службу dkclient, если ошибка повторится.";
    }
    if (containsAscii(error, "pipe is not available") || containsAscii(error, "Cannot open DistKontrol pipe")) {
        return L"Не удалось связаться со службой DistKontrolUSB. Проверьте, что служба dkclient запущена.";
    }
    if (containsAscii(error, "Cannot read response from DistKontrol pipe") ||
        containsAscii(error, "Cannot write command to DistKontrol pipe") ||
        containsAscii(error, "DistKontrol pipe operation failed")) {
        return L"Связь со службой DistKontrolUSB прервалась во время операции. Проверьте службу dkclient и подключение к USB-концентратору.";
    }
    if (containsAscii(error, "Cannot open config file")) {
        return L"Не удалось открыть файл доступа allow.json. Проверьте, что файл существует и доступен для чтения.";
    }
    if (containsAscii(error, "Config parent path is not a directory") ||
        containsAscii(error, "Cannot create config directory")) {
        return L"Не удалось подготовить папку с конфигурацией DistControl. Проверьте права на %LOCALAPPDATA%\\DistControl.";
    }
    if (containsAscii(error, "Invalid JSON") ||
        containsAscii(error, "Unexpected JSON") ||
        containsAscii(error, "Config root must be an object") ||
        containsAscii(error, "Config must contain userAssignments array")) {
        return L"Файл allow.json повреждён или имеет неправильный формат. Он не изменялся автоматически; исправьте файл или восстановите его резервную копию.";
    }
    if (containsAscii(error, "Timed out waiting for usage state lock")) {
        return L"Файл таймеров usage.json занят другим компьютером слишком долго. Повторите действие через несколько секунд.";
    }
    if (containsAscii(error, "usage state") || containsAscii(error, "Usage state")) {
        return L"Не удалось прочитать или обновить общий файл таймеров usage.json. Проверьте путь к общей папке и права на запись.";
    }
    if (containsAscii(error, "User name is required")) {
        return L"Не указан пользователь. Выберите пользователя и повторите действие.";
    }
    if (containsAscii(error, "Policy changed since it was loaded")) {
        return L"Конфигурация уже изменена другим администратором. Нажмите «Обновить», проверьте изменения и повторите сохранение.";
    }
    if (containsAscii(error, "Timed out waiting for policy write lock")) {
        return L"Другой администратор сейчас сохраняет конфигурацию. Подождите несколько секунд, обновите список и повторите действие.";
    }
    if (containsAscii(error, "Network profile id and Windows profile are required")) {
        return L"Не выбран профиль VPN Windows.";
    }
    return L"Произошла ошибка DistControl. Подробности записаны в журнал %LOCALAPPDATA%\\DistControl\\logs.";
}

void logUiError(const std::wstring& action, const char* technicalError, const std::wstring& userMessage) {
    AuditEvent event;
    event.action = action;
    event.result = L"ERROR";
    event.details = L"userMessage=" + userMessage + L"; technical=" + widenAscii(technicalError);
    AuditLogger::log(event);
}

std::wstring tokenActionErrorMessage(const char* error, bool connect) {
    if (containsAscii(error, "Cannot verify the previously connected token before switching VPN")) {
        return L"Не удалось проверить состояние предыдущего токена. Смена VPN и подключение нового токена остановлены; нажмите «Обновить» и повторите попытку.";
    }
    if (containsAscii(error, "Cannot verify the token catalog before switching VPN")) {
        return L"Не удалось полностью проверить активные токены. Чтобы не подключить два токена одновременно, смена VPN остановлена; нажмите «Обновить» и повторите попытку.";
    }
    if (containsAscii(error, "DistKontrol returned FAILED") || containsAscii(error, "DistKontrol returned ERROR")) {
        return connect
            ? L"DistKontrolUSB отказал в подключении токена. Проверьте, не занят ли токен, доступность USB-концентратора и права службы dkclient."
            : L"DistKontrolUSB отказал в отключении токена. Нажмите «Обновить» и проверьте состояние токена.";
    }
    if (containsAscii(error, "pipe read timed out")) {
        return connect
            ? L"Подключение токена заняло слишком много времени. DistKontrolUSB может ещё выполнять команду; подождите минуту и нажмите «Обновить». Если повторится, проверьте службу dkclient и связь с USB-концентратором."
            : L"Отключение токена заняло слишком много времени. Подождите минуту и нажмите «Обновить». Если токен остался подключён, проверьте службу dkclient.";
    }
    if (containsAscii(error, "pipe is not available") || containsAscii(error, "Cannot open DistKontrol pipe")) {
        return L"Не удалось связаться со службой DistKontrolUSB. Проверьте, что служба dkclient запущена.";
    }
    return (connect ? L"Ошибка подключения токена. " : L"Ошибка отключения токена. ") + userFriendlyErrorMessage(error);
}

std::wstring trim(const std::wstring& text) {
    const size_t first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) {
        return {};
    }
    const size_t last = text.find_last_not_of(L" \t\r\n");
    return text.substr(first, last - first + 1);
}

std::wstring dialogItemText(HWND dialog, int controlId) {
    const int length = GetWindowTextLengthW(GetDlgItem(dialog, controlId));
    std::wstring value(static_cast<size_t>(length) + 1, L'\0');
    GetDlgItemTextW(dialog, controlId, value.data(), length + 1);
    value.resize(static_cast<size_t>(length));
    return value;
}

bool sameWindowsVpnBinding(
    const VpnProfile& profile,
    const WindowsVpnProfileInfo& windowsProfile) {
    return profile.mode == VpnProfileMode::WindowsVpn &&
        profile.phonebookScope == windowsProfile.phonebookScope &&
        CompareStringOrdinal(
            profile.name.c_str(), static_cast<int>(profile.name.size()),
            windowsProfile.name.c_str(), static_cast<int>(windowsProfile.name.size()),
            TRUE) == CSTR_EQUAL;
}

std::wstring automaticVpnProfileId(
    const std::vector<VpnProfile>& profiles,
    VpnProfileMode mode,
    const WindowsVpnProfileInfo* windowsProfile) {
    for (const VpnProfile& existing : profiles) {
        if ((mode == VpnProfileMode::Direct && existing.mode == VpnProfileMode::Direct) ||
            (windowsProfile && sameWindowsVpnBinding(existing, *windowsProfile))) {
            return existing.id;
        }
    }

    const std::wstring base = mode == VpnProfileMode::Direct
        ? L"direct"
        : (windowsProfile->phonebookScope == VpnPhonebookScope::AllUsers
            ? L"windows-all:"
            : L"windows-user:") + windowsProfile->name;
    std::wstring candidate = base;
    for (unsigned int suffix = 2;; ++suffix) {
        const bool occupied = std::any_of(profiles.begin(), profiles.end(),
            [&candidate](const VpnProfile& profile) {
                return CompareStringOrdinal(
                    profile.id.c_str(), static_cast<int>(profile.id.size()),
                    candidate.c_str(), static_cast<int>(candidate.size()), TRUE) == CSTR_EQUAL;
            });
        if (!occupied) {
            return candidate;
        }
        candidate = base + L"-" + std::to_wstring(suffix);
    }
}

std::wstring windowsVpnDisplayName(const WindowsVpnProfileInfo& profile) {
    return profile.name + (profile.phonebookScope == VpnPhonebookScope::AllUsers
        ? L" [все пользователи]"
        : L" [пользователь]");
}
void addColumn(HWND listView, int index, int width, const wchar_t* title);
void setItemText(HWND listView, int row, int column, const std::wstring& text);
std::wstring lowerCopy(std::wstring text);
bool containsIgnoreCase(const std::wstring& text, const std::wstring& query);
void loadListColumnLayout(HWND listView, int columnCount, const wchar_t* layoutName);
void saveListColumnLayout(HWND listView, int columnCount, const wchar_t* layoutName);

struct VpnBulkDialogData {
    DeviceAccessService* service = nullptr;
    std::wstring userName;
    std::wstring expectedRevision;
    std::wstring savedRevision;
    std::vector<DeviceViewModel> devices;
    std::vector<VpnProfile> profiles;
    std::vector<WindowsVpnProfileInfo> windowsProfiles;
    HWND editorCombo = nullptr;
    size_t editedDeviceIndex = static_cast<size_t>(-1);
    std::vector<std::wstring> choiceNames;
    std::vector<LPARAM> choiceValues;
    std::wstring lastEditorText;
    bool filteringEditor = false;
    bool changed = false;
};

constexpr UINT WM_BULK_VPN_COMMIT = WM_APP + 40;

constexpr LPARAM kBulkVpnNotAssigned = -1;
constexpr LPARAM kBulkVpnDirect = -2;
constexpr LPARAM kBulkVpnUnavailable = -3;

const VpnProfile* bulkProfileById(
    const VpnBulkDialogData& data,
    const std::wstring& profileId) {
    const auto found = std::find_if(data.profiles.begin(), data.profiles.end(),
        [&profileId](const VpnProfile& profile) {
            return CompareStringOrdinal(profile.id.c_str(), -1,
                profileId.c_str(), -1, TRUE) == CSTR_EQUAL;
        });
    return found == data.profiles.end() ? nullptr : &*found;
}

const WindowsVpnProfileInfo* installedBulkVpnProfile(
    const VpnBulkDialogData& data,
    const VpnProfile& profile,
    size_t* index = nullptr) {
    for (size_t candidateIndex = 0; candidateIndex < data.windowsProfiles.size(); ++candidateIndex) {
        if (sameWindowsVpnBinding(profile, data.windowsProfiles[candidateIndex])) {
            if (index) {
                *index = candidateIndex;
            }
            return &data.windowsProfiles[candidateIndex];
        }
    }
    return nullptr;
}

std::wstring bulkVpnDisplayText(
    const VpnBulkDialogData& data,
    const DeviceViewModel& device) {
    if (device.vpnProfileId.empty()) {
        return L"Не назначен";
    }
    const VpnProfile* profile = bulkProfileById(data, device.vpnProfileId);
    if (!profile) {
        return L"Профиль недоступен: " + (device.vpnProfileDisplay.empty()
            ? device.vpnProfileId : device.vpnProfileDisplay);
    }
    if (profile->mode == VpnProfileMode::Direct) {
        return L"БЕЗ VPN";
    }
    if (!installedBulkVpnProfile(data, *profile)) {
        return L"Профиль недоступен: " +
            (profile->name.empty() ? profile->id : profile->name);
    }
    return profile->name;
}

void setBulkVpnRow(
    HWND list,
    int row,
    const VpnBulkDialogData& data,
    const DeviceViewModel& device) {
    setItemText(list, row, 0, device.nickname.empty() ? device.product : device.nickname);
    setItemText(list, row, 1, device.endpoint);
    setItemText(list, row, 2, bulkVpnDisplayText(data, device) + L"   ▼");
}

bool matchesBulkVpnSearch(
    const VpnBulkDialogData& data,
    const DeviceViewModel& device,
    const std::wstring& query) {
    if (query.empty()) {
        return true;
    }
    return containsIgnoreCase(device.nickname, query) ||
        containsIgnoreCase(device.product, query) ||
        containsIgnoreCase(device.endpoint, query) ||
        containsIgnoreCase(bulkVpnDisplayText(data, device), query);
}

std::wstring rawControlText(HWND hwnd) {
    const int length = GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(hwnd, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
    return text;
}

void hideBulkVpnEditor(VpnBulkDialogData& data) {
    if (data.editorCombo) {
        if (SendMessageW(data.editorCombo, CB_GETDROPPEDSTATE, 0, 0)) {
            SendMessageW(data.editorCombo, CB_SHOWDROPDOWN, FALSE, 0);
        }
        ShowWindow(data.editorCombo, SW_HIDE);
    }
    data.editedDeviceIndex = static_cast<size_t>(-1);
}

void populateBulkVpnList(HWND dialog, VpnBulkDialogData& data) {
    hideBulkVpnEditor(data);
    HWND list = GetDlgItem(dialog, IDC_VPN_BULK_LIST);
    const std::wstring query = trim(dialogItemText(dialog, IDC_VPN_BULK_SEARCH));
    ListView_DeleteAllItems(list);
    int row = 0;
    for (size_t index = 0; index < data.devices.size(); ++index) {
        if (!matchesBulkVpnSearch(data, data.devices[index], query)) {
            continue;
        }
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = row;
        item.lParam = static_cast<LPARAM>(index);
        item.pszText = const_cast<wchar_t*>(L"");
        ListView_InsertItem(list, &item);
        setBulkVpnRow(list, row, data, data.devices[index]);
        ++row;
    }
    const std::wstring count = L"Показано токенов: " + std::to_wstring(row) +
        L" из " + std::to_wstring(data.devices.size());
    SetDlgItemTextW(dialog, IDC_VPN_BULK_COUNT, count.c_str());
}

std::wstring normalizedVpnMatchName(std::wstring value) {
    value = lowerCopy(trim(value));
    if (value.rfind(L"vpn", 0) == 0) {
        value.erase(0, 3);
    }
    else if (value.rfind(L"впн", 0) == 0) {
        value.erase(0, 3);
    }
    std::wstring normalized;
    bool pendingSpace = false;
    for (wchar_t ch : value) {
        if (iswalnum(ch)) {
            if (pendingSpace && !normalized.empty()) {
                normalized.push_back(L' ');
            }
            normalized.push_back(ch);
            pendingSpace = false;
        }
        else {
            pendingSpace = true;
        }
    }
    return normalized;
}

VpnProfile ensureBulkVpnProfile(
    VpnBulkDialogData& data,
    const WindowsVpnProfileInfo& windowsProfile) {
    VpnProfile profile;
    profile.id = automaticVpnProfileId(
        data.profiles, VpnProfileMode::WindowsVpn, &windowsProfile);
    profile.name = windowsProfile.name;
    profile.serverAddress = windowsProfile.serverAddress;
    profile.tunnelType = windowsProfile.tunnelType;
    profile.phonebookScope = windowsProfile.phonebookScope;
    profile.enabled = true;

    const auto existing = std::find_if(data.profiles.begin(), data.profiles.end(),
        [&profile](const VpnProfile& candidate) {
            return CompareStringOrdinal(candidate.id.c_str(), -1,
                profile.id.c_str(), -1, TRUE) == CSTR_EQUAL;
        });
    if (existing == data.profiles.end()) {
        data.profiles.push_back(profile);
    }
    else {
        *existing = profile;
    }
    return profile;
}

VpnProfile ensureBulkDirectProfile(VpnBulkDialogData& data) {
    VpnProfile profile;
    profile.id = automaticVpnProfileId(data.profiles, VpnProfileMode::Direct, nullptr);
    profile.name = L"Без VPN";
    profile.mode = VpnProfileMode::Direct;
    profile.enabled = true;

    const auto existing = std::find_if(data.profiles.begin(), data.profiles.end(),
        [&profile](const VpnProfile& candidate) {
            return CompareStringOrdinal(candidate.id.c_str(), -1,
                profile.id.c_str(), -1, TRUE) == CSTR_EQUAL;
        });
    if (existing == data.profiles.end()) {
        data.profiles.push_back(profile);
    }
    else {
        *existing = profile;
    }
    return profile;
}

LRESULT addBulkVpnComboItem(HWND combo, const std::wstring& text, LPARAM value) {
    const LRESULT item = SendMessageW(
        combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str()));
    if (item != CB_ERR && item != CB_ERRSPACE) {
        SendMessageW(combo, CB_SETITEMDATA, item, value);
    }
    return item;
}

bool bulkVpnEditorSelection(
    VpnBulkDialogData& data,
    DeviceViewModel& device,
    LRESULT choice) {
    const std::wstring oldId = device.vpnProfileId;
    if (choice == kBulkVpnNotAssigned) {
        device.vpnProfileId.clear();
        device.vpnProfileDisplay.clear();
    }
    else if (choice == kBulkVpnDirect) {
        const VpnProfile profile = ensureBulkDirectProfile(data);
        device.vpnProfileId = profile.id;
        device.vpnProfileDisplay = L"Без VPN";
    }
    else if (choice >= 0 && static_cast<size_t>(choice) < data.windowsProfiles.size()) {
        const VpnProfile profile = ensureBulkVpnProfile(
            data, data.windowsProfiles[static_cast<size_t>(choice)]);
        device.vpnProfileId = profile.id;
        device.vpnProfileDisplay = profile.name;
    }
    return CompareStringOrdinal(oldId.c_str(), -1,
        device.vpnProfileId.c_str(), -1, TRUE) != CSTR_EQUAL;
}

bool applyBulkVpnChoice(HWND list, VpnBulkDialogData& data, LPARAM choice) {
    if (data.editedDeviceIndex >= data.devices.size() || choice == kBulkVpnUnavailable) {
        return false;
    }

    DeviceViewModel& device = data.devices[data.editedDeviceIndex];
    data.changed = bulkVpnEditorSelection(data, device, choice) || data.changed;
    for (int row = 0; row < ListView_GetItemCount(list); ++row) {
        LVITEMW item{};
        item.mask = LVIF_PARAM;
        item.iItem = row;
        if (ListView_GetItem(list, &item) && item.lParam >= 0 &&
            static_cast<size_t>(item.lParam) == data.editedDeviceIndex) {
            setBulkVpnRow(list, row, data, device);
            return true;
        }
    }
    return true;
}

void showBulkVpnEditor(
    HWND dialog,
    VpnBulkDialogData& data,
    int row) {
    HWND list = GetDlgItem(dialog, IDC_VPN_BULK_LIST);
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = row;
    if (!ListView_GetItem(list, &item) || item.lParam < 0 ||
        static_cast<size_t>(item.lParam) >= data.devices.size()) {
        return;
    }
    const size_t deviceIndex = static_cast<size_t>(item.lParam);
    const DeviceViewModel& device = data.devices[deviceIndex];

    HWND combo = data.editorCombo;
    data.choiceNames = { L"Не назначен", L"БЕЗ VPN" };
    data.choiceValues = { kBulkVpnNotAssigned, kBulkVpnDirect };
    for (size_t index = 0; index < data.windowsProfiles.size(); ++index) {
        data.choiceNames.push_back(windowsVpnDisplayName(data.windowsProfiles[index]));
        data.choiceValues.push_back(static_cast<LPARAM>(index));
    }
    data.filteringEditor = true;
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    const LRESULT unassignedItem = addBulkVpnComboItem(
        combo, data.choiceNames[0], kBulkVpnNotAssigned);
    const LRESULT directItem = addBulkVpnComboItem(combo, data.choiceNames[1], kBulkVpnDirect);
    std::vector<LRESULT> windowsItems;
    windowsItems.reserve(data.windowsProfiles.size());
    for (size_t index = 0; index < data.windowsProfiles.size(); ++index) {
        windowsItems.push_back(addBulkVpnComboItem(
            combo, data.choiceNames[index + 2], static_cast<LPARAM>(index)));
    }

    LRESULT selectedItem = unassignedItem;
    const VpnProfile* currentProfile = bulkProfileById(data, device.vpnProfileId);
    if (currentProfile && currentProfile->mode == VpnProfileMode::Direct) {
        selectedItem = directItem;
    }
    else if (currentProfile) {
        size_t windowsIndex = 0;
        if (installedBulkVpnProfile(data, *currentProfile, &windowsIndex)) {
            selectedItem = windowsItems[windowsIndex];
        }
        else {
            selectedItem = addBulkVpnComboItem(
                combo,
                L"Профиль недоступен: " + (currentProfile->name.empty()
                    ? currentProfile->id : currentProfile->name),
                kBulkVpnUnavailable);
        }
    }
    else if (!device.vpnProfileId.empty()) {
        selectedItem = addBulkVpnComboItem(combo,
            L"Профиль недоступен: " + device.vpnProfileId, kBulkVpnUnavailable);
    }

    RECT cell{};
    ListView_EnsureVisible(list, row, FALSE);
    if (!ListView_GetSubItemRect(list, row, 2, LVIR_BOUNDS, &cell)) {
        return;
    }
    MapWindowPoints(list, dialog, reinterpret_cast<POINT*>(&cell), 2);
    data.editedDeviceIndex = deviceIndex;
    SendMessageW(combo, CB_SETCURSEL, selectedItem, 0);
    data.filteringEditor = false;
    data.lastEditorText = rawControlText(combo);
    // Keep the whole editor, including its drop-down button, inside the
    // visible part of the list even when the VPN column is partly scrolled out.
    RECT listClient{};
    GetClientRect(list, &listClient);
    MapWindowPoints(list, dialog, reinterpret_cast<POINT*>(&listClient), 2);
    const int editorRight = (std::min)(static_cast<int>(cell.right), static_cast<int>(listClient.right));
    const int editorLeft = (std::max)(static_cast<int>(listClient.left),
        (std::min)(static_cast<int>(cell.left), editorRight - 200));
    SendMessageW(combo, CB_SETDROPPEDWIDTH, 420, 0);
    SetWindowPos(combo, HWND_TOP, editorLeft, cell.top - 1,
        editorRight - editorLeft, 320, SWP_SHOWWINDOW);
    SetFocus(combo);
    SendMessageW(combo, CB_SETEDITSEL, 0, MAKELPARAM(0, -1));
    SetDlgItemTextW(dialog, IDC_VPN_BULK_HINT,
        L"Откройте список кнопкой ▼ (или F4) либо вставьте скопированное название (Ctrl+V) и нажмите Enter. "
        L"Esc — отмена.");
}

void filterBulkVpnEditor(HWND dialog, VpnBulkDialogData& data) {
    if (data.filteringEditor || !data.editorCombo || data.editedDeviceIndex >= data.devices.size()) {
        return;
    }
    HWND combo = data.editorCombo;
    const std::wstring text = rawControlText(combo);
    const bool pasted = text.size() > data.lastEditorText.size() + 1;
    data.lastEditorText = text;
    const VpnNameMatch match = matchVpnChoiceName(data.choiceNames, text);

    DWORD selectionStart = 0;
    DWORD selectionEnd = 0;
    SendMessageW(combo, CB_GETEDITSEL,
        reinterpret_cast<WPARAM>(&selectionStart), reinterpret_cast<LPARAM>(&selectionEnd));

    data.filteringEditor = true;
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    for (size_t index : match.candidates) {
        addBulkVpnComboItem(combo, data.choiceNames[index], data.choiceValues[index]);
    }
    if (!match.candidates.empty() && !SendMessageW(combo, CB_GETDROPPEDSTATE, 0, 0)) {
        SendMessageW(combo, CB_SHOWDROPDOWN, TRUE, 0);
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
    }
    SetWindowTextW(combo, text.c_str());
    SendMessageW(combo, CB_SETEDITSEL, 0, MAKELPARAM(selectionStart, selectionEnd));
    data.filteringEditor = false;

    std::wstring hint;
    if (normalizeVpnChoiceText(text).empty()) {
        hint = L"Введите или вставьте название VPN.";
    }
    else if (match.kind == VpnNameMatchKind::Exact) {
        hint = L"Найдено: " + data.choiceNames[match.index] + L". Нажмите Enter, чтобы назначить.";
    }
    else if (match.kind == VpnNameMatchKind::Unique) {
        hint = L"Подходит один вариант: " + data.choiceNames[match.index] +
            L". Нажмите Enter, чтобы назначить.";
    }
    else if (match.kind == VpnNameMatchKind::Ambiguous) {
        hint = L"Подходит вариантов: " + std::to_wstring(match.candidates.size()) +
            L". Выберите нужный в списке.";
    }
    else {
        hint = L"⚠ VPN «" + trim(text) + L"» не найден среди подключений Windows. Проверьте название.";
    }
    SetDlgItemTextW(dialog, IDC_VPN_BULK_HINT, hint.c_str());

    if (pasted && match.kind == VpnNameMatchKind::Exact) {
        PostMessageW(dialog, WM_BULK_VPN_COMMIT, TRUE, 0);
    }
}

// Applies the editor value to the edited token. Returns false and leaves the
// mapping unchanged when the text does not identify exactly one choice.
bool commitBulkVpnEditor(HWND dialog, VpnBulkDialogData& data) {
    if (!data.editorCombo || !IsWindowVisible(data.editorCombo) ||
        data.editedDeviceIndex >= data.devices.size()) {
        return true;
    }
    HWND combo = data.editorCombo;
    HWND list = GetDlgItem(dialog, IDC_VPN_BULK_LIST);
    const std::wstring text = rawControlText(combo);

    LPARAM choice = kBulkVpnUnavailable;
    std::wstring chosenName;
    const LRESULT selection = SendMessageW(combo, CB_GETCURSEL, 0, 0);
    if (selection != CB_ERR) {
        const int length = (std::max)(static_cast<int>(SendMessageW(combo, CB_GETLBTEXTLEN, selection, 0)), 0);
        std::wstring itemText(static_cast<size_t>(length) + 1, L'\0');
        SendMessageW(combo, CB_GETLBTEXT, selection, reinterpret_cast<LPARAM>(itemText.data()));
        itemText.resize(static_cast<size_t>(length));
        if (normalizeVpnChoiceText(itemText) == normalizeVpnChoiceText(text)) {
            choice = SendMessageW(combo, CB_GETITEMDATA, selection, 0);
            chosenName = itemText;
        }
    }
    if (choice == kBulkVpnUnavailable && selection != CB_ERR &&
        SendMessageW(combo, CB_GETITEMDATA, selection, 0) == kBulkVpnUnavailable &&
        text == data.lastEditorText) {
        // The current mapping points to a missing profile and was not edited.
        hideBulkVpnEditor(data);
        return true;
    }
    if (choice == kBulkVpnUnavailable) {
        if (normalizeVpnChoiceText(text).empty()) {
            hideBulkVpnEditor(data);
            return true;
        }
        const VpnNameMatch match = matchVpnChoiceName(data.choiceNames, text);
        if (match.kind != VpnNameMatchKind::Exact && match.kind != VpnNameMatchKind::Unique) {
            const std::wstring warning = match.kind == VpnNameMatchKind::Ambiguous
                ? L"⚠ Название «" + trim(text) + L"» подходит к нескольким VPN. Выберите нужный в списке. Сопоставление не изменено."
                : L"⚠ VPN «" + trim(text) + L"» не найден среди подключений Windows. Сопоставление не изменено.";
            SetDlgItemTextW(dialog, IDC_VPN_BULK_HINT, warning.c_str());
            MessageBeep(MB_ICONWARNING);
            return false;
        }
        choice = data.choiceValues[match.index];
        chosenName = data.choiceNames[match.index];
    }

    const DeviceViewModel& device = data.devices[data.editedDeviceIndex];
    const std::wstring tokenName = device.nickname.empty() ? device.product : device.nickname;
    applyBulkVpnChoice(list, data, choice);
    hideBulkVpnEditor(data);
    const std::wstring done = L"Назначено: " + tokenName + L" → " + chosenName +
        L". Не забудьте нажать «Сохранить».";
    SetDlgItemTextW(dialog, IDC_VPN_BULK_HINT, done.c_str());
    return true;
}

INT_PTR CALLBACK vpnBulkDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* data = reinterpret_cast<VpnBulkDialogData*>(GetWindowLongPtrW(dialog, DWLP_USER));
    if (message == WM_INITDIALOG) {
        data = reinterpret_cast<VpnBulkDialogData*>(lParam);
        SetWindowLongPtrW(dialog, DWLP_USER, reinterpret_cast<LONG_PTR>(data));
        SetDlgItemTextW(dialog, IDC_VPN_BULK_USER, data->userName.c_str());

        HWND list = GetDlgItem(dialog, IDC_VPN_BULK_LIST);
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
        addColumn(list, 0, 210, L"Название токена");
        addColumn(list, 1, 170, L"Endpoint");
        addColumn(list, 2, 250, L"VPN");
        loadListColumnLayout(list, 3, L"VpnMappings");
        data->editorCombo = CreateWindowExW(
            0, WC_COMBOBOXW, L"",
            WS_CHILD | WS_VSCROLL | WS_TABSTOP | CBS_DROPDOWN | CBS_AUTOHSCROLL,
            0, 0, 0, 0, dialog,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_VPN_BULK_EDITOR)),
            reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(dialog, GWLP_HINSTANCE)), nullptr);
        SendMessageW(data->editorCombo, CB_SETMINVISIBLE, 20, 0);
        SendMessageW(data->editorCombo, WM_SETFONT,
            SendMessageW(dialog, WM_GETFONT, 0, 0), FALSE);
        populateBulkVpnList(dialog, *data);
        return TRUE;
    }
    if (!data) {
        return FALSE;
    }

    HWND list = GetDlgItem(dialog, IDC_VPN_BULK_LIST);
    if (message == WM_NOTIFY && reinterpret_cast<NMHDR*>(lParam)->hwndFrom == list) {
        const auto* header = reinterpret_cast<NMHDR*>(lParam);
        if (header->code == NM_CLICK || header->code == NM_DBLCLK) {
            const auto* activate = reinterpret_cast<NMITEMACTIVATE*>(lParam);
            if (IsWindowVisible(data->editorCombo) && !commitBulkVpnEditor(dialog, *data)) {
                hideBulkVpnEditor(*data);
            }
            if (activate->iItem >= 0 && activate->iSubItem == 2) {
                showBulkVpnEditor(dialog, *data, activate->iItem);
            }
            else {
                hideBulkVpnEditor(*data);
            }
            return TRUE;
        }
        if (header->code == LVN_KEYDOWN) {
            const auto* key = reinterpret_cast<NMLVKEYDOWN*>(lParam);
            if (key->wVKey == VK_RETURN || key->wVKey == VK_SPACE || key->wVKey == VK_F2) {
                const int row = ListView_GetNextItem(list, -1, LVNI_SELECTED);
                if (row >= 0) {
                    showBulkVpnEditor(dialog, *data, row);
                }
                return TRUE;
            }
        }
        if (header->code == LVN_BEGINSCROLL) {
            hideBulkVpnEditor(*data);
            return TRUE;
        }
    }

    if (message == WM_COMMAND) {
        if (LOWORD(wParam) == IDC_VPN_BULK_SEARCH && HIWORD(wParam) == EN_CHANGE) {
            populateBulkVpnList(dialog, *data);
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VPN_BULK_CLEAR_SEARCH) {
            SetDlgItemTextW(dialog, IDC_VPN_BULK_SEARCH, L"");
            SetFocus(GetDlgItem(dialog, IDC_VPN_BULK_SEARCH));
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VPN_BULK_EDITOR && HIWORD(wParam) == CBN_EDITUPDATE) {
            filterBulkVpnEditor(dialog, *data);
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VPN_BULK_EDITOR && HIWORD(wParam) == CBN_SELENDOK &&
            !data->filteringEditor && IsWindowVisible(data->editorCombo)) {
            PostMessageW(dialog, WM_BULK_VPN_COMMIT, TRUE, 0);
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VPN_BULK_EDITOR && HIWORD(wParam) == CBN_SELENDCANCEL &&
            (GetKeyState(VK_ESCAPE) & 0x8000) != 0) {
            hideBulkVpnEditor(*data);
            SetDlgItemTextW(dialog, IDC_VPN_BULK_HINT, L"Изменение VPN отменено.");
            SetFocus(list);
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VPN_BULK_EDITOR && HIWORD(wParam) == CBN_KILLFOCUS &&
            IsWindowVisible(data->editorCombo)) {
            PostMessageW(dialog, WM_BULK_VPN_COMMIT, FALSE, 0);
            return TRUE;
        }

        if (LOWORD(wParam) == IDC_VPN_BULK_AUTO_MATCH) {
            size_t matchedCount = 0;
            for (DeviceViewModel& device : data->devices) {
                if (!device.vpnProfileId.empty()) {
                    continue;
                }
                const std::wstring tokenName = normalizedVpnMatchName(
                    device.nickname.empty() ? device.product : device.nickname);
                if (tokenName.empty()) {
                    continue;
                }
                const WindowsVpnProfileInfo* uniqueMatch = nullptr;
                bool ambiguous = false;
                for (const WindowsVpnProfileInfo& windowsProfile : data->windowsProfiles) {
                    if (normalizedVpnMatchName(windowsProfile.name) != tokenName) {
                        continue;
                    }
                    if (uniqueMatch) {
                        ambiguous = true;
                        break;
                    }
                    uniqueMatch = &windowsProfile;
                }
                if (!uniqueMatch || ambiguous) {
                    continue;
                }
                const VpnProfile profile = ensureBulkVpnProfile(*data, *uniqueMatch);
                device.vpnProfileId = profile.id;
                device.vpnProfileDisplay = profile.name;
                ++matchedCount;
            }
            populateBulkVpnList(dialog, *data);
            data->changed = data->changed || matchedCount != 0;
            const std::wstring messageText = matchedCount == 0
                ? L"Для неназначенных токенов однозначных совпадений не найдено."
                : L"Автоматически сопоставлено: " + std::to_wstring(matchedCount) +
                    L". Проверьте таблицу и нажмите «Сохранить».";
            MessageBoxW(dialog, messageText.c_str(), L"DistControl Admin",
                MB_OK | MB_ICONINFORMATION);
            return TRUE;
        }

        if (LOWORD(wParam) == IDC_VPN_BULK_SAVE && IsWindowVisible(data->editorCombo) &&
            IsChild(data->editorCombo, GetFocus())) {
            // Enter in the VPN editor confirms the typed value instead of saving.
            PostMessageW(dialog, WM_BULK_VPN_COMMIT, TRUE, 0);
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VPN_BULK_SAVE) {
            if (!commitBulkVpnEditor(dialog, *data)) {
                return TRUE;
            }
            if (!data->changed) {
                EndDialog(dialog, IDCANCEL);
                return TRUE;
            }
            try {
                data->savedRevision = data->service->saveVpnAssignmentsForDevices(
                    data->profiles, data->devices, data->userName, data->expectedRevision);
                EndDialog(dialog, IDOK);
            }
            catch (const std::exception& error) {
                const std::wstring errorMessage = L"Не удалось сохранить сопоставления. " +
                    userFriendlyErrorMessage(error.what());
                logUiError(L"UI BULK VPN SAVE ERROR", error.what(), errorMessage);
                MessageBoxW(dialog, errorMessage.c_str(), L"DistControl Admin",
                    MB_OK | MB_ICONERROR);
            }
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL && IsWindowVisible(data->editorCombo)) {
            hideBulkVpnEditor(*data);
            SetDlgItemTextW(dialog, IDC_VPN_BULK_HINT, L"Изменение VPN отменено.");
            SetFocus(list);
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            if (data->changed && MessageBoxW(dialog,
                    L"Есть несохранённые сопоставления. Закрыть окно без сохранения?",
                    L"DistControl Admin", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
                return TRUE;
            }
            EndDialog(dialog, IDCANCEL);
            return TRUE;
        }
    }
    if (message == WM_BULK_VPN_COMMIT) {
        if (!IsWindowVisible(data->editorCombo)) {
            return TRUE;
        }
        const bool keepEditing = wParam != FALSE;
        if (commitBulkVpnEditor(dialog, *data)) {
            SetFocus(list);
        }
        else if (keepEditing) {
            SetFocus(data->editorCombo);
        }
        else {
            hideBulkVpnEditor(*data);
        }
        return TRUE;
    }
    if (message == WM_DESTROY) {
        saveListColumnLayout(list, 3, L"VpnMappings");
        return TRUE;
    }
    return FALSE;
}

std::wstring getControlText(HWND hwnd) {
    const int length = GetWindowTextLengthW(hwnd);
    std::wstring buffer(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(hwnd, buffer.data(), length + 1);
    buffer.resize(static_cast<size_t>(length));
    return trim(buffer);
}

std::wstring lowerCopy(std::wstring text) {
    if (!text.empty()) {
        CharLowerBuffW(text.data(), static_cast<DWORD>(text.size()));
    }
    return text;
}

bool containsIgnoreCase(const std::wstring& text, const std::wstring& query) {
    if (query.empty()) {
        return true;
    }
    return lowerCopy(text).find(lowerCopy(query)) != std::wstring::npos;
}

bool matchesSearch(const DeviceViewModel& device, const std::wstring& query) {
    return containsIgnoreCase(device.endpoint, query) ||
        containsIgnoreCase(device.nickname, query) ||
        containsIgnoreCase(device.product, query) ||
        containsIgnoreCase(device.vpnProfileId, query) ||
        containsIgnoreCase(device.vpnProfileDisplay, query) ||
        containsIgnoreCase(device.statusText, query) ||
        containsIgnoreCase(device.usedBy, query) ||
        containsIgnoreCase(device.usedAt, query);
}

std::wstring endpointGroupName(const std::wstring& endpoint);
std::wstring adminEndpointGroupName(const std::wstring& endpoint);
std::wstring adminRemainingText(const DeviceViewModel& device);
void updateAdminListTimers(HWND listView, const std::vector<DeviceViewModel>& devices);

void addColumn(HWND listView, int index, int width, const wchar_t* title) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<wchar_t*>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(listView, index, &column);
}

std::wstring columnLayoutSettingsPath() {
    wchar_t localAppData[32768]{};
    const DWORD length = GetEnvironmentVariableW(
        L"LOCALAPPDATA", localAppData, static_cast<DWORD>(std::size(localAppData)));
    if (length == 0 || length >= std::size(localAppData)) {
        return {};
    }
    const std::wstring directory = std::wstring(localAppData) + L"\\DistControl";
    CreateDirectoryW(directory.c_str(), nullptr);
    return directory + L"\\admin-ui.ini";
}

std::vector<int> parseColumnLayout(const std::wstring& text, int columnCount) {
    std::vector<int> values;
    std::wistringstream stream(text);
    std::wstring part;
    while (std::getline(stream, part, L',')) {
        try {
            size_t consumed = 0;
            const int value = std::stoi(trim(part), &consumed);
            if (consumed == trim(part).size()) {
                values.push_back(value);
            }
        }
        catch (...) {
            return {};
        }
    }
    return values.size() == static_cast<size_t>(columnCount) ? values : std::vector<int>{};
}

std::wstring serializeColumnLayout(const std::vector<int>& values) {
    std::wstring result;
    for (int value : values) {
        if (!result.empty()) {
            result += L',';
        }
        result += std::to_wstring(value);
    }
    return result;
}

void loadListColumnLayout(HWND listView, int columnCount, const wchar_t* layoutName) {
    const std::wstring settingsPath = columnLayoutSettingsPath();
    if (settingsPath.empty() || !listView || columnCount <= 0) {
        return;
    }
    wchar_t orderBuffer[512]{};
    wchar_t widthsBuffer[512]{};
    const std::wstring orderKey = std::wstring(layoutName) + L"Order";
    const std::wstring widthsKey = std::wstring(layoutName) + L"Widths";
    GetPrivateProfileStringW(L"Columns", orderKey.c_str(), L"", orderBuffer,
        static_cast<DWORD>(std::size(orderBuffer)), settingsPath.c_str());
    GetPrivateProfileStringW(L"Columns", widthsKey.c_str(), L"", widthsBuffer,
        static_cast<DWORD>(std::size(widthsBuffer)), settingsPath.c_str());

    const std::vector<int> order = parseColumnLayout(orderBuffer, columnCount);
    if (!order.empty()) {
        std::vector<bool> seen(static_cast<size_t>(columnCount), false);
        bool valid = true;
        for (int value : order) {
            if (value < 0 || value >= columnCount || seen[static_cast<size_t>(value)]) {
                valid = false;
                break;
            }
            seen[static_cast<size_t>(value)] = true;
        }
        if (valid) {
            ListView_SetColumnOrderArray(listView, columnCount, const_cast<int*>(order.data()));
        }
    }

    const std::vector<int> widths = parseColumnLayout(widthsBuffer, columnCount);
    if (!widths.empty()) {
        for (int index = 0; index < columnCount; ++index) {
            const int width = widths[static_cast<size_t>(index)];
            if (width >= 40 && width <= 1200) {
                ListView_SetColumnWidth(listView, index, width);
            }
        }
    }
}

void saveListColumnLayout(HWND listView, int columnCount, const wchar_t* layoutName) {
    const std::wstring settingsPath = columnLayoutSettingsPath();
    if (settingsPath.empty() || !listView || columnCount <= 0) {
        return;
    }
    std::vector<int> order(static_cast<size_t>(columnCount));
    if (!ListView_GetColumnOrderArray(listView, columnCount, order.data())) {
        return;
    }
    std::vector<int> widths(static_cast<size_t>(columnCount));
    for (int index = 0; index < columnCount; ++index) {
        widths[static_cast<size_t>(index)] = ListView_GetColumnWidth(listView, index);
    }
    const std::wstring orderKey = std::wstring(layoutName) + L"Order";
    const std::wstring widthsKey = std::wstring(layoutName) + L"Widths";
    const std::wstring orderText = serializeColumnLayout(order);
    const std::wstring widthsText = serializeColumnLayout(widths);
    WritePrivateProfileStringW(
        L"Columns", orderKey.c_str(), orderText.c_str(), settingsPath.c_str());
    WritePrivateProfileStringW(
        L"Columns", widthsKey.c_str(), widthsText.c_str(), settingsPath.c_str());
}

void setItemText(HWND listView, int row, int column, const std::wstring& text) {
    ListView_SetItemText(listView, row, column, const_cast<wchar_t*>(text.c_str()));
}

void setItemTextIfChanged(HWND listView, int row, int column, const std::wstring& text) {
    wchar_t current[256]{};
    ListView_GetItemText(listView, row, column, current, static_cast<int>(std::size(current)));
    if (text != current) {
        setItemText(listView, row, column, text);
    }
}

void addDeviceColumns(HWND listView, bool includeAccessColumn) {
    addColumn(listView, 0, 170, L"Endpoint");
    addColumn(listView, 1, 190, L"Имя");
    addColumn(listView, 2, 150, L"VPN");
    addColumn(listView, 3, 110, L"Состояние");
    addColumn(listView, 4, 150, L"Кем занят");
    addColumn(listView, 5, 120, L"Адрес");
    addColumn(listView, 6, 110, L"Осталось");
    addColumn(listView, 7, 110, L"Продукт");
    if (includeAccessColumn) {
        addColumn(listView, 8, 100, L"Доступ");
    }
}

std::wstring networkProfileText(const DeviceViewModel& device) {
    if (!device.vpnProfileDisplay.empty()) {
        return device.vpnProfileDisplay;
    }
    return device.vpnProfileId.empty() ? std::wstring{} : L"Неизвестная настройка";
}

void insertDeviceRow(HWND listView, int row, const DeviceViewModel& device, bool includeAccessColumn) {
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.pszText = const_cast<wchar_t*>(device.endpoint.c_str());
    ListView_InsertItem(listView, &item);
    setItemText(listView, row, 1, device.nickname);
    setItemText(listView, row, 2, networkProfileText(device));
    setItemText(listView, row, 3, device.statusText);
    setItemText(listView, row, 4, device.usedBy);
    setItemText(listView, row, 5, device.usedAt);
    setItemText(listView, row, 6, adminRemainingText(device));
    setItemText(listView, row, 7, device.product);
    if (includeAccessColumn) {
        setItemText(listView, row, 8, device.allowed ? L"Разрешён" : L"Запрещён");
    }
}

void populateGroupedDeviceList(HWND listView, const std::vector<DeviceViewModel>& devices) {
    ListView_DeleteAllItems(listView);
    ListView_RemoveAllGroups(listView);
    ListView_EnableGroupView(listView, TRUE);

    std::map<std::wstring, int> groupIds;
    int nextGroupId = 1;
    for (const DeviceViewModel& device : devices) {
        const std::wstring groupName = adminEndpointGroupName(device.endpoint);
        if (groupIds.find(groupName) != groupIds.end()) {
            continue;
        }

        const int groupId = nextGroupId++;
        LVGROUP group{};
        group.cbSize = sizeof(group);
        group.mask = LVGF_HEADER | LVGF_GROUPID;
        group.pszHeader = const_cast<wchar_t*>(groupName.c_str());
        group.iGroupId = groupId;
        ListView_InsertGroup(listView, -1, &group);
        groupIds.emplace(groupName, groupId);
    }

    for (size_t i = 0; i < devices.size(); ++i) {
        const DeviceViewModel& device = devices[i];
        const std::wstring groupName = adminEndpointGroupName(device.endpoint);
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_GROUPID;
        item.iItem = static_cast<int>(i);
        item.iGroupId = groupIds[groupName];
        item.pszText = const_cast<wchar_t*>(device.endpoint.c_str());
        ListView_InsertItem(listView, &item);
        setItemText(listView, static_cast<int>(i), 1, device.nickname);
        setItemText(listView, static_cast<int>(i), 2, networkProfileText(device));
        setItemText(listView, static_cast<int>(i), 3, device.statusText);
        setItemText(listView, static_cast<int>(i), 4, device.usedBy);
        setItemText(listView, static_cast<int>(i), 5, device.usedAt);
        setItemText(listView, static_cast<int>(i), 6, adminRemainingText(device));
        setItemText(listView, static_cast<int>(i), 7, device.product);
    }
}

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr) != size) {
        return {};
    }
    result.resize(static_cast<size_t>(size - 1));
    return result;
}

std::string csvEscape(const std::wstring& value) {
    std::string text = wideToUtf8(value);
    bool mustQuote = false;
    for (char ch : text) {
        if (ch == '"' || ch == ',' || ch == '\n' || ch == '\r') {
            mustQuote = true;
            break;
        }
    }
    if (!mustQuote) {
        return text;
    }

    std::string escaped = "\"";
    for (char ch : text) {
        escaped += ch == '"' ? "\"\"" : std::string(1, ch);
    }
    escaped.push_back('"');
    return escaped;
}

std::string htmlEscape(const std::wstring& value) {
    std::string text = wideToUtf8(value);
    std::string escaped;
    escaped.reserve(text.size());
    for (char ch : text) {
        switch (ch) {
        case '&': escaped += "&amp;"; break;
        case '<': escaped += "&lt;"; break;
        case '>': escaped += "&gt;"; break;
        case '"': escaped += "&quot;"; break;
        default: escaped.push_back(ch); break;
        }
    }
    return escaped;
}

std::string jsonEscape(const std::wstring& value) {
    std::string text = wideToUtf8(value);
    std::string escaped = "\"";
    for (unsigned char ch : text) {
        switch (ch) {
        case '"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (ch < 0x20) {
                const char* digits = "0123456789abcdef";
                escaped += "\\u00";
                escaped.push_back(digits[(ch >> 4) & 0x0F]);
                escaped.push_back(digits[ch & 0x0F]);
            }
            else {
                escaped.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    escaped.push_back('"');
    return escaped;
}

std::wstring currentComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (GetComputerNameW(buffer, &size)) {
        return buffer;
    }
    return {};
}

std::wstring currentDomainPrefix() {
    const std::wstring currentUser = PolicyManager::currentUserName();
    const size_t slash = currentUser.find(L'\\');
    if (slash == std::wstring::npos || slash == 0) {
        return {};
    }
    return currentUser.substr(0, slash + 1);
}

bool isLocalComputerName(const std::wstring& computerName) {
    const std::wstring trimmed = trim(computerName);
    if (trimmed.empty() || trimmed == L"." || trimmed == L"localhost") {
        return true;
    }
    return lowerCopy(trimmed) == lowerCopy(currentComputerName());
}

std::wstring profilesRootForComputer(const std::wstring& computerName) {
    const std::wstring trimmed = trim(computerName);
    if (isLocalComputerName(trimmed)) {
        return L"C:\\Users";
    }
    return L"\\\\" + trimmed + L"\\c$\\Users";
}

std::wstring profileFolderName(const std::wstring& userName) {
    const size_t slash = userName.find_last_of(L"\\/");
    return slash == std::wstring::npos ? userName : userName.substr(slash + 1);
}

bool isSystemProfileName(const std::wstring& name);
std::vector<std::wstring> profileUsersFromRoot(const std::wstring& root);

std::wstring accountNameForSid(const std::wstring& computerName, const std::wstring& sidText) {
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(sidText.c_str(), &sid)) {
        return {};
    }

    DWORD nameLength = 0;
    DWORD domainLength = 0;
    SID_NAME_USE use{};
    const std::wstring lookupComputer = trim(computerName);
    const wchar_t* systemName = isLocalComputerName(computerName) ? nullptr : lookupComputer.c_str();
    LookupAccountSidW(systemName, sid, nullptr, &nameLength, nullptr, &domainLength, &use);
    std::vector<wchar_t> name(nameLength + 1);
    std::vector<wchar_t> domain(domainLength + 1);
    std::wstring result;
    if (nameLength != 0 && LookupAccountSidW(
            systemName, sid, name.data(), &nameLength, domain.data(), &domainLength, &use)) {
        result = domainLength == 0
            ? std::wstring(name.data())
            : std::wstring(domain.data()) + L"\\" + name.data();
    }
    LocalFree(sid);
    return result;
}

std::wstring expandLocalProfilePath(const std::wstring& path) {
    wchar_t expanded[32768]{};
    const DWORD length = ExpandEnvironmentStringsW(
        path.c_str(), expanded, static_cast<DWORD>(std::size(expanded)));
    return length != 0 && length < std::size(expanded) ? std::wstring(expanded) : path;
}

std::wstring accessibleProfilePath(
    const std::wstring& computerName,
    const std::wstring& registeredPath) {
    std::wstring path = registeredPath;
    if (isLocalComputerName(computerName)) {
        return expandLocalProfilePath(path);
    }

    const std::wstring systemDrive = L"%SystemDrive%";
    if (path.size() >= systemDrive.size() &&
        CompareStringOrdinal(path.c_str(), static_cast<int>(systemDrive.size()),
            systemDrive.c_str(), static_cast<int>(systemDrive.size()), TRUE) == CSTR_EQUAL) {
        path = L"C:" + path.substr(systemDrive.size());
    }
    if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
        std::wstring result = L"\\\\" + trim(computerName) + L"\\";
        result.push_back(static_cast<wchar_t>(towlower(path[0])));
        result += L"$" + path.substr(2);
        return result;
    }
    return profilesRootForComputer(computerName) + L"\\" + profileFolderName(path);
}

UserProfileEntry makeProfileEntry(
    const std::wstring& computerName,
    const std::wstring& accountName,
    const std::wstring& sid,
    const std::wstring& registeredPath) {
    UserProfileEntry entry;
    entry.accountName = accountName;
    entry.sid = sid;
    entry.profileDirectory = accessibleProfilePath(computerName, registeredPath);
    entry.policyPath = entry.profileDirectory + L"\\AppData\\Local\\DistControl\\allow.json";
    entry.phonebookPath = entry.profileDirectory +
        L"\\AppData\\Roaming\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk";
    entry.networkStatePath = entry.profileDirectory +
        L"\\AppData\\Local\\DistControl\\state\\network-state.json";
    return entry;
}

std::vector<UserProfileEntry> profileUsersForComputer(const std::wstring& computerName) {
    std::vector<UserProfileEntry> profiles;
    HKEY connected = nullptr;
    HKEY machine = HKEY_LOCAL_MACHINE;
    if (!isLocalComputerName(computerName)) {
        const std::wstring remoteName = L"\\\\" + trim(computerName);
        if (RegConnectRegistryW(remoteName.c_str(), HKEY_LOCAL_MACHINE, &connected) != ERROR_SUCCESS) {
            connected = nullptr;
        }
        machine = connected;
    }

    HKEY profileList = nullptr;
    if (machine && RegOpenKeyExW(machine,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
            0, KEY_READ, &profileList) == ERROR_SUCCESS) {
        for (DWORD index = 0;; ++index) {
            wchar_t sidName[256]{};
            DWORD sidLength = static_cast<DWORD>(std::size(sidName));
            const LONG enumResult = RegEnumKeyExW(
                profileList, index, sidName, &sidLength, nullptr, nullptr, nullptr, nullptr);
            if (enumResult == ERROR_NO_MORE_ITEMS) {
                break;
            }
            if (enumResult != ERROR_SUCCESS) {
                continue;
            }

            HKEY profileKey = nullptr;
            if (RegOpenKeyExW(profileList, sidName, 0, KEY_READ, &profileKey) != ERROR_SUCCESS) {
                continue;
            }
            wchar_t path[32768]{};
            DWORD pathBytes = sizeof(path);
            DWORD valueType = 0;
            const LONG readResult = RegQueryValueExW(profileKey, L"ProfileImagePath", nullptr,
                &valueType, reinterpret_cast<BYTE*>(path), &pathBytes);
            RegCloseKey(profileKey);
            if (readResult != ERROR_SUCCESS ||
                (valueType != REG_SZ && valueType != REG_EXPAND_SZ) || path[0] == L'\0') {
                continue;
            }

            std::wstring account = accountNameForSid(computerName, sidName);
            const std::wstring folder = profileFolderName(path);
            if (isSystemProfileName(folder)) {
                continue;
            }
            if (account.empty()) {
                const std::wstring domain = currentDomainPrefix();
                account = domain.empty() ? folder : domain + folder;
            }
            profiles.push_back(makeProfileEntry(computerName, account, sidName, path));
        }
        RegCloseKey(profileList);
    }
    if (connected) {
        RegCloseKey(connected);
    }

    if (profiles.empty()) {
        const std::wstring root = profilesRootForComputer(computerName);
        for (const std::wstring& account : profileUsersFromRoot(root)) {
            profiles.push_back(makeProfileEntry(
                computerName, account, L"", root + L"\\" + profileFolderName(account)));
        }
    }

    std::sort(profiles.begin(), profiles.end(),
        [](const UserProfileEntry& left, const UserProfileEntry& right) {
            return lowerCopy(left.accountName) < lowerCopy(right.accountName);
        });
    profiles.erase(std::unique(profiles.begin(), profiles.end(),
        [](const UserProfileEntry& left, const UserProfileEntry& right) {
            return lowerCopy(left.accountName) == lowerCopy(right.accountName);
        }), profiles.end());
    return profiles;
}

std::wstring allUsersPhonebookPathForComputer(const std::wstring& computerName) {
    if (isLocalComputerName(computerName)) {
        return VpnManager::allUsersPhonebook();
    }
    return L"\\\\" + trim(computerName) +
        L"\\c$\\ProgramData\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk";
}

std::uint64_t currentFileTimeTicks() {
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

std::wstring win32ErrorText(DWORD error) {
    LPWSTR buffer = nullptr;
    const DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);
    std::wstring text = size && buffer ? trim(buffer) : L"код " + std::to_wstring(error);
    if (buffer) {
        LocalFree(buffer);
    }
    return text;
}

std::wstring humanPathError(const std::wstring& path, DWORD error) {
    std::wstring reason;
    switch (error) {
    case ERROR_ACCESS_DENIED:
        reason = L"нет прав доступа. Запустите админку от администратора и проверьте доступ к административной шаре C$";
        break;
    case ERROR_BAD_NETPATH:
    case ERROR_BAD_NET_NAME:
    case ERROR_NETWORK_UNREACHABLE:
    case ERROR_HOST_UNREACHABLE:
        reason = L"компьютер не найден или недоступен по сети. Проверьте имя компьютера, сеть и включённую административную шару C$";
        break;
    case ERROR_PATH_NOT_FOUND:
    case ERROR_FILE_NOT_FOUND:
        reason = L"путь не найден. Возможно, на этом компьютере ещё не установлен DistControl или нет папки профилей";
        break;
    case ERROR_LOGON_FAILURE:
        reason = L"Windows не приняла учётные данные для доступа к удалённому компьютеру";
        break;
    default:
        reason = win32ErrorText(error);
        break;
    }
    return L"Не удалось открыть " + path + L": " + reason + L".";
}

bool ensureReadablePath(const std::wstring& path, std::wstring& errorText) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    errorText = humanPathError(path, GetLastError());
    return false;
}

bool isSystemProfileName(const std::wstring& name) {
    const std::wstring lowered = lowerCopy(name);
    return lowered == L"public" ||
        lowered == L"default" ||
        lowered == L"default user" ||
        lowered == L"all users" ||
        lowered == L"desktop.ini";
}

std::vector<std::wstring> profileUsersFromRoot(const std::wstring& root) {
    std::vector<std::wstring> users;
    const std::wstring domain = currentDomainPrefix();
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((root + L"\\*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        return users;
    }

    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            continue;
        }
        const std::wstring name = data.cFileName;
        if (name == L"." || name == L".." || isSystemProfileName(name)) {
            continue;
        }
        users.push_back(domain.empty() ? name : domain + name);
    } while (FindNextFileW(find, &data));
    FindClose(find);

    std::sort(users.begin(), users.end(),
        [](const std::wstring& left, const std::wstring& right) {
            return lowerCopy(left) < lowerCopy(right);
        });
    return users;
}

std::wstring formatDuration(ULONGLONG elapsedMs) {
    const ULONGLONG totalSeconds = elapsedMs / 1000ULL;
    const ULONGLONG minutes = totalSeconds / 60ULL;
    const ULONGLONG seconds = totalSeconds % 60ULL;
    std::wostringstream stream;
    stream << minutes << L":"
        << std::setw(2) << std::setfill(L'0') << seconds;
    return stream.str();
}

// Usage time comes from the UTC event time of the timer record; records from
// older versions only carry local "updatedAt" text (see usageElapsedMs).
bool elapsedMsFromStartIfKnown(const DeviceViewModel& device, ULONGLONG& elapsedMs) {
    FILETIME nowFileTime{};
    GetSystemTimeAsFileTime(&nowFileTime);
    ULARGE_INTEGER now{};
    now.LowPart = nowFileTime.dwLowDateTime;
    now.HighPart = nowFileTime.dwHighDateTime;
    unsigned long long elapsed = 0;
    if (!usageElapsedMs(device.usageStartedAt, device.usageStartedFileTime, now.QuadPart, elapsed)) {
        return false;
    }
    elapsedMs = elapsed;
    return true;
}

std::wstring remainingTextFromStartIfKnown(const DeviceViewModel& device) {
    ULONGLONG elapsedMs = 0;
    if (!elapsedMsFromStartIfKnown(device, elapsedMs)) {
        return {};
    }
    const ULONGLONG remainingMs = elapsedMs >= kTokenSessionLimitMs ? 0 : kTokenSessionLimitMs - elapsedMs;
    return L"осталось " + formatDuration(remainingMs);
}

std::wstring remainingTextFromStart(const DeviceViewModel& device) {
    const std::wstring text = remainingTextFromStartIfKnown(device);
    return text.empty() ? L"нет данных" : text;
}

int timedMessageBox(HWND owner, const std::wstring& text, const std::wstring& title, UINT flags, DWORD timeoutMs) {
    using MessageBoxTimeoutWFn = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    auto* fn = user32
        ? reinterpret_cast<MessageBoxTimeoutWFn>(GetProcAddress(user32, "MessageBoxTimeoutW"))
        : nullptr;
    if (fn) {
        return fn(owner, text.c_str(), title.c_str(), flags, 0, timeoutMs);
    }
    return MessageBoxW(owner, text.c_str(), title.c_str(), flags);
}

std::wstring timestampForFileName() {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    std::wostringstream stream;
    stream << std::setfill(L'0')
        << time.wYear
        << std::setw(2) << time.wMonth
        << std::setw(2) << time.wDay
        << L"-"
        << std::setw(2) << time.wHour
        << std::setw(2) << time.wMinute
        << std::setw(2) << time.wSecond;
    return stream.str();
}

bool sameDeviceIdentity(const DeviceViewModel& left, const DeviceViewModel& right) {
    return left.endpoint == right.endpoint &&
        left.nickname == right.nickname &&
        left.product == right.product;
}

std::wstring columnValue(const DeviceViewModel& device, int column) {
    switch (column) {
    case 0: return device.endpoint;
    case 1: return device.nickname;
    case 2: return networkProfileText(device);
    case 3: return device.statusText;
    case 4: return device.usedBy;
    case 5: return device.usedAt;
    case 6: return adminRemainingText(device);
    case 7: return device.product;
    case 8: return device.allowed ? L"1" : L"0";
    default: return {};
    }
}

std::wstring displayDeviceName(const DeviceViewModel& device) {
    if (!device.nickname.empty()) {
        return device.nickname;
    }
    if (!device.product.empty()) {
        return device.product;
    }
    return device.endpoint;
}

std::wstring endpointGroupName(const std::wstring& endpoint) {
    const size_t dot = endpoint.find_last_of(L'.');
    if (dot == std::wstring::npos || dot == 0) {
        return L"USB";
    }
    return endpoint.substr(0, dot);
}

std::wstring adminEndpointGroupName(const std::wstring& endpoint) {
    const std::wstring lowered = lowerCopy(endpoint);
    std::wstring hubType = L"USB";
    if (lowered.find(L"usb64") != std::wstring::npos) {
        hubType = L"USB 64";
    }
    else if (lowered.find(L"usb32") != std::wstring::npos) {
        hubType = L"USB 32";
    }
    else if (lowered.find(L"usb16") != std::wstring::npos) {
        hubType = L"USB 16";
    }

    return hubType + L" - " + endpointGroupName(endpoint);
}

std::wstring adminRemainingText(const DeviceViewModel& device) {
    const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
    if (usage.isFree) {
        return {};
    }
    return remainingTextFromStart(device);
}

void updateAdminListTimers(HWND listView, const std::vector<DeviceViewModel>& devices) {
    if (!listView) {
        return;
    }

    for (size_t i = 0; i < devices.size(); ++i) {
        setItemTextIfChanged(listView, static_cast<int>(i), 6, adminRemainingText(devices[i]));
    }
}

std::wstring usageSuffix(const DeviceViewModel& device) {
    const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
    if (usage.isFree) {
        return {};
    }
    if (usage.isUsedByCurrentUser) {
        return L" (Подключён вами)";
    }
    if (!usage.userText.empty()) {
        std::wstring text = L" (Используется " + usage.userText;
        if (!usage.locationText.empty()) {
            text += L" на " + usage.locationText;
        }
        text += L")";
        return text;
    }
    return L" (Занят)";
}

std::wstring treeDeviceText(const DeviceViewModel& device, bool withNetwork = true) {
    std::wstring text = displayDeviceName(device);
    if (withNetwork) {
        if (!device.vpnProfileId.empty()) {
            text += L" [Сеть: " + networkProfileText(device) + L"]";
        }
        else {
            text += L" [сеть не настроена]";
        }
    }
    return text + usageSuffix(device);
}

int treeImageIndexForDevice(const DeviceViewModel& device) {
    const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
    if (usage.isUsedByCurrentUser) {
        return 2;
    }
    if (!usage.isFree) {
        return 3;
    }
    return 1;
}

HBITMAP createDotBitmap(COLORREF color) {
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bitmap = CreateCompatibleBitmap(screen, 16, 16);
    HGDIOBJ oldBitmap = SelectObject(mem, bitmap);

    RECT rect{ 0, 0, 16, 16 };
    HBRUSH maskBrush = CreateSolidBrush(RGB(255, 0, 255));
    FillRect(mem, &rect, maskBrush);
    DeleteObject(maskBrush);

    HBRUSH brush = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(80, 110, 145));
    HGDIOBJ oldBrush = SelectObject(mem, brush);
    HGDIOBJ oldPen = SelectObject(mem, pen);
    RoundRect(mem, 3, 4, 13, 12, 3, 3);
    SelectObject(mem, oldPen);
    SelectObject(mem, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);

    SelectObject(mem, oldBitmap);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return bitmap;
}

HIMAGELIST createTreeImageList() {
    HIMAGELIST images = ImageList_Create(16, 16, ILC_COLOR24 | ILC_MASK, 4, 1);
    if (!images) {
        return nullptr;
    }

    const COLORREF colors[] = {
        RGB(55, 176, 82),
        RGB(105, 162, 224),
        RGB(139, 92, 246),
        RGB(229, 146, 56)
    };
    for (COLORREF color : colors) {
        HBITMAP bitmap = createDotBitmap(color);
        ImageList_AddMasked(images, bitmap, RGB(255, 0, 255));
        DeleteObject(bitmap);
    }
    return images;
}
}

bool MainWindow::create(HINSTANCE instance, int showCommand) {
    instance_ = instance;

    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&controls);

    const wchar_t* className = L"DistControlMainWindow";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainWindow::windowProc;
    wc.hInstance = instance_;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    appIcon_ = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_DISKCONTROL));
    wc.hIcon = appIcon_ ? appIcon_ : LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = appIcon_ ? appIcon_ : LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = className;

    if (!RegisterClassExW(&wc)) {
        return false;
    }

    hwnd_ = CreateWindowExW(0, className, kWindowTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1120, 520, nullptr, nullptr, instance_, this);

    if (!hwnd_) {
        return false;
    }

    SendMessageW(hwnd_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(wc.hIcon));
    SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(wc.hIconSm));
    ShowWindow(hwnd_, showCommand);
    UpdateWindow(hwnd_);
    return true;
}

LRESULT CALLBACK MainWindow::windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = nullptr;
    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        window = static_cast<MainWindow*>(create->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
        window->hwnd_ = hwnd;
    }
    else {
        window = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }

    return window ? window->handleMessage(message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT MainWindow::handleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        createControls();
        SetTimer(hwnd_, IDT_USAGE_WATCHDOG, 1000, nullptr);
        SetTimer(hwnd_, IDT_USAGE_SYNC, 5000, nullptr);
        try {
            service_.requestUsageStateSync();
        }
        catch (const std::exception&) {
        }
        applyAutoRefreshInterval();
        refreshDevices();
        return 0;
    case WM_QUERYENDSESSION:
        // Windows is signing out or shutting down: release tokens now, while
        // the dkclient service still answers, so they are not left occupied.
        if (!kAdminBuild && !sessionEndReleaseDone_) {
            ShutdownBlockReasonCreate(hwnd_, L"DistControl отключает токены");
            closing_ = true;
            releaseActiveDevices(false);
            sessionEndReleaseDone_ = true;
            ShutdownBlockReasonDestroy(hwnd_);
        }
        return TRUE;
    case WM_ENDSESSION:
        if (wParam && !kAdminBuild && !sessionEndReleaseDone_) {
            // Forced sign-out may skip WM_QUERYENDSESSION.
            closing_ = true;
            releaseActiveDevices(false);
            sessionEndReleaseDone_ = true;
        }
        else if (!wParam) {
            // Sign-out was cancelled; the program keeps working.
            closing_ = false;
            sessionEndReleaseDone_ = false;
            scheduleDelayedRefresh();
        }
        return 0;
    case WM_CLOSE:
        if (kAdminBuild && !confirmDiscardAdminChanges()) {
            return 0;
        }
        closing_ = true;
        if (tokenActionRunning_) {
            closing_ = false;
            updateStatus(L"Дождитесь завершения операции с токеном.");
            return 0;
        }
        if (!kAdminBuild) {
            releaseActiveDevices(false);
        }
        DestroyWindow(hwnd_);
        return 0;
    case WM_REFRESH_COMPLETE:
        finishRefresh();
        return 0;
    case WM_REFRESH_PROGRESS:
        updateRefreshProgress();
        return 0;
    case WM_COMPUTER_LOAD_COMPLETE:
        finishComputerLoad();
        return 0;
    case WM_TOKEN_ACTION_COMPLETE:
        finishTokenAction();
        return 0;
    case WM_TOKEN_ACTION_PROGRESS:
        updateTokenActionProgress();
        return 0;
    case WM_VPN_WATCHDOG_COMPLETE:
        finishVpnHealthCheck();
        return 0;
    case WM_NETWORK_STATE_COMPLETE:
        finishNetworkStatePublish();
        return 0;
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) {
            return 0;
        }
        layoutControls();
        return 0;
    case WM_TIMER:
        if (wParam == IDT_USAGE_SYNC) {
            if (!tokenActionRunning_ && !closing_) {
                try {
                    service_.requestUsageStateSync();
                    updateHeaderText();
                }
                catch (const std::exception&) {
                    // Policy errors are shown by the regular device refresh.
                }
            }
            return 0;
        }
        if (wParam == IDT_AUTO_REFRESH) {
            if (!kAdminBuild && !diagnosticsMode_ && !closing_ && !refreshing_ && !tokenActionRunning_ &&
                !vpnWatchdogRunning_ && !timeoutPromptActive_ && !allDevices_.empty() &&
                GetTickCount64() >= quietRefreshResumeAt_) {
                refreshDevices(true);
            }
            return 0;
        }
        if (wParam == IDT_DELAYED_REFRESH) {
            KillTimer(hwnd_, IDT_DELAYED_REFRESH);
            refreshDevices();
            return 0;
        }
        if (wParam == IDT_USAGE_WATCHDOG) {
            checkActiveDeviceTimeouts();
            checkActiveVpnHealth();
            publishNetworkState();
            if (kAdminBuild) {
                updateAdminListTimers(listView_, allowedDevices_);
                updateAdminListTimers(availableListView_, availableDevices_);
            }
            else if (treeView_) {
                updateTreeTimerText();
            }
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        SetBkColor(dc, GetSysColor(COLOR_WINDOW));
        if (reinterpret_cast<HWND>(lParam) == statusLabel_ && statusColor_ != CLR_DEFAULT) {
            SetTextColor(dc, statusColor_);
        }
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
    }
    case WM_NOTIFY:
        if (listView_ && reinterpret_cast<NMHDR*>(lParam)->hwndFrom == listView_) {
            const auto* header = reinterpret_cast<NMHDR*>(lParam);
            if (header->code == LVN_COLUMNCLICK) {
                const auto* info = reinterpret_cast<NMLISTVIEW*>(lParam);
                sortByColumn(info->iSubItem);
                return 0;
            }
            if (kAdminBuild && header->code == NM_DBLCLK) {
                removeSelectedDeviceFromUser();
                return 0;
            }
            if (kAdminBuild && header->code == LVN_ITEMCHANGED) {
                const auto* change = reinterpret_cast<NMLISTVIEW*>(lParam);
                if ((change->uChanged & LVIF_STATE) != 0 &&
                    ((change->uOldState ^ change->uNewState) & LVIS_SELECTED) != 0) {
                    updateAdminMoveButtons(IsWindowEnabled(refreshButton_) != FALSE);
                }
            }
        }
        if (availableListView_ && reinterpret_cast<NMHDR*>(lParam)->hwndFrom == availableListView_) {
            const auto* header = reinterpret_cast<NMHDR*>(lParam);
            if (header->code == LVN_COLUMNCLICK) {
                const auto* info = reinterpret_cast<NMLISTVIEW*>(lParam);
                sortByColumn(info->iSubItem);
                return 0;
            }
            if (header->code == NM_DBLCLK) {
                assignSelectedDeviceToUser();
                return 0;
            }
            if (kAdminBuild && header->code == LVN_ITEMCHANGED) {
                const auto* change = reinterpret_cast<NMLISTVIEW*>(lParam);
                if ((change->uChanged & LVIF_STATE) != 0 &&
                    ((change->uOldState ^ change->uNewState) & LVIS_SELECTED) != 0) {
                    updateAdminMoveButtons(IsWindowEnabled(refreshButton_) != FALSE);
                }
            }
        }
        if (treeView_ && reinterpret_cast<NMHDR*>(lParam)->hwndFrom == treeView_) {
            const auto* header = reinterpret_cast<NMHDR*>(lParam);
            if (header->code == NM_CUSTOMDRAW) {
                return customDrawTree(reinterpret_cast<NMTVCUSTOMDRAW*>(lParam));
            }
            if (header->code == TVN_SELCHANGEDW) {
                const auto* change = reinterpret_cast<NMTREEVIEWW*>(lParam);
                // The selected label is drawn wider than the tree knows, so
                // repaint whole rows of the old and new selection.
                for (HTREEITEM changed : { change->itemOld.hItem, change->itemNew.hItem }) {
                    RECT row{};
                    if (changed && TreeView_GetItemRect(treeView_, changed, &row, FALSE)) {
                        InvalidateRect(treeView_, &row, TRUE);
                    }
                }
                updateActionButton();
                const DeviceViewModel* device = selectedDevice();
                if (device && change->action != TVC_UNKNOWN && !tokenActionRunning_ && !refreshing_) {
                    const DeviceUsageInfo usage = DeviceParser::parseUsage(
                        device->inUseBy, PolicyManager::currentUserName());
                    std::wstring hint = L"Выбран токен «" + displayDeviceName(*device) + L"». ";
                    if (usage.isUsedByCurrentUser) {
                        hint += L"Чтобы отключить: двойной щелчок, Enter или кнопка «Отключить».";
                    }
                    else if (usage.isFree) {
                        hint += L"Чтобы подключить: двойной щелчок, Enter или кнопка «Подключить».";
                    }
                    else {
                        hint += L"Токен сейчас занят другим пользователем.";
                    }
                    updateStatus(hint.c_str());
                }
                return 0;
            }
            if (header->code == NM_DBLCLK) {
                if (selectedDevice()) {
                    activateSelectedDevice();
                }
                return 0;
            }
            if (header->code == TVN_KEYDOWN) {
                const auto* key = reinterpret_cast<NMTVKEYDOWN*>(lParam);
                if (key->wVKey == VK_RETURN && selectedDevice()) {
                    activateSelectedDevice();
                    return 0;
                }
            }
        }
        break;
    case WM_COMMAND:
        if (reinterpret_cast<HWND>(lParam) == searchEdit_ && HIWORD(wParam) == EN_CHANGE) {
            applyDeviceFilter();
            return 0;
        }
        if (kAdminBuild && reinterpret_cast<HWND>(lParam) == assignUserEdit_ &&
            (HIWORD(wParam) == CBN_SELCHANGE || HIWORD(wParam) == CBN_KILLFOCUS)) {
            if (suppressAdminUserChange_) {
                return 0;
            }
            const std::wstring requestedUser = getControlText(assignUserEdit_);
            if (adminAccessDirty_ && lowerCopy(requestedUser) != lowerCopy(loadedPolicyUser_)) {
                if (!confirmDiscardAdminChanges()) {
                    suppressAdminUserChange_ = true;
                    SetWindowTextW(assignUserEdit_, loadedPolicyUser_.c_str());
                    suppressAdminUserChange_ = false;
                    return 0;
                }
            }
            selectAdminUserProfile(requestedUser, true);
            return 0;
        }
        switch (LOWORD(wParam)) {
        case IDC_REFRESH:
            if (kAdminBuild && !confirmDiscardAdminChanges()) {
                return 0;
            }
            refreshDevices();
            return 0;
        case IDC_DIAGNOSTICS:
            if (kAdminBuild) {
                return 0;
            }
            diagnosticsMode_ = !diagnosticsMode_;
            SetWindowTextW(diagnosticsButton_, diagnosticsMode_ ? L"Обычный режим" : L"Админ режим");
            ShowWindow(assignUserLabel_, diagnosticsMode_ ? SW_SHOW : SW_HIDE);
            ShowWindow(assignUserEdit_, diagnosticsMode_ ? SW_SHOW : SW_HIDE);
            ShowWindow(assignUserButton_, diagnosticsMode_ ? SW_SHOW : SW_HIDE);
            ShowWindow(removeUserButton_, diagnosticsMode_ ? SW_SHOW : SW_HIDE);
            ShowWindow(searchLabel_, diagnosticsMode_ ? SW_SHOW : SW_HIDE);
            ShowWindow(searchEdit_, diagnosticsMode_ ? SW_SHOW : SW_HIDE);
            ShowWindow(clearSearchButton_, diagnosticsMode_ ? SW_SHOW : SW_HIDE);
            layoutControls();
            refreshDevices();
            return 0;
        case IDC_ASSIGN_USER:
            assignSelectedDeviceToUser();
            return 0;
        case IDC_REMOVE_USER:
            removeSelectedDeviceFromUser();
            return 0;
        case IDC_LOAD_COMPUTER:
            if (!confirmDiscardAdminChanges()) {
                return 0;
            }
            loadProfilesAndPolicyFromComputer();
            return 0;
        case IDC_OPEN_POLICY:
            if (!confirmDiscardAdminChanges()) {
                return 0;
            }
            openPolicyFile();
            return 0;
        case IDC_SAVE_POLICY:
            saveCheckedDevicesForUser();
            return 0;
        case IDC_CLEAR_SEARCH:
            SetWindowTextW(searchEdit_, L"");
            applyDeviceFilter();
            return 0;
        case IDC_EXPORT:
            exportExcel();
            return 0;
        case IDC_VPN_MAPPINGS:
            manageVpnMappings();
            return 0;
        case IDC_EXPORT_JSON:
            return 0;
        case IDC_USE:
            if (treeView_) {
                if (selectedDevice()) {
                    activateSelectedDevice();
                }
                else {
                    updateStatus(L"Сначала выберите токен в списке.");
                }
                return 0;
            }
            if (listView_ && ListView_GetSelectedCount(listView_) > 1) {
                updateStatus(L"Для подключения выберите один токен.");
                return 0;
            }
            if (auto* device = selectedDevice()) {
                if (!device->allowed) {
                    AuditLogger::logDeviceAction(L"DENY", *device, L"DENIED", L"Выбранное устройство запрещено политикой.");
                    updateStatus(L"Выбранное устройство запрещено политикой.");
                    return 0;
                }
                startTokenAction(*device, true);
                return 0;
            }
            else {
                updateStatus(L"Сначала выберите устройство.");
            }
            return 0;
        case IDC_STOP:
            if (listView_ && ListView_GetSelectedCount(listView_) > 1) {
                updateStatus(L"Для отключения выберите один токен.");
                return 0;
            }
            if (auto* device = selectedDevice()) {
                const DeviceUsageInfo usage = DeviceParser::parseUsage(device->inUseBy, PolicyManager::currentUserName());
                if (!usage.isUsedByCurrentUser) {
                    AuditLogger::logDeviceAction(L"DENY", *device, L"DENIED", L"Выбранное устройство запрещено политикой.");
                    updateStatus(L"Можно отключить только токен, подключённый вами.");
                    return 0;
                }
                startTokenAction(*device, false);
                return 0;
            }
            else {
                updateStatus(L"Сначала выберите устройство.");
            }
            return 0;
        default:
            break;
        }
        break;
    case WM_DESTROY:
        closing_ = true;
        if (kAdminBuild) {
            saveListColumnLayout(listView_, 8, L"AdminAllowed");
            saveListColumnLayout(availableListView_, 8, L"AdminAvailable");
        }
        KillTimer(hwnd_, IDT_DELAYED_REFRESH);
        KillTimer(hwnd_, IDT_USAGE_WATCHDOG);
        KillTimer(hwnd_, IDT_USAGE_SYNC);
        KillTimer(hwnd_, IDT_AUTO_REFRESH);
        if (treeImageList_) {
            ImageList_Destroy(treeImageList_);
            treeImageList_ = nullptr;
        }
        for (HFONT* font : { &uiFont_, &treeFont_, &treeSelectedFont_, &statusFont_ }) {
            if (*font) {
                DeleteObject(*font);
                *font = nullptr;
            }
        }
        if (refreshThread_.joinable()) {
            refreshThread_.join();
        }
        if (computerLoadThread_.joinable()) {
            computerLoadThread_.join();
        }
        if (tokenActionThread_.joinable()) {
            tokenActionThread_.join();
        }
        if (vpnWatchdogThread_.joinable()) {
            vpnWatchdogThread_.join();
        }
        if (networkStateThread_.joinable()) {
            networkStateThread_.join();
        }
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return DefWindowProcW(hwnd_, message, wParam, lParam);
}

void MainWindow::createControls() {
    userInfoLabel_ = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
        0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);

    if (kAdminBuild) {
        listView_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
            0, 0, 0, 0, hwnd_, controlId(IDC_DEVICE_LIST), instance_, nullptr);
        availableListView_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, nullptr,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
            0, 0, 0, 0, hwnd_, controlId(IDC_AVAILABLE_LIST), instance_, nullptr);
        allowedTitleLabel_ = CreateWindowW(L"STATIC", L"Разрешено пользователю", WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
            0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
        availableTitleLabel_ = CreateWindowW(L"STATIC", L"Можно добавить", WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
            0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);

        const DWORD listStyle =
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP;
        ListView_SetExtendedListViewStyle(listView_, listStyle);
        ListView_SetExtendedListViewStyle(availableListView_, listStyle);
        addDeviceColumns(listView_, false);
        addDeviceColumns(availableListView_, false);
        loadListColumnLayout(listView_, 8, L"AdminAllowed");
        loadListColumnLayout(availableListView_, 8, L"AdminAvailable");
    }
    else {
        treeView_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, nullptr,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASLINES | TVS_LINESATROOT |
            TVS_HASBUTTONS | TVS_SHOWSELALWAYS | TVS_FULLROWSELECT,
            0, 0, 0, 0, hwnd_, controlId(IDC_DEVICE_LIST), instance_, nullptr);
        treeImageList_ = createTreeImageList();
        if (treeImageList_) {
            TreeView_SetImageList(treeView_, treeImageList_, TVSIL_NORMAL);
        }
    }

    const DWORD userActionStyle = WS_CHILD | (kAdminBuild ? 0 : WS_VISIBLE);
    const DWORD adminActionStyle = WS_CHILD | (kAdminBuild ? WS_VISIBLE : 0);

    refreshButton_ = CreateWindowW(L"BUTTON", L"Обновить", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
        hwnd_, controlId(IDC_REFRESH), instance_, nullptr);
    useButton_ = CreateWindowW(L"BUTTON", L"Подключить", userActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_USE), instance_, nullptr);
    stopButton_ = CreateWindowW(L"BUTTON", L"Отключить", userActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_STOP), instance_, nullptr);
    diagnosticsButton_ = CreateWindowW(L"BUTTON", L"Админ режим", WS_CHILD, 0, 0, 0, 0,
        hwnd_, controlId(IDC_DIAGNOSTICS), instance_, nullptr);
    assignUserLabel_ = CreateWindowW(L"STATIC", L"Пользователь:", adminActionStyle | SS_LEFTNOWORDWRAP,
        0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
    assignUserEdit_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", PolicyManager::currentUserName().c_str(),
        adminActionStyle | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, 0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
    computerLabel_ = CreateWindowW(L"STATIC", L"Компьютер:", adminActionStyle | SS_LEFTNOWORDWRAP,
        0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
    computerEdit_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", currentComputerName().c_str(),
        adminActionStyle | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd_, controlId(IDC_COMPUTER), instance_, nullptr);
    loadComputerButton_ = CreateWindowW(L"BUTTON", L"Загрузить", adminActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_LOAD_COMPUTER), instance_, nullptr);
    computerProgressBar_ = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        adminActionStyle | PBS_MARQUEE, 0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
    ShowWindow(computerProgressBar_, SW_HIDE);
    assignUserButton_ = CreateWindowW(L"BUTTON", L"← Добавить выбранные", adminActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_ASSIGN_USER), instance_, nullptr);
    removeUserButton_ = CreateWindowW(L"BUTTON", L"Убрать выбранные →", adminActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_REMOVE_USER), instance_, nullptr);
    openPolicyButton_ = CreateWindowW(L"BUTTON", L"Открыть конфиг", adminActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_OPEN_POLICY), instance_, nullptr);
    savePolicyButton_ = CreateWindowW(L"BUTTON", L"Сохранить доступ", adminActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_SAVE_POLICY), instance_, nullptr);
    searchLabel_ = CreateWindowW(L"STATIC", L"Поиск:", adminActionStyle | SS_LEFTNOWORDWRAP,
        0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
    searchEdit_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        adminActionStyle | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd_, controlId(IDC_SEARCH), instance_, nullptr);
    clearSearchButton_ = CreateWindowW(L"BUTTON", L"Сброс", adminActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_CLEAR_SEARCH), instance_, nullptr);
    exportButton_ = CreateWindowW(L"BUTTON", L"Экспорт Excel", adminActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_EXPORT), instance_, nullptr);
    exportJsonButton_ = CreateWindowW(L"BUTTON", L"", WS_CHILD, 0, 0, 0, 0,
        hwnd_, controlId(IDC_EXPORT_JSON), instance_, nullptr);
    vpnMappingsButton_ = CreateWindowW(L"BUTTON", L"Токены → VPN", adminActionStyle,
        0, 0, 0, 0, hwnd_, controlId(IDC_VPN_MAPPINGS), instance_, nullptr);
    statusLabel_ = CreateWindowW(L"STATIC", L"Готово.", WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
        0, 0, 0, 0, hwnd_, controlId(IDC_STATUS), instance_, nullptr);
    refreshProgressLabel_ = CreateWindowW(L"STATIC", L"", WS_CHILD | SS_CENTER,
        0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
    refreshProgressBar_ = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        WS_CHILD | PBS_SMOOTH | PBS_MARQUEE, 0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
    SendMessageW(refreshProgressBar_, PBM_SETRANGE32, 0, 100);

    if (kAdminBuild) {
        loadProfilesForComputer(currentComputerName());
    }

    createFonts();
    updateActionButton();
    updateHeaderText();
    layoutControls();
}

static BOOL CALLBACK applyFontToChild(HWND child, LPARAM font) {
    SendMessageW(child, WM_SETFONT, static_cast<WPARAM>(font), FALSE);
    return TRUE;
}

void MainWindow::createFonts() {
    HDC screen = GetDC(nullptr);
    const int dpi = screen ? GetDeviceCaps(screen, LOGPIXELSY) : 96;
    if (screen) {
        ReleaseDC(nullptr, screen);
    }
    const auto makeFont = [dpi](int points, int weight) {
        return CreateFontW(-MulDiv(points, dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    };
    uiFont_ = makeFont(10, FW_NORMAL);
    statusFont_ = makeFont(10, FW_SEMIBOLD);
    treeFont_ = makeFont(10, FW_NORMAL);
    treeSelectedFont_ = makeFont(11, FW_BOLD);

    if (uiFont_) {
        EnumChildWindows(hwnd_, applyFontToChild, reinterpret_cast<LPARAM>(uiFont_));
    }
    if (statusFont_) {
        SendMessageW(statusLabel_, WM_SETFONT, reinterpret_cast<WPARAM>(statusFont_), FALSE);
        if (useButton_) {
            SendMessageW(useButton_, WM_SETFONT, reinterpret_cast<WPARAM>(statusFont_), FALSE);
        }
    }
    if (treeView_ && treeFont_) {
        SendMessageW(treeView_, WM_SETFONT, reinterpret_cast<WPARAM>(treeFont_), TRUE);
        HDC dc = GetDC(treeView_);
        if (dc) {
            // Rows are tall enough for the larger bold text of the selected token.
            HGDIOBJ old = SelectObject(dc, treeSelectedFont_ ? treeSelectedFont_ : treeFont_);
            TEXTMETRICW metrics{};
            GetTextMetricsW(dc, &metrics);
            SelectObject(dc, old);
            ReleaseDC(treeView_, dc);
            TreeView_SetItemHeight(treeView_, metrics.tmHeight + MulDiv(4, dpi, 96));
        }
    }
}

void MainWindow::updateActionButton() {
    if (!useButton_ || kAdminBuild) {
        return;
    }
    const DeviceViewModel* device = selectedDevice();
    const bool busy = tokenActionRunning_ || refreshing_ || vpnWatchdogRunning_;
    const wchar_t* text = L"Подключить";
    bool enabled = false;
    if (device) {
        const DeviceUsageInfo usage = DeviceParser::parseUsage(device->inUseBy, PolicyManager::currentUserName());
        if (usage.isUsedByCurrentUser) {
            text = L"Отключить";
            enabled = true;
        }
        else if (!usage.isFree) {
            text = L"Занят";
        }
        else {
            enabled = device->allowed;
        }
    }
    wchar_t current[32]{};
    GetWindowTextW(useButton_, current, static_cast<int>(std::size(current)));
    if (wcscmp(current, text) != 0) {
        SetWindowTextW(useButton_, text);
    }
    EnableWindow(useButton_, enabled && !busy ? TRUE : FALSE);
}

LRESULT MainWindow::customDrawTree(NMTVCUSTOMDRAW* draw) {
    switch (draw->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT: {
        const HTREEITEM item = reinterpret_cast<HTREEITEM>(draw->nmcd.dwItemSpec);
        if (item == TreeView_GetSelection(treeView_)) {
            // Keep the classic blue selection even after focus moves to a button.
            draw->clrText = GetSysColor(COLOR_HIGHLIGHTTEXT);
            draw->clrTextBk = GetSysColor(COLOR_HIGHLIGHT);
            return CDRF_NOTIFYPOSTPAINT;
        }
        const LPARAM param = draw->nmcd.lItemlParam;
        if (param == kTreeGroupParam) {
            draw->clrText = RGB(70, 70, 70);
        }
        else if (param >= 0 && static_cast<size_t>(param) < devices_.size()) {
            const DeviceUsageInfo usage = DeviceParser::parseUsage(
                devices_[static_cast<size_t>(param)].inUseBy, PolicyManager::currentUserName());
            if (usage.isUsedByCurrentUser) {
                draw->clrText = RGB(109, 40, 217);
            }
            else if (!usage.isFree) {
                draw->clrText = RGB(150, 150, 150);
            }
        }
        return CDRF_DODEFAULT;
    }
    case CDDS_ITEMPOSTPAINT:
        drawSelectedTreeLabel(draw);
        return CDRF_DODEFAULT;
    default:
        return CDRF_DODEFAULT;
    }
}

void MainWindow::drawSelectedTreeLabel(const NMTVCUSTOMDRAW* draw) {
    const HTREEITEM item = reinterpret_cast<HTREEITEM>(draw->nmcd.dwItemSpec);
    RECT label{};
    if (!TreeView_GetItemRect(treeView_, item, &label, TRUE)) {
        return;
    }

    std::wstring text;
    const LPARAM param = draw->nmcd.lItemlParam;
    if (param >= 0 && static_cast<size_t>(param) < devices_.size()) {
        const DeviceViewModel& device = devices_[static_cast<size_t>(param)];
        text = treeDeviceText(device, true);
        const std::wstring duration = activeDurationText(device);
        if (!duration.empty()) {
            text += L" [" + duration + L"]";
        }
    }
    else {
        wchar_t buffer[512]{};
        TVITEMW info{};
        info.mask = TVIF_TEXT;
        info.hItem = item;
        info.pszText = buffer;
        info.cchTextMax = static_cast<int>(std::size(buffer));
        if (TreeView_GetItem(treeView_, &info)) {
            text = buffer;
        }
    }

    HDC dc = draw->nmcd.hdc;
    HGDIOBJ oldFont = SelectObject(dc, treeSelectedFont_ ? treeSelectedFont_ : treeFont_);
    RECT measure{ 0, 0, 0, 0 };
    DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &measure,
        DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
    RECT client{};
    GetClientRect(treeView_, &client);
    RECT box = label;
    box.right = (std::min)((std::max)(label.right, label.left + (measure.right - measure.left) + 8),
        client.right);

    // Paint over the default label: blue background, white bold text and a
    // focus frame, kept even when focus is on a button.
    HBRUSH highlight = GetSysColorBrush(COLOR_HIGHLIGHT);
    FillRect(dc, &box, highlight);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, GetSysColor(COLOR_HIGHLIGHTTEXT));
    RECT textBox = box;
    textBox.left += 4;
    DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &textBox,
        DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS);
    SelectObject(dc, oldFont);
    SetTextColor(dc, RGB(0, 0, 0));
    DrawFocusRect(dc, &box);
}

void MainWindow::layoutControls() {
    RECT client{};
    GetClientRect(hwnd_, &client);

    constexpr int margin = 12;
    constexpr int buttonWidth = 120;
    constexpr int buttonHeight = 32;
    constexpr int gap = 10;
    constexpr int userInfoHeight = 24;
    constexpr int statusHeight = 24;
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    const int buttonTop = height - margin - statusHeight - gap - buttonHeight;
    const int listTop = margin + userInfoHeight + gap;

    MoveWindow(userInfoLabel_, margin, margin, width - 2 * margin, userInfoHeight, TRUE);

    if (kAdminBuild) {
        const int userTop = buttonTop - gap - buttonHeight;
        const int computerTop = userTop - gap - buttonHeight;
        const int searchTop = computerTop - gap - buttonHeight;
        int listBottom = searchTop - margin;
        if (listBottom < listTop + 120) {
            listBottom = listTop + 120;
        }

        constexpr int titleHeight = 34;
        constexpr int moveButtonWidth = 230;
        constexpr int moveButtonHeight = 28;
        const int paneGap = 14;
        const int paneWidth = (width - 2 * margin - paneGap) / 2;
        const int rightPaneX = margin + paneWidth + paneGap;
        const int listY = listTop + titleHeight;
        const int listHeight = listBottom - listY;
        const int titleWidth = (std::max)(paneWidth - moveButtonWidth - gap, 120);

        MoveWindow(allowedTitleLabel_, margin, listTop + 8, titleWidth, 22, TRUE);
        MoveWindow(availableTitleLabel_, rightPaneX, listTop + 8, titleWidth, 22, TRUE);
        // Move buttons sit right above the list they take tokens from.
        MoveWindow(removeUserButton_, margin + paneWidth - moveButtonWidth, listTop,
            moveButtonWidth, moveButtonHeight, TRUE);
        MoveWindow(assignUserButton_, rightPaneX + paneWidth - moveButtonWidth, listTop,
            moveButtonWidth, moveButtonHeight, TRUE);
        MoveWindow(listView_, margin, listY, paneWidth, listHeight, TRUE);
        MoveWindow(availableListView_, rightPaneX, listY, paneWidth, listHeight, TRUE);

        constexpr int labelWidth = 95;
        constexpr int searchWidth = 420;
        constexpr int clearWidth = 90;
        int rowX = margin;
        MoveWindow(searchLabel_, rowX, searchTop + 7, labelWidth, 20, TRUE);
        rowX += labelWidth + gap;
        MoveWindow(searchEdit_, rowX, searchTop, searchWidth, buttonHeight, TRUE);
        rowX += searchWidth + gap;
        MoveWindow(clearSearchButton_, rowX, searchTop, clearWidth, buttonHeight, TRUE);

        constexpr int computerWidth = 260;
        constexpr int loadWidth = 110;
        constexpr int progressWidth = 180;
        rowX = margin;
        MoveWindow(computerLabel_, rowX, computerTop + 7, labelWidth, 20, TRUE);
        rowX += labelWidth + gap;
        MoveWindow(computerEdit_, rowX, computerTop, computerWidth, buttonHeight, TRUE);
        rowX += computerWidth + gap;
        MoveWindow(loadComputerButton_, rowX, computerTop, loadWidth, buttonHeight, TRUE);
        rowX += loadWidth + gap;
        MoveWindow(computerProgressBar_, rowX, computerTop + 7, progressWidth, 18, TRUE);

        constexpr int userWidth = 300;
        rowX = margin;
        MoveWindow(assignUserLabel_, rowX, userTop + 7, labelWidth, 20, TRUE);
        rowX += labelWidth + gap;
        MoveWindow(assignUserEdit_, rowX, userTop, userWidth, 180, TRUE);

        int x = margin;
        MoveWindow(refreshButton_, x, buttonTop, buttonWidth, buttonHeight, TRUE);
        constexpr int openPolicyWidth = 130;
        constexpr int savePolicyWidth = 150;
        x += buttonWidth + gap;
        MoveWindow(openPolicyButton_, x, buttonTop, openPolicyWidth, buttonHeight, TRUE);
        x += openPolicyWidth + gap;
        MoveWindow(savePolicyButton_, x, buttonTop, savePolicyWidth, buttonHeight, TRUE);
        x += savePolicyWidth + gap;
        MoveWindow(exportButton_, x, buttonTop, 130, buttonHeight, TRUE);
        x += 130 + gap;
        MoveWindow(vpnMappingsButton_, x, buttonTop, 150, buttonHeight, TRUE);
    }
    else {
        int listBottom = buttonTop - margin;
        if (listBottom < listTop + 80) {
            listBottom = listTop + 80;
        }

        if (treeView_) {
            MoveWindow(treeView_, margin, listTop, width - 2 * margin, listBottom - listTop, TRUE);
        }

        MoveWindow(refreshButton_, margin, buttonTop, buttonWidth, buttonHeight, TRUE);
        MoveWindow(useButton_, margin + buttonWidth + gap, buttonTop, 170, buttonHeight, TRUE);
    }

    constexpr int refreshProgressWidth = 230;
    constexpr int refreshPercentWidth = 62;
    const int statusTop = height - margin - statusHeight;
    const int progressX = width - margin - refreshProgressWidth;
    const int percentX = progressX - refreshPercentWidth;
    const int statusWidth = (IsWindowVisible(refreshProgressBar_) ? percentX - gap : width - margin) - margin;
    MoveWindow(statusLabel_, margin, statusTop, (std::max)(statusWidth, 100), statusHeight, TRUE);
    MoveWindow(refreshProgressLabel_, percentX, statusTop + 3, refreshPercentWidth, statusHeight - 3, TRUE);
    MoveWindow(refreshProgressBar_, progressX, statusTop + 3, refreshProgressWidth, 18, TRUE);
}

void MainWindow::setMainControlsEnabled(bool enabled) {
    const BOOL value = enabled ? TRUE : FALSE;
    if (refreshButton_) {
        EnableWindow(refreshButton_, value);
    }
    if (useButton_) {
        EnableWindow(useButton_, value);
    }
    if (stopButton_) {
        EnableWindow(stopButton_, value);
    }
    if (kAdminBuild) {
        updateAdminMoveButtons(enabled);
    }
    else {
        if (assignUserButton_) {
            EnableWindow(assignUserButton_, value);
        }
        if (removeUserButton_) {
            EnableWindow(removeUserButton_, value);
        }
    }
    if (openPolicyButton_) {
        EnableWindow(openPolicyButton_, value);
    }
    if (savePolicyButton_) {
        EnableWindow(savePolicyButton_, value && adminAccessLoaded_ && adminAccessDirty_);
    }
    if (computerEdit_) {
        EnableWindow(computerEdit_, value);
    }
    if (assignUserEdit_) {
        EnableWindow(assignUserEdit_, value);
    }
    if (loadComputerButton_) {
        EnableWindow(loadComputerButton_, value);
    }
    if (searchEdit_) {
        EnableWindow(searchEdit_, value);
    }
    if (clearSearchButton_) {
        EnableWindow(clearSearchButton_, value);
    }
    if (vpnMappingsButton_) {
        EnableWindow(vpnMappingsButton_, value && adminAccessLoaded_);
    }
    if (enabled) {
        updateActionButton();
    }
}

bool MainWindow::ensureVpnCredentials(const DeviceViewModel& device) {
    if (device.vpnProfileId.empty()) {
        updateStatus(L"Для токена не выбран VPN Windows или режим «Без VPN». Обратитесь к администратору.");
        return false;
    }

    try {
        const std::vector<VpnProfile> profiles = service_.vpnProfiles();
        const auto found = std::find_if(profiles.begin(), profiles.end(), [&device](const VpnProfile& profile) {
            return CompareStringOrdinal(
                profile.id.c_str(), static_cast<int>(profile.id.size()),
                device.vpnProfileId.c_str(), static_cast<int>(device.vpnProfileId.size()),
                TRUE) == CSTR_EQUAL;
        });
        if (found == profiles.end()) {
            updateStatus(L"Для токена назначен неизвестный VPN-профиль. Обратитесь к администратору.");
            return false;
        }
        if (!found->enabled) {
            updateStatus(L"VPN-профиль для этого токена отключён администратором.");
            return false;
        }
        if (found->mode == VpnProfileMode::Direct) {
            return true;
        }
        if (!VpnManager::profileExists(*found)) {
            updateStatus(L"Нужный профиль VPN Windows не найден. Создайте его в параметрах Windows или обратитесь к администратору.");
            return false;
        }
        if (VpnManager::hasStoredCredentials(*found)) {
            return true;
        }

        updateStatus(L"Для выбранного VPN не сохранены логин и пароль. Обратитесь к администратору для настройки подключения в Windows.");
        return false;
    }
    catch (const std::exception& error) {
        const std::wstring message = L"Не удалось проверить настройки VPN. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI VPN CREDENTIALS ERROR", error.what(), message);
        updateStatus(message.c_str());
        return false;
    }
}

void MainWindow::manageVpnMappings() {
#ifndef DISKCONTROL_ADMIN
    return;
#else
    if (adminAccessDirty_) {
        updateStatus(L"Сначала сохраните изменения доступа, затем откройте сопоставление VPN.");
        return;
    }
    const std::wstring userName = getControlText(assignUserEdit_);
    if (userName.empty() || !adminAccessLoaded_ ||
        lowerCopy(userName) != lowerCopy(loadedPolicyUser_)) {
        updateStatus(L"Сначала выберите пользователя и дождитесь загрузки его доступов.");
        return;
    }
    if (allowedDevices_.empty()) {
        updateStatus(L"У выбранного пользователя нет разрешённых токенов для сопоставления.");
        return;
    }

    try {
        VpnBulkDialogData data;
        data.service = &service_;
        data.userName = userName;
        data.expectedRevision = loadedPolicyRevision_;
        data.devices = allowedDevices_;
        data.profiles = service_.vpnProfiles();

        const std::wstring computerName = getControlText(computerEdit_);
        const auto selectedProfile = std::find_if(profileUsers_.begin(), profileUsers_.end(),
            [&userName](const UserProfileEntry& profile) {
                return lowerCopy(profile.accountName) == lowerCopy(userName);
            });
        if (isLocalComputerName(computerName) &&
            lowerCopy(userName) == lowerCopy(PolicyManager::currentUserName())) {
            data.windowsProfiles = VpnManager::installedProfiles();
        }
        else if (selectedProfile != profileUsers_.end()) {
            data.windowsProfiles = VpnManager::installedProfiles(
                selectedProfile->phonebookPath,
                allUsersPhonebookPathForComputer(computerName));
        }
        std::stable_sort(data.windowsProfiles.begin(), data.windowsProfiles.end(),
            [](const WindowsVpnProfileInfo& left, const WindowsVpnProfileInfo& right) {
                const int byName = CompareStringOrdinal(left.name.c_str(), -1,
                    right.name.c_str(), -1, TRUE);
                if (byName != CSTR_EQUAL) {
                    return byName == CSTR_LESS_THAN;
                }
                return left.phonebookScope == VpnPhonebookScope::CurrentUser &&
                    right.phonebookScope == VpnPhonebookScope::AllUsers;
            });

        const INT_PTR result = DialogBoxParamW(instance_, MAKEINTRESOURCEW(IDD_VPN_BULK), hwnd_,
            vpnBulkDialogProc, reinterpret_cast<LPARAM>(&data));
        if (result == IDOK) {
            const std::wstring revision = service_.updateAccessForUser(allDevices_, userName);
            captureAdminAccessState(userName, revision);
            applyDeviceFilter();
            updateStatus(L"Сопоставления токенов и VPN сохранены.");
        }
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Не удалось открыть сопоставление токенов и VPN. " +
            userFriendlyErrorMessage(error.what());
        logUiError(L"UI BULK VPN ERROR", error.what(), status);
        updateStatus(status.c_str());
        MessageBoxW(hwnd_, status.c_str(), L"DistControl Admin", MB_OK | MB_ICONERROR);
    }
#endif
}

void MainWindow::startTokenAction(DeviceViewModel device, bool connect) {
    const std::wstring operationId = AuditLogger::createOperationId(connect ? L"CONNECT" : L"DISCONNECT");
    AuditLogger::trace(operationId,
        std::wstring(L"Интерфейс принял команду пользователя: ") +
            (connect ? L"подключить" : L"отключить") + L" токен «" + device.nickname +
            L"», endpoint=" + device.endpoint + L".");
    if (refreshing_ && quietRefresh_) {
        AuditLogger::trace(operationId, L"Идёт фоновое обновление списка; команда будет выполнена сразу после него.");
        queuedTokenAction_ = { device, connect, true };
        updateStatus(L"Обновляем список токенов, команда выполнится через секунду...");
        return;
    }
    if (vpnWatchdogRunning_) {
        AuditLogger::trace(operationId, L"Операция не начата: сейчас выполняется фоновая проверка VPN.");
        updateStatus(L"Дождитесь окончания проверки VPN.");
        return;
    }
    if (refreshing_) {
        AuditLogger::trace(operationId, L"Операция не начата: ещё обновляется список токенов.");
        updateStatus(L"Дождитесь окончания обновления списка устройств.");
        return;
    }
    if (connect && !ensureVpnCredentials(device)) {
        AuditLogger::trace(operationId,
            L"Операция не начата: настройки VPN или сохранённые учётные данные Windows не прошли проверку.");
        return;
    }

    bool expected = false;
    if (!tokenActionRunning_.compare_exchange_strong(expected, true)) {
        AuditLogger::trace(operationId, L"Операция не начата: другая команда с токеном уже выполняется.");
        updateStatus(L"Операция с токеном уже выполняется...");
        return;
    }

    if (refreshing_) {
        tokenActionRunning_ = false;
        AuditLogger::trace(operationId, L"Операция отменена: одновременно началось обновление списка токенов.");
        updateStatus(L"Дождитесь окончания обновления списка устройств.");
        return;
    }

    if (connect) {
        const ULONGLONG now = GetTickCount64();
        const auto failure = tokenActionFailureTicks_.find(device.endpoint);
        if (failure != tokenActionFailureTicks_.end() && now - failure->second < kTokenActionFailureCooldownMs) {
            tokenActionRunning_ = false;
            AuditLogger::trace(operationId,
                L"Операция отложена: после предыдущей ошибки ещё действует минутная защита от частых повторов.");
            updateStatus(L"Недавняя попытка подключения этого токена завершилась ошибкой. Подождите минуту и нажмите «Обновить».");
            return;
        }
    }

    KillTimer(hwnd_, IDT_DELAYED_REFRESH);
    setMainControlsEnabled(false);
    updateStatus(connect ? L"Подключение токена..." : L"Отключение токена...");
    SetWindowTextW(refreshProgressLabel_, L"0%");
    SendMessageW(refreshProgressBar_, PBM_SETMARQUEE, FALSE, 0);
    SendMessageW(refreshProgressBar_, PBM_SETPOS, 0, 0);
    ShowWindow(refreshProgressLabel_, SW_SHOW);
    ShowWindow(refreshProgressBar_, SW_SHOW);
    layoutControls();
    AuditLogger::trace(operationId, L"Кнопки временно заблокированы, операция передана в фоновый поток.");

    if (tokenActionThread_.joinable()) {
        tokenActionThread_.join();
    }

    tokenActionThread_ = std::thread([this, device, connect, operationId]() {
        std::wstring status;
        std::wstring errorText;
        bool vpnError = false;
        const TokenActionProgressCallback progress = [this](size_t step, size_t total, const std::wstring& message) {
            {
                std::lock_guard<std::mutex> lock(tokenActionMutex_);
                pendingTokenActionProgressStep_ = step;
                pendingTokenActionProgressTotal_ = total;
                pendingTokenActionProgressText_ = message;
            }
            if (!closing_) PostMessageW(hwnd_, WM_TOKEN_ACTION_PROGRESS, 0, 0);
        };
        try {
            status = connect
                ? service_.useDevice(device, operationId, progress)
                : service_.stopUsingOwnedDevice(device, operationId, progress);
        }
        catch (const std::exception& error) {
            vpnError = containsAscii(error.what(), "VPN ");
            errorText = tokenActionErrorMessage(error.what(), connect);
            logUiError(connect ? L"UI USE ERROR" : L"UI STOP ERROR", error.what(), errorText);
        }

        {
            std::lock_guard<std::mutex> lock(tokenActionMutex_);
            pendingTokenActionStatus_ = std::move(status);
            pendingTokenActionError_ = std::move(errorText);
            pendingTokenActionEndpoint_ = device.endpoint;
            pendingTokenActionOperationId_ = operationId;
            pendingTokenActionConnect_ = connect;
            pendingTokenActionVpnError_ = vpnError;
        }

        if (!closing_) {
            PostMessageW(hwnd_, WM_TOKEN_ACTION_COMPLETE, 0, 0);
        }
    });
}

void MainWindow::finishTokenAction() {
    if (tokenActionThread_.joinable()) {
        tokenActionThread_.join();
    }

    std::wstring status;
    std::wstring errorText;
    std::wstring endpoint;
    std::wstring operationId;
    bool connect = false;
    bool vpnError = false;
    {
        std::lock_guard<std::mutex> lock(tokenActionMutex_);
        status = std::move(pendingTokenActionStatus_);
        errorText = std::move(pendingTokenActionError_);
        endpoint = std::move(pendingTokenActionEndpoint_);
        operationId = std::move(pendingTokenActionOperationId_);
        connect = pendingTokenActionConnect_;
        vpnError = pendingTokenActionVpnError_;
        pendingTokenActionStatus_.clear();
        pendingTokenActionError_.clear();
        pendingTokenActionEndpoint_.clear();
        pendingTokenActionOperationId_.clear();
        pendingTokenActionConnect_ = false;
        pendingTokenActionVpnError_ = false;
    }

    tokenActionRunning_ = false;
    updateHeaderText();
    hideRefreshProgress();
    setMainControlsEnabled(true);

    if (!errorText.empty()) {
        if (connect && !vpnError && !endpoint.empty()) {
            tokenActionFailureTicks_[endpoint] = GetTickCount64();
        }
        updateStatus((L"Ошибка: " + errorText).c_str(), RGB(190, 30, 30));
        AuditLogger::trace(operationId,
            L"Интерфейс получил ошибку операции и показал её пользователю: " + errorText);
        scheduleDelayedRefresh();
        return;
    }

    autoReleaseRequestTicks_.erase(endpoint);
    tokenActionFailureTicks_.erase(endpoint);
    if (connect) {
        activeDeviceStartTicks_[endpoint] = GetTickCount64();
    }
    else {
        activeDeviceStartTicks_.erase(endpoint);
        markDeviceLocallyReleased(endpoint);
    }

    updateStatus((L"✔ " + status).c_str(), RGB(20, 120, 50));
    updateTreeTimerText();
    lastNetworkStateTick_ = 0;
    AuditLogger::trace(operationId,
        L"Интерфейс применил успешный результат и запланировал контрольное обновление списка через 1,2 секунды.");
    scheduleDelayedRefresh();
}

void MainWindow::refreshDevices(bool quiet) {
    if (vpnWatchdogRunning_) {
        if (!quiet) {
            updateStatus(L"Дождитесь окончания проверки VPN.");
        }
        return;
    }
    if (tokenActionRunning_) {
        if (!quiet) {
            updateStatus(L"Сейчас выполняется операция с токеном...");
        }
        return;
    }

    bool expected = false;
    if (!refreshing_.compare_exchange_strong(expected, true)) {
        if (!quiet) {
            updateStatus(L"Обновление уже выполняется...");
        }
        return;
    }

    // A quiet refresh runs in the background on a timer: it keeps the buttons,
    // status line and tree state untouched and only re-reads changed tokens.
    quietRefresh_ = quiet;
    if (!quiet) {
        KillTimer(hwnd_, IDT_DELAYED_REFRESH);
        setMainControlsEnabled(false);
        showRefreshProgress();
        updateStatus(L"Загрузка списка устройств...");
    }

    if (refreshThread_.joinable()) {
        refreshThread_.join();
    }

    const bool includeDenied = kAdminBuild || diagnosticsMode_;
    const std::wstring policyUser = kAdminBuild ? getControlText(assignUserEdit_) : L"";
    std::vector<DeviceViewModel> previous;
    if (quiet) {
        previous = allDevices_;
    }
    refreshThread_ = std::thread([this, includeDenied, policyUser, quiet, previous = std::move(previous)]() {
        std::vector<DeviceViewModel> loadedDevices;
        std::wstring loadedError;
        std::wstring loadedPolicyRevision;
        const DeviceListProgressCallback progress = [this](size_t processed, size_t total) {
            refreshProcessed_.store(processed, std::memory_order_relaxed);
            refreshTotal_.store(total, std::memory_order_relaxed);
            if (!closing_) {
                PostMessageW(hwnd_, WM_REFRESH_PROGRESS, 0, 0);
            }
        };
        try {
            loadedDevices = quiet
                ? service_.listVisibleDevicesQuick(previous)
                : kAdminBuild
                ? service_.listAllDevicesForUser(policyUser, progress, &loadedPolicyRevision)
                : (includeDenied ? service_.listAllDevices(progress) : service_.listVisibleDevices(progress));
        }
        catch (const std::exception& error) {
            loadedError = L"Не удалось обновить список токенов. " + userFriendlyErrorMessage(error.what());
            if (!quiet) {
                logUiError(L"UI REFRESH ERROR", error.what(), loadedError);
            }
        }

        {
            std::lock_guard<std::mutex> lock(refreshMutex_);
            pendingDevices_ = std::move(loadedDevices);
            pendingError_ = std::move(loadedError);
            pendingPolicyRevision_ = std::move(loadedPolicyRevision);
            pendingPolicyUser_ = policyUser;
        }

        if (!closing_) {
            PostMessageW(hwnd_, WM_REFRESH_COMPLETE, 0, 0);
        }
    });
}

void MainWindow::updateTokenActionProgress() {
    if (!tokenActionRunning_) return;
    size_t step = 0;
    size_t total = 0;
    std::wstring message;
    {
        std::lock_guard<std::mutex> lock(tokenActionMutex_);
        step = pendingTokenActionProgressStep_;
        total = pendingTokenActionProgressTotal_;
        message = pendingTokenActionProgressText_;
    }
    if (total == 0) return;
    const int percent = static_cast<int>((std::min)(step * 100 / total, static_cast<size_t>(100)));
    SendMessageW(refreshProgressBar_, PBM_SETMARQUEE, FALSE, 0);
    SendMessageW(refreshProgressBar_, PBM_SETPOS, percent, 0);
    const std::wstring percentText = std::to_wstring(percent) + L"%";
    SetWindowTextW(refreshProgressLabel_, percentText.c_str());
    const std::wstring status = message + L". Шаг " + std::to_wstring(step) + L" из " +
        std::to_wstring(total) + L" (" + percentText + L").";
    updateStatus(status.c_str(), RGB(0, 90, 170));
}

void MainWindow::publishNetworkState() {
#ifdef DISKCONTROL_ADMIN
    return;
#else
    if (closing_ || tokenActionRunning_ || vpnWatchdogRunning_) {
        return;
    }
    const ULONGLONG now = GetTickCount64();
    if (lastNetworkStateTick_ != 0 && now - lastNetworkStateTick_ < kVpnWatchdogIntervalMs) {
        return;
    }
    bool expected = false;
    if (!networkStateRunning_.compare_exchange_strong(expected, true)) {
        return;
    }
    if (networkStateThread_.joinable()) {
        networkStateThread_.join();
    }
    lastNetworkStateTick_ = now;
    networkStateThread_ = std::thread([this]() {
        std::wstring errorText;
        try {
            NetworkStateSnapshot state;
            state.computerName = currentComputerName();
            state.userName = PolicyManager::currentUserName();
            state.publicIp = VpnManager::currentPublicIp();
            for (const ActiveVpnConnectionInfo& connection : VpnManager::activeConnections()) {
                state.activeVpnNames.push_back(connection.name);
            }
            state.updatedAtFileTime = currentFileTimeTicks();
            PolicyManager::writeNetworkState(state);
        }
        catch (const std::exception& error) {
            errorText = widenAscii(error.what());
        }
        {
            std::lock_guard<std::mutex> lock(networkStateMutex_);
            pendingNetworkStateError_ = std::move(errorText);
        }
        if (!closing_) {
            PostMessageW(hwnd_, WM_NETWORK_STATE_COMPLETE, 0, 0);
        }
    });
#endif
}

void MainWindow::finishNetworkStatePublish() {
#ifdef DISKCONTROL_ADMIN
    return;
#else
    if (networkStateThread_.joinable()) {
        networkStateThread_.join();
    }
    std::wstring errorText;
    {
        std::lock_guard<std::mutex> lock(networkStateMutex_);
        errorText = std::move(pendingNetworkStateError_);
        pendingNetworkStateError_.clear();
    }
    networkStateRunning_ = false;
    if (!errorText.empty()) {
        AuditEvent event;
        event.action = L"NETWORK STATE";
        event.result = L"WARNING";
        event.details = L"Не удалось обновить отчёт о внешнем IP и VPN. technical=" + errorText;
        AuditLogger::log(event);
    }
#endif
}

void MainWindow::scheduleDelayedRefresh() {
    SetTimer(hwnd_, IDT_DELAYED_REFRESH, 1200, nullptr);
}

void MainWindow::finishRefresh() {
    if (refreshThread_.joinable()) {
        refreshThread_.join();
    }

    std::vector<DeviceViewModel> loadedDevices;
    std::wstring loadedError;
    std::wstring loadedPolicyRevision;
    std::wstring loadedPolicyUser;
    {
        std::lock_guard<std::mutex> lock(refreshMutex_);
        loadedDevices = std::move(pendingDevices_);
        loadedError = std::move(pendingError_);
        loadedPolicyRevision = std::move(pendingPolicyRevision_);
        loadedPolicyUser = std::move(pendingPolicyUser_);
        pendingError_.clear();
    }

    const bool quiet = quietRefresh_;
    quietRefresh_ = false;
    if (quiet && !loadedError.empty()) {
        // Keep the current list; back off up to a minute while the service is unavailable.
        ++quietRefreshFailures_;
        const ULONGLONG delay = (std::min)(60000ULL,
            static_cast<ULONGLONG>(autoRefreshSeconds_ == 0 ? 5 : autoRefreshSeconds_) * 1000ULL *
                (1ULL << (std::min)(quietRefreshFailures_, 4u)));
        quietRefreshResumeAt_ = GetTickCount64() + delay;
        refreshing_ = false;
        runQueuedTokenAction();
        return;
    }
    quietRefreshFailures_ = 0;
    quietRefreshResumeAt_ = 0;

    if (!loadedError.empty()) {
        ++consecutiveRefreshFailures_;
        if (!allDevices_.empty()) {
            loadedError += L" Предыдущий список оставлен на экране.";
        }
        updateStatus(loadedError.c_str());
        hideRefreshProgress();
        refreshing_ = false;
        setMainControlsEnabled(true);
        if (!closing_ && consecutiveRefreshFailures_ <= kMaximumAutomaticRefreshRetries) {
            SetTimer(hwnd_, IDT_DELAYED_REFRESH, kRefreshRetryDelayMs, nullptr);
        }
        return;
    }

    consecutiveRefreshFailures_ = 0;
    allDevices_ = std::move(loadedDevices);

    if (kAdminBuild) {
        captureAdminAccessState(loadedPolicyUser, loadedPolicyRevision);
    }

    try {
        updateHeaderText();
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Ошибка политики. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI HEADER ERROR", error.what(), status);
        SetWindowTextW(userInfoLabel_, status.c_str());
    }

    updateActiveDeviceTracking();
    applyDeviceFilter(!quiet);
    refreshing_ = false;
    if (quiet) {
        updateActionButton();
    }
    else {
        hideRefreshProgress();
        setMainControlsEnabled(true);
        applyAutoRefreshInterval();
    }
    runQueuedTokenAction();
}

void MainWindow::applyAutoRefreshInterval() {
    if (kAdminBuild) {
        return;
    }
    unsigned int seconds = 5;
    try {
        seconds = PolicyManager().refreshSeconds();
    }
    catch (const std::exception&) {
        // The regular refresh reports policy errors.
    }
    if (seconds != autoRefreshSeconds_) {
        autoRefreshSeconds_ = seconds;
        SetTimer(hwnd_, IDT_AUTO_REFRESH, seconds * 1000U, nullptr);
    }
}

void MainWindow::runQueuedTokenAction() {
    if (!queuedTokenAction_.valid) {
        return;
    }
    const DeviceViewModel requested = queuedTokenAction_.device;
    const bool connect = queuedTokenAction_.connect;
    queuedTokenAction_ = {};

    const auto found = std::find_if(devices_.begin(), devices_.end(),
        [&requested](const DeviceViewModel& device) { return device.endpoint == requested.endpoint; });
    if (found == devices_.end()) {
        updateStatus(L"Токен больше не доступен в списке.");
        return;
    }
    const DeviceUsageInfo usage = DeviceParser::parseUsage(found->inUseBy, PolicyManager::currentUserName());
    if (connect && !usage.isFree) {
        updateStatus(usage.isUsedByCurrentUser ? L"Токен уже подключён вами." : L"Токен только что занял другой пользователь.");
        return;
    }
    if (!connect && !usage.isUsedByCurrentUser) {
        updateStatus(L"Токен уже отключён.");
        return;
    }
    startTokenAction(*found, connect);
}

void MainWindow::exportExcel() {
    const std::vector<DeviceViewModel>& source = allDevices_.empty() ? devices_ : allDevices_;
    if (source.empty()) {
        updateStatus(L"Нет данных для экспорта.");
        return;
    }

    wchar_t fileName[MAX_PATH]{};
    const std::wstring defaultName = L"dk-usb-list-" + timestampForFileName() + L".xls";
    const size_t copyLength = (std::min)(defaultName.size(), static_cast<size_t>(MAX_PATH - 1));
    std::copy_n(defaultName.c_str(), copyLength, fileName);
    fileName[copyLength] = L'\0';

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = hwnd_;
    dialog.lpstrFilter = L"Excel (*.xls)\0*.xls\0HTML (*.html)\0*.html\0Все файлы (*.*)\0*.*\0";
    dialog.lpstrFile = fileName;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrDefExt = L"xls";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    dialog.lpstrTitle = L"Сохранить список токенов";

    if (!GetSaveFileNameW(&dialog)) {
        updateStatus(L"Экспорт Excel отменён.");
        return;
    }

    const std::wstring selectedPath = fileName;
    std::ofstream stream(selectedPath, std::ios::binary);
    if (!stream) {
        updateStatus(L"Не удалось создать Excel-файл.");
        return;
    }

    stream << "\xEF\xBB\xBF";
    stream
        << "<html><head><meta charset=\"utf-8\"></head><body>"
        << "<table border=\"1\">"
        << "<tr>"
        << "<th>Endpoint</th><th>Имя</th><th>VPN</th><th>Состояние</th>"
        << "<th>Кем занят</th><th>Адрес</th><th>Осталось</th><th>Продукт</th><th>Доступ</th>"
        << "</tr>";
    for (const DeviceViewModel& device : source) {
        stream << "<tr>"
            << "<td>" << htmlEscape(device.endpoint) << "</td>"
            << "<td>" << htmlEscape(device.nickname) << "</td>"
            << "<td>" << htmlEscape(networkProfileText(device)) << "</td>"
            << "<td>" << htmlEscape(device.statusText) << "</td>"
            << "<td>" << htmlEscape(device.usedBy) << "</td>"
            << "<td>" << htmlEscape(device.usedAt) << "</td>"
            << "<td>" << htmlEscape(adminRemainingText(device)) << "</td>"
            << "<td>" << htmlEscape(device.product) << "</td>"
            << "<td>" << (device.allowed ? "Разрешён" : "Запрещён") << "</td>"
            << "</tr>";
    }
    stream << "</table></body></html>";

    const std::wstring status = L"Excel-файл создан: " + selectedPath;
    updateStatus(status.c_str());
}

void MainWindow::applyDeviceFilter(bool showSummary) {
    const std::wstring query = diagnosticsMode_ ? getControlText(searchEdit_) : L"";
    devices_.clear();
    for (const DeviceViewModel& device : allDevices_) {
        if (matchesSearch(device, query)) {
            devices_.push_back(device);
        }
    }

    sortDevices();
    populateListView();

    size_t allowedCount = 0;
    for (const DeviceViewModel& device : devices_) {
        if (device.allowed) {
            ++allowedCount;
        }
    }

    std::wstring status;
    if (diagnosticsMode_) {
        const std::wstring userName = kAdminBuild ? getControlText(assignUserEdit_) : PolicyManager::currentUserName();
        const std::wstring userLabel = userName.empty() ? L"(не указан)" : userName;
        status = query.empty()
            ? L"Админ режим: всего устройств " + std::to_wstring(devices_.size()) +
                L", разрешено для " + userLabel + L": " + std::to_wstring(allowedCount)
            : L"Поиск: найдено " + std::to_wstring(devices_.size()) +
                L" из " + std::to_wstring(allDevices_.size());
    }
    else {
        status = L"Найдено разрешённых устройств: " + std::to_wstring(devices_.size());
    }
    if (showSummary) {
        updateStatus(status.c_str());
    }
}

void MainWindow::populateListView() {
    if (!listView_) {
        populateTreeView();
        return;
    }

    if (kAdminBuild) {
        populateAdminListViews();
        return;
    }

    populatingList_ = true;
    ListView_DeleteAllItems(listView_);
    for (size_t i = 0; i < devices_.size(); ++i) {
        insertDeviceRow(listView_, static_cast<int>(i), devices_[i], true);
    }
    populatingList_ = false;
}

void MainWindow::populateAdminListViews() {
    allowedDevices_.clear();
    availableDevices_.clear();
    for (const DeviceViewModel& device : devices_) {
        if (device.allowed) {
            allowedDevices_.push_back(device);
        }
        else {
            availableDevices_.push_back(device);
        }
    }

    populateGroupedDeviceList(listView_, allowedDevices_);
    populateGroupedDeviceList(availableListView_, availableDevices_);

    const std::wstring leftTitle = L"Разрешено пользователю: " + std::to_wstring(allowedDevices_.size());
    const std::wstring rightTitle = L"Можно добавить: " + std::to_wstring(availableDevices_.size());
    SetWindowTextW(allowedTitleLabel_, leftTitle.c_str());
    SetWindowTextW(availableTitleLabel_, rightTitle.c_str());
    updateAdminMoveButtons(IsWindowEnabled(refreshButton_) != FALSE);
}

void MainWindow::updateAdminMoveButtons(bool controlsEnabled) {
    if (!kAdminBuild || !assignUserButton_ || !removeUserButton_) {
        return;
    }
    const UINT toAdd = availableListView_ ? ListView_GetSelectedCount(availableListView_) : 0;
    const UINT toRemove = listView_ ? ListView_GetSelectedCount(listView_) : 0;
    const std::wstring addText = toAdd == 0
        ? L"← Добавить выбранные"
        : L"← Добавить выбранные (" + std::to_wstring(toAdd) + L")";
    const std::wstring removeText = toRemove == 0
        ? L"Убрать выбранные →"
        : L"Убрать выбранные (" + std::to_wstring(toRemove) + L") →";
    if (getControlText(assignUserButton_) != addText) {
        SetWindowTextW(assignUserButton_, addText.c_str());
    }
    if (getControlText(removeUserButton_) != removeText) {
        SetWindowTextW(removeUserButton_, removeText.c_str());
    }
    const bool canEdit = controlsEnabled && adminAccessLoaded_;
    EnableWindow(assignUserButton_, canEdit && toAdd != 0 ? TRUE : FALSE);
    EnableWindow(removeUserButton_, canEdit && toRemove != 0 ? TRUE : FALSE);
}

void MainWindow::populateTreeView() {
    if (!treeView_) {
        return;
    }

    std::vector<std::wstring> endpoints;
    endpoints.reserve(devices_.size());
    for (const DeviceViewModel& device : devices_) {
        endpoints.push_back(device.endpoint);
    }
    if (!endpoints.empty() && endpoints == treeEndpoints_ && TreeView_GetCount(treeView_) != 0) {
        // Same tokens in the same order: update texts and icons in place.
        updateTreeTimerText();
        return;
    }

    // Remember what the user sees, keyed by endpoint or group name, because
    // item handles and indexes change with the rebuild.
    const auto itemKey = [this](HTREEITEM item) -> std::wstring {
        wchar_t text[512]{};
        TVITEMW info{};
        info.mask = TVIF_PARAM | TVIF_TEXT;
        info.hItem = item;
        info.pszText = text;
        info.cchTextMax = static_cast<int>(std::size(text));
        if (!item || !TreeView_GetItem(treeView_, &info)) {
            return {};
        }
        if (info.lParam == kTreeGroupParam) {
            return L"group:" + std::wstring(text);
        }
        const size_t index = static_cast<size_t>(info.lParam);
        return index < treeEndpoints_.size() ? treeEndpoints_[index] : std::wstring{};
    };
    const std::wstring selectedKey = itemKey(TreeView_GetSelection(treeView_));
    const std::wstring firstVisibleKey = itemKey(TreeView_GetFirstVisible(treeView_));
    std::set<std::wstring> collapsedGroups;
    for (HTREEITEM group = TreeView_GetRoot(treeView_); group; group = TreeView_GetNextSibling(treeView_, group)) {
        if ((TreeView_GetItemState(treeView_, group, TVIS_EXPANDED) & TVIS_EXPANDED) == 0) {
            collapsedGroups.insert(itemKey(group));
        }
    }

    SendMessageW(treeView_, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(treeView_);
    std::map<std::wstring, HTREEITEM> itemsByKey;
    std::map<std::wstring, HTREEITEM> groups;
    for (size_t i = 0; i < devices_.size(); ++i) {
        const DeviceViewModel& device = devices_[i];
        const std::wstring groupName = endpointGroupName(device.endpoint);
        HTREEITEM groupItem = nullptr;
        auto existing = groups.find(groupName);
        if (existing == groups.end()) {
            TVINSERTSTRUCTW groupInsert{};
            groupInsert.hParent = TVI_ROOT;
            groupInsert.hInsertAfter = TVI_LAST;
            groupInsert.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
            groupInsert.item.pszText = const_cast<wchar_t*>(groupName.c_str());
            groupInsert.item.lParam = kTreeGroupParam;
            groupInsert.item.iImage = 0;
            groupInsert.item.iSelectedImage = 0;
            groupItem = TreeView_InsertItem(treeView_, &groupInsert);
            groups.emplace(groupName, groupItem);
            itemsByKey[L"group:" + groupName] = groupItem;
        }
        else {
            groupItem = existing->second;
        }

        const std::wstring duration = activeDurationText(device);
        const std::wstring text = duration.empty()
            ? treeDeviceText(device)
            : treeDeviceText(device) + L" [" + duration + L"]";
        const int image = treeImageIndexForDevice(device);
        TVINSERTSTRUCTW itemInsert{};
        itemInsert.hParent = groupItem;
        itemInsert.hInsertAfter = TVI_LAST;
        itemInsert.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
        itemInsert.item.pszText = const_cast<wchar_t*>(text.c_str());
        itemInsert.item.lParam = static_cast<LPARAM>(i);
        itemInsert.item.iImage = image;
        itemInsert.item.iSelectedImage = image;
        itemsByKey[device.endpoint] = TreeView_InsertItem(treeView_, &itemInsert);
        if (collapsedGroups.count(L"group:" + groupName) == 0) {
            TreeView_Expand(treeView_, groupItem, TVE_EXPAND);
        }
    }

    treeEndpoints_ = std::move(endpoints);
    const auto restored = itemsByKey.find(selectedKey);
    if (restored != itemsByKey.end()) {
        TreeView_SelectItem(treeView_, restored->second);
    }
    const auto firstVisible = itemsByKey.find(firstVisibleKey);
    if (firstVisible != itemsByKey.end()) {
        TreeView_SelectSetFirstVisible(treeView_, firstVisible->second);
    }
    SendMessageW(treeView_, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(treeView_, nullptr, TRUE);
    updateActionButton();
}

void MainWindow::updateTreeTimerText() {
    if (!treeView_) {
        return;
    }

    updateTreeTimerTextRecursive(TreeView_GetRoot(treeView_));
    updateActionButton();
}

void MainWindow::updateTreeTimerTextRecursive(HTREEITEM item) {
    while (item) {
        TVITEMW info{};
        wchar_t currentText[1024]{};
        info.mask = TVIF_PARAM | TVIF_TEXT | TVIF_IMAGE;
        info.hItem = item;
        info.pszText = currentText;
        info.cchTextMax = static_cast<int>(std::size(currentText));
        if (TreeView_GetItem(treeView_, &info) && info.lParam != kTreeGroupParam) {
            const size_t index = static_cast<size_t>(info.lParam);
            if (index < devices_.size()) {
                const DeviceViewModel& device = devices_[index];
                const std::wstring duration = activeDurationText(device);
                const std::wstring text = duration.empty()
                    ? treeDeviceText(device)
                    : treeDeviceText(device) + L" [" + duration + L"]";
                const int image = treeImageIndexForDevice(device);
                if (text != currentText || image != info.iImage) {
                    TVITEMW update{};
                    update.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
                    update.hItem = item;
                    update.pszText = const_cast<wchar_t*>(text.c_str());
                    update.iImage = image;
                    update.iSelectedImage = image;
                    TreeView_SetItem(treeView_, &update);
                    RECT row{};
                    if (item == TreeView_GetSelection(treeView_) &&
                        TreeView_GetItemRect(treeView_, item, &row, FALSE)) {
                        InvalidateRect(treeView_, &row, TRUE);
                    }
                }
            }
        }

        HTREEITEM child = TreeView_GetChild(treeView_, item);
        if (child) {
            updateTreeTimerTextRecursive(child);
        }
        item = TreeView_GetNextSibling(treeView_, item);
    }
}

void MainWindow::sortDevices() {
    const int column = sortColumn_;
    const bool ascending = sortAscending_;
    std::stable_sort(devices_.begin(), devices_.end(),
        [column, ascending](const DeviceViewModel& left, const DeviceViewModel& right) {
            const std::wstring leftValue = lowerCopy(columnValue(left, column));
            const std::wstring rightValue = lowerCopy(columnValue(right, column));
            if (leftValue == rightValue) {
                return lowerCopy(left.endpoint) < lowerCopy(right.endpoint);
            }
            return ascending ? leftValue < rightValue : rightValue < leftValue;
        });
}

void MainWindow::sortByColumn(int column) {
    if (sortColumn_ == column) {
        sortAscending_ = !sortAscending_;
    }
    else {
        sortColumn_ = column;
        sortAscending_ = true;
    }

    sortDevices();
    populateListView();
}

void MainWindow::updateHeaderText() {
    try {
        if (kAdminBuild) {
            const std::wstring userName = getControlText(assignUserEdit_);
            std::wstring text = L"Конфиг: " + service_.currentPolicyPath() +
                L" | Пользователь: " + (userName.empty() ? L"(не указан)" : userName);
            if (adminAccessDirty_) {
                text += L" | НЕ СОХРАНЕНО";
            }
            else if (!adminAccessLoaded_) {
                text += L" | данные доступа не загружены";
            }
            SetWindowTextW(userInfoLabel_, text.c_str());
        }
        else {
            std::wstring text = service_.currentUserSummary();
            try {
                const size_t pending = service_.pendingUsageSyncCount();
                if (pending != 0) {
                    text += L" | Общий таймер: ожидает синхронизации (" + std::to_wstring(pending) + L")";
                }
            }
            catch (const std::exception& error) {
                text += L" | Локальные таймеры недоступны";
                logUiError(L"UI USAGE STATE ERROR", error.what(), text);
            }
            SetWindowTextW(userInfoLabel_, text.c_str());
        }
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Ошибка политики. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI HEADER ERROR", error.what(), status);
        SetWindowTextW(userInfoLabel_, status.c_str());
    }
}

bool MainWindow::selectAdminUserProfile(
    const std::wstring& userName,
    bool refreshDeviceList) {
#ifndef DISKCONTROL_ADMIN
    (void)userName;
    (void)refreshDeviceList;
    return false;
#else
    const auto found = std::find_if(profileUsers_.begin(), profileUsers_.end(),
        [&userName](const UserProfileEntry& profile) {
            return lowerCopy(profile.accountName) == lowerCopy(userName);
        });
    if (found == profileUsers_.end()) {
        invalidateAdminAccessState();
        updateStatus(L"Выберите пользователя из списка профилей Windows.");
        return false;
    }
    if (GetFileAttributesW(found->policyPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        invalidateAdminAccessState();
        const std::wstring status = L"Для пользователя " + found->accountName +
            L" не найден файл " + found->policyPath +
            L". Установите DistControl для этого пользователя.";
        updateStatus(status.c_str());
        updateHeaderText();
        return false;
    }

    try {
        PolicyManager policy(found->policyPath);
        PolicyManager::setConfigPathOverride(found->policyPath);
        invalidateAdminAccessState();
        updateHeaderText();
        const std::wstring status = L"Выбран пользователь " + found->accountName +
            L". Конфигурация: " + found->policyPath;
        updateStatus(status.c_str());
        if (refreshDeviceList) {
            refreshDevices();
        }
        return true;
    }
    catch (const std::exception& error) {
        invalidateAdminAccessState();
        const std::wstring status = L"Не удалось открыть настройки пользователя " +
            found->accountName + L". " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI SELECT USER POLICY ERROR", error.what(), status);
        updateStatus(status.c_str());
        updateHeaderText();
        return false;
    }
#endif
}

void MainWindow::refreshAccessForEditedUser() {
#ifndef DISKCONTROL_ADMIN
    return;
#else
    if (refreshing_) {
        return;
    }

    updateHeaderText();
    const std::wstring userName = getControlText(assignUserEdit_);
    if (userName.empty()) {
        invalidateAdminAccessState();
        applyDeviceFilter();
        updateStatus(L"Введите или выберите пользователя.");
        return;
    }
    if (allDevices_.empty()) {
        invalidateAdminAccessState();
        return;
    }

    try {
        const std::wstring revision = service_.updateAccessForUser(allDevices_, userName);
        captureAdminAccessState(userName, revision);
        applyDeviceFilter();
    }
    catch (const std::exception& error) {
        invalidateAdminAccessState();
        applyDeviceFilter();
        const std::wstring status = L"Не удалось прочитать доступ пользователя. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI POLICY READ ERROR", error.what(), status);
        updateStatus(status.c_str());
    }
#endif
}

bool MainWindow::confirmDiscardAdminChanges() {
#ifndef DISKCONTROL_ADMIN
    return true;
#else
    if (!adminAccessDirty_) {
        return true;
    }
    const int answer = MessageBoxW(
        hwnd_,
        L"Есть несохранённые изменения доступа. Отменить их и продолжить?",
        L"DistControl Admin",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (answer != IDYES) {
        return false;
    }
    for (DeviceViewModel& device : allDevices_) {
        device.allowed = wasDeviceAllowedAtLoad(device);
    }
    adminAccessDirty_ = false;
    applyDeviceFilter();
    updateHeaderText();
    updateAdminSaveState();
    return true;
#endif
}

void MainWindow::captureAdminAccessState(
    const std::wstring& userName,
    const std::wstring& revision) {
#ifdef DISKCONTROL_ADMIN
    loadedPolicyUser_ = userName;
    loadedPolicyRevision_ = revision;
    baselineAllowedDevices_.clear();
    for (const DeviceViewModel& device : allDevices_) {
        if (device.allowed) {
            baselineAllowedDevices_.push_back(device);
        }
    }
    adminAccessLoaded_ = true;
    adminAccessDirty_ = false;
    updateHeaderText();
    updateAdminSaveState();
#else
    (void)userName;
    (void)revision;
#endif
}

void MainWindow::invalidateAdminAccessState() {
#ifdef DISKCONTROL_ADMIN
    loadedPolicyUser_.clear();
    loadedPolicyRevision_.clear();
    baselineAllowedDevices_.clear();
    adminAccessLoaded_ = false;
    adminAccessDirty_ = false;
    for (DeviceViewModel& device : allDevices_) {
        device.allowed = false;
        device.vpnProfileId.clear();
        device.vpnProfileDisplay.clear();
    }
    updateHeaderText();
    updateAdminSaveState();
#endif
}

void MainWindow::markAdminAccessDirty() {
#ifdef DISKCONTROL_ADMIN
    if (!adminAccessLoaded_) {
        return;
    }
    adminAccessDirty_ = true;
    updateHeaderText();
    updateAdminSaveState();
#endif
}

void MainWindow::updateAdminSaveState() {
#ifdef DISKCONTROL_ADMIN
    if (savePolicyButton_) {
        EnableWindow(savePolicyButton_, adminAccessLoaded_ && adminAccessDirty_ &&
            !refreshing_ && !computerLoading_);
    }
#endif
}

bool MainWindow::wasDeviceAllowedAtLoad(const DeviceViewModel& device) const {
#ifdef DISKCONTROL_ADMIN
    return std::any_of(
        baselineAllowedDevices_.begin(), baselineAllowedDevices_.end(),
        [&device](const DeviceViewModel& baseline) {
            return sameDeviceIdentity(baseline, device);
        });
#else
    (void)device;
    return false;
#endif
}

void MainWindow::loadProfilesForComputer(const std::wstring& computerName) {
#ifndef DISKCONTROL_ADMIN
    (void)computerName;
    return;
#else
    if (!assignUserEdit_) {
        return;
    }

    const std::wstring currentUser = PolicyManager::currentUserName();
    profileUsers_ = profileUsersForComputer(computerName);

    suppressAdminUserChange_ = true;
    ComboBox_ResetContent(assignUserEdit_);
    const UserProfileEntry* selected = nullptr;
    for (const UserProfileEntry& profile : profileUsers_) {
        ComboBox_AddString(assignUserEdit_, profile.accountName.c_str());
        if (!currentUser.empty() && lowerCopy(profile.accountName) == lowerCopy(currentUser)) {
            selected = &profile;
        }
    }
    if (!selected) {
        const auto found = std::find_if(profileUsers_.begin(), profileUsers_.end(),
            [](const UserProfileEntry& profile) {
                return GetFileAttributesW(profile.policyPath.c_str()) != INVALID_FILE_ATTRIBUTES;
            });
        selected = found == profileUsers_.end()
            ? (profileUsers_.empty() ? nullptr : &profileUsers_.front())
            : &*found;
    }
    if (selected) {
        SetWindowTextW(assignUserEdit_, selected->accountName.c_str());
        if (GetFileAttributesW(selected->policyPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            PolicyManager::setConfigPathOverride(selected->policyPath);
        }
    }
    suppressAdminUserChange_ = false;
#endif
}

void MainWindow::loadProfilesAndPolicyFromComputer() {
    if (!kAdminBuild) {
        return;
    }
    if (computerLoading_) {
        updateStatus(L"Загрузка компьютера уже выполняется...");
        return;
    }

    if (computerLoadThread_.joinable()) {
        computerLoadThread_.join();
    }

    const std::wstring computerName = getControlText(computerEdit_);
    const std::wstring profilesRoot = profilesRootForComputer(computerName);
    const std::wstring requestedUser = getControlText(assignUserEdit_);

    computerLoading_ = true;
    setMainControlsEnabled(false);
    ShowWindow(computerProgressBar_, SW_SHOW);
    SendMessageW(computerProgressBar_, PBM_SETMARQUEE, TRUE, 30);
    updateStatus(L"Подключение к компьютеру и чтение профилей...");

    computerLoadThread_ = std::thread([this, computerName, profilesRoot, requestedUser]() {
        std::vector<UserProfileEntry> profiles;
        std::wstring policyPath;
        std::wstring selectedUser;
        std::wstring errorText;
        bool repaired = false;

        try {
            if (!ensureReadablePath(profilesRoot, errorText)) {
                throw std::runtime_error("profiles");
            }

            profiles = profileUsersForComputer(computerName);
            const UserProfileEntry* selected = nullptr;
            for (const UserProfileEntry& profile : profiles) {
                if (!requestedUser.empty() &&
                    lowerCopy(profile.accountName) == lowerCopy(requestedUser)) {
                    selected = &profile;
                    break;
                }
            }
            if (!selected) {
                const auto found = std::find_if(profiles.begin(), profiles.end(),
                    [](const UserProfileEntry& profile) {
                        return GetFileAttributesW(profile.policyPath.c_str()) != INVALID_FILE_ATTRIBUTES;
                    });
                selected = found == profiles.end() ? nullptr : &*found;
            }
            if (!selected) {
                errorText = L"Не найден файл %LOCALAPPDATA%\\DistControl\\allow.json "
                    L"ни в одном пользовательском профиле выбранного компьютера.";
                throw std::runtime_error("policy parent");
            }
            selectedUser = selected->accountName;
            policyPath = selected->policyPath;
            if (GetFileAttributesW(policyPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                errorText = L"Для пользователя " + selectedUser + L" не найден файл " +
                    policyPath + L". Установите DistControl для этой учётной записи.";
                throw std::runtime_error("policy missing");
            }
            repaired = PolicyManager::ensureEditableConfig(policyPath);
        }
        catch (const std::exception& error) {
            if (errorText.empty()) {
                errorText = L"Не удалось открыть или подготовить конфиг " + policyPath + L". " +
                    userFriendlyErrorMessage(error.what()) +
                    L" Проверьте имя компьютера, сеть, административную шару C$, права администратора и наличие DistControl на машине.";
            }
            logUiError(L"UI REMOTE COMPUTER ERROR", error.what(), errorText);
        }

        {
            std::lock_guard<std::mutex> lock(computerLoadMutex_);
            pendingComputerName_ = computerName;
            pendingComputerUser_ = selectedUser;
            pendingComputerPolicyPath_ = policyPath;
            pendingProfileUsers_ = std::move(profiles);
            pendingComputerPolicyRepaired_ = repaired;
            pendingComputerError_ = std::move(errorText);
        }

        if (!closing_) {
            PostMessageW(hwnd_, WM_COMPUTER_LOAD_COMPLETE, 0, 0);
        }
    });
}

void MainWindow::finishComputerLoad() {
    if (computerLoadThread_.joinable()) {
        computerLoadThread_.join();
    }

    std::vector<UserProfileEntry> profiles;
    std::wstring computerName;
    std::wstring selectedUser;
    std::wstring policyPath;
    std::wstring errorText;
    bool repaired = false;
    {
        std::lock_guard<std::mutex> lock(computerLoadMutex_);
        profiles = std::move(pendingProfileUsers_);
        computerName = std::move(pendingComputerName_);
        selectedUser = std::move(pendingComputerUser_);
        policyPath = std::move(pendingComputerPolicyPath_);
        errorText = std::move(pendingComputerError_);
        repaired = pendingComputerPolicyRepaired_;
        pendingComputerPolicyRepaired_ = false;
    }

    computerLoading_ = false;
    SendMessageW(computerProgressBar_, PBM_SETMARQUEE, FALSE, 0);
    ShowWindow(computerProgressBar_, SW_HIDE);
    setMainControlsEnabled(true);

    if (!errorText.empty()) {
        updateStatus(errorText.c_str());
        MessageBoxW(hwnd_, errorText.c_str(), L"DistControl Admin", MB_ICONERROR | MB_OK);
        return;
    }

    PolicyManager::setConfigPathOverride(policyPath);
    invalidateAdminAccessState();

    profileUsers_ = std::move(profiles);
    suppressAdminUserChange_ = true;
    ComboBox_ResetContent(assignUserEdit_);
    for (const UserProfileEntry& profile : profileUsers_) {
        ComboBox_AddString(assignUserEdit_, profile.accountName.c_str());
    }
    if (!selectedUser.empty()) {
        SetWindowTextW(assignUserEdit_, selectedUser.c_str());
    }
    else if (!profileUsers_.empty()) {
        SetWindowTextW(assignUserEdit_, profileUsers_.front().accountName.c_str());
    }
    suppressAdminUserChange_ = false;

    updateHeaderText();
    refreshDevices();

    std::wstring status = L"Загружен конфиг: " + policyPath;
    if (repaired) {
        status += L" (создан новый пустой allow.json)";
    }
    if (profileUsers_.empty()) {
        status += L". Профили пользователей не найдены.";
    }
    updateStatus(status.c_str());
}

void MainWindow::openPolicyFile() {
    if (!kAdminBuild) {
        return;
    }

    wchar_t path[MAX_PATH]{};
    try {
        const std::wstring currentPath = service_.currentPolicyPath();
        const size_t copyLength = (std::min)(currentPath.size(), static_cast<size_t>(MAX_PATH - 1));
        std::copy_n(currentPath.c_str(), copyLength, path);
        path[copyLength] = L'\0';
    }
    catch (...) {
        path[0] = L'\0';
    }

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = hwnd_;
    dialog.lpstrFilter = L"JSON (*.json)\0*.json\0Все файлы (*.*)\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrDefExt = L"json";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (!GetOpenFileNameW(&dialog)) {
        return;
    }

    bool repaired = false;
    try {
        repaired = PolicyManager::ensureEditableConfig(path);
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Не удалось подготовить конфиг. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI OPEN POLICY ERROR", error.what(), status);
        updateStatus(status.c_str());
        MessageBoxW(hwnd_, status.c_str(), L"DistControl Admin", MB_ICONERROR | MB_OK);
        return;
    }

    PolicyManager::setConfigPathOverride(path);
    invalidateAdminAccessState();
    updateHeaderText();
    refreshDevices();

    if (repaired) {
        MessageBoxW(hwnd_,
            L"Файл конфигурации отсутствовал и был создан как пустой allow.json.",
            L"DistControl Admin",
            MB_ICONWARNING | MB_OK);
    }
}

void MainWindow::saveCheckedDevicesForUser() {
    if (!kAdminBuild) {
        return;
    }

    const std::wstring userName = getControlText(assignUserEdit_);
    if (userName.empty()) {
        updateStatus(L"Введите пользователя для сохранения доступа.");
        return;
    }
    if (!adminAccessLoaded_ || lowerCopy(userName) != lowerCopy(loadedPolicyUser_)) {
        updateStatus(L"Доступ этого пользователя не был успешно загружен. Нажмите «Обновить» и повторите действие.");
        return;
    }

    std::vector<DeviceViewModel> addedDevices;
    std::vector<DeviceViewModel> removedDevices;
    for (const DeviceViewModel& device : allDevices_) {
        const bool wasAllowed = wasDeviceAllowedAtLoad(device);
        if (device.allowed && !wasAllowed) {
            addedDevices.push_back(device);
        }
        else if (!device.allowed && wasAllowed) {
            removedDevices.push_back(device);
        }
    }

    if (addedDevices.empty() && removedDevices.empty()) {
        adminAccessDirty_ = false;
        updateHeaderText();
        updateAdminSaveState();
        updateStatus(L"Изменений доступа нет.");
        return;
    }

    if (!baselineAllowedDevices_.empty() &&
        removedDevices.size() == baselineAllowedDevices_.size() &&
        MessageBoxW(
            hwnd_,
            L"Будет снят доступ ко всем отображаемым токенам пользователя. Продолжить?",
            L"DistControl Admin",
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
        updateStatus(L"Сохранение отменено.");
        return;
    }

    try {
        const std::wstring newRevision = service_.applyDeviceAccessChanges(
            addedDevices, removedDevices, userName, loadedPolicyRevision_);
        const std::wstring verifiedRevision = service_.updateAccessForUser(allDevices_, userName);
        captureAdminAccessState(userName, verifiedRevision.empty() ? newRevision : verifiedRevision);
        applyDeviceFilter();
        const std::wstring status = L"Доступ сохранён: добавлено " +
            std::to_wstring(addedDevices.size()) + L", убрано " +
            std::to_wstring(removedDevices.size()) + L". Остальные записи не изменялись.";
        updateStatus(status.c_str());
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Не удалось сохранить доступ. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI SAVE POLICY ERROR", error.what(), status);
        updateStatus(status.c_str());
    }
}

void MainWindow::exportJson() {
    if (devices_.empty()) {
        updateStatus(L"Нет данных для экспорта.");
        return;
    }

    const std::wstring fileName = L"dk-usb-list-cpp-" + timestampForFileName() + L".json";
    std::ofstream stream(fileName, std::ios::binary);
    if (!stream) {
        updateStatus(L"Не удалось создать JSON-файл.");
        return;
    }

    stream << "\xEF\xBB\xBF";
    stream << "[\n";
    for (size_t i = 0; i < devices_.size(); ++i) {
        const DeviceViewModel& device = devices_[i];
        stream
            << "  {\n"
            << "    \"endpoint\": " << jsonEscape(device.endpoint) << ",\n"
            << "    \"nickname\": " << jsonEscape(device.nickname) << ",\n"
            << "    \"product\": " << jsonEscape(device.product) << ",\n"
            << "    \"status\": " << jsonEscape(device.statusText) << ",\n"
            << "    \"usedBy\": " << jsonEscape(device.usedBy) << ",\n"
            << "    \"usedAt\": " << jsonEscape(device.usedAt) << ",\n"
            << "    \"inUseBy\": " << jsonEscape(device.inUseBy) << ",\n"
            << "    \"allowed\": " << (device.allowed ? "true" : "false") << "\n"
            << "  }" << (i + 1 < devices_.size() ? "," : "") << "\n";
    }
    stream << "]\n";

    const std::wstring status = L"JSON экспортирован: " + fileName;
    updateStatus(status.c_str());
}

void MainWindow::assignSelectedDeviceToUser() {
    const std::vector<DeviceViewModel> selected = kAdminBuild
        ? selectedDevicesFrom(availableListView_, availableDevices_)
        : selectedDevices();
    if (selected.empty()) {
        updateStatus(L"Сначала выберите один или несколько токенов справа.");
        return;
    }

    const std::wstring userName = getControlText(assignUserEdit_);
    if (userName.empty()) {
        updateStatus(L"Введите пользователя для файла политики.");
        return;
    }
    if (kAdminBuild && (!adminAccessLoaded_ || lowerCopy(userName) != lowerCopy(loadedPolicyUser_))) {
        updateStatus(L"Сначала успешно загрузите доступ выбранного пользователя.");
        return;
    }

    for (const DeviceViewModel& selectedDevice : selected) {
        for (DeviceViewModel& device : allDevices_) {
            if (sameDeviceIdentity(device, selectedDevice)) {
                device.allowed = true;
                break;
            }
        }
    }

    applyDeviceFilter();
    markAdminAccessDirty();
    const std::wstring status = L"Добавлено в доступ пользователя " + userName +
        L": " + std::to_wstring(selected.size()) + L". Нажмите «Сохранить доступ».";
    updateStatus(status.c_str());
}

void MainWindow::removeSelectedDeviceFromUser() {
    const std::vector<DeviceViewModel> selected = kAdminBuild
        ? selectedDevicesFrom(listView_, allowedDevices_)
        : selectedDevices();
    if (selected.empty()) {
        updateStatus(L"Сначала выберите один или несколько токенов слева.");
        return;
    }

    const std::wstring userName = getControlText(assignUserEdit_);
    if (userName.empty()) {
        updateStatus(L"Введите пользователя для изменения доступа.");
        return;
    }
    if (kAdminBuild && (!adminAccessLoaded_ || lowerCopy(userName) != lowerCopy(loadedPolicyUser_))) {
        updateStatus(L"Сначала успешно загрузите доступ выбранного пользователя.");
        return;
    }

    for (const DeviceViewModel& selectedDevice : selected) {
        for (DeviceViewModel& device : allDevices_) {
            if (sameDeviceIdentity(device, selectedDevice)) {
                device.allowed = false;
                break;
            }
        }
    }

    applyDeviceFilter();
    markAdminAccessDirty();
    const std::wstring status = L"Убрано из доступа пользователя " + userName +
        L": " + std::to_wstring(selected.size()) + L". Нажмите «Сохранить доступ».";
    updateStatus(status.c_str());
}

void MainWindow::activateSelectedDevice() {
    DeviceViewModel* device = selectedDevice();
    if (!device) {
        return;
    }
    const DeviceUsageInfo usage = DeviceParser::parseUsage(device->inUseBy, PolicyManager::currentUserName());
    if (!device->allowed && !usage.isUsedByCurrentUser) {
        AuditLogger::logDeviceAction(L"DENY", *device, L"DENIED", L"Selected device is denied by policy.");
        updateStatus(L"Выбранный токен запрещён политикой.");
        return;
    }

    if (usage.isFree) {
        startTokenAction(*device, true);
        return;
    }
    if (usage.isUsedByCurrentUser) {
        startTokenAction(*device, false);
        return;
    }

    std::wstring status = L"Токен занят";
    if (!usage.userText.empty()) {
        status += L": " + usage.userText;
        if (!usage.locationText.empty()) {
            status += L" на " + usage.locationText;
        }
    }
    status += L".";
    updateStatus(status.c_str());
}

void MainWindow::releaseActiveDevices(bool interactive) {
    if (kAdminBuild) {
        return;
    }

    size_t released = 0;
    for (const DeviceViewModel& device : allDevices_) {
        const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
        if (!usage.isUsedByCurrentUser) {
            continue;
        }

        try {
            service_.stopUsingOwnedDevice(device);
            autoReleaseRequestTicks_.erase(device.endpoint);
            activeDeviceStartTicks_.erase(device.endpoint);
            ++released;
        }
        catch (const std::exception& error) {
            AuditLogger::logDeviceAction(L"AUTO STOP", device, L"ERROR", widenAscii(error.what()));
        }
    }

    if (interactive && released > 0) {
        const std::wstring status = L"Автоматически освобождено токенов: " + std::to_wstring(released);
        updateStatus(status.c_str());
    }
}

void MainWindow::updateActiveDeviceTracking() {
    if (kAdminBuild) {
        return;
    }

    std::map<std::wstring, bool> stillActive;
    const ULONGLONG now = GetTickCount64();
    for (const DeviceViewModel& device : allDevices_) {
        const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
        if (!usage.isUsedByCurrentUser) {
            continue;
        }

        stillActive[device.endpoint] = true;
        if (autoReleaseRequestTicks_.find(device.endpoint) != autoReleaseRequestTicks_.end()) {
            continue;
        }

        if (activeDeviceStartTicks_.find(device.endpoint) == activeDeviceStartTicks_.end()) {
            activeDeviceStartTicks_[device.endpoint] = now;
        }
    }

    for (auto it = activeDeviceStartTicks_.begin(); it != activeDeviceStartTicks_.end();) {
        if (stillActive.find(it->first) == stillActive.end()) {
            it = activeDeviceStartTicks_.erase(it);
        }
        else {
            ++it;
        }
    }

    for (auto it = autoReleaseRequestTicks_.begin(); it != autoReleaseRequestTicks_.end();) {
        if (stillActive.find(it->first) == stillActive.end()) {
            it = autoReleaseRequestTicks_.erase(it);
        }
        else {
            ++it;
        }
    }
}

void MainWindow::checkActiveVpnHealth() {
#ifdef DISKCONTROL_ADMIN
    return;
#else
    if (closing_ || timeoutPromptActive_ || tokenActionRunning_ || refreshing_ || vpnWatchdogRunning_) {
        return;
    }

    const ULONGLONG now = GetTickCount64();
    if (lastVpnWatchdogTick_ != 0 && now - lastVpnWatchdogTick_ < kVpnWatchdogIntervalMs) {
        return;
    }

    std::vector<DeviceViewModel> devicesToCheck;
    for (const DeviceViewModel& device : allDevices_) {
        if (device.vpnProfileId.empty()) {
            continue;
        }
        const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
        if (usage.isUsedByCurrentUser) {
            devicesToCheck.push_back(device);
        }
    }
    lastVpnWatchdogTick_ = now;
    if (devicesToCheck.empty()) {
        return;
    }

    bool expected = false;
    if (!vpnWatchdogRunning_.compare_exchange_strong(expected, true)) {
        return;
    }
    if (vpnWatchdogThread_.joinable()) {
        vpnWatchdogThread_.join();
    }

    vpnWatchdogThread_ = std::thread([this, devicesToCheck]() {
        DeviceViewModel failedDevice;
        std::wstring errorText;
        for (const DeviceViewModel& device : devicesToCheck) {
            try {
                service_.verifyVpnForDevice(device);
            }
            catch (const std::exception& error) {
                failedDevice = device;
                errorText = widenAscii(error.what());
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(vpnWatchdogMutex_);
            pendingVpnFailureDevice_ = std::move(failedDevice);
            pendingVpnFailureError_ = std::move(errorText);
        }
        if (!closing_) {
            PostMessageW(hwnd_, WM_VPN_WATCHDOG_COMPLETE, 0, 0);
        }
    });
#endif
}

void MainWindow::finishVpnHealthCheck() {
#ifdef DISKCONTROL_ADMIN
    return;
#else
    if (vpnWatchdogThread_.joinable()) {
        vpnWatchdogThread_.join();
    }

    DeviceViewModel failedDevice;
    std::wstring technicalError;
    {
        std::lock_guard<std::mutex> lock(vpnWatchdogMutex_);
        failedDevice = std::move(pendingVpnFailureDevice_);
        technicalError = std::move(pendingVpnFailureError_);
        pendingVpnFailureDevice_ = {};
        pendingVpnFailureError_.clear();
    }
    vpnWatchdogRunning_ = false;
    if (closing_ || technicalError.empty()) {
        return;
    }

    auto current = std::find_if(allDevices_.begin(), allDevices_.end(), [&failedDevice](const DeviceViewModel& device) {
        return device.endpoint == failedDevice.endpoint;
    });
    if (current == allDevices_.end() ||
        !DeviceParser::parseUsage(current->inUseBy, PolicyManager::currentUserName()).isUsedByCurrentUser) {
        return;
    }

    std::string asciiError;
    asciiError.reserve(technicalError.size());
    for (wchar_t ch : technicalError) {
        asciiError.push_back(ch <= 127 ? static_cast<char>(ch) : '?');
    }
    const std::wstring status = L"Защитная проверка VPN не пройдена. " +
        userFriendlyErrorMessage(asciiError.c_str()) + L" Токен будет освобождён.";
    logUiError(L"UI VPN WATCHDOG ERROR", asciiError.c_str(), status);
    updateStatus(status.c_str());
    requestAutoRelease(*current);
#endif
}

void MainWindow::checkActiveDeviceTimeouts() {
#ifdef DISKCONTROL_ADMIN
    return;
#else
    if (closing_ || timeoutPromptActive_ || tokenActionRunning_) {
        return;
    }

    const ULONGLONG now = GetTickCount64();
    retryPendingAutoReleases(now);

    for (DeviceViewModel& device : allDevices_) {
        const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
        if (!usage.isUsedByCurrentUser) {
            continue;
        }
        if (autoReleaseRequestTicks_.find(device.endpoint) != autoReleaseRequestTicks_.end()) {
            continue;
        }

        auto found = activeDeviceStartTicks_.find(device.endpoint);
        if (found == activeDeviceStartTicks_.end()) {
            activeDeviceStartTicks_[device.endpoint] = now;
            continue;
        }

        ULONGLONG elapsedMs = now - found->second;
        ULONGLONG sharedElapsedMs = 0;
        if (elapsedMsFromStartIfKnown(device, sharedElapsedMs)) {
            elapsedMs = sharedElapsedMs;
        }
        if (elapsedMs < kTokenSessionLimitMs) {
            continue;
        }

        const std::wstring endpoint = device.endpoint;
        const std::wstring text =
            L"Токен «" + displayDeviceName(device) + L"» используется больше 20 минут.\n\n"
            L"Продолжить работу с токеном?\n"
            L"Если ответа не будет 1 минуту, токен будет автоматически освобождён.";
        timeoutPromptActive_ = true;
        const int answer = timedMessageBox(hwnd_, text, L"DistControl", MB_YESNO | MB_ICONQUESTION | MB_TOPMOST, kTokenPromptTimeoutMs);
        timeoutPromptActive_ = false;

        if (closing_) {
            return;
        }

        auto currentDevice = std::find_if(allDevices_.begin(), allDevices_.end(),
            [&endpoint](const DeviceViewModel& current) {
                return current.endpoint == endpoint;
            });
        if (currentDevice == allDevices_.end()) {
            activeDeviceStartTicks_.erase(endpoint);
            autoReleaseRequestTicks_.erase(endpoint);
            updateStatus(L"Токен уже освобождён или исчез из списка.");
            return;
        }

        const DeviceUsageInfo currentUsage =
            DeviceParser::parseUsage(currentDevice->inUseBy, PolicyManager::currentUserName());
        if (!currentUsage.isUsedByCurrentUser) {
            activeDeviceStartTicks_.erase(endpoint);
            autoReleaseRequestTicks_.erase(endpoint);
            updateStatus(L"Токен уже освобождён.");
            return;
        }

        if (answer == IDYES) {
            try {
                service_.refreshUsageTimer(*currentDevice);
            }
            catch (const std::exception& error) {
                const std::wstring status = L"Не удалось продлить общий таймер. " +
                    userFriendlyErrorMessage(error.what()) + L" Токен будет освобождён.";
                logUiError(L"UI USAGE TIMER ERROR", error.what(), status);
                updateStatus(status.c_str());
                requestAutoRelease(*currentDevice);
                return;
            }
            activeDeviceStartTicks_[endpoint] = GetTickCount64();
            auto clearSharedStart = [&endpoint](std::vector<DeviceViewModel>& devices) {
                for (DeviceViewModel& current : devices) {
                    if (current.endpoint == endpoint) {
                        current.usageStartedAt.clear();
                        current.usageStartedFileTime = 0;
                    }
                }
            };
            clearSharedStart(allDevices_);
            clearSharedStart(devices_);
            clearSharedStart(allowedDevices_);
            clearSharedStart(availableDevices_);
            updateStatus(L"Работа с токеном продлена ещё на 20 минут.");
            updateTreeTimerText();
            scheduleDelayedRefresh();
            return;
        }

        requestAutoRelease(*currentDevice);
        return;
    }
#endif
}

void MainWindow::retryPendingAutoReleases(ULONGLONG now) {
    if (autoReleaseRequestTicks_.empty()) {
        return;
    }

    for (auto it = autoReleaseRequestTicks_.begin(); it != autoReleaseRequestTicks_.end();) {
        if (now - it->second < kAutoReleaseRetryMs) {
            ++it;
            continue;
        }

        DeviceViewModel* device = nullptr;
        for (DeviceViewModel& current : allDevices_) {
            if (current.endpoint == it->first) {
                device = &current;
                break;
            }
        }

        if (!device) {
            activeDeviceStartTicks_.erase(it->first);
            it = autoReleaseRequestTicks_.erase(it);
            continue;
        }

        const DeviceUsageInfo usage = DeviceParser::parseUsage(device->inUseBy, PolicyManager::currentUserName());
        if (!usage.isUsedByCurrentUser) {
            activeDeviceStartTicks_.erase(device->endpoint);
            it = autoReleaseRequestTicks_.erase(it);
            continue;
        }

        it->second = now;
        try {
            const std::wstring status = service_.stopUsingOwnedDevice(*device);
            markDeviceLocallyReleased(device->endpoint);
            activeDeviceStartTicks_.erase(device->endpoint);
            it = autoReleaseRequestTicks_.erase(it);
            updateStatus(status.c_str());
            updateTreeTimerText();
            scheduleDelayedRefresh();
        }
        catch (const std::exception& error) {
            const std::wstring status = L"Повторная попытка освобождения не прошла. " +
                userFriendlyErrorMessage(error.what()) + L" Повторим автоматически.";
            logUiError(L"UI AUTO RELEASE RETRY ERROR", error.what(), status);
            updateStatus(status.c_str());
            ++it;
        }
    }
}

void MainWindow::requestAutoRelease(DeviceViewModel& device) {
    autoReleaseRequestTicks_[device.endpoint] = GetTickCount64();
    activeDeviceStartTicks_.erase(device.endpoint);
    updateTreeTimerText();
    updateStatus(L"Освобождаем токен...");

    try {
        const std::wstring status = service_.stopUsingOwnedDevice(device);
        markDeviceLocallyReleased(device.endpoint);
        autoReleaseRequestTicks_.erase(device.endpoint);
        updateStatus(status.c_str());
        updateTreeTimerText();
        scheduleDelayedRefresh();
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Не удалось автоматически освободить токен. " +
            userFriendlyErrorMessage(error.what()) + L" Повторим автоматически.";
        logUiError(L"UI AUTO RELEASE ERROR", error.what(), status);
        updateStatus(status.c_str());
    }
}

void MainWindow::markDeviceLocallyReleased(const std::wstring& endpoint) {
    auto markReleased = [&endpoint](std::vector<DeviceViewModel>& devices) {
        for (DeviceViewModel& device : devices) {
            if (device.endpoint != endpoint) {
                continue;
            }
            device.inUseBy.clear();
            device.statusText = L"Свободен";
            device.usedBy.clear();
            device.usedAt.clear();
            device.usageStartedAt.clear();
            device.usageStartedFileTime = 0;
        }
    };

    markReleased(allDevices_);
    markReleased(devices_);
    markReleased(allowedDevices_);
    markReleased(availableDevices_);
}

std::wstring MainWindow::activeDurationText(const DeviceViewModel& device) const {
    if (kAdminBuild) {
        return {};
    }

    if (autoReleaseRequestTicks_.find(device.endpoint) != autoReleaseRequestTicks_.end()) {
        return L"освобождается";
    }

    const DeviceUsageInfo usage = DeviceParser::parseUsage(device.inUseBy, PolicyManager::currentUserName());
    if (usage.isFree) {
        return {};
    }

    const std::wstring sharedDuration = remainingTextFromStartIfKnown(device);
    if (!sharedDuration.empty()) {
        return sharedDuration;
    }

    if (!usage.isUsedByCurrentUser) {
        return {};
    }

    const auto found = activeDeviceStartTicks_.find(device.endpoint);
    if (found == activeDeviceStartTicks_.end()) {
        return {};
    }

    const ULONGLONG elapsed = GetTickCount64() - found->second;
    const ULONGLONG remaining = elapsed >= kTokenSessionLimitMs ? 0 : kTokenSessionLimitMs - elapsed;
    return L"осталось " + formatDuration(remaining);
}

void MainWindow::updateStatus(const wchar_t* text, COLORREF color) {
    statusColor_ = color;
    SetWindowTextW(statusLabel_, text);
    InvalidateRect(statusLabel_, nullptr, TRUE);
}

void MainWindow::showRefreshProgress() {
    refreshProcessed_.store(0, std::memory_order_relaxed);
    refreshTotal_.store(0, std::memory_order_relaxed);
    SetWindowTextW(refreshProgressLabel_, L"подготовка");
    SendMessageW(refreshProgressBar_, PBM_SETPOS, 0, 0);
    SendMessageW(refreshProgressBar_, PBM_SETMARQUEE, TRUE, 30);
    ShowWindow(refreshProgressLabel_, SW_SHOW);
    ShowWindow(refreshProgressBar_, SW_SHOW);
    layoutControls();
}

void MainWindow::updateRefreshProgress() {
    if (!refreshing_) {
        return;
    }
    const size_t processed = refreshProcessed_.load(std::memory_order_relaxed);
    const size_t total = refreshTotal_.load(std::memory_order_relaxed);
    if (total == 0) {
        return;
    }

    const int percent = static_cast<int>((std::min)(processed * 100 / total, static_cast<size_t>(100)));
    SendMessageW(refreshProgressBar_, PBM_SETMARQUEE, FALSE, 0);
    SendMessageW(refreshProgressBar_, PBM_SETPOS, percent, 0);
    const std::wstring percentText = std::to_wstring(percent) + L"%";
    SetWindowTextW(refreshProgressLabel_, percentText.c_str());
    const std::wstring status = L"Обновление списка: " + percentText + L" (" +
        std::to_wstring(processed) + L" из " + std::to_wstring(total) + L")";
    updateStatus(status.c_str());
}

void MainWindow::hideRefreshProgress() {
    SendMessageW(refreshProgressBar_, PBM_SETMARQUEE, FALSE, 0);
    ShowWindow(refreshProgressLabel_, SW_HIDE);
    ShowWindow(refreshProgressBar_, SW_HIDE);
    layoutControls();
}

DeviceViewModel* MainWindow::selectedDevice() {
    if (treeView_) {
        HTREEITEM selected = TreeView_GetSelection(treeView_);
        if (!selected) {
            return nullptr;
        }

        TVITEMW item{};
        item.mask = TVIF_PARAM;
        item.hItem = selected;
        if (!TreeView_GetItem(treeView_, &item) || item.lParam == kTreeGroupParam) {
            return nullptr;
        }

        const size_t index = static_cast<size_t>(item.lParam);
        if (index >= devices_.size()) {
            return nullptr;
        }
        return &devices_[index];
    }

    if (!listView_) {
        return nullptr;
    }

    const int index = ListView_GetNextItem(listView_, -1, LVNI_SELECTED);
    std::vector<DeviceViewModel>& source = kAdminBuild ? allowedDevices_ : devices_;
    if (index < 0 || static_cast<size_t>(index) >= source.size()) {
        return nullptr;
    }

    return &source[static_cast<size_t>(index)];
}

std::vector<DeviceViewModel> MainWindow::selectedDevices() const {
    return selectedDevicesFrom(listView_, devices_);
}

std::vector<DeviceViewModel> MainWindow::selectedDevicesFrom(HWND listView, const std::vector<DeviceViewModel>& source) const {
    std::vector<DeviceViewModel> selected;
    if (!listView) {
        return selected;
    }
    int index = -1;
    while ((index = ListView_GetNextItem(listView, index, LVNI_SELECTED)) >= 0) {
        if (static_cast<size_t>(index) < source.size()) {
            selected.push_back(source[static_cast<size_t>(index)]);
        }
    }
    return selected;
}
