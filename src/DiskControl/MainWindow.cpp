#include "MainWindow.h"

#include "AuditLogger.h"
#include "DeviceParser.h"
#include "PolicyManager.h"
#include "VpnManager.h"
#include "resource.h"

#include <algorithm>
#include <commdlg.h>
#include <commctrl.h>
#include <windows.h>
#include <windowsx.h>

#include <cstdint>
#include <exception>
#include <fstream>
#include <iomanip>
#include <map>
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
constexpr int IDC_VPN = 1021;
constexpr UINT_PTR IDT_DELAYED_REFRESH = 2001;
constexpr UINT_PTR IDT_USAGE_WATCHDOG = 2002;
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
constexpr const wchar_t* kWindowTitle = L"DiskControl Admin";
#else
constexpr bool kAdminBuild = false;
constexpr const wchar_t* kWindowTitle = L"DiskControl";
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
        return L"Для токена не выбран VPN Windows или режим «Без VPN». Обратитесь к администратору DiskControl.";
    }
    if (containsAscii(error, "VPN profile mapping references an unknown profile")) {
        return L"Токену назначен VPN-профиль, которого нет в конфигурации. Токен не подключён; исправьте назначение в админке.";
    }
    if (containsAscii(error, "VPN Windows profile is not installed")) {
        return L"На компьютере не найден нужный профиль VPN Windows. Создайте его в параметрах Windows или обратитесь к администратору.";
    }
    if (containsAscii(error, "VPN credentials are not configured")) {
        return L"Не сохранены логин и пароль VPN. Выберите токен и нажмите «Учётные данные VPN».";
    }
    if (containsAscii(error, "RAS error 691")) {
        return L"VPN отклонил логин или пароль. Нажмите «Учётные данные VPN» и введите их заново.";
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
        return L"Этот токен не разрешён текущему пользователю. Обратитесь к администратору DiskControl.";
    }
    if (containsAscii(error, "The token is not connected by the current user")) {
        return L"Токен нельзя отключить из DiskControl: сейчас он не закреплён за вашим пользователем.";
    }
    if (containsAscii(error, "The token is occupied by another user")) {
        return L"Токен уже занят другим пользователем. Обновите список, чтобы увидеть актуального владельца.";
    }
    if (containsAscii(error, "Another active token requires a different VPN profile")) {
        return L"Сначала отключите другой активный токен: он использует иной VPN-профиль.";
    }
    if (containsAscii(error, "Invalid address")) {
        return L"Служба DistKontrolUSB видит токен в списке, но пока не принимает его адрес после изменения сети. DiskControl уже выполнил повторные попытки; проверьте доступность концентратора и повторите подключение.";
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
        return L"Не удалось подготовить папку с конфигурацией DiskControl. Проверьте права на C:\\ProgramData\\DiskControl.";
    }
    if (containsAscii(error, "Invalid JSON") ||
        containsAscii(error, "Unexpected JSON") ||
        containsAscii(error, "Config root must be an object") ||
        containsAscii(error, "Config must contain userAssignments array")) {
        return L"Файл allow.json повреждён или имеет неправильный формат. Откройте админку и сохраните конфиг заново.";
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
    if (containsAscii(error, "Network profile id and Windows profile are required")) {
        return L"Не выбран профиль VPN Windows.";
    }
    return L"Произошла ошибка DiskControl. Подробности записаны в журнал C:\\ProgramData\\DiskControl\\logs.";
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

struct VpnCredentialDialogData {
    std::wstring profileName;
    std::wstring userName;
    std::wstring password;
};

std::wstring dialogItemText(HWND dialog, int controlId) {
    const int length = GetWindowTextLengthW(GetDlgItem(dialog, controlId));
    std::wstring value(static_cast<size_t>(length) + 1, L'\0');
    GetDlgItemTextW(dialog, controlId, value.data(), length + 1);
    value.resize(static_cast<size_t>(length));
    return value;
}

INT_PTR CALLBACK vpnCredentialDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* data = reinterpret_cast<VpnCredentialDialogData*>(GetWindowLongPtrW(dialog, DWLP_USER));
    if (message == WM_INITDIALOG) {
        data = reinterpret_cast<VpnCredentialDialogData*>(lParam);
        SetWindowLongPtrW(dialog, DWLP_USER, reinterpret_cast<LONG_PTR>(data));
        SetDlgItemTextW(dialog, IDC_VPN_PROFILE_NAME, data->profileName.c_str());
        SetDlgItemTextW(dialog, IDC_VPN_USER_NAME, data->userName.c_str());
        return TRUE;
    }
    if (message != WM_COMMAND || !data) {
        return FALSE;
    }
    if (LOWORD(wParam) == IDOK) {
        data->userName = trim(dialogItemText(dialog, IDC_VPN_USER_NAME));
        data->password = dialogItemText(dialog, IDC_VPN_PASSWORD);
        if (data->userName.empty() || data->password.empty()) {
            MessageBoxW(dialog, L"Введите логин и пароль VPN.", L"DiskControl", MB_OK | MB_ICONWARNING);
            return TRUE;
        }
        EndDialog(dialog, IDOK);
        return TRUE;
    }
    if (LOWORD(wParam) == IDCANCEL) {
        EndDialog(dialog, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

struct VpnAdminDialogData {
    DeviceAccessService* service = nullptr;
    DeviceViewModel device;
    std::wstring userName;
    std::vector<VpnProfile> profiles;
    std::vector<WindowsVpnProfileInfo> windowsProfiles;
    NetworkStateSnapshot networkState;
    bool networkStateFresh = false;
    bool changed = false;
};

std::wstring joinTextValues(const std::vector<std::wstring>& values) {
    std::wstring result;
    for (const std::wstring& value : values) {
        if (!result.empty()) {
            result += L", ";
        }
        result += value;
    }
    return result;
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
    const VpnAdminDialogData& data,
    VpnProfileMode mode,
    const WindowsVpnProfileInfo* windowsProfile) {
    for (const VpnProfile& existing : data.profiles) {
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
        const bool occupied = std::any_of(data.profiles.begin(), data.profiles.end(),
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

const WindowsVpnProfileInfo* selectedWindowsVpnProfile(HWND dialog, const VpnAdminDialogData& data) {
    const LRESULT selection = SendDlgItemMessageW(
        dialog, IDC_VPN_ADMIN_WINDOWS_PROFILE, CB_GETCURSEL, 0, 0);
    if (selection == CB_ERR) {
        return nullptr;
    }
    const LRESULT index = SendDlgItemMessageW(
        dialog, IDC_VPN_ADMIN_WINDOWS_PROFILE, CB_GETITEMDATA,
        static_cast<WPARAM>(selection), 0);
    if (index == CB_ERR || static_cast<size_t>(index) >= data.windowsProfiles.size()) {
        return nullptr;
    }
    return &data.windowsProfiles[static_cast<size_t>(index)];
}

void updateVpnAdminMode(HWND dialog, const VpnAdminDialogData& data) {
    const bool windowsVpn = IsDlgButtonChecked(dialog, IDC_VPN_ADMIN_MODE_VPN) == BST_CHECKED;
    EnableWindow(GetDlgItem(dialog, IDC_VPN_ADMIN_WINDOWS_PROFILE), windowsVpn);
    const WindowsVpnProfileInfo* selected = windowsVpn ? selectedWindowsVpnProfile(dialog, data) : nullptr;
    if (!windowsVpn) {
        SetDlgItemTextW(dialog, IDC_VPN_ADMIN_SERVER, L"VPN Windows будет отключён перед проверкой IP.");
    }
    else if (!selected) {
        SetDlgItemTextW(dialog, IDC_VPN_ADMIN_SERVER, L"Выберите существующий профиль VPN Windows.");
    }
    else {
        std::wstring details = selected->serverAddress.empty() ? L"сервер не указан" : selected->serverAddress;
        if (!selected->tunnelType.empty()) {
            details += L" / " + selected->tunnelType;
        }
        SetDlgItemTextW(dialog, IDC_VPN_ADMIN_SERVER, details.c_str());
    }
}

void selectWindowsVpnProfile(
    HWND dialog,
    const VpnAdminDialogData& data,
    const std::wstring& name,
    VpnPhonebookScope scope) {
    for (size_t index = 0; index < data.windowsProfiles.size(); ++index) {
        const WindowsVpnProfileInfo& candidate = data.windowsProfiles[index];
        if (candidate.phonebookScope == scope && CompareStringOrdinal(
            candidate.name.c_str(), static_cast<int>(candidate.name.size()),
            name.c_str(), static_cast<int>(name.size()), TRUE) == CSTR_EQUAL) {
            SendDlgItemMessageW(dialog, IDC_VPN_ADMIN_WINDOWS_PROFILE, CB_SETCURSEL, index, 0);
            return;
        }
    }
    SendDlgItemMessageW(dialog, IDC_VPN_ADMIN_WINDOWS_PROFILE, CB_SETCURSEL,
        name.empty() && !data.windowsProfiles.empty() ? 0 : static_cast<WPARAM>(-1), 0);
}

void loadVpnAdminProfile(HWND dialog, const VpnAdminDialogData& data) {
    const auto found = std::find_if(data.profiles.begin(), data.profiles.end(), [&data](const VpnProfile& profile) {
        return CompareStringOrdinal(
            profile.id.c_str(), static_cast<int>(profile.id.size()),
            data.device.vpnProfileId.c_str(), static_cast<int>(data.device.vpnProfileId.size()),
            TRUE) == CSTR_EQUAL;
    });
    if (found == data.profiles.end()) {
        CheckRadioButton(dialog, IDC_VPN_ADMIN_MODE_VPN, IDC_VPN_ADMIN_MODE_DIRECT,
            IDC_VPN_ADMIN_MODE_VPN);
        selectWindowsVpnProfile(dialog, data, L"", VpnPhonebookScope::CurrentUser);
        CheckDlgButton(dialog, IDC_VPN_ADMIN_ENABLED, BST_CHECKED);
        updateVpnAdminMode(dialog, data);
        return;
    }
    CheckRadioButton(dialog, IDC_VPN_ADMIN_MODE_VPN, IDC_VPN_ADMIN_MODE_DIRECT,
        found->mode == VpnProfileMode::Direct
            ? IDC_VPN_ADMIN_MODE_DIRECT
            : IDC_VPN_ADMIN_MODE_VPN);
    selectWindowsVpnProfile(dialog, data, found->name, found->phonebookScope);
    CheckDlgButton(dialog, IDC_VPN_ADMIN_ENABLED, found->enabled ? BST_CHECKED : BST_UNCHECKED);
    updateVpnAdminMode(dialog, data);
}

INT_PTR CALLBACK vpnAdminDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* data = reinterpret_cast<VpnAdminDialogData*>(GetWindowLongPtrW(dialog, DWLP_USER));
    if (message == WM_INITDIALOG) {
        data = reinterpret_cast<VpnAdminDialogData*>(lParam);
        SetWindowLongPtrW(dialog, DWLP_USER, reinterpret_cast<LONG_PTR>(data));
        HWND windowsCombo = GetDlgItem(dialog, IDC_VPN_ADMIN_WINDOWS_PROFILE);
        for (size_t index = 0; index < data->windowsProfiles.size(); ++index) {
            const std::wstring display = windowsVpnDisplayName(data->windowsProfiles[index]);
            const LRESULT item = SendMessageW(
                windowsCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(display.c_str()));
            if (item != CB_ERR && item != CB_ERRSPACE) {
                SendMessageW(windowsCombo, CB_SETITEMDATA, item, static_cast<LPARAM>(index));
            }
        }
        loadVpnAdminProfile(dialog, *data);
        if (data->networkStateFresh) {
            std::wstring state = L"Текущий внешний IP: " + data->networkState.publicIp + L". VPN Windows: ";
            if (data->networkState.activeVpnNames.empty()) {
                state += L"нет";
            }
            else {
                state += joinTextValues(data->networkState.activeVpnNames);
            }
            SetDlgItemTextW(dialog, IDC_VPN_ADMIN_STATE, state.c_str());
        }
        else {
            SetDlgItemTextW(dialog, IDC_VPN_ADMIN_STATE,
                L"Нет свежего отчёта клиента о состоянии сети.");
        }
        return TRUE;
    }
    if (message != WM_COMMAND || !data) {
        return FALSE;
    }

    if ((LOWORD(wParam) == IDC_VPN_ADMIN_MODE_VPN ||
         LOWORD(wParam) == IDC_VPN_ADMIN_MODE_DIRECT) && HIWORD(wParam) == BN_CLICKED) {
        updateVpnAdminMode(dialog, *data);
        return TRUE;
    }
    if (LOWORD(wParam) == IDC_VPN_ADMIN_WINDOWS_PROFILE && HIWORD(wParam) == CBN_SELCHANGE) {
        updateVpnAdminMode(dialog, *data);
        return TRUE;
    }

    try {
        if (LOWORD(wParam) == IDC_VPN_ADMIN_SAVE) {
            VpnProfile profile;
            profile.enabled = IsDlgButtonChecked(dialog, IDC_VPN_ADMIN_ENABLED) == BST_CHECKED;
            profile.mode = IsDlgButtonChecked(dialog, IDC_VPN_ADMIN_MODE_DIRECT) == BST_CHECKED
                ? VpnProfileMode::Direct
                : VpnProfileMode::WindowsVpn;
            const WindowsVpnProfileInfo* selected = nullptr;
            if (profile.mode == VpnProfileMode::Direct) {
                profile.name = L"Без VPN";
                profile.tunnelType.clear();
            }
            else {
                selected = selectedWindowsVpnProfile(dialog, *data);
                if (!selected) {
                    MessageBoxW(dialog, L"Выберите существующий профиль VPN Windows.",
                        L"DiskControl Admin", MB_OK | MB_ICONWARNING);
                    return TRUE;
                }
                profile.name = selected->name;
                profile.serverAddress = selected->serverAddress;
                profile.tunnelType = selected->tunnelType;
                profile.phonebookScope = selected->phonebookScope;
            }
            profile.id = automaticVpnProfileId(*data, profile.mode, selected);
            data->service->upsertVpnProfile(profile);
            data->service->setVpnProfileForDevice(data->device, data->userName, profile.id);
            data->changed = true;
            EndDialog(dialog, IDOK);
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VPN_ADMIN_UNASSIGN) {
            data->service->setVpnProfileForDevice(data->device, data->userName, L"");
            data->changed = true;
            EndDialog(dialog, IDOK);
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VPN_ADMIN_DELETE) {
            const std::wstring id = data->device.vpnProfileId;
            if (id.empty()) {
                MessageBoxW(dialog, L"У токена нет назначенной сетевой настройки.",
                    L"DiskControl Admin", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            const std::wstring display = data->device.vpnProfileDisplay.empty()
                ? id
                : data->device.vpnProfileDisplay;
            const std::wstring question = L"Удалить сетевую настройку «" + display +
                L"» и снять её со всех токенов в этом allow.json?";
            if (MessageBoxW(dialog, question.c_str(), L"DiskControl Admin", MB_YESNO | MB_ICONWARNING) != IDYES) {
                return TRUE;
            }
            data->service->removeVpnProfile(id);
            data->changed = true;
            EndDialog(dialog, IDOK);
            return TRUE;
        }
    }
    catch (const std::exception& error) {
        const std::wstring errorMessage = L"Не удалось сохранить сетевую настройку. " +
            userFriendlyErrorMessage(error.what());
        logUiError(L"UI VPN ADMIN SAVE ERROR", error.what(), errorMessage);
        MessageBoxW(dialog, errorMessage.c_str(), L"DiskControl Admin", MB_OK | MB_ICONERROR);
        return TRUE;
    }

    if (LOWORD(wParam) == IDCANCEL) {
        EndDialog(dialog, IDCANCEL);
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
        containsIgnoreCase(device.product, query);
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

std::wstring policyPathForComputer(const std::wstring& computerName) {
    const std::wstring trimmed = trim(computerName);
    if (isLocalComputerName(trimmed)) {
        return L"C:\\ProgramData\\DiskControl\\allow.json";
    }
    return L"\\\\" + trimmed + L"\\c$\\ProgramData\\DiskControl\\allow.json";
}

std::wstring profileFolderName(const std::wstring& userName) {
    const size_t slash = userName.find_last_of(L"\\/");
    return slash == std::wstring::npos ? userName : userName.substr(slash + 1);
}

std::wstring userPhonebookPathForComputer(
    const std::wstring& computerName,
    const std::wstring& userName) {
    const std::wstring folder = profileFolderName(userName);
    if (folder.empty()) {
        return {};
    }
    return profilesRootForComputer(computerName) + L"\\" + folder +
        L"\\AppData\\Roaming\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk";
}

std::wstring allUsersPhonebookPathForComputer(const std::wstring& computerName) {
    if (isLocalComputerName(computerName)) {
        return VpnManager::allUsersPhonebook();
    }
    return L"\\\\" + trim(computerName) +
        L"\\c$\\ProgramData\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk";
}

std::wstring networkStatePathForComputer(
    const std::wstring& computerName,
    const std::wstring& userName) {
    const std::wstring folder = profileFolderName(userName);
    if (folder.empty()) {
        return {};
    }
    return profilesRootForComputer(computerName) + L"\\" + folder +
        L"\\AppData\\Local\\DiskControl\\network-state.json";
}

std::uint64_t currentFileTimeTicks() {
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

bool isFreshNetworkState(const NetworkStateSnapshot& state) {
    constexpr std::uint64_t maximumAge = 2ULL * 60ULL * 10000000ULL;
    const std::uint64_t now = currentFileTimeTicks();
    return state.updatedAtFileTime != 0 && now >= state.updatedAtFileTime &&
        now - state.updatedAtFileTime <= maximumAge && !state.publicIp.empty();
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
        reason = L"путь не найден. Возможно, на этом компьютере ещё не установлен DiskControl или нет папки профилей";
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

bool parseFixedNumber(const std::wstring& text, size_t offset, size_t length, WORD& value) {
    if (offset + length > text.size()) {
        return false;
    }

    WORD result = 0;
    for (size_t i = 0; i < length; ++i) {
        const wchar_t ch = text[offset + i];
        if (ch < L'0' || ch > L'9') {
            return false;
        }
        result = static_cast<WORD>(result * 10 + (ch - L'0'));
    }
    value = result;
    return true;
}

ULONGLONG fileTimeToTicks(const FILETIME& fileTime) {
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

bool parseLocalTimestampFileTime(const std::wstring& text, FILETIME& fileTime) {
    if (text.size() < 19 || text[4] != L'-' || text[7] != L'-' || text[10] != L'T' ||
        text[13] != L':' || text[16] != L':') {
        return false;
    }

    SYSTEMTIME localTime{};
    if (!parseFixedNumber(text, 0, 4, localTime.wYear) ||
        !parseFixedNumber(text, 5, 2, localTime.wMonth) ||
        !parseFixedNumber(text, 8, 2, localTime.wDay) ||
        !parseFixedNumber(text, 11, 2, localTime.wHour) ||
        !parseFixedNumber(text, 14, 2, localTime.wMinute) ||
        !parseFixedNumber(text, 17, 2, localTime.wSecond)) {
        return false;
    }

    SYSTEMTIME utcTime{};
    if (!TzSpecificLocalTimeToSystemTime(nullptr, &localTime, &utcTime)) {
        return false;
    }
    return SystemTimeToFileTime(&utcTime, &fileTime) != FALSE;
}

std::wstring remainingTextFromStart(const std::wstring& startedAt) {
    if (startedAt.empty()) {
        return L"нет данных";
    }

    FILETIME startFileTime{};
    if (!parseLocalTimestampFileTime(startedAt, startFileTime)) {
        return L"нет данных";
    }

    FILETIME nowFileTime{};
    GetSystemTimeAsFileTime(&nowFileTime);

    const ULONGLONG startTicks = fileTimeToTicks(startFileTime);
    const ULONGLONG nowTicks = fileTimeToTicks(nowFileTime);
    if (nowTicks <= startTicks) {
        return L"осталось " + formatDuration(kTokenSessionLimitMs);
    }

    const ULONGLONG elapsedMs = (nowTicks - startTicks) / 10000ULL;
    const ULONGLONG remainingMs = elapsedMs >= kTokenSessionLimitMs ? 0 : kTokenSessionLimitMs - elapsedMs;
    return L"осталось " + formatDuration(remainingMs);
}

std::wstring remainingTextFromStartIfKnown(const std::wstring& startedAt) {
    if (startedAt.empty()) {
        return {};
    }

    FILETIME startFileTime{};
    if (!parseLocalTimestampFileTime(startedAt, startFileTime)) {
        return {};
    }

    FILETIME nowFileTime{};
    GetSystemTimeAsFileTime(&nowFileTime);

    const ULONGLONG startTicks = fileTimeToTicks(startFileTime);
    const ULONGLONG nowTicks = fileTimeToTicks(nowFileTime);
    if (nowTicks <= startTicks) {
        return L"осталось " + formatDuration(kTokenSessionLimitMs);
    }

    const ULONGLONG elapsedMs = (nowTicks - startTicks) / 10000ULL;
    const ULONGLONG remainingMs = elapsedMs >= kTokenSessionLimitMs ? 0 : kTokenSessionLimitMs - elapsedMs;
    return L"осталось " + formatDuration(remainingMs);
}

bool elapsedMsFromStartIfKnown(const std::wstring& startedAt, ULONGLONG& elapsedMs) {
    FILETIME startFileTime{};
    if (startedAt.empty() || !parseLocalTimestampFileTime(startedAt, startFileTime)) {
        return false;
    }

    FILETIME nowFileTime{};
    GetSystemTimeAsFileTime(&nowFileTime);
    const ULONGLONG startTicks = fileTimeToTicks(startFileTime);
    const ULONGLONG nowTicks = fileTimeToTicks(nowFileTime);
    elapsedMs = nowTicks <= startTicks ? 0 : (nowTicks - startTicks) / 10000ULL;
    return true;
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
    return remainingTextFromStart(device.usageStartedAt);
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

std::wstring treeDeviceText(const DeviceViewModel& device) {
    std::wstring text = displayDeviceName(device);
    if (!device.vpnProfileId.empty()) {
        text += L" [Сеть: " + networkProfileText(device) + L"]";
    }
    else {
        text += L" [сеть не настроена]";
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
        RGB(53, 170, 85),
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

    const wchar_t* className = L"DiskControlMainWindow";
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
        refreshDevices();
        return 0;
    case WM_CLOSE:
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
        }
        if (treeView_ && reinterpret_cast<NMHDR*>(lParam)->hwndFrom == treeView_) {
            const auto* header = reinterpret_cast<NMHDR*>(lParam);
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
            (HIWORD(wParam) == CBN_EDITCHANGE || HIWORD(wParam) == CBN_SELCHANGE)) {
            refreshAccessForEditedUser();
            return 0;
        }
        switch (LOWORD(wParam)) {
        case IDC_REFRESH:
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
            loadProfilesAndPolicyFromComputer();
            return 0;
        case IDC_OPEN_POLICY:
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
        case IDC_VPN:
            configureVpnForSelectedDevice();
            return 0;
        case IDC_EXPORT_JSON:
            return 0;
        case IDC_USE:
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
        KillTimer(hwnd_, IDT_DELAYED_REFRESH);
        KillTimer(hwnd_, IDT_USAGE_WATCHDOG);
        if (treeImageList_) {
            ImageList_Destroy(treeImageList_);
            treeImageList_ = nullptr;
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

        const DWORD listStyle = LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES;
        ListView_SetExtendedListViewStyle(listView_, listStyle);
        ListView_SetExtendedListViewStyle(availableListView_, listStyle);
        addDeviceColumns(listView_, false);
        addDeviceColumns(availableListView_, false);
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

    const DWORD userActionStyle = WS_CHILD;
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
    assignUserButton_ = CreateWindowW(L"BUTTON", L"Добавить →", adminActionStyle, 0, 0, 0, 0,
        hwnd_, controlId(IDC_ASSIGN_USER), instance_, nullptr);
    removeUserButton_ = CreateWindowW(L"BUTTON", L"← Убрать", adminActionStyle, 0, 0, 0, 0,
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
    vpnButton_ = CreateWindowW(L"BUTTON", kAdminBuild ? L"VPN для токена" : L"Учётные данные VPN",
        WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
        hwnd_, controlId(IDC_VPN), instance_, nullptr);
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

    updateHeaderText();
    layoutControls();
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

        constexpr int titleHeight = 22;
        const int paneGap = 14;
        const int paneWidth = (width - 2 * margin - paneGap) / 2;
        const int rightPaneX = margin + paneWidth + paneGap;
        const int listY = listTop + titleHeight;
        const int listHeight = listBottom - listY;

        MoveWindow(allowedTitleLabel_, margin, listTop, paneWidth, titleHeight, TRUE);
        MoveWindow(availableTitleLabel_, rightPaneX, listTop, paneWidth, titleHeight, TRUE);
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
        constexpr int moveWidth = 120;
        rowX = margin;
        MoveWindow(assignUserLabel_, rowX, userTop + 7, labelWidth, 20, TRUE);
        rowX += labelWidth + gap;
        MoveWindow(assignUserEdit_, rowX, userTop, userWidth, 180, TRUE);
        rowX += userWidth + gap;
        MoveWindow(assignUserButton_, rowX, userTop, moveWidth, buttonHeight, TRUE);
        rowX += moveWidth + gap;
        MoveWindow(removeUserButton_, rowX, userTop, moveWidth, buttonHeight, TRUE);

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
        MoveWindow(vpnButton_, x, buttonTop, 140, buttonHeight, TRUE);
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
        MoveWindow(vpnButton_, margin + buttonWidth + gap, buttonTop, 180, buttonHeight, TRUE);
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
    if (assignUserButton_) {
        EnableWindow(assignUserButton_, value);
    }
    if (removeUserButton_) {
        EnableWindow(removeUserButton_, value);
    }
    if (openPolicyButton_) {
        EnableWindow(openPolicyButton_, value);
    }
    if (savePolicyButton_) {
        EnableWindow(savePolicyButton_, value);
    }
    if (computerEdit_) {
        EnableWindow(computerEdit_, value);
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
    if (vpnButton_) {
        EnableWindow(vpnButton_, value);
    }
}

bool MainWindow::ensureVpnCredentials(const DeviceViewModel& device, bool forcePrompt) {
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
        if (!forcePrompt && VpnManager::hasStoredCredentials(*found)) {
            return true;
        }

        VpnCredentialDialogData data;
        data.profileName = found->name;
        const INT_PTR answer = DialogBoxParamW(
            instance_, MAKEINTRESOURCEW(IDD_VPN_CREDENTIALS), hwnd_, vpnCredentialDialogProc,
            reinterpret_cast<LPARAM>(&data));
        if (answer != IDOK) {
            if (answer == -1) {
                updateStatus(L"Не удалось открыть окно ввода учётных данных VPN.");
            }
            return false;
        }

        VpnManager::saveCredentials(*found, data.userName, data.password);
        if (!data.password.empty()) {
            SecureZeroMemory(data.password.data(), data.password.size() * sizeof(wchar_t));
            data.password.clear();
        }
        AuditEvent event;
        event.action = L"VPN CREDENTIALS";
        event.result = L"OK";
        event.details = L"profileId=" + found->id + L"; profileName=" + found->name +
            L"; user=" + data.userName + L"; password=<not logged>";
        AuditLogger::log(event);
        updateStatus(L"Учётные данные VPN сохранены средствами Windows.");
        return true;
    }
    catch (const std::exception& error) {
        const std::wstring message = L"Не удалось сохранить учётные данные VPN. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI VPN CREDENTIALS ERROR", error.what(), message);
        updateStatus(message.c_str());
        return false;
    }
}

void MainWindow::configureVpnForSelectedDevice() {
    if (kAdminBuild) {
        manageVpnForSelectedDevice();
        return;
    }
    DeviceViewModel* device = selectedDevice();
    if (!device) {
        updateStatus(L"Выберите токен, для которого нужно изменить учётные данные VPN.");
        return;
    }
    if (device->vpnProfileId.empty()) {
        updateStatus(L"Для выбранного токена не назначен VPN Windows или режим «Без VPN».");
        return;
    }
    ensureVpnCredentials(*device, true);
}

void MainWindow::manageVpnForSelectedDevice() {
#ifndef DISKCONTROL_ADMIN
    return;
#else
    DeviceViewModel* device = selectedDevice();
    if (!device) {
        updateStatus(L"Выберите разрешённый токен для настройки VPN.");
        return;
    }
    if (!device->allowed) {
        updateStatus(L"Сначала добавьте токен пользователю и сохраните доступ, затем назначьте VPN.");
        return;
    }
    const std::wstring userName = getControlText(assignUserEdit_);
    if (userName.empty()) {
        updateStatus(L"Выберите пользователя для назначения VPN.");
        return;
    }

    try {
        VpnAdminDialogData data;
        data.service = &service_;
        data.device = *device;
        data.userName = userName;
        data.profiles = service_.vpnProfiles();
        const std::wstring computerName = getControlText(computerEdit_);
        if (isLocalComputerName(computerName) &&
            lowerCopy(userName) == lowerCopy(PolicyManager::currentUserName())) {
            data.windowsProfiles = VpnManager::installedProfiles();
        }
        else {
            data.windowsProfiles = VpnManager::installedProfiles(
                userPhonebookPathForComputer(computerName, userName),
                allUsersPhonebookPathForComputer(computerName));
        }
        const std::wstring statePath = networkStatePathForComputer(computerName, userName);
        std::wstring stateError;
        if (!statePath.empty() && PolicyManager::tryReadNetworkState(
            statePath, data.networkState, &stateError)) {
            const bool matchingUser = lowerCopy(profileFolderName(data.networkState.userName)) ==
                lowerCopy(profileFolderName(userName));
            const bool matchingComputer = isLocalComputerName(computerName) ||
                lowerCopy(data.networkState.computerName) == lowerCopy(trim(computerName));
            data.networkStateFresh = isFreshNetworkState(data.networkState) &&
                matchingUser && matchingComputer;
        }
        DialogBoxParamW(instance_, MAKEINTRESOURCEW(IDD_VPN_ADMIN), hwnd_, vpnAdminDialogProc,
            reinterpret_cast<LPARAM>(&data));
        if (data.changed) {
            service_.updateAccessForUser(allDevices_, userName);
            applyDeviceFilter();
            updateHeaderText();
            updateStatus(L"Настройка VPN токена сохранена в allow.json выбранного компьютера.");
        }
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Не удалось открыть VPN-настройки. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI VPN ADMIN ERROR", error.what(), status);
        updateStatus(status.c_str());
    }
#endif
}

void MainWindow::startTokenAction(DeviceViewModel device, bool connect) {
    const std::wstring operationId = AuditLogger::createOperationId(connect ? L"CONNECT" : L"DISCONNECT");
    AuditLogger::trace(operationId,
        std::wstring(L"Интерфейс принял команду пользователя: ") +
            (connect ? L"подключить" : L"отключить") + L" токен «" + device.nickname +
            L"», endpoint=" + device.endpoint + L".");
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
    if (connect && !ensureVpnCredentials(device, false)) {
        AuditLogger::trace(operationId,
            L"Операция не начата: учётные данные VPN не подтверждены или пользователь закрыл окно ввода.");
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
    hideRefreshProgress();
    setMainControlsEnabled(true);

    if (!errorText.empty()) {
        if (connect && !vpnError && !endpoint.empty()) {
            tokenActionFailureTicks_[endpoint] = GetTickCount64();
        }
        updateStatus(errorText.c_str());
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

    updateStatus(status.c_str());
    updateTreeTimerText();
    lastNetworkStateTick_ = 0;
    AuditLogger::trace(operationId,
        L"Интерфейс применил успешный результат и запланировал контрольное обновление списка через 1,2 секунды.");
    scheduleDelayedRefresh();
}

void MainWindow::refreshDevices() {
    if (vpnWatchdogRunning_) {
        updateStatus(L"Дождитесь окончания проверки VPN.");
        return;
    }
    if (tokenActionRunning_) {
        updateStatus(L"Сейчас выполняется операция с токеном...");
        return;
    }

    bool expected = false;
    if (!refreshing_.compare_exchange_strong(expected, true)) {
        updateStatus(L"Обновление уже выполняется...");
        return;
    }

    KillTimer(hwnd_, IDT_DELAYED_REFRESH);
    setMainControlsEnabled(false);
    showRefreshProgress();
    updateStatus(L"Загрузка списка устройств...");

    if (refreshThread_.joinable()) {
        refreshThread_.join();
    }

    const bool includeDenied = kAdminBuild || diagnosticsMode_;
    const std::wstring policyUser = kAdminBuild ? getControlText(assignUserEdit_) : L"";
    refreshThread_ = std::thread([this, includeDenied, policyUser]() {
        std::vector<DeviceViewModel> loadedDevices;
        std::wstring loadedError;
        const DeviceListProgressCallback progress = [this](size_t processed, size_t total) {
            refreshProcessed_.store(processed, std::memory_order_relaxed);
            refreshTotal_.store(total, std::memory_order_relaxed);
            if (!closing_) {
                PostMessageW(hwnd_, WM_REFRESH_PROGRESS, 0, 0);
            }
        };
        try {
            loadedDevices = kAdminBuild
                ? service_.listAllDevicesForUser(policyUser, progress)
                : (includeDenied ? service_.listAllDevices(progress) : service_.listVisibleDevices(progress));
        }
        catch (const std::exception& error) {
            loadedError = L"Не удалось обновить список токенов. " + userFriendlyErrorMessage(error.what());
            logUiError(L"UI REFRESH ERROR", error.what(), loadedError);
        }

        {
            std::lock_guard<std::mutex> lock(refreshMutex_);
            pendingDevices_ = std::move(loadedDevices);
            pendingError_ = std::move(loadedError);
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
    updateStatus(status.c_str());
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
    {
        std::lock_guard<std::mutex> lock(refreshMutex_);
        loadedDevices = std::move(pendingDevices_);
        loadedError = std::move(pendingError_);
        pendingError_.clear();
    }

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

    try {
        updateHeaderText();
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Ошибка политики. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI HEADER ERROR", error.what(), status);
        SetWindowTextW(userInfoLabel_, status.c_str());
    }

    updateActiveDeviceTracking();
    applyDeviceFilter();
    hideRefreshProgress();
    refreshing_ = false;
    setMainControlsEnabled(true);
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

void MainWindow::applyDeviceFilter() {
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
    updateStatus(status.c_str());
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
}

void MainWindow::populateTreeView() {
    if (!treeView_) {
        return;
    }

    TreeView_DeleteAllItems(treeView_);
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
        TreeView_InsertItem(treeView_, &itemInsert);
        TreeView_Expand(treeView_, groupItem, TVE_EXPAND);
    }
}

void MainWindow::updateTreeTimerText() {
    if (!treeView_) {
        return;
    }

    updateTreeTimerTextRecursive(TreeView_GetRoot(treeView_));
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
            const std::wstring text = L"Конфиг: " + service_.currentPolicyPath() +
                L" | Пользователь: " + (userName.empty() ? L"(не указан)" : userName);
            SetWindowTextW(userInfoLabel_, text.c_str());
        }
        else {
            SetWindowTextW(userInfoLabel_, service_.currentUserSummary().c_str());
        }
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Ошибка политики. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI HEADER ERROR", error.what(), status);
        SetWindowTextW(userInfoLabel_, status.c_str());
    }
}

void MainWindow::refreshAccessForEditedUser() {
#ifndef DISKCONTROL_ADMIN
    return;
#else
    if (refreshing_) {
        return;
    }

    updateHeaderText();
    if (allDevices_.empty()) {
        return;
    }

    try {
        service_.updateAccessForUser(allDevices_, getControlText(assignUserEdit_));
        applyDeviceFilter();
    }
    catch (const std::exception& error) {
        const std::wstring status = L"Не удалось прочитать доступ пользователя. " + userFriendlyErrorMessage(error.what());
        logUiError(L"UI POLICY READ ERROR", error.what(), status);
        updateStatus(status.c_str());
    }
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
    profileUsers_ = profileUsersFromRoot(profilesRootForComputer(computerName));

    ComboBox_ResetContent(assignUserEdit_);
    bool hasCurrentUser = false;
    if (!currentUser.empty()) {
        ComboBox_AddString(assignUserEdit_, currentUser.c_str());
        hasCurrentUser = true;
    }
    for (const std::wstring& user : profileUsers_) {
        if (!currentUser.empty() && lowerCopy(user) == lowerCopy(currentUser)) {
            continue;
        }
        ComboBox_AddString(assignUserEdit_, user.c_str());
    }

    if (hasCurrentUser) {
        SetWindowTextW(assignUserEdit_, currentUser.c_str());
    }
    else if (!profileUsers_.empty()) {
        SetWindowTextW(assignUserEdit_, profileUsers_.front().c_str());
    }
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
    const std::wstring policyPath = policyPathForComputer(computerName);
    const std::wstring profilesRoot = profilesRootForComputer(computerName);
    const std::wstring policyParent = policyPath.substr(0, policyPath.find_last_of(L"\\/"));

    computerLoading_ = true;
    EnableWindow(loadComputerButton_, FALSE);
    EnableWindow(computerEdit_, FALSE);
    ShowWindow(computerProgressBar_, SW_SHOW);
    SendMessageW(computerProgressBar_, PBM_SETMARQUEE, TRUE, 30);
    updateStatus(L"Подключение к компьютеру и чтение профилей...");

    computerLoadThread_ = std::thread([this, computerName, policyPath, profilesRoot, policyParent]() {
        std::vector<std::wstring> profiles;
        std::wstring errorText;
        bool repaired = false;

        try {
            if (!ensureReadablePath(profilesRoot, errorText)) {
                throw std::runtime_error("profiles");
            }
            if (!ensureReadablePath(policyParent, errorText)) {
                errorText += L"\n\nПроверьте, установлен ли DiskControl на выбранном компьютере.";
                throw std::runtime_error("policy parent");
            }

            profiles = profileUsersFromRoot(profilesRoot);
            repaired = PolicyManager::ensureEditableConfig(policyPath);
        }
        catch (const std::exception& error) {
            if (errorText.empty()) {
                errorText = L"Не удалось открыть или подготовить конфиг " + policyPath +
                    L". Проверьте имя компьютера, сеть, административную шару C$, права администратора и наличие DiskControl на машине.";
            }
            logUiError(L"UI REMOTE COMPUTER ERROR", error.what(), errorText);
        }

        {
            std::lock_guard<std::mutex> lock(computerLoadMutex_);
            pendingComputerName_ = computerName;
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

    std::vector<std::wstring> profiles;
    std::wstring computerName;
    std::wstring policyPath;
    std::wstring errorText;
    bool repaired = false;
    {
        std::lock_guard<std::mutex> lock(computerLoadMutex_);
        profiles = std::move(pendingProfileUsers_);
        computerName = std::move(pendingComputerName_);
        policyPath = std::move(pendingComputerPolicyPath_);
        errorText = std::move(pendingComputerError_);
        repaired = pendingComputerPolicyRepaired_;
        pendingComputerPolicyRepaired_ = false;
    }

    computerLoading_ = false;
    SendMessageW(computerProgressBar_, PBM_SETMARQUEE, FALSE, 0);
    ShowWindow(computerProgressBar_, SW_HIDE);
    EnableWindow(loadComputerButton_, TRUE);
    EnableWindow(computerEdit_, TRUE);

    if (!errorText.empty()) {
        updateStatus(errorText.c_str());
        MessageBoxW(hwnd_, errorText.c_str(), L"DiskControl Admin", MB_ICONERROR | MB_OK);
        return;
    }

    PolicyManager::setConfigPathOverride(policyPath);

    profileUsers_ = std::move(profiles);
    ComboBox_ResetContent(assignUserEdit_);
    const std::wstring currentUser = PolicyManager::currentUserName();
    if (!currentUser.empty()) {
        ComboBox_AddString(assignUserEdit_, currentUser.c_str());
    }
    for (const std::wstring& user : profileUsers_) {
        if (!currentUser.empty() && lowerCopy(user) == lowerCopy(currentUser)) {
            continue;
        }
        ComboBox_AddString(assignUserEdit_, user.c_str());
    }
    if (!currentUser.empty()) {
        SetWindowTextW(assignUserEdit_, currentUser.c_str());
    }
    else if (!profileUsers_.empty()) {
        SetWindowTextW(assignUserEdit_, profileUsers_.front().c_str());
    }

    updateHeaderText();
    refreshDevices();

    std::wstring status = L"Загружен конфиг: " + policyPath;
    if (repaired) {
        status += L" (файл был восстановлен как пустой allow.json)";
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
        MessageBoxW(hwnd_, status.c_str(), L"DiskControl Admin", MB_ICONERROR | MB_OK);
        return;
    }

    PolicyManager::setConfigPathOverride(path);
    updateHeaderText();
    refreshDevices();

    if (repaired) {
        MessageBoxW(hwnd_,
            L"Файл конфигурации был некорректным и заменён пустым allow.json.\n"
            L"Старое содержимое сохранено рядом в файле *.invalid-*.bak.",
            L"DiskControl Admin",
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

    std::vector<DeviceViewModel> checkedDevices;
    for (const DeviceViewModel& device : allDevices_) {
        if (device.allowed) {
            checkedDevices.push_back(device);
        }
    }

    try {
        const std::wstring status = service_.setDevicesForUser(checkedDevices, userName);
        service_.updateAccessForUser(allDevices_, userName);
        applyDeviceFilter();
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

    for (const DeviceViewModel& selectedDevice : selected) {
        for (DeviceViewModel& device : allDevices_) {
            if (sameDeviceIdentity(device, selectedDevice)) {
                device.allowed = true;
                break;
            }
        }
    }

    applyDeviceFilter();
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

    for (const DeviceViewModel& selectedDevice : selected) {
        for (DeviceViewModel& device : allDevices_) {
            if (sameDeviceIdentity(device, selectedDevice)) {
                device.allowed = false;
                break;
            }
        }
    }

    applyDeviceFilter();
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
        if (elapsedMsFromStartIfKnown(device.usageStartedAt, sharedElapsedMs)) {
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
        const int answer = timedMessageBox(hwnd_, text, L"DiskControl", MB_YESNO | MB_ICONQUESTION | MB_TOPMOST, kTokenPromptTimeoutMs);
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

    const std::wstring sharedDuration = remainingTextFromStartIfKnown(device.usageStartedAt);
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

void MainWindow::updateStatus(const wchar_t* text) {
    SetWindowTextW(statusLabel_, text);
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
