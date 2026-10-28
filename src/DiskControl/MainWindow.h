#pragma once

#include "DeviceAccessService.h"

#include <windows.h>
#include <commctrl.h>

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct UserProfileEntry {
    std::wstring accountName;
    std::wstring sid;
    std::wstring profileDirectory;
    std::wstring policyPath;
    std::wstring phonebookPath;
    std::wstring networkStatePath;
};

class MainWindow {
public:
    bool create(HINSTANCE instance, int showCommand);

private:
    static LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT handleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    void createControls();
    void layoutControls();
    void refreshDevices(bool quiet = false);
    void applyAutoRefreshInterval();
    void runQueuedTokenAction();
    void exportExcel();
    void exportJson();
    void assignSelectedDeviceToUser();
    void removeSelectedDeviceFromUser();
    void openPolicyFile();
    void saveCheckedDevicesForUser();
    void refreshAccessForEditedUser();
    bool confirmDiscardAdminChanges();
    void captureAdminAccessState(const std::wstring& userName, const std::wstring& revision);
    void invalidateAdminAccessState();
    void markAdminAccessDirty();
    void updateAdminSaveState();
    bool wasDeviceAllowedAtLoad(const DeviceViewModel& device) const;
    void loadProfilesAndPolicyFromComputer();
    void loadProfilesForComputer(const std::wstring& computerName);
    void finishComputerLoad();
    bool selectAdminUserProfile(const std::wstring& userName, bool refreshDeviceList);
    void startTokenAction(DeviceViewModel device, bool connect);
    bool ensureVpnCredentials(const DeviceViewModel& device);
    void manageVpnMappings();
    void showUsageReport();
    void generateUsageReport(long long periodStart, long long periodEnd, const std::wstring& title);
    void finishTokenAction();
    void updateTokenActionProgress();
    void setMainControlsEnabled(bool enabled);
    void scheduleDelayedRefresh();
    void applyDeviceFilter(bool showSummary = true);
    void populateListView();
    void populateAdminListViews();
    void populateTreeView();
    void sortDevices();
    void sortByColumn(int column);
    void activateSelectedDevice();
    // reason is written to the audit log as "STOP REASON" for the usage report.
    void releaseActiveDevices(bool interactive, const wchar_t* reason);
    void updateActiveDeviceTracking();
    void checkActiveDeviceTimeouts();
    void checkActiveVpnHealth();
    void finishVpnHealthCheck();
    void publishNetworkState();
    void finishNetworkStatePublish();
    void retryPendingAutoReleases(ULONGLONG now);
    void requestAutoRelease(DeviceViewModel& device, const wchar_t* reason = L"TIMER");
    void markDeviceLocallyReleased(const std::wstring& endpoint);
    void updateTreeTimerText();
    void updateTreeTimerTextRecursive(HTREEITEM item);
    std::wstring activeDurationText(const DeviceViewModel& device) const;
    void updateHeaderText();
    void updateStatus(const wchar_t* text, COLORREF color = CLR_DEFAULT);
    void createFonts();
    void updateActionButton();
    void updateAdminMoveButtons(bool controlsEnabled);
    void drawTreeLabel(const NMTVCUSTOMDRAW* draw);
    LRESULT customDrawTree(NMTVCUSTOMDRAW* draw);
    void updateRefreshProgress();
    void showRefreshProgress();
    void hideRefreshProgress();
    void finishRefresh();
    DeviceViewModel* selectedDevice();
    std::vector<DeviceViewModel> selectedDevices() const;
    std::vector<DeviceViewModel> selectedDevicesFrom(HWND listView, const std::vector<DeviceViewModel>& source) const;

    HINSTANCE instance_ = nullptr;
    HWND hwnd_ = nullptr;
    HICON appIcon_ = nullptr;
    HWND userInfoLabel_ = nullptr;
    HWND listView_ = nullptr;
    HWND availableListView_ = nullptr;
    HWND allowedTitleLabel_ = nullptr;
    HWND availableTitleLabel_ = nullptr;
    HWND treeView_ = nullptr;
    HIMAGELIST treeImageList_ = nullptr;
    HFONT uiFont_ = nullptr;
    HFONT treeFont_ = nullptr;
    HFONT treeSelectedFont_ = nullptr;
    std::vector<std::wstring> treeEndpoints_;
    struct QueuedTokenAction {
        DeviceViewModel device;
        bool connect = false;
        bool valid = false;
    } queuedTokenAction_;
    bool quietRefresh_ = false;
    bool sessionEndReleaseDone_ = false;
    unsigned int autoRefreshSeconds_ = 0;
    unsigned int quietRefreshFailures_ = 0;
    ULONGLONG quietRefreshResumeAt_ = 0;
    HFONT statusFont_ = nullptr;
    COLORREF statusColor_ = CLR_DEFAULT;
    HWND refreshButton_ = nullptr;
    HWND useButton_ = nullptr;
    HWND stopButton_ = nullptr;
    HWND diagnosticsButton_ = nullptr;
    HWND assignUserLabel_ = nullptr;
    HWND assignUserEdit_ = nullptr;
    HWND computerLabel_ = nullptr;
    HWND computerEdit_ = nullptr;
    HWND loadComputerButton_ = nullptr;
    HWND computerProgressBar_ = nullptr;
    HWND assignUserButton_ = nullptr;
    HWND removeUserButton_ = nullptr;
    HWND openPolicyButton_ = nullptr;
    HWND savePolicyButton_ = nullptr;
    HWND searchLabel_ = nullptr;
    HWND searchEdit_ = nullptr;
    HWND clearSearchButton_ = nullptr;
    HWND exportButton_ = nullptr;
    HWND exportJsonButton_ = nullptr;
    HWND vpnMappingsButton_ = nullptr;
    HWND usageReportButton_ = nullptr;
    HWND statusLabel_ = nullptr;
    HWND refreshProgressBar_ = nullptr;
    HWND refreshProgressLabel_ = nullptr;
    DeviceAccessService service_;
    std::vector<DeviceViewModel> devices_;
    std::vector<DeviceViewModel> allDevices_;
    std::vector<DeviceViewModel> allowedDevices_;
    std::vector<DeviceViewModel> availableDevices_;
    std::vector<DeviceViewModel> pendingDevices_;
    std::vector<DeviceViewModel> baselineAllowedDevices_;
    std::vector<UserProfileEntry> profileUsers_;
    std::map<std::wstring, ULONGLONG> activeDeviceStartTicks_;
    std::map<std::wstring, ULONGLONG> autoReleaseRequestTicks_;
    std::map<std::wstring, ULONGLONG> tokenActionFailureTicks_;
    std::wstring pendingError_;
    std::wstring pendingPolicyRevision_;
    std::wstring pendingPolicyUser_;
    std::wstring loadedPolicyRevision_;
    std::wstring loadedPolicyUser_;
    std::vector<UserProfileEntry> pendingProfileUsers_;
    std::wstring pendingComputerName_;
    std::wstring pendingComputerUser_;
    std::wstring pendingComputerPolicyPath_;
    std::wstring pendingComputerError_;
    std::wstring pendingTokenActionStatus_;
    std::wstring pendingTokenActionError_;
    std::wstring pendingTokenActionEndpoint_;
    std::wstring pendingTokenActionOperationId_;
    std::wstring pendingTokenActionProgressText_;
    size_t pendingTokenActionProgressStep_ = 0;
    size_t pendingTokenActionProgressTotal_ = 0;
    bool pendingComputerPolicyRepaired_ = false;
    bool pendingTokenActionConnect_ = false;
    bool pendingTokenActionVpnError_ = false;
    DeviceViewModel pendingVpnFailureDevice_;
    std::wstring pendingVpnFailureError_;
    std::wstring pendingNetworkStateError_;
    ULONGLONG lastVpnWatchdogTick_ = 0;
    ULONGLONG lastNetworkStateTick_ = 0;
    std::thread refreshThread_;
    std::thread computerLoadThread_;
    std::thread tokenActionThread_;
    std::thread vpnWatchdogThread_;
    std::thread networkStateThread_;
    std::mutex refreshMutex_;
    std::mutex computerLoadMutex_;
    std::mutex tokenActionMutex_;
    std::mutex vpnWatchdogMutex_;
    std::mutex networkStateMutex_;
    std::atomic_bool refreshing_ = false;
    std::atomic_size_t refreshProcessed_ = 0;
    std::atomic_size_t refreshTotal_ = 0;
    unsigned int consecutiveRefreshFailures_ = 0;
    std::atomic_bool computerLoading_ = false;
    std::atomic_bool tokenActionRunning_ = false;
    std::atomic_bool vpnWatchdogRunning_ = false;
    std::atomic_bool networkStateRunning_ = false;
    std::atomic_bool closing_ = false;
    bool populatingList_ = false;
    bool timeoutPromptActive_ = false;
    bool adminAccessLoaded_ = false;
    bool adminAccessDirty_ = false;
    bool suppressAdminUserChange_ = false;
    int sortColumn_ = 0;
    bool sortAscending_ = true;
#ifdef DISKCONTROL_ADMIN
    bool diagnosticsMode_ = true;
#else
    bool diagnosticsMode_ = false;
#endif
};
