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

class MainWindow {
public:
    bool create(HINSTANCE instance, int showCommand);

private:
    static LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT handleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    void createControls();
    void layoutControls();
    void refreshDevices();
    void exportExcel();
    void exportJson();
    void assignSelectedDeviceToUser();
    void removeSelectedDeviceFromUser();
    void openPolicyFile();
    void saveCheckedDevicesForUser();
    void refreshAccessForEditedUser();
    void loadProfilesAndPolicyFromComputer();
    void loadProfilesForComputer(const std::wstring& computerName);
    void finishComputerLoad();
    void startTokenAction(DeviceViewModel device, bool connect);
    bool ensureVpnCredentials(const DeviceViewModel& device, bool forcePrompt);
    void configureVpnForSelectedDevice();
    void manageVpnForSelectedDevice();
    void finishTokenAction();
    void updateTokenActionProgress();
    void setMainControlsEnabled(bool enabled);
    void scheduleDelayedRefresh();
    void applyDeviceFilter();
    void populateListView();
    void populateAdminListViews();
    void populateTreeView();
    void sortDevices();
    void sortByColumn(int column);
    void activateSelectedDevice();
    void releaseActiveDevices(bool interactive);
    void updateActiveDeviceTracking();
    void checkActiveDeviceTimeouts();
    void checkActiveVpnHealth();
    void finishVpnHealthCheck();
    void publishNetworkState();
    void finishNetworkStatePublish();
    void retryPendingAutoReleases(ULONGLONG now);
    void requestAutoRelease(DeviceViewModel& device);
    void markDeviceLocallyReleased(const std::wstring& endpoint);
    void updateTreeTimerText();
    void updateTreeTimerTextRecursive(HTREEITEM item);
    std::wstring activeDurationText(const DeviceViewModel& device) const;
    void updateHeaderText();
    void updateStatus(const wchar_t* text);
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
    HWND vpnButton_ = nullptr;
    HWND statusLabel_ = nullptr;
    HWND refreshProgressBar_ = nullptr;
    HWND refreshProgressLabel_ = nullptr;
    DeviceAccessService service_;
    std::vector<DeviceViewModel> devices_;
    std::vector<DeviceViewModel> allDevices_;
    std::vector<DeviceViewModel> allowedDevices_;
    std::vector<DeviceViewModel> availableDevices_;
    std::vector<DeviceViewModel> pendingDevices_;
    std::vector<std::wstring> profileUsers_;
    std::map<std::wstring, ULONGLONG> activeDeviceStartTicks_;
    std::map<std::wstring, ULONGLONG> autoReleaseRequestTicks_;
    std::map<std::wstring, ULONGLONG> tokenActionFailureTicks_;
    std::wstring pendingError_;
    std::vector<std::wstring> pendingProfileUsers_;
    std::wstring pendingComputerName_;
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
    int sortColumn_ = 0;
    bool sortAscending_ = true;
#ifdef DISKCONTROL_ADMIN
    bool diagnosticsMode_ = true;
#else
    bool diagnosticsMode_ = false;
#endif
};
