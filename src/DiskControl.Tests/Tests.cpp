#include "AuditLogger.h"
#include "DeviceAccessService.h"
#include "DeviceParser.h"
#include "IpcClient.h"
#include "PolicyManager.h"
#include "UsageStateStore.h"
#include "UsageStateSync.h"
#include "VpnManager.h"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class StubbedNetworkOperationsGuard {
public:
    StubbedNetworkOperationsGuard() {
        VpnManager::setNetworkOperationsStubbedForTests(true);
    }

    ~StubbedNetworkOperationsGuard() {
        VpnManager::setNetworkOperationsStubbedForTests(false);
    }
};

bool removeFirstMatch(const char* pattern) {
    WIN32_FIND_DATAA data{};
    HANDLE find = FindFirstFileA(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool removed = false;
    do {
        std::remove(data.cFileName);
        removed = true;
    } while (FindNextFileA(find, &data));
    FindClose(find);
    return removed;
}

std::wstring testPipeName(const wchar_t* suffix) {
    return L"DistControl.Tests." + std::to_wstring(GetCurrentProcessId()) + L"." + suffix;
}

std::string narrowAscii(const std::wstring& value) {
    std::string result;
    result.reserve(value.size());
    for (wchar_t ch : value) {
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

HANDLE createTestPipe(const std::wstring& name) {
    return CreateNamedPipeW(
        (L"\\\\.\\pipe\\" + name).c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        4096,
        4096,
        0,
        nullptr);
}

bool connectTestPipe(HANDLE pipe) {
    return ConnectNamedPipe(pipe, nullptr) != FALSE || GetLastError() == ERROR_PIPE_CONNECTED;
}

void testIpcRoundTrip() {
    const std::wstring pipeName = testPipeName(L"roundtrip");
    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Test named pipe could not be created.");

    std::atomic_bool serverOk = false;
    std::thread server([pipe, &serverOk]() {
        char request[64]{};
        DWORD read = 0;
        if (connectTestPipe(pipe) && ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
            const std::string response = u8"Ответ: 148 токенов";
            DWORD written = 0;
            serverOk = WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr) &&
                written == response.size() && std::string(request, request + read) == "LIST";
            FlushFileBuffers(pipe);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    });

    IpcClient client(pipeName);
    std::wstring response;
    try {
        response = client.issueCommand(L"LIST", 1000);
    }
    catch (...) {
        server.join();
        throw;
    }
    server.join();
    require(serverOk, "Named pipe test server did not receive/write the expected payload.");
    require(response == L"Ответ: 148 токенов", "Named pipe UTF-8 response mismatch.");
}

void testIpcReadTimeout() {
    const std::wstring pipeName = testPipeName(L"timeout");
    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Timeout test named pipe could not be created.");

    std::thread server([pipe]() {
        char request[64]{};
        DWORD read = 0;
        if (connectTestPipe(pipe)) {
            const BOOL readOk = ReadFile(pipe, request, sizeof(request), &read, nullptr);
            if (readOk) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    });

    bool timedOut = false;
    try {
        IpcClient(pipeName).issueCommand(L"LIST", 50);
    }
    catch (const std::exception& error) {
        timedOut = std::string(error.what()).find("timed out") != std::string::npos;
    }
    server.join();
    require(timedOut, "Named pipe read timeout should cancel the pending operation.");
}

void testIpcRetriesBusyPipe() {
    const std::wstring pipeName = testPipeName(L"busy-retry");
    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Busy retry test named pipe could not be created.");

    HANDLE blocker = CreateFileW(
        (L"\\\\.\\pipe\\" + pipeName).c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    require(blocker != INVALID_HANDLE_VALUE, "Busy retry test could not occupy the pipe instance.");

    std::atomic_bool serverOk = false;
    std::thread server([pipe, &serverOk]() {
        connectTestPipe(pipe);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        DisconnectNamedPipe(pipe);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        char request[64]{};
        DWORD read = 0;
        if (connectTestPipe(pipe) && ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
            const std::string response = "OK";
            DWORD written = 0;
            serverOk = std::string(request, request + read) == "LIST" &&
                WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr) &&
                written == response.size();
            FlushFileBuffers(pipe);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    });

    std::wstring response;
    try {
        response = IpcClient(pipeName).issueCommand(L"LIST", 2000);
    }
    catch (...) {
        CloseHandle(blocker);
        server.join();
        throw;
    }
    CloseHandle(blocker);
    server.join();
    require(serverOk && response == L"OK", "IPC client should retry while every pipe instance is busy.");
}

void testDeviceInfoErrorKeepsAllowedListEntry() {
    const char* policyFile = "policy-info-error-list-test.json";
    const std::wstring pipeName = testPipeName(L"info-error-list");
    std::remove(policyFile);
    {
        std::ofstream stream(policyFile, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"" << narrowAscii(pipeName) << "\",\n"
            << "  \"usageStatePath\": \"usage-info-error-list-test.json\",\n"
            << "  \"userAssignments\": [{\"users\": [\""
            << narrowAscii(PolicyManager::currentUserSid())
            << "\"], \"groups\": [], \"allowedDevices\": [{\"endpoint\": \"OFFICE-HUB-Gr-1.3\", "
            << "\"nickname\": \"Allowed Key\", \"product\": \"Rutoken\"}]}]\n"
            << "}\n";
    }

    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "DEVICE INFO error test pipe could not be created.");
    std::atomic_bool serverOk = true;
    std::thread server([pipe, &serverOk]() {
        for (int requestIndex = 0; requestIndex < 2; ++requestIndex) {
            char request[256]{};
            DWORD read = 0;
            if (!connectTestPipe(pipe) || !ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
                serverOk = false;
                break;
            }
            const std::string command(request, request + read);
            const std::string response = command == "LIST"
                ? "--> Allowed Key (OFFICE-HUB-Gr-1.3)\n"
                : "ERROR: Invalid address";
            if (command != "LIST" && command != "DEVICE INFO,OFFICE-HUB-Gr-1.3") {
                serverOk = false;
            }
            DWORD written = 0;
            if (!WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr) ||
                written != response.size()) {
                serverOk = false;
            }
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    });

    try {
        PolicyManager::setConfigPathOverride(L"policy-info-error-list-test.json");
        std::vector<std::pair<size_t, size_t>> progressUpdates;
        const std::vector<DeviceViewModel> devices = DeviceAccessService().listVisibleDevices(
            [&progressUpdates](size_t processed, size_t total) {
                progressUpdates.emplace_back(processed, total);
            });
        require(devices.size() == 1 && devices[0].endpoint == L"OFFICE-HUB-Gr-1.3",
            "A transient DEVICE INFO error must not hide an allowed LIST entry.");
        require(progressUpdates.size() == 2 && progressUpdates.front() == std::pair<size_t, size_t>{0, 1} &&
                progressUpdates.back() == std::pair<size_t, size_t>{1, 1},
            "Device list progress should report the catalog size and every processed device.");
    }
    catch (...) {
        server.join();
        PolicyManager::setConfigPathOverride(L"");
        std::remove(policyFile);
        throw;
    }
    server.join();
    PolicyManager::setConfigPathOverride(L"");
    require(serverOk, "DEVICE INFO error test pipe server failed.");
    std::remove(policyFile);
}

void testEmptyDeviceCatalogIsTransientError() {
    const char* policyFile = "policy-empty-list-test.json";
    const std::wstring pipeName = testPipeName(L"empty-list");
    std::remove(policyFile);
    {
        std::ofstream stream(policyFile, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"" << narrowAscii(pipeName) << "\",\n"
            << "  \"userAssignments\": []\n"
            << "}\n";
    }

    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Empty LIST test pipe could not be created.");
    std::thread server([pipe]() {
        char request[64]{};
        DWORD read = 0;
        if (connectTestPipe(pipe) && ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
            const std::string response = "DistKontrolUSB Client IPC, below are the available devices:\n";
            DWORD written = 0;
            WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr);
            FlushFileBuffers(pipe);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    });

    bool rejected = false;
    try {
        PolicyManager::setConfigPathOverride(L"policy-empty-list-test.json");
        DeviceAccessService().listVisibleDevices();
    }
    catch (const std::exception& error) {
        rejected = std::string(error.what()).find("temporarily empty") != std::string::npos;
    }
    server.join();
    PolicyManager::setConfigPathOverride(L"");
    std::remove(policyFile);
    require(rejected, "An empty DistKontrol catalog must be reported as a transient error.");
}

void testUseDeviceAllowsSlowUseResponse() {
    const char* policyFile = "policy-slow-use-test.json";
    const char* usageFile = "usage-slow-use-test.json";
    std::remove(policyFile);
    std::remove(usageFile);
    std::remove("usage-slow-use-test.json.lock");
    removeFirstMatch("usage-slow-use-test.json.tmp-*");

    const std::wstring pipeName = testPipeName(L"slow-use");
    {
        std::ofstream stream(policyFile, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"" << narrowAscii(pipeName) << "\",\n"
            << "  \"usageStatePath\": \"" << usageFile << "\",\n"
            << "  \"vpnProfiles\": [{\"id\": \"test-direct\", \"mode\": \"direct\", \"enabled\": true}],\n"
            << "  \"userAssignments\": [\n"
            << "    {\n"
            << "      \"users\": [\"" << narrowAscii(PolicyManager::currentUserSid()) << "\"],\n"
            << "      \"groups\": [],\n"
            << "      \"allowedDevices\": [\n"
            << "        { \"endpoint\": \"OFFICE-HUB-Gr-1.3\", \"nickname\": \"Slow Key\", "
            << "\"product\": \"Rutoken\", \"vpnProfile\": \"test-direct\" }\n"
            << "      ]\n"
            << "    }\n"
            << "  ]\n"
            << "}\n";
    }

    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Slow USE test named pipe could not be created.");

    std::vector<std::string> commands;
    std::atomic_bool serverOk = true;
    std::thread server([pipe, &commands, &serverOk]() {
        bool useReceived = false;
        for (int requestIndex = 0; requestIndex < 7; ++requestIndex) {
            char request[256]{};
            DWORD read = 0;
            if (!connectTestPipe(pipe) || !ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
                serverOk = false;
                break;
            }

            const std::string command(request, request + read);
            commands.push_back(command);
            std::string response;
            if (command == "DEVICE INFO,OFFICE-HUB-Gr-1.3") {
                response = useReceived
                    ? "NICKNAME: Slow Key\r\nPRODUCT: Rutoken\r\nIN USE BY: YOU\r\n"
                    : "NICKNAME: Slow Key\r\nPRODUCT: Rutoken\r\nIN USE BY: NO ONE\r\n";
            }
            else if (command == "LIST") {
                response = "--> Slow Key (OFFICE-HUB-Gr-1.3)\n";
            }
            else if (command == "SERVER INFO,OFFICE-HUB-Gr-1") {
                response = "STATE: Logged in\r\n";
            }
            else if (command == "USE,OFFICE-HUB-Gr-1.3") {
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                useReceived = true;
                response = "OK";
            }
            else {
                serverOk = false;
                response = "ERROR";
            }

            DWORD written = 0;
            if (!WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr) ||
                written != response.size()) {
                serverOk = false;
            }
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    });

    try {
        PolicyManager::setConfigPathOverride(L"policy-slow-use-test.json");
        StubbedNetworkOperationsGuard networkGuard;
        DeviceAccessService service;
        DeviceViewModel device;
        device.endpoint = L"OFFICE-HUB-Gr-1.3";
        device.nickname = L"Slow Key";
        device.product = L"Rutoken";
        device.inUseBy = L"NO ONE";
        device.allowed = true;

        require(service.useDevice(device).find(L"Токен подключён") != std::wstring::npos,
            "Slow USE response should be accepted.");
    }
    catch (...) {
        server.join();
        PolicyManager::setConfigPathOverride(L"");
        std::remove(policyFile);
        std::remove(usageFile);
        std::remove("usage-slow-use-test.json.lock");
        removeFirstMatch("usage-slow-use-test.json.tmp-*");
        throw;
    }

    server.join();
    PolicyManager::setConfigPathOverride(L"");
    require(serverOk, "Slow USE test pipe server failed.");
    const std::vector<std::string> expectedCommands{
        "DEVICE INFO,OFFICE-HUB-Gr-1.3",
        "LIST",
        "LIST",
        "SERVER INFO,OFFICE-HUB-Gr-1",
        "DEVICE INFO,OFFICE-HUB-Gr-1.3",
        "USE,OFFICE-HUB-Gr-1.3",
        "DEVICE INFO,OFFICE-HUB-Gr-1.3"
    };
    require(commands == expectedCommands,
        "Slow USE test should prepare the network and verify ownership before and after USE.");

    std::remove(policyFile);
    std::remove(usageFile);
    std::remove("usage-slow-use-test.json.lock");
    removeFirstMatch("usage-slow-use-test.json.tmp-*");
}

void testUseDeviceFailedResponseIsError() {
    const char* policyFile = "policy-failed-use-test.json";
    const char* usageFile = "usage-failed-use-test.json";
    std::remove(policyFile);
    std::remove(usageFile);
    std::remove("usage-failed-use-test.json.lock");
    removeFirstMatch("usage-failed-use-test.json.tmp-*");

    const std::wstring pipeName = testPipeName(L"failed-use");
    {
        std::ofstream stream(policyFile, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"" << narrowAscii(pipeName) << "\",\n"
            << "  \"usageStatePath\": \"" << usageFile << "\",\n"
            << "  \"vpnProfiles\": [{\"id\": \"test-direct\", \"mode\": \"direct\", \"enabled\": true}],\n"
            << "  \"userAssignments\": [\n"
            << "    {\n"
            << "      \"users\": [\"" << narrowAscii(PolicyManager::currentUserSid()) << "\"],\n"
            << "      \"groups\": [],\n"
            << "      \"allowedDevices\": [\n"
            << "        { \"endpoint\": \"OFFICE-HUB-Gr-1.3\", \"nickname\": \"Failed Key\", "
            << "\"product\": \"Rutoken\", \"vpnProfile\": \"test-direct\" }\n"
            << "      ]\n"
            << "    }\n"
            << "  ]\n"
            << "}\n";
    }

    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Failed USE test named pipe could not be created.");

    std::atomic_bool serverOk = true;
    std::thread server([pipe, &serverOk]() {
        // One preparation cycle, four USE attempts with recovery between them,
        // and one final DEVICE INFO confirmation.
        for (int requestIndex = 0; requestIndex < 19; ++requestIndex) {
            char request[256]{};
            DWORD read = 0;
            if (!connectTestPipe(pipe) || !ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
                serverOk = false;
                break;
            }

            const std::string command(request, request + read);
            std::string response;
            if (command == "DEVICE INFO,OFFICE-HUB-Gr-1.3") {
                response = "NICKNAME: Failed Key\r\nPRODUCT: Rutoken\r\nIN USE BY: NO ONE\r\n";
            }
            else if (command == "LIST") {
                response = "--> Failed Key (OFFICE-HUB-Gr-1.3)\n";
            }
            else if (command == "SERVER INFO,OFFICE-HUB-Gr-1") {
                response = "STATE: Logged in\r\n";
            }
            else if (command == "USE,OFFICE-HUB-Gr-1.3") {
                response = "FAILED";
            }
            else {
                serverOk = false;
                response = "ERROR";
            }

            DWORD written = 0;
            if (!WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr) ||
                written != response.size()) {
                serverOk = false;
            }
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    });

    bool failed = false;
    try {
        PolicyManager::setConfigPathOverride(L"policy-failed-use-test.json");
        StubbedNetworkOperationsGuard networkGuard;
        DeviceAccessService service;
        DeviceViewModel device;
        device.endpoint = L"OFFICE-HUB-Gr-1.3";
        device.nickname = L"Failed Key";
        device.product = L"Rutoken";
        device.inUseBy = L"NO ONE";
        device.allowed = true;

        service.useDevice(device);
    }
    catch (const std::exception& error) {
        failed = std::string(error.what()).find("FAILED") != std::string::npos;
    }

    server.join();
    PolicyManager::setConfigPathOverride(L"");
    require(serverOk, "Failed USE test pipe server failed.");
    require(failed, "FAILED USE response should be treated as an error.");
    require(GetFileAttributesA(usageFile) == INVALID_FILE_ATTRIBUTES,
        "Failed USE response must not create usage timer state.");

    std::remove(policyFile);
    std::remove(usageFile);
    std::remove("usage-failed-use-test.json.lock");
    removeFirstMatch("usage-failed-use-test.json.tmp-*");
}

void testRevokedActiveTokenCanBeStopped() {
    const char* policyFile = "policy-revoked-active-test.json";
    const char* usageFile = "usage-revoked-active-test.json";
    std::remove(policyFile);
    std::remove(usageFile);
    std::remove("usage-revoked-active-test.json.lock");

    const std::wstring pipeName = testPipeName(L"revoked-active");
    {
        std::ofstream stream(policyFile, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"";
        const std::wstring widePipeName = pipeName;
        for (wchar_t ch : widePipeName) {
            stream << static_cast<char>(ch);
        }
        stream << "\",\n"
            << "  \"usageStatePath\": \"usage-revoked-active-test.json\",\n"
            << "  \"userAssignments\": []\n"
            << "}\n";
    }

    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Revoked token test pipe could not be created.");
    std::vector<std::string> commands;
    std::atomic_bool serverOk = true;
    std::thread server([pipe, &commands, &serverOk]() {
        for (int requestIndex = 0; requestIndex < 5; ++requestIndex) {
            char request[256]{};
            DWORD read = 0;
            if (!connectTestPipe(pipe) || !ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
                serverOk = false;
                break;
            }

            const std::string command(request, request + read);
            commands.push_back(command);
            std::string response;
            if (command == "LIST") {
                response = "--> Revoked Key (OFFICE-HUB-Gr-1.3) (In-use by:YOU)\n";
            }
            else if (command == "DEVICE INFO,OFFICE-HUB-Gr-1.3") {
                response = requestIndex < 4
                    ? "NICKNAME: Revoked Key\r\nPRODUCT: Rutoken\r\nIN USE BY: YOU\r\n"
                    : "NICKNAME: Revoked Key\r\nPRODUCT: Rutoken\r\nIN USE BY: NO ONE\r\n";
            }
            else if (command == "STOP USING,OFFICE-HUB-Gr-1.3") {
                response = "OK";
            }
            else {
                serverOk = false;
                response = "ERROR";
            }

            DWORD written = 0;
            if (!WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr) ||
                written != response.size()) {
                serverOk = false;
            }
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    });

    try {
        PolicyManager::setConfigPathOverride(L"policy-revoked-active-test.json");
        DeviceAccessService service;
        const std::vector<DeviceViewModel> devices = service.listVisibleDevices();
        require(devices.size() == 1, "A revoked token connected by the current user must remain visible.");
        require(!devices[0].allowed, "The visible revoked token must remain denied for new connections.");
        require(DeviceParser::parseUsage(devices[0].inUseBy, PolicyManager::currentUserName()).isUsedByCurrentUser,
            "The revoked token should still be recognized as connected by the current user.");
        require(service.stopUsingOwnedDevice(devices[0]) == L"OK",
            "A revoked token connected by the current user should still be releasable.");
    }
    catch (...) {
        server.join();
        PolicyManager::setConfigPathOverride(L"");
        std::remove(policyFile);
        std::remove(usageFile);
        std::remove("usage-revoked-active-test.json.lock");
        throw;
    }

    server.join();
    PolicyManager::setConfigPathOverride(L"");
    require(serverOk, "Revoked token test pipe server failed.");
    require(commands.size() == 5 && commands[3] == "STOP USING,OFFICE-HUB-Gr-1.3" &&
        commands.back() == "DEVICE INFO,OFFICE-HUB-Gr-1.3",
        "Revoked token cleanup must verify release after STOP USING.");
    std::remove(policyFile);
    std::remove(usageFile);
    std::remove("usage-revoked-active-test.json.lock");
}

void testParseList() {
    const std::wstring sample =
        L"OFFICE-HUB-Gr-1 (192.168.1.10:7575)\n"
        L"KeyOne (OFFICE-HUB-Gr-1.3)\n"
        L"KeyTwo (OFFICE-HUB-Gr-1.4)\n"
        L"KeyOne duplicate (OFFICE-HUB-Gr-1.3)\n";

    const auto devices = DeviceParser::parseList(sample);
    require(devices.size() == 2, "parseList should return unique endpoints.");
    require(devices[0].endpoint == L"OFFICE-HUB-Gr-1.3", "Unexpected first endpoint.");
    require(devices[0].nickname == L"KeyOne", "LIST nickname should be parsed without DEVICE INFO.");
    require(devices[1].endpoint == L"OFFICE-HUB-Gr-1.4", "Unexpected second endpoint.");

    const std::wstring occupiedSample =
        L"--> Token A (OFFICE-HUB-Gr-1.5) (In-use by:d.karev (d.karev) at 10.14.32.148 (WRK-114))\n";

    const auto occupiedDevices = DeviceParser::parseList(occupiedSample);
    require(occupiedDevices.size() == 1, "parseList should keep occupied endpoint.");
    require(occupiedDevices[0].endpoint == L"OFFICE-HUB-Gr-1.5", "Occupied endpoint was not parsed.");
    require(occupiedDevices[0].nickname == L"Token A", "Occupied LIST nickname should be parsed.");
    require(occupiedDevices[0].inUseBy == L"d.karev (d.karev) at 10.14.32.148 (WRK-114)",
        "LIST In-use by value should be preserved.");

    const auto autoUseDevices = DeviceParser::parseList(
        L"* --> Auto Key (OFFICE-HUB-Gr-1.7)\n");
    require(autoUseDevices.size() == 1 && autoUseDevices[0].nickname == L"Auto Key",
        "LIST auto-use markers should not become part of the nickname.");

    std::wstring largeList;
    for (int i = 0; i < 148; ++i) {
        largeList += L"--> Token " + std::to_wstring(i) +
            L" (OFFICE-HUB-Gr-1." + std::to_wstring(1000 + i) + L")\n";
    }
    const auto largeDevices = DeviceParser::parseList(largeList);
    require(largeDevices.size() == 148, "LIST parser should handle 148 unique tokens.");
    require(largeDevices.back().nickname == L"Token 147", "Large LIST nickname mismatch.");
}

void testApplyDeviceInfo() {
    ParsedDevice device;
    device.endpoint = L"OFFICE-HUB-Gr-1.3";

    DeviceParser::applyDeviceInfo(
        device,
        L"NICKNAME: BANK-KEY-01\r\n"
        L"PRODUCT: Rutoken\r\n"
        L"IN USE BY: NO ONE\r\n");

    require(device.nickname == L"BANK-KEY-01", "NICKNAME was not parsed.");
    require(device.product == L"Rutoken", "PRODUCT was not parsed.");
    require(device.inUseBy == L"NO ONE", "IN USE BY was not parsed.");

    ParsedDevice occupied;
    occupied.endpoint = L"OFFICE-HUB-Gr-1.5";
    occupied.inUseBy = L"d.karev (d.karev) at 10.14.32.148 (WRK-114)";

    DeviceParser::applyDeviceInfo(
        occupied,
        L"NICKNAME: BANK-KEY-02\r\n"
        L"PRODUCT: Rutoken\r\n"
        L"IN USE BY: SYSTEM AT WRK-220\r\n");

    require(occupied.nickname == L"BANK-KEY-02", "Occupied NICKNAME was not parsed.");
    require(occupied.product == L"Rutoken", "Occupied PRODUCT was not parsed.");
    require(occupied.inUseBy == L"d.karev (d.karev) at 10.14.32.148 (WRK-114)",
        "Human LIST usage should not be overwritten by SYSTEM from DEVICE INFO.");

    ParsedDevice partial;
    partial.endpoint = L"OFFICE-HUB-Gr-1.6";
    partial.nickname = L"LIST-NAME";
    DeviceParser::applyDeviceInfo(partial, L"PRODUCT: Rutoken\r\nIN USE BY: NO ONE\r\n");
    require(partial.nickname == L"LIST-NAME",
        "Missing DEVICE INFO nickname must not erase the nickname parsed from LIST.");
}

void testPolicyMatching() {
    const std::vector<DeviceRule> rules = {
        { L"OFFICE-HUB-Gr-1.3", L"BANK-KEY-01", L"Rutoken" },
        { L"OFFICE-HUB-Gr-2.4", L"REPORT-KEY-01", L"" }
    };

    ParsedDevice allowed{ L"office-hub-Gr-1.3", L"BANK-KEY-01", L"Rutoken", L"NO ONE" };
    require(PolicyManager::isAllowedByRules(allowed, rules), "Expected matching device to be allowed.");

    ParsedDevice wrongName = allowed;
    wrongName.nickname = L"OTHER-KEY";
    require(!PolicyManager::isAllowedByRules(wrongName, rules), "Nickname mismatch must deny access.");

    ParsedDevice optionalProduct{ L"OFFICE-HUB-Gr-2.4", L"REPORT-KEY-01", L"Any Product", L"NO ONE" };
    require(PolicyManager::isAllowedByRules(optionalProduct, rules), "Empty product rule should not restrict product.");

    ParsedDevice unknown{ L"OFFICE-HUB-Gr-9.9", L"BANK-KEY-01", L"Rutoken", L"NO ONE" };
    require(!PolicyManager::isAllowedByRules(unknown, rules), "Unknown endpoint must deny access.");

    require(!PolicyManager::isAllowedByRules(allowed, {}), "Empty rules must deny access.");
}

void testUsageParsing() {
    DeviceUsageInfo freeUsage = DeviceParser::parseUsage(L"NO ONE", L"DOMAIN\\ivanov");
    require(freeUsage.statusText == L"Свободен", "NO ONE should be shown as free.");
    require(freeUsage.isFree, "NO ONE should set isFree.");

    DeviceUsageInfo ownUsage = DeviceParser::parseUsage(L"YOU", L"DOMAIN\\ivanov");
    require(ownUsage.statusText == L"Подключён вами", "YOU should be shown as used by current user.");
    require(ownUsage.isUsedByCurrentUser, "YOU should set isUsedByCurrentUser.");

    DeviceUsageInfo remoteUsage = DeviceParser::parseUsage(L"DOMAIN\\petrov (session) AT 10.10.10.5", L"DOMAIN\\ivanov");
    require(remoteUsage.statusText == L"Занят", "Remote user should be shown as busy.");
    require(remoteUsage.userText == L"DOMAIN\\petrov (session)", "Remote user should be extracted.");
    require(remoteUsage.locationText == L"10.10.10.5", "Remote location should be extracted.");
    require(!remoteUsage.isUsedByCurrentUser, "Remote user should not match current user.");

    DeviceUsageInfo similarLoginUsage = DeviceParser::parseUsage(L"ivanov AT WRK-2", L"DOMAIN\\ivan");
    require(!similarLoginUsage.isUsedByCurrentUser,
        "A login that only contains the current login must not be treated as the same user.");

    DeviceUsageInfo otherDomainUsage = DeviceParser::parseUsage(L"OTHER\\ivan AT WRK-3", L"DOMAIN\\ivan");
    require(!otherDomainUsage.isUsedByCurrentUser,
        "Equal short logins from different domains must not be treated as the same user.");

    DeviceUsageInfo compactUserUsage = DeviceParser::parseUsage(L"d.karev (d.karev) AT 10.14.32.148 (WRK-114)", L"DOMAIN\\ivanov");
    require(compactUserUsage.userText == L"d.karev", "Repeated login should be shown once.");
    require(compactUserUsage.locationText == L"10.14.32.148 (WRK-114)", "Workstation should stay in location.");

    DeviceUsageInfo systemUsage = DeviceParser::parseUsage(L"SYSTEM AT WRK-220", L"DOMAIN\\ivanov");
    require(systemUsage.userText.empty(), "SYSTEM should not be shown as token user.");
    require(systemUsage.locationText == L"WRK-220", "SYSTEM workstation should stay in location.");

    DeviceUsageInfo russianSystemUsage = DeviceParser::parseUsage(L"СИСТЕМА НА 10.14.32.179 (WRK-406)", L"DOMAIN\\ivanov");
    require(russianSystemUsage.userText.empty(), "Russian SYSTEM should not be shown as token user.");
    require(russianSystemUsage.locationText == L"10.14.32.179 (WRK-406)",
        "Russian SYSTEM workstation should stay in location.");
}

void testUsageStateStore() {
    const char* fileName = "usage-state-test.json";
    std::remove(fileName);
    removeFirstMatch("usage-state-test.json.tmp-*");

    UsageStateStore store(L"usage-state-test.json");
    ParsedDevice device{ L"OFFICE-HUB-Gr-1.3", L"BANK-KEY-01", L"Rutoken", L"SYSTEM AT WRK-220" };
    store.markUsed(device, L"DOMAIN\\ivanov");

    const std::vector<UsageStateRecord> snapshot = store.snapshot();
    require(snapshot.size() == 1, "Usage state snapshot should contain the active device.");
    require(snapshot[0].endpoint == device.endpoint, "Usage state snapshot endpoint mismatch.");

    ParsedDevice busyFromService = device;
    busyFromService.inUseBy = L"SYSTEM AT WRK-220";
    require(store.applyRecordedUsage(busyFromService), "SYSTEM usage should be replaced by recorded owner.");
    require(busyFromService.inUseBy.find(L"DOMAIN\\ivanov") != std::wstring::npos,
        "Recorded user should be shown instead of SYSTEM.");

    ParsedDevice russianBusyFromService = device;
    russianBusyFromService.inUseBy = L"СИСТЕМА НА WRK-406";
    require(store.applyRecordedUsage(russianBusyFromService), "Russian SYSTEM usage should be replaced by recorded owner.");
    require(russianBusyFromService.inUseBy.find(L"DOMAIN\\ivanov") != std::wstring::npos,
        "Recorded user should be shown instead of Russian SYSTEM.");

    ParsedDevice freeFromService = device;
    freeFromService.inUseBy = L"NO ONE";
    require(!store.applyRecordedUsage(freeFromService), "Free device should not use stale recorded owner.");
    require(freeFromService.inUseBy == L"NO ONE", "Free device usage text should stay unchanged.");

    ParsedDevice ownFromService = device;
    ownFromService.inUseBy = L"YOU";
    require(!store.applyRecordedUsage(ownFromService), "Own device should not be replaced by recorded owner.");
    require(ownFromService.inUseBy == L"YOU", "Own usage text should stay unchanged.");

    store.markReleased(device);
    ParsedDevice releasedFromService = device;
    releasedFromService.inUseBy = L"SYSTEM AT WRK-220";
    require(!store.applyRecordedUsage(releasedFromService), "Released device should not have recorded owner.");

    std::remove(fileName);
    removeFirstMatch("usage-state-test.json.tmp-*");
}

class UsageSyncFixture {
public:
    explicit UsageSyncFixture(const wchar_t* name)
        : sharedPath(L"usage-sync-case-" + std::to_wstring(GetCurrentProcessId()) + L"-" + name + L"-shared.json"),
          localPath(L"usage-sync-case-" + std::to_wstring(GetCurrentProcessId()) + L"-" + name + L"-local.json"),
          sync(sharedPath, localPath), shared(sharedPath) {
        cleanup();
    }
    ~UsageSyncFixture() { cleanup(); }
    std::wstring sharedPath;
    std::wstring localPath;
    UsageStateSync sync;
    UsageStateStore shared;
    ParsedDevice device{L"SYNC-HUB-Gr-1.1", L"Тестовый токен", L"Rutoken", L"YOU"};
    std::wstring user = L"DOMAIN\\test";
private:
    void cleanup() {
        for (const std::wstring& path : {sharedPath, localPath}) {
            DeleteFileW(path.c_str());
            DeleteFileW((path + L".lock").c_str());
            DeleteFileW((path + L".sync.lock").c_str());
            removeFirstMatch((narrowAscii(path) + ".tmp-*").c_str());
        }
    }
};

void testUsageSyncOfflinePersistenceAndMetadata() {
    UsageSyncFixture f(L"metadata");
    const UsageStateRecord original = f.sync.markUsed(f.device, f.user, L"203.0.113.10",
        L"vpn-one", L"VPN - Компания", L"CONNECT-TEST");
    require(f.shared.snapshot().empty(), "Connecting must not synchronously write the shared file.");
    require(f.sync.pendingCount() == 1, "Connecting must durably queue one change.");
    UsageStateSync reopened(f.sharedPath, f.localPath);
    require(reopened.snapshot().size() == 1 && reopened.pendingCount() == 1,
        "The queue and local timer must survive restarting the application.");
    require(reopened.synchronize([](const UsageStateRecord&) { return true; }), "Synchronization should succeed.");
    const UsageStateRecord sent = f.shared.snapshot().at(0);
    require(sent.updatedAt == original.updatedAt && sent.eventFileTime == original.eventFileTime &&
        sent.publicIp == original.publicIp && sent.vpnProfileId == original.vpnProfileId &&
        sent.vpnProfileName == original.vpnProfileName && sent.connectionId == original.connectionId &&
        sent.operationId == original.operationId, "Synchronization must preserve the original time, IP and session.");
    require(reopened.pendingCount() == 0, "A synchronized change must leave the queue.");
    const UsageStateRecord extended = reopened.markUsed(f.device, f.user, {}, {}, {}, L"EXTEND", true);
    require(extended.connectionId == original.connectionId && extended.publicIp == original.publicIp &&
        extended.vpnProfileName == original.vpnProfileName, "Extending the timer must preserve its IP and session.");
    reopened.markReleased(f.device, f.user, L"DISCONNECT-TEST");
    require(reopened.snapshot().empty(), "A local release must hide the old cached timer immediately.");
    require(reopened.synchronize([](const UsageStateRecord&) { return false; }), "Release should synchronize.");
    require(f.shared.snapshot().empty() && reopened.snapshot().empty() && reopened.pendingCount() == 0,
        "A released timer must disappear from both the shared file and local cache.");
}

void testUsageSyncSharedFileUnavailable() {
    UsageSyncFixture f(L"offline");
    f.sync.markUsed(f.device, f.user);
    require(f.sync.synchronize([](const UsageStateRecord&) { return true; }), "Initial synchronization should succeed.");
    HANDLE unavailable = CreateFileW(f.sharedPath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    require(unavailable != INVALID_HANDLE_VALUE, "Test must exclusively hold the shared file.");
    bool fast = false;
    bool retryable = false;
    try {
        const ULONGLONG started = GetTickCount64();
        f.sync.markUsed(f.device, f.user, L"203.0.113.20");
        fast = f.sync.snapshot().at(0).publicIp == L"203.0.113.20" && GetTickCount64() - started < 1000;
        retryable = !f.sync.synchronize([](const UsageStateRecord&) { return true; }) && f.sync.pendingCount() == 1;
    }
    catch (...) {
        CloseHandle(unavailable);
        throw;
    }
    CloseHandle(unavailable);
    require(fast, "Local writes and reads must remain fast when the shared file is inaccessible.");
    require(retryable, "An inaccessible shared file must leave the change queued, not erase shared records.");
    require(f.sync.synchronize([](const UsageStateRecord&) { return true; }) &&
        f.shared.snapshot().at(0).publicIp == L"203.0.113.20", "Retry must send the queued original IP.");
}

void testUsageSyncCoalescingAndStaleRelease() {
    UsageSyncFixture f(L"stale");
    UsageStateRecord old = f.sync.markUsed(f.device, f.user, L"203.0.113.1");
    f.sync.markReleased(f.device, f.user);
    const UsageStateRecord current = f.sync.markUsed(f.device, f.user, L"203.0.113.2");
    require(f.sync.pendingCount() == 1 && current.connectionId != old.connectionId,
        "Fast reconnects should keep only the latest state with a new session ID.");
    require(f.sync.synchronize([](const UsageStateRecord&) { return true; }), "Latest session should synchronize.");
    old.eventFileTime = current.eventFileTime + 100;
    f.shared.applyReleasedRecord(old);
    require(f.shared.snapshot().at(0).connectionId == current.connectionId,
        "An old session release must not delete a newer session, even with a later timestamp.");
    f.sync.markReleased(f.device, f.user);
    UsageStateRecord other = current;
    other.user = L"DOMAIN\\other";
    other.computer = L"OTHER-PC";
    other.connectionId = L"OTHER-SESSION";
    other.eventFileTime += 1000;
    f.shared.applyUsedRecord(other);
    require(f.sync.synchronize([](const UsageStateRecord&) { return false; }) &&
        f.shared.snapshot().at(0).user == other.user, "A queued release must not delete another user's timer.");
    f.shared.applyUsedRecord(current);
    require(f.shared.snapshot().at(0).user == other.user, "A delayed old use must not replace a newer shared record.");
}

void testUsageSyncConcurrentChangesRemainQueued() {
    UsageSyncFixture f(L"concurrent");
    f.sync.markUsed(f.device, f.user, L"203.0.113.1");
    std::atomic_bool waiting = false;
    std::atomic_bool proceed = false;
    bool result = false;
    int checks = 0;
    std::thread background([&]() {
        result = f.sync.synchronize([&](const UsageStateRecord&) {
            if (++checks == 2) {
                waiting = true;
                while (!proceed) Sleep(1);
            }
            return true;
        });
    });
    const ULONGLONG started = GetTickCount64();
    while (!waiting && GetTickCount64() - started < 2000) Sleep(1);
    const bool didWait = waiting;
    UsageStateRecord latest;
    bool localStayedFast = false;
    try {
        const ULONGLONG beforeWrite = GetTickCount64();
        f.sync.markReleased(f.device, f.user);
        latest = f.sync.markUsed(f.device, f.user, L"203.0.113.2");
        localStayedFast = GetTickCount64() - beforeWrite < 1000;
    }
    catch (...) {
        proceed = true;
        background.join();
        throw;
    }
    proceed = true;
    background.join();
    require(didWait && result && localStayedFast, "A background service/network wait must not hold the local journal lock.");
    require(f.sync.pendingCount() == 1 && f.sync.snapshot().at(0).connectionId == latest.connectionId,
        "Acknowledging an older change must not discard a concurrent reconnect.");
    require(f.sync.synchronize([](const UsageStateRecord&) { return true; }) &&
        f.shared.snapshot().at(0).publicIp == L"203.0.113.2", "The next run must synchronize the newest session.");
}

void testUsageSyncReconciliationAndInvalidFiles() {
    UsageSyncFixture f(L"recovery");
    f.sync.markUsed(f.device, f.user);
    require(f.sync.synchronize([](const UsageStateRecord&) { return true; }), "Initial timer should synchronize.");
    UsageStateSync restarted(f.sharedPath, f.localPath);
    require(restarted.synchronize([](const UsageStateRecord&) { return false; }) &&
        restarted.snapshot().empty() && f.shared.snapshot().empty(),
        "Restart recovery must reconcile a token that was released while the application was closed.");
    f.sync.markUsed(f.device, f.user);
    {
        std::ofstream stream(narrowAscii(f.sharedPath), std::ios::binary);
        stream << "{broken shared state";
    }
    require(!f.sync.synchronize([](const UsageStateRecord&) { return true; }) && f.sync.pendingCount() == 1,
        "Invalid shared JSON must not be overwritten or acknowledged.");
    {
        std::ifstream stream(narrowAscii(f.sharedPath), std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        require(text == "{broken shared state", "Invalid shared contents must remain intact.");
    }
    {
        std::ofstream stream(narrowAscii(f.localPath), std::ios::binary);
        stream << "{broken local state";
    }
    bool rejected = false;
    try { f.sync.markReleased(f.device, f.user); }
    catch (const std::exception&) { rejected = true; }
    require(rejected, "Invalid local JSON must not be silently replaced with an empty queue.");
}

void testUsageSyncProductionOwnerValidation() {
    UsageSyncFixture f(L"owner");
    f.sync.markUsed(f.device, f.user, L"203.0.113.10");
    const std::wstring pipeName = testPipeName(L"usage-sync");
    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Usage sync test pipe must be created.");
    bool serverOk = true;
    std::thread server([&]() {
        for (int i = 0; i < 2; ++i) {
            char request[4096]{};
            DWORD read = 0;
            if (!connectTestPipe(pipe) || !ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
                serverOk = false;
                break;
            }
            serverOk = serverOk && std::string(request, read) == "DEVICE INFO,SYNC-HUB-Gr-1.1";
            const std::string response = "IN USE BY: DOMAIN\\test AT 10.14.32.100 (" +
                narrowAscii(UsageStateStore::currentComputerName()) + ")\r\n";
            DWORD written = 0;
            serverOk = serverOk && WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr);
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    });
    const int result = UsageStateSync::runBackgroundSync(f.sharedPath, f.localPath, pipeName);
    server.join();
    require(serverOk && result == 0 && f.shared.snapshot().size() == 1,
        "Background owner validation must recognize the workstation in an IP (COMPUTER) location.");
    f.sync.markUsed(f.device, f.user);
    pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Invalid owner test pipe must be created.");
    std::thread invalidServer([pipe]() {
        char request[4096]{};
        DWORD read = 0;
        if (connectTestPipe(pipe) && ReadFile(pipe, request, sizeof(request), &read, nullptr)) {
            const char* response = "NICKNAME: incomplete response\r\n";
            DWORD written = 0;
            WriteFile(pipe, response, static_cast<DWORD>(strlen(response)), &written, nullptr);
            FlushFileBuffers(pipe);
        }
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    });
    const int invalidResult = UsageStateSync::runBackgroundSync(f.sharedPath, f.localPath, pipeName);
    invalidServer.join();
    require(invalidResult == 1 && f.sync.pendingCount() == 1 && f.sync.snapshot().size() == 1,
        "An incomplete owner response must retain the queue, not treat a token as released.");
}

void testUsageSyncLargeQueueAndEscaping() {
    UsageSyncFixture f(L"large");
    f.device.nickname = L"Токен «Компания» \\\"\n" + std::wstring(1, L'\x01');
    for (int i = 0; i < 150; ++i) {
        f.device.endpoint = L"SYNC-HUB-Gr-1." + std::to_wstring(i);
        f.sync.markUsed(f.device, f.user);
    }
    for (int i = 0; i < 20; ++i) f.sync.markUsed(f.device, f.user);
    require(f.sync.pendingCount() == 150 && f.sync.snapshot().size() == 150,
        "Offline repeated operations must coalesce instead of growing the queue indefinitely.");
    require(f.sync.snapshot().at(0).nickname == f.device.nickname, "Russian names and JSON escapes must round-trip.");
}

void testAuditCsvEscaping() {
    require(AuditLogger::csvEscapeForTest(L"plain") == "plain", "Plain CSV value should not be quoted.");
    require(AuditLogger::csvEscapeForTest(L"a,b") == "\"a,b\"", "Comma CSV value should be quoted.");
    require(AuditLogger::csvEscapeForTest(L"a\"b") == "\"a\"\"b\"", "Quote CSV value should be escaped.");

    const std::wstring firstOperation = AuditLogger::createOperationId(L"TEST");
    const std::wstring secondOperation = AuditLogger::createOperationId(L"TEST");
    require(firstOperation.rfind(L"TEST-", 0) == 0, "Operation ID should contain the requested prefix.");
    require(firstOperation != secondOperation, "Operation IDs should be unique within the process.");
}

void testAssignDeviceToUser() {
    const char* fileName = "policy-assign-test.json";
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"userAssignments\": []\n"
            << "}\n";
    }

    ParsedDevice device{ L"OFFICE-HUB-Gr-1.3", L"BANK-KEY-01", L"Rutoken", L"NO ONE" };
    PolicyManager policy(L"policy-assign-test.json");
    policy.assignDeviceToUser(device, L"DOMAIN\\petrov");

    {
        std::ifstream stream(fileName, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        require(text.find("DOMAIN\\\\petrov") != std::string::npos, "Assigned user should be written to policy.");
        require(text.find("OFFICE-HUB-Gr-1.3") != std::string::npos, "Assigned endpoint should be written to policy.");
    }

    std::remove(fileName);
}

void testRemoveDeviceFromUser() {
    const char* fileName = "policy-remove-test.json";
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"userAssignments\": []\n"
            << "}\n";
    }

    ParsedDevice device{ L"OFFICE-HUB-Gr-1.3", L"BANK-KEY-01", L"Rutoken", L"NO ONE" };
    PolicyManager policy(L"policy-remove-test.json");
    policy.assignDeviceToUser(device, L"DOMAIN\\petrov");
    policy.removeDeviceFromUser(device, L"DOMAIN\\petrov");

    {
        std::ifstream stream(fileName, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        require(text.find("DOMAIN\\\\petrov") != std::string::npos, "User block should remain after revoke.");
        require(text.find("OFFICE-HUB-Gr-1.3") == std::string::npos, "Revoked endpoint should be removed from policy.");
    }

    std::remove(fileName);
}

void testSetDevicesForUser() {
    const char* fileName = "policy-set-user-test.json";
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"userAssignments\": [\n"
            << "    {\n"
            << "      \"users\": [\"DOMAIN\\\\petrov\"],\n"
            << "      \"groups\": [],\n"
            << "      \"allowedDevices\": [\n"
            << "        {\"endpoint\": \"OFFICE-HUB-Gr-1.3\", \"nickname\": \"OLD-KEY\", \"product\": \"Rutoken\"}\n"
            << "      ]\n"
            << "    },\n"
            << "    {\n"
            << "      \"users\": [\"DOMAIN\\\\sidorov\"],\n"
            << "      \"groups\": [],\n"
            << "      \"allowedDevices\": [\n"
            << "        {\"endpoint\": \"OFFICE-HUB-Gr-9.9\", \"nickname\": \"OTHER-KEY\", \"product\": \"Rutoken\"}\n"
            << "      ]\n"
            << "    }\n"
            << "  ]\n"
            << "}\n";
    }

    ParsedDevice newDevice{ L"OFFICE-HUB-Gr-2.4", L"NEW-KEY", L"Rutoken", L"NO ONE" };
    ParsedDevice oldDevice{ L"OFFICE-HUB-Gr-1.3", L"OLD-KEY", L"Rutoken", L"NO ONE" };
    ParsedDevice otherUserDevice{ L"OFFICE-HUB-Gr-9.9", L"OTHER-KEY", L"Rutoken", L"NO ONE" };

    PolicyManager policy(L"policy-set-user-test.json");
    policy.setDevicesForUser({ newDevice }, L"petrov");

    require(policy.isAllowedForUser(newDevice, L"DOMAIN\\petrov"), "New device should be allowed for target user.");
    require(!policy.isAllowedForUser(oldDevice, L"petrov"), "Old target user device should be replaced.");
    require(policy.isAllowedForUser(otherUserDevice, L"sidorov"), "Other user assignment should remain.");

    {
        std::ifstream stream(fileName, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        require(text.find("DOMAIN\\\\petrov") != std::string::npos, "Existing DOMAIN user block should remain.");
        require(text.find("OFFICE-HUB-Gr-2.4") != std::string::npos, "Saved endpoint should be written.");
        require(text.find("OFFICE-HUB-Gr-1.3") == std::string::npos, "Replaced endpoint should be removed.");
    }

    std::remove(fileName);
}

void testPolicyPatchPreservesUnseenDevicesAndRejectsStaleRevision() {
    const char* fileName = "policy-patch-test.json";
    std::remove(fileName);
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"vpnProfiles\": [],\n"
            << "  \"userAssignments\": [{\n"
            << "    \"users\": [\"DOMAIN\\\\petrov\"],\n"
            << "    \"groups\": [],\n"
            << "    \"allowedDevices\": [\n"
            << "      {\"endpoint\": \"HUB-Gr-1.1\", \"nickname\": \"VISIBLE\", \"product\": \"Rutoken\"},\n"
            << "      {\"endpoint\": \"HUB-Gr-9.9\", \"nickname\": \"OFFLINE\", \"product\": \"Rutoken\", \"vpnProfile\": \"legacy\"}\n"
            << "    ]\n"
            << "  }]\n"
            << "}\n";
    }

    ParsedDevice visible{ L"HUB-Gr-1.1", L"VISIBLE", L"Rutoken", L"NO ONE" };
    ParsedDevice offline{ L"HUB-Gr-9.9", L"OFFLINE", L"Rutoken", L"NO ONE" };
    ParsedDevice added{ L"HUB-Gr-2.2", L"ADDED", L"Rutoken", L"NO ONE" };
    PolicyManager policy(L"policy-patch-test.json");
    const std::wstring originalRevision = policy.revision();
    const std::wstring updatedRevision = policy.applyDeviceAccessChanges(
        { added }, { visible }, L"petrov", originalRevision);

    require(updatedRevision != originalRevision, "Policy patch should change the revision.");
    PolicyManager updated(L"policy-patch-test.json");
    require(!updated.isAllowedForUser(visible, L"petrov"), "Explicitly removed device should be revoked.");
    require(updated.isAllowedForUser(added, L"petrov"), "Explicitly added device should be allowed.");
    require(updated.isAllowedForUser(offline, L"petrov"),
        "A policy-only device missing from the live catalog must be preserved.");

    bool conflictDetected = false;
    try {
        policy.applyDeviceAccessChanges({ visible }, {}, L"petrov", originalRevision);
    }
    catch (const std::exception& error) {
        conflictDetected = std::string(error.what()).find("Policy changed since it was loaded") != std::string::npos;
    }
    require(conflictDetected, "A stale policy revision must be rejected.");
    std::remove(fileName);
}

void testPolicyWriteReportsAccessDenied() {
    const char* fileName = "policy-readonly-test.json";
    std::remove(fileName);
    removeFirstMatch("policy-readonly-test.json.tmp-*");

    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"userAssignments\": []\n"
            << "}\n";
    }

    SetFileAttributesA(fileName, FILE_ATTRIBUTE_READONLY);

    bool caught = false;
    try {
        ParsedDevice device{ L"OFFICE-HUB-Gr-1.3", L"BANK-KEY-01", L"Rutoken", L"NO ONE" };
        PolicyManager policy(L"policy-readonly-test.json");
        policy.assignDeviceToUser(device, L"DOMAIN\\petrov");
    }
    catch (const std::exception& error) {
        caught = true;
        const std::string message = error.what();
        require(message.find("Access denied") != std::string::npos ||
            message.find("Win32 error 5") != std::string::npos,
            "Read-only policy write should report access denied.");
    }

    SetFileAttributesA(fileName, FILE_ATTRIBUTE_NORMAL);
    std::remove(fileName);
    removeFirstMatch("policy-readonly-test.json.tmp-*");
    require(caught, "Read-only policy write should fail.");
}

void testInvalidPolicyFileIsNotOverwritten() {
    const char* fileName = "policy-invalid-test.json";
    std::remove(fileName);
    removeFirstMatch("policy-invalid-test.json.invalid-*.bak");

    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{ broken json";
    }

    bool rejected = false;
    try {
        PolicyManager::ensureEditableConfig(L"policy-invalid-test.json");
    }
    catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, "Invalid policy file should be rejected.");

    {
        std::ifstream stream(fileName, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        require(text == "{ broken json", "Invalid policy file must remain unchanged.");
    }

    require(!removeFirstMatch("policy-invalid-test.json.invalid-*.bak"),
        "Reading an invalid policy should not create a replacement backup.");
    std::remove(fileName);
}

void testPolicyUsageStatePath() {
    const char* fileName = "policy-usage-path-test.json";
    std::remove(fileName);

    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"usageStatePath\": \"\\\\\\\\srv\\\\share\\\\DiskControl\\\\usage.json\",\n"
            << "  \"userAssignments\": []\n"
            << "}\n";
    }

    PolicyManager policy(L"policy-usage-path-test.json");
    require(policy.usageStatePath() == L"\\\\srv\\share\\DiskControl\\usage.json",
        "Custom usageStatePath should be read from policy.");

    std::remove(fileName);
}

void testVpnPolicyRoundTrip() {
    const char* fileName = "policy-vpn-test.json";
    std::remove(fileName);

    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"vpnProfiles\": [\n"
            << "    {\"id\": \"salut\", \"name\": \"Salut\", \"serverAddress\": \"89.108.64.96\", "
            << "\"tunnelType\": \"L2TP\", "
            << "\"ipCheckUrl\": \"https://api.ipify.org\", \"mode\": \"windowsVpn\", "
            << "\"phonebookScope\": \"allUsers\", \"fullTunnel\": false, \"enabled\": true},\n"
            << "    {\"id\": \"backup\", \"name\": \"Direct network\", \"mode\": \"direct\", "
            << "\"ipCheckUrl\": \"https://api.ipify.org\", \"enabled\": true}\n"
            << "  ],\n"
            << "  \"userAssignments\": [\n"
            << "    {\"users\": [\"" << narrowAscii(PolicyManager::currentUserSid()) << "\"], \"groups\": [], "
            << "\"allowedDevices\": [{\"endpoint\": \"OFFICE-HUB-Gr-1.3\", \"nickname\": \"VPN Key\", "
            << "\"product\": \"Rutoken\", \"vpnProfile\": \"salut\"}, "
            << "{\"endpoint\": \"OFFICE-HUB-Gr-2.4\", \"nickname\": \"Backup Key\", "
            << "\"product\": \"Rutoken\", \"vpnProfile\": \"backup\"}]}\n"
            << "  ]\n"
            << "}\n";
    }

    ParsedDevice device{ L"OFFICE-HUB-Gr-1.3", L"VPN Key", L"Rutoken", L"NO ONE" };
    ParsedDevice backupDevice{ L"OFFICE-HUB-Gr-2.4", L"Backup Key", L"Rutoken", L"NO ONE" };
    {
        PolicyManager policy(L"policy-vpn-test.json");
        require(policy.vpnProfiles().size() == 2, "Multiple VPN profiles should be parsed.");
        const VpnProfile& profile = policy.vpnProfiles()[0];
        require(profile.id == L"salut" && profile.name == L"Salut", "VPN profile identity mismatch.");
        require(profile.mode == VpnProfileMode::WindowsVpn &&
            profile.phonebookScope == VpnPhonebookScope::AllUsers,
            "Windows VPN mode and phonebook scope should be parsed.");
        require(profile.serverAddress == L"89.108.64.96", "VPN server should be parsed.");
        require(profile.enabled, "VPN enabled setting should be parsed.");

        VpnProfile matched;
        require(policy.tryGetVpnProfileForDevice(device, matched), "Token should resolve its VPN profile.");
        require(matched.id == L"salut", "Resolved VPN profile mismatch.");
        require(policy.tryGetVpnProfileForDevice(backupDevice, matched),
            "A second token should resolve its independent VPN profile.");
        require(matched.id == L"backup" && matched.mode == VpnProfileMode::Direct,
            "Direct network profile mapping mismatch.");

        policy.setDevicesForUser({ device, backupDevice }, PolicyManager::currentUserSid());
    }

    {
        PolicyManager policy(L"policy-vpn-test.json");
        VpnProfile matched;
        require(policy.tryGetVpnProfileForDevice(device, matched),
            "Saving the user token list must preserve its VPN mapping.");

        VpnProfile updated = policy.vpnProfiles()[0];
        updated.enabled = false;
        policy.upsertVpnProfile(updated);
    }

    {
        PolicyManager policy(L"policy-vpn-test.json");
        require(policy.vpnProfiles().size() == 2 &&
            !policy.vpnProfiles()[0].enabled,
            "A VPN profile without an allowed IP list should be written and updated.");
        {
            std::ifstream stream(fileName, std::ios::binary);
            const std::string saved((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
            require(saved.find("fullTunnel") == std::string::npos,
                "Legacy fullTunnel setting should be removed when VPN policy is saved.");
            require(saved.find("expectedPublicIps") == std::string::npos,
                "The removed allowed IP setting should not be written.");
            require(saved.find("\"mode\": \"windowsVpn\"") != std::string::npos &&
                saved.find("\"mode\": \"direct\"") != std::string::npos &&
                saved.find("\"phonebookScope\": \"allUsers\"") != std::string::npos,
                "Network mode and Windows phonebook scope should be persisted.");
        }
        policy.removeVpnProfile(L"salut");
    }

    {
        PolicyManager policy(L"policy-vpn-test.json");
        VpnProfile matched;
        require(policy.vpnProfiles().size() == 1 && policy.vpnProfiles()[0].id == L"backup",
            "Removing one VPN profile must preserve other profiles.");
        require(!policy.tryGetVpnProfileForDevice(device, matched),
            "Removing a VPN profile must remove token references to it.");
        require(policy.tryGetVpnProfileForDevice(backupDevice, matched) && matched.id == L"backup",
            "Removing one VPN profile must preserve other token mappings.");
    }

    std::remove(fileName);
}

void testAtomicVpnAssignmentForMultipleDevices() {
    const char* fileName = "policy-vpn-atomic-test.json";
    const std::wstring currentUser = PolicyManager::currentUserSid();
    std::remove(fileName);
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"vpnProfiles\": [],\n"
            << "  \"userAssignments\": [{\n"
            << "    \"users\": [\"" << narrowAscii(currentUser) << "\"],\n"
            << "    \"groups\": [],\n"
            << "    \"allowedDevices\": [\n"
            << "      {\"endpoint\": \"HUB-Gr-1.1\", \"nickname\": \"ONE\", \"product\": \"Rutoken\"},\n"
            << "      {\"endpoint\": \"HUB-Gr-1.2\", \"nickname\": \"TWO\", \"product\": \"Rutoken\"}\n"
            << "    ]\n"
            << "  }]\n"
            << "}\n";
    }

    ParsedDevice first{ L"HUB-Gr-1.1", L"ONE", L"Rutoken", L"NO ONE" };
    ParsedDevice second{ L"HUB-Gr-1.2", L"TWO", L"Rutoken", L"NO ONE" };
    VpnProfile profile;
    profile.id = L"windows-user:VPN Test";
    profile.name = L"VPN Test";
    profile.serverAddress = L"192.0.2.10";

    PolicyManager policy(L"policy-vpn-atomic-test.json");
    const std::wstring revision = policy.saveVpnProfileForDevices(
        profile, { first, second }, currentUser, policy.revision());
    require(!revision.empty(), "Atomic VPN assignment should return the new revision.");

    PolicyManager updated(L"policy-vpn-atomic-test.json");
    VpnProfile resolved;
    require(updated.tryGetVpnProfileForDevice(first, resolved) && resolved.id == profile.id,
        "The first token should receive the VPN profile.");
    require(updated.tryGetVpnProfileForDevice(second, resolved) && resolved.id == profile.id,
        "The second token should receive the VPN profile in the same write.");

    const std::wstring clearedRevision = updated.clearVpnProfileForDevices(
        { first, second }, currentUser, updated.revision());
    PolicyManager cleared(L"policy-vpn-atomic-test.json");
    require(!clearedRevision.empty() && !cleared.tryGetVpnProfileForDevice(first, resolved) &&
        !cleared.tryGetVpnProfileForDevice(second, resolved),
        "Bulk VPN unassignment should clear both token mappings.");
    std::remove(fileName);
}

void testAtomicDifferentVpnMappingsForMultipleDevices() {
    const char* fileName = "policy-vpn-mappings-test.json";
    const std::wstring currentUser = PolicyManager::currentUserSid();
    std::remove(fileName);
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"vpnProfiles\": [],\n"
            << "  \"userAssignments\": [{\n"
            << "    \"users\": [\"" << narrowAscii(currentUser) << "\"],\n"
            << "    \"groups\": [],\n"
            << "    \"allowedDevices\": [\n"
            << "      {\"endpoint\": \"HUB-Gr-2.1\", \"nickname\": \"ALPHA\", \"product\": \"Rutoken\"},\n"
            << "      {\"endpoint\": \"HUB-Gr-2.2\", \"nickname\": \"BETA\", \"product\": \"Rutoken\"}\n"
            << "    ]\n"
            << "  }]\n"
            << "}\n";
    }

    VpnProfile alphaProfile;
    alphaProfile.id = L"windows-user:VPN Alpha";
    alphaProfile.name = L"VPN Alpha";
    VpnProfile betaProfile;
    betaProfile.id = L"windows-user:VPN Beta";
    betaProfile.name = L"VPN Beta";

    DeviceRule alpha;
    alpha.endpoint = L"HUB-Gr-2.1";
    alpha.vpnProfileId = alphaProfile.id;
    DeviceRule beta;
    beta.endpoint = L"HUB-Gr-2.2";
    beta.vpnProfileId = betaProfile.id;

    PolicyManager policy(L"policy-vpn-mappings-test.json");
    const std::wstring revision = policy.saveVpnAssignmentsForDevices(
        { alphaProfile, betaProfile }, { alpha, beta }, currentUser, policy.revision());
    require(!revision.empty(), "Bulk VPN mapping should return the new revision.");

    PolicyManager updated(L"policy-vpn-mappings-test.json");
    VpnProfile resolved;
    ParsedDevice alphaDevice{ L"HUB-Gr-2.1", L"ALPHA", L"Rutoken", L"NO ONE" };
    ParsedDevice betaDevice{ L"HUB-Gr-2.2", L"BETA", L"Rutoken", L"NO ONE" };
    require(updated.tryGetVpnProfileForDevice(alphaDevice, resolved) &&
        resolved.id == alphaProfile.id,
        "Bulk mapping should assign the first VPN to the first token.");
    require(updated.tryGetVpnProfileForDevice(betaDevice, resolved) &&
        resolved.id == betaProfile.id,
        "Bulk mapping should assign the second VPN to the second token.");

    alpha.vpnProfileId.clear();
    updated.saveVpnAssignmentsForDevices(
        updated.vpnProfiles(), { alpha, beta }, currentUser, updated.revision());
    PolicyManager cleared(L"policy-vpn-mappings-test.json");
    require(!cleared.tryGetVpnProfileForDevice(alphaDevice, resolved),
        "Bulk mapping should clear an individual token mapping.");
    require(cleared.tryGetVpnProfileForDevice(betaDevice, resolved) &&
        resolved.id == betaProfile.id,
        "Clearing one bulk mapping should preserve the other token mapping.");
    std::remove(fileName);
}

void testNetworkStateReportParsing() {
    require(VpnManager::isValidPublicIp(L"89.108.64.96") &&
        VpnManager::isValidPublicIp(L"2001:db8::10") &&
        !VpnManager::isValidPublicIp(L"89.108.64.999"),
        "Network policy should accept only valid IPv4 or IPv6 addresses.");
    const char* fileName = "network-state-test.json";
    std::remove(fileName);
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"schemaVersion\": 1,\n"
            << "  \"computerName\": \"WRK-406\",\n"
            << "  \"userName\": \"OSNOVA\\\\a.nikitin\",\n"
            << "  \"publicIp\": \"89.108.64.96\",\n"
            << "  \"activeVpnNames\": [\"Salut\"],\n"
            << "  \"updatedAtFileTime\": \"134000000000000000\"\n"
            << "}\n";
    }

    NetworkStateSnapshot state;
    std::wstring error;
    require(PolicyManager::tryReadNetworkState(L"network-state-test.json", state, &error),
        "A valid network state report should be parsed.");
    require(state.computerName == L"WRK-406" && state.userName == L"OSNOVA\\a.nikitin" &&
        state.publicIp == L"89.108.64.96" && state.activeVpnNames.size() == 1 &&
        state.activeVpnNames[0] == L"Salut" && state.updatedAtFileTime == 134000000000000000ULL,
        "Network state report fields mismatch.");

    {
        std::ofstream stream(fileName, std::ios::binary | std::ios::trunc);
        stream << "{\"publicIp\":\"89.108.64.96\",\"activeVpnNames\":[]}";
    }
    require(!PolicyManager::tryReadNetworkState(L"network-state-test.json", state, &error) && !error.empty(),
        "A network state report without a timestamp must be rejected.");
    std::remove(fileName);
}

void testUnknownVpnMappingFailsClosed() {
    const char* fileName = "policy-vpn-missing-profile-test.json";
    std::remove(fileName);
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"vpnProfiles\": [],\n"
            << "  \"userAssignments\": [{\"users\": [\""
            << narrowAscii(PolicyManager::currentUserSid())
            << "\"], \"groups\": [], \"allowedDevices\": [{\"endpoint\": \"OFFICE-HUB-Gr-1.3\", "
            << "\"nickname\": \"VPN Key\", \"product\": \"Rutoken\", \"vpnProfile\": \"missing\"}]}]\n"
            << "}\n";
    }

    bool rejected = false;
    try {
        PolicyManager policy(L"policy-vpn-missing-profile-test.json");
        ParsedDevice device{ L"OFFICE-HUB-Gr-1.3", L"VPN Key", L"Rutoken", L"NO ONE" };
        VpnProfile profile;
        policy.tryGetVpnProfileForDevice(device, profile);
    }
    catch (const std::exception& error) {
        rejected = std::string(error.what()).find("unknown profile") != std::string::npos;
    }
    require(rejected, "A token mapped to a missing VPN profile must fail closed.");
    std::remove(fileName);
}

void testVpnWatchdogRejectsUnmappedToken() {
    const char* fileName = "policy-vpn-unmapped-watchdog-test.json";
    std::remove(fileName);
    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{\n"
            << "  \"pipeName\": \"dkclient\",\n"
            << "  \"vpnProfiles\": [],\n"
            << "  \"userAssignments\": [{\"users\": [\""
            << narrowAscii(PolicyManager::currentUserSid())
            << "\"], \"groups\": [], \"allowedDevices\": [{\"endpoint\": \"OFFICE-HUB-Gr-1.3\", "
            << "\"nickname\": \"Unmapped Key\", \"product\": \"Rutoken\"}]}]\n"
            << "}\n";
    }

    bool rejected = false;
    try {
        PolicyManager::setConfigPathOverride(L"policy-vpn-unmapped-watchdog-test.json");
        DeviceViewModel device;
        device.endpoint = L"OFFICE-HUB-Gr-1.3";
        device.nickname = L"Unmapped Key";
        device.product = L"Rutoken";
        DeviceAccessService().verifyVpnForDevice(device);
    }
    catch (const std::exception& error) {
        rejected = std::string(error.what()).find("not assigned") != std::string::npos;
    }
    PolicyManager::setConfigPathOverride(L"");
    std::remove(fileName);
    require(rejected, "VPN watchdog must reject an active token without a network mapping.");
}

void testLocalRouteInspection() {
    const size_t routeCount = VpnManager::localPhysicalRouteCount();
    (void)routeCount;
}
}

int main() {
    try {
        removeFirstMatch("usage-sync-test-*");
        testIpcRoundTrip();
        testIpcReadTimeout();
        testIpcRetriesBusyPipe();
        testDeviceInfoErrorKeepsAllowedListEntry();
        testEmptyDeviceCatalogIsTransientError();
        testUseDeviceAllowsSlowUseResponse();
        testUseDeviceFailedResponseIsError();
        testRevokedActiveTokenCanBeStopped();
        testParseList();
        testApplyDeviceInfo();
        testPolicyMatching();
        testUsageParsing();
        testUsageStateStore();
        testUsageSyncOfflinePersistenceAndMetadata();
        testUsageSyncSharedFileUnavailable();
        testUsageSyncCoalescingAndStaleRelease();
        testUsageSyncConcurrentChangesRemainQueued();
        testUsageSyncReconciliationAndInvalidFiles();
        testUsageSyncProductionOwnerValidation();
        testUsageSyncLargeQueueAndEscaping();
        testAuditCsvEscaping();
        testAssignDeviceToUser();
        testRemoveDeviceFromUser();
        testSetDevicesForUser();
        testPolicyPatchPreservesUnseenDevicesAndRejectsStaleRevision();
        testPolicyWriteReportsAccessDenied();
        testInvalidPolicyFileIsNotOverwritten();
        testPolicyUsageStatePath();
        testVpnPolicyRoundTrip();
        testAtomicVpnAssignmentForMultipleDevices();
        testAtomicDifferentVpnMappingsForMultipleDevices();
        testUnknownVpnMappingFailsClosed();
        testVpnWatchdogRejectsUnmappedToken();
        testNetworkStateReportParsing();
        testLocalRouteInspection();
        removeFirstMatch("usage-sync-test-*");
        std::cout << "All DistControl C++ tests passed.\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "Test failed: " << error.what() << "\n";
        return 1;
    }
}
