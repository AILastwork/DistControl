#include "AuditLogger.h"
#include "DeviceAccessService.h"
#include "DeviceParser.h"
#include "IpcClient.h"
#include "PolicyManager.h"
#include "UsageStateStore.h"

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
    return L"DiskControl.Tests." + std::to_wstring(GetCurrentProcessId()) + L"." + suffix;
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
            << "  \"userAssignments\": [\n"
            << "    {\n"
            << "      \"users\": [\"" << narrowAscii(PolicyManager::currentUserSid()) << "\"],\n"
            << "      \"groups\": [],\n"
            << "      \"allowedDevices\": [\n"
            << "        { \"endpoint\": \"OFFICE-HUB-Gr-1.3\", \"nickname\": \"Slow Key\", \"product\": \"Rutoken\" }\n"
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
        for (int requestIndex = 0; requestIndex < 2; ++requestIndex) {
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
                response = "NICKNAME: Slow Key\r\nPRODUCT: Rutoken\r\nIN USE BY: NO ONE\r\n";
            }
            else if (command == "USE,OFFICE-HUB-Gr-1.3") {
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
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
        DeviceAccessService service;
        DeviceViewModel device;
        device.endpoint = L"OFFICE-HUB-Gr-1.3";
        device.nickname = L"Slow Key";
        device.product = L"Rutoken";
        device.inUseBy = L"NO ONE";
        device.allowed = true;

        require(service.useDevice(device) == L"OK", "Slow USE response should be accepted.");
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
    require(commands.size() == 2 && commands[0] == "DEVICE INFO,OFFICE-HUB-Gr-1.3" &&
        commands[1] == "USE,OFFICE-HUB-Gr-1.3",
        "Slow USE test should issue DEVICE INFO before USE.");

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
            << "  \"userAssignments\": [\n"
            << "    {\n"
            << "      \"users\": [\"" << narrowAscii(PolicyManager::currentUserSid()) << "\"],\n"
            << "      \"groups\": [],\n"
            << "      \"allowedDevices\": [\n"
            << "        { \"endpoint\": \"OFFICE-HUB-Gr-1.3\", \"nickname\": \"Failed Key\", \"product\": \"Rutoken\" }\n"
            << "      ]\n"
            << "    }\n"
            << "  ]\n"
            << "}\n";
    }

    HANDLE pipe = createTestPipe(pipeName);
    require(pipe != INVALID_HANDLE_VALUE, "Failed USE test named pipe could not be created.");

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
            std::string response;
            if (command == "DEVICE INFO,OFFICE-HUB-Gr-1.3") {
                response = "NICKNAME: Failed Key\r\nPRODUCT: Rutoken\r\nIN USE BY: NO ONE\r\n";
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
        for (int requestIndex = 0; requestIndex < 4; ++requestIndex) {
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
                response = "NICKNAME: Revoked Key\r\nPRODUCT: Rutoken\r\nIN USE BY: YOU\r\n";
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
    require(commands.size() == 4 && commands.back() == "STOP USING,OFFICE-HUB-Gr-1.3",
        "Revoked token cleanup must send STOP USING after ownership verification.");
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

void testAuditCsvEscaping() {
    require(AuditLogger::csvEscapeForTest(L"plain") == "plain", "Plain CSV value should not be quoted.");
    require(AuditLogger::csvEscapeForTest(L"a,b") == "\"a,b\"", "Comma CSV value should be quoted.");
    require(AuditLogger::csvEscapeForTest(L"a\"b") == "\"a\"\"b\"", "Quote CSV value should be escaped.");
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

void testRepairInvalidPolicyFile() {
    const char* fileName = "policy-invalid-test.json";
    std::remove(fileName);
    removeFirstMatch("policy-invalid-test.json.invalid-*.bak");

    {
        std::ofstream stream(fileName, std::ios::binary);
        stream << "{ broken json";
    }

    const bool repaired = PolicyManager::ensureEditableConfig(L"policy-invalid-test.json");
    require(repaired, "Invalid policy file should be repaired.");

    {
        std::ifstream stream(fileName, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        require(text.find("\"pipeName\"") != std::string::npos, "Repaired policy should contain pipeName.");
        require(text.find("\"userAssignments\"") != std::string::npos, "Repaired policy should contain userAssignments.");
        require(text.find("[]") != std::string::npos, "Repaired policy should contain empty assignments.");
    }

    require(removeFirstMatch("policy-invalid-test.json.invalid-*.bak"), "Invalid policy backup should be created.");
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
}

int main() {
    try {
        testIpcRoundTrip();
        testIpcReadTimeout();
        testUseDeviceAllowsSlowUseResponse();
        testUseDeviceFailedResponseIsError();
        testRevokedActiveTokenCanBeStopped();
        testParseList();
        testApplyDeviceInfo();
        testPolicyMatching();
        testUsageParsing();
        testUsageStateStore();
        testAuditCsvEscaping();
        testAssignDeviceToUser();
        testRemoveDeviceFromUser();
        testSetDevicesForUser();
        testPolicyWriteReportsAccessDenied();
        testRepairInvalidPolicyFile();
        testPolicyUsageStatePath();
        std::cout << "All DiskControl C++ tests passed.\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "Test failed: " << error.what() << "\n";
        return 1;
    }
}
