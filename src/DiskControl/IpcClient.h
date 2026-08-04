#pragma once

#include <string>

class IpcClient {
public:
    explicit IpcClient(std::wstring pipeName = L"dkclient");

    std::wstring issueCommand(const std::wstring& command, unsigned long timeoutMs = 3000) const;

private:
    std::wstring pipeName_;
};
