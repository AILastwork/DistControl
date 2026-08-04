#include "IpcClient.h"

#include <windows.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw std::runtime_error("WideCharToMultiByte failed.");
    }
    std::string result(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr) != size) {
        throw std::runtime_error("WideCharToMultiByte failed.");
    }
    result.resize(static_cast<size_t>(size - 1));
    return result;
}

std::wstring utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        throw std::runtime_error("MultiByteToWideChar failed.");
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

class HandleGuard {
public:
    explicit HandleGuard(HANDLE handle = INVALID_HANDLE_VALUE)
        : handle_(handle) {
    }

    ~HandleGuard() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
            CloseHandle(handle_);
        }
    }

    HANDLE get() const {
        return handle_;
    }

    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;

private:
    HANDLE handle_;
};

std::string win32Message(DWORD error) {
    LPSTR buffer = nullptr;
    const DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer),
        0,
        nullptr);
    std::string text = size && buffer ? std::string(buffer, size) : std::string("Unknown Windows error");
    if (buffer) {
        LocalFree(buffer);
    }
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ' || text.back() == '.')) {
        text.pop_back();
    }
    return text;
}

std::runtime_error win32Error(const char* message) {
    const DWORD error = GetLastError();
    return std::runtime_error(
        std::string(message) + " Win32 error " + std::to_string(error) + ": " + win32Message(error) + ".");
}

DWORD waitForPipeIo(HANDLE pipe, OVERLAPPED& overlapped, DWORD timeoutMs, const char* operationName) {
    const DWORD wait = WaitForSingleObject(overlapped.hEvent, timeoutMs);
    if (wait == WAIT_TIMEOUT) {
        CancelIoEx(pipe, &overlapped);
        WaitForSingleObject(overlapped.hEvent, INFINITE);
        DWORD ignored = 0;
        GetOverlappedResult(pipe, &overlapped, &ignored, FALSE);
        throw std::runtime_error(std::string("DistKontrol pipe ") + operationName + " timed out.");
    }
    if (wait != WAIT_OBJECT_0) {
        throw win32Error("Cannot wait for DistKontrol pipe operation.");
    }

    DWORD transferred = 0;
    if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE)) {
        throw win32Error("DistKontrol pipe operation failed.");
    }
    return transferred;
}

DWORD writePipeWithTimeout(HANDLE pipe, const std::string& request, DWORD timeoutMs) {
    HandleGuard event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.get()) {
        throw win32Error("Cannot create DistKontrol write event.");
    }

    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD written = 0;
    const BOOL ok = WriteFile(
        pipe,
        request.data(),
        static_cast<DWORD>(request.size()),
        &written,
        &overlapped);
    if (ok) {
        return written;
    }

    const DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) {
        throw win32Error("Cannot write command to DistKontrol pipe.");
    }
    return waitForPipeIo(pipe, overlapped, timeoutMs, "write");
}

std::string readPipeWithTimeout(HANDLE pipe, DWORD timeoutMs) {
    std::vector<char> buffer(1024 * 1024);
    HandleGuard event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event.get()) {
        throw win32Error("Cannot create DistKontrol read event.");
    }

    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD read = 0;
    const BOOL ok = ReadFile(
        pipe,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &read,
        &overlapped);
    if (!ok) {
        const DWORD error = GetLastError();
        if (error == ERROR_MORE_DATA) {
            throw std::runtime_error("DistKontrol pipe response is too large.");
        }
        if (error != ERROR_IO_PENDING) {
            throw win32Error("Cannot read response from DistKontrol pipe.");
        }
        read = waitForPipeIo(pipe, overlapped, timeoutMs, "read");
    }

    return std::string(buffer.data(), buffer.data() + read);
}
}

IpcClient::IpcClient(std::wstring pipeName)
    : pipeName_(std::move(pipeName)) {
}

std::wstring IpcClient::issueCommand(const std::wstring& command, unsigned long timeoutMs) const {
    const std::wstring pipePath = L"\\\\.\\pipe\\" + pipeName_;
    if (!WaitNamedPipeW(pipePath.c_str(), timeoutMs)) {
        throw win32Error("DistKontrol pipe is not available.");
    }

    HANDLE pipe = CreateFileW(
        pipePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        nullptr);

    if (pipe == INVALID_HANDLE_VALUE) {
        throw win32Error("Cannot open DistKontrol pipe.");
    }
    HandleGuard pipeGuard(pipe);

    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
        throw win32Error("Cannot configure DistKontrol pipe message mode.");
    }

    const std::string request = wideToUtf8(command);
    const DWORD written = writePipeWithTimeout(pipe, request, timeoutMs);
    if (written != request.size()) {
        throw std::runtime_error("Incomplete DistKontrol pipe write.");
    }

    return utf8ToWide(readPipeWithTimeout(pipe, timeoutMs));
}
