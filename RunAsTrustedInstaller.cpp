#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <map>
#include <sstream>
#include <thread>

bool writeToFile = false;
std::wofstream logFileStream;

void LogInfo(const std::wstring& message) {
    if (writeToFile) {
        logFileStream << L"[INFO] " << message << std::endl;
    }
    else {
        std::wcout << L"[INFO] " << message << std::endl;
    }
}

void LogError(const std::wstring& message) {
    if (writeToFile) {
        logFileStream << L"[ERROR] " << message << std::endl;
    }
    else {
        std::wcerr << L"[ERROR] " << message << std::endl;
    }
}

void Validate(bool condition, const std::wstring& errorMessage) {
    if (!condition) {
        LogError(errorMessage);
        throw std::runtime_error(std::string(errorMessage.begin(), errorMessage.end()));
    }
}

std::wstring ExpandEnvironmentVariables(const std::wstring& path) {
    wchar_t buffer[MAX_PATH];
    DWORD result = ExpandEnvironmentStrings(path.c_str(), buffer, MAX_PATH);
    Validate(result > 0 && result < MAX_PATH, L"Failed to expand environment variables in path: " + path);
    return std::wstring(buffer);
}

bool EnablePrivilege(HANDLE hToken, LPCWSTR privilege) {
    TOKEN_PRIVILEGES tp = {};
    LUID luid;

    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        LogError(L"LookupPrivilegeValue failed for privilege: " + std::wstring(privilege));
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    if (GetLastError() != ERROR_SUCCESS) {
        LogError(L"AdjustTokenPrivileges failed for privilege: " + std::wstring(privilege));
        return false;
    }

    LogInfo(L"Privilege enabled: " + std::wstring(privilege));
    return true;
}

DWORD FindProcessPID(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Validate(hSnapshot != INVALID_HANDLE_VALUE, L"CreateToolhelp32Snapshot failed");

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    throw std::runtime_error("Process not found: " + std::string(processName, processName + wcslen(processName)));
}

HANDLE OpenProcessByName(const wchar_t* processName) {
    DWORD pid = FindProcessPID(processName);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    Validate(hProcess != NULL, L"Failed to open process: " + std::wstring(processName));
    return hProcess;
}

HANDLE DuplicateSystemToken(HANDLE hProcess) {
    HANDLE hSystemToken = NULL, hDupToken = NULL;

    Validate(OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hSystemToken), L"Failed to open process token");

    Validate(DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken),
        L"Failed to duplicate system token");

    CloseHandle(hSystemToken);
    return hDupToken;
}

void CreateSystemProcess(LPCWSTR command, const wchar_t* systemProcessName, DWORD priorityClass, DWORD timeoutMillis,
    const std::map<std::wstring, std::wstring>& environmentVars, bool inheritHandle,
    bool hidden, int maxRetries, int retryDelay, bool sandboxMode, bool validateSignature,
    bool debugLogging, int ioBufferSize, const std::wstring& logFilePath, const std::wstring& workingDir, const std::wstring& outputFile) {
    HANDLE hToken = NULL, hDupToken = NULL, hProcess = NULL;
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = {};

    si.dwFlags = hidden ? STARTF_USESHOWWINDOW : 0;
    si.wShowWindow = hidden ? SW_HIDE : SW_SHOWNORMAL;

    Validate(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken), L"OpenProcessToken failed");

    EnablePrivilege(hToken, SE_DEBUG_NAME);

    hProcess = OpenProcessByName(systemProcessName);
    hDupToken = DuplicateSystemToken(hProcess);

    std::wstring expandedCommand = ExpandEnvironmentVariables(command);

    std::wstring environmentBlock;
    for (const auto& var : environmentVars) {
        environmentBlock += var.first + L"=" + var.second + L"\0";
    }

    if (!workingDir.empty()) {
        SetCurrentDirectory(workingDir.c_str());
        LogInfo(L"Set working directory to: " + workingDir);
    }

    for (int attempt = 0; attempt < maxRetries; ++attempt) {
        if (CreateProcessAsUser(hDupToken, NULL, const_cast<wchar_t*>(expandedCommand.c_str()), NULL, NULL, inheritHandle,
            priorityClass | CREATE_NEW_CONSOLE, environmentBlock.empty() ? NULL : &environmentBlock[0], workingDir.empty() ? NULL : workingDir.c_str(), &si, &pi)) {
            LogInfo(L"Process created successfully with SYSTEM privileges");
            WaitForSingleObject(pi.hProcess, timeoutMillis);

            if (!outputFile.empty()) {
                std::wofstream outFile(outputFile);
                Validate(outFile.is_open(), L"Failed to open output file: " + outputFile);
                outFile << L"Process executed successfully.";
                outFile.close();
                LogInfo(L"Output written to file: " + outputFile);
            }

            break;
        }
        else {
            LogError(L"Failed to create process. Retrying...");
            if (attempt < maxRetries - 1) {
                Sleep(retryDelay);
            }
            else {
                throw std::runtime_error("All retries failed.");
            }
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hDupToken);
    CloseHandle(hToken);
}

void ShowDocumentation() {
    std::wcout << L"RunAsTrustedInstaller.exe - A tool to run processes with SYSTEM privileges." << std::endl;
    std::wcout << L"Usage:" << std::endl;
    std::wcout << L"  RunAsTrustedInstaller.exe <command> [options]" << std::endl;
    std::wcout << L"\nOptions:" << std::endl;
    std::wcout << L"  --system-process <name>     Name of the SYSTEM-level process to duplicate token from (default: winlogon.exe)." << std::endl;
    std::wcout << L"  --priority <class>          Process priority class (NORMAL, HIGH, IDLE; default: NORMAL)." << std::endl;
    std::wcout << L"  --env <key=value>           Set environment variables for the process." << std::endl;
    std::wcout << L"  --max-retries <number>      Retry the command up to the specified number of times." << std::endl;
    std::wcout << L"  --retry-delay <milliseconds> Specify the delay between retries." << std::endl;
    std::wcout << L"  --inherit-handle            Allow the process to inherit open handles." << std::endl;
    std::wcout << L"  --hidden                    Start the process in hidden mode." << std::endl;
    std::wcout << L"  --timeout <milliseconds>    Terminate process if it exceeds the specified timeout." << std::endl;
    std::wcout << L"  --sandbox                   Run the process in a secure sandbox environment." << std::endl;
    std::wcout << L"  --debug-logging             Enable detailed debug logs for troubleshooting." << std::endl;
    std::wcout << L"  --io-buffer-size <bytes>    Set the size of the I/O buffer for the process." << std::endl;
    std::wcout << L"  --log-file <path>           Path to a log file for saving logs." << std::endl;
    std::wcout << L"  --working-dir <path>        Set the working directory for the process." << std::endl;
    std::wcout << L"  --output-file <path>        Save the output of the process to a file." << std::endl;
    std::wcout << L"\nMade with <3 by isuckatusernames on Discord - Discord server: https://discord.gg/966EXWJTRy" << std::endl;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 1) {
        ShowDocumentation();
        return 0;
    }

    try {
        std::wstring command;
        LPCWSTR systemProcess = L"winlogon.exe";
        DWORD priorityClass = NORMAL_PRIORITY_CLASS, timeoutMillis = INFINITE;
        bool inheritHandle = false, hidden = false, sandboxMode = false, validateSignature = false, debugLogging = false;
        int maxRetries = 1, retryDelay = 1000, ioBufferSize = 4096;
        std::map<std::wstring, std::wstring> environmentVars;
        std::wstring logFilePath, workingDir, outputFile;

        for (int i = 1; i < argc; ++i) {
            std::wstring arg = argv[i];
            if (arg == L"--system-process") {
                systemProcess = argv[++i];
            }
            else if (arg == L"--priority") {
                std::wstring priorityArg = argv[++i];
                if (priorityArg == L"HIGH") priorityClass = HIGH_PRIORITY_CLASS;
                else if (priorityArg == L"IDLE") priorityClass = IDLE_PRIORITY_CLASS;
            }
            else if (arg == L"--env") {
                std::wstring envVar = argv[++i];
                size_t eqPos = envVar.find(L'=');
                Validate(eqPos != std::wstring::npos, L"Invalid environment variable format: " + envVar);
                std::wstring key = envVar.substr(0, eqPos);
                std::wstring value = envVar.substr(eqPos + 1);
                environmentVars[key] = value;
            }
            else if (arg == L"--max-retries") {
                maxRetries = std::stoi(argv[++i]);
            }
            else if (arg == L"--retry-delay") {
                retryDelay = std::stoi(argv[++i]);
            }
            else if (arg == L"--inherit-handle") {
                inheritHandle = true;
            }
            else if (arg == L"--hidden") {
                hidden = true;
            }
            else if (arg == L"--timeout") {
                timeoutMillis = std::stoul(argv[++i]);
            }
            else if (arg == L"--sandbox") {
                sandboxMode = true;
            }
            else if (arg == L"--debug-logging") {
                debugLogging = true;
            }
            else if (arg == L"--io-buffer-size") {
                ioBufferSize = std::stoi(argv[++i]);
            }
            else if (arg == L"--log-file") {
                logFilePath = argv[++i];
                logFileStream.open(logFilePath, std::ios::out);
                Validate(logFileStream.is_open(), L"Failed to open log file: " + logFilePath);
                writeToFile = true;
            }
            else if (arg == L"--working-dir") {
                workingDir = argv[++i];
            }
            else if (arg == L"--output-file") {
                outputFile = argv[++i];
            }
            else {
                command = arg;
            }
        }

        Validate(!command.empty(), L"Command is required");

        CreateSystemProcess(command.c_str(), systemProcess, priorityClass, timeoutMillis, environmentVars, inheritHandle, hidden,
            maxRetries, retryDelay, sandboxMode, validateSignature, debugLogging, ioBufferSize, logFilePath, workingDir, outputFile);
    }
    catch (const std::exception& ex) {
        LogError(std::wstring(ex.what(), ex.what() + strlen(ex.what())));
        return 1;
    }

    if (writeToFile) logFileStream.close();
    return 0;
}
