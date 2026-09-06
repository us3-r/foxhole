#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define RUN_KEY_PATH L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_VALUE_NAME L"FoxholeTestToDownloadExe"

static BOOL get_install_path(wchar_t *path, size_t path_length) {
    wchar_t local_app_data[MAX_PATH];
    wchar_t install_directory[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(
        L"LOCALAPPDATA",
        local_app_data,
        ARRAYSIZE(local_app_data)
    );

    if (length == 0 || length >= ARRAYSIZE(local_app_data)) {
        fwprintf(stderr, L"LOCALAPPDATA is unavailable.\n");
        return FALSE;
    }
    if (swprintf_s(
            install_directory,
            ARRAYSIZE(install_directory),
            L"%ls\\FoxholeTests",
            local_app_data
        ) < 0 ||
        swprintf_s(
            path,
            path_length,
            L"%ls\\test_toDownloadExe.exe",
            install_directory
        ) < 0) {
        fwprintf(stderr, L"Startup-test path is too long.\n");
        return FALSE;
    }

    if (!CreateDirectoryW(install_directory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        fwprintf(stderr, L"Could not create %ls (error %lu)\n", install_directory, GetLastError());
        return FALSE;
    }
    return TRUE;
}

static BOOL install_startup_entry(const wchar_t *installed_path) {
    HKEY run_key = NULL;
    DWORD disposition = 0;
    wchar_t command_line[(MAX_PATH * 2) + 32];
    LSTATUS status;

    if (swprintf_s(
            command_line,
            ARRAYSIZE(command_line),
            L"\"%ls\" --startup",
            installed_path
        ) < 0) {
        fwprintf(stderr, L"Startup command is too long.\n");
        return FALSE;
    }

    status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        RUN_KEY_PATH,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        NULL,
        &run_key,
        &disposition
    );
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr, L"Could not open the per-user Run key (error %ld)\n", status);
        return FALSE;
    }

    status = RegSetValueExW(
        run_key,
        RUN_VALUE_NAME,
        0,
        REG_SZ,
        (const BYTE *)command_line,
        (DWORD)((wcslen(command_line) + 1) * sizeof(wchar_t))
    );
    RegCloseKey(run_key);
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr, L"Could not create the startup entry (error %ld)\n", status);
        return FALSE;
    }

    wprintf(L"Installed per-user startup entry: %ls\n", RUN_VALUE_NAME);
    return TRUE;
}

static BOOL remove_startup_entry(void) {
    HKEY run_key = NULL;
    LSTATUS status = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        RUN_KEY_PATH,
        0,
        KEY_SET_VALUE,
        &run_key
    );

    if (status == ERROR_FILE_NOT_FOUND) {
        wprintf(L"Startup entry was not present.\n");
        return TRUE;
    }
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr, L"Could not open the per-user Run key (error %ld)\n", status);
        return FALSE;
    }

    status = RegDeleteValueW(run_key, RUN_VALUE_NAME);
    RegCloseKey(run_key);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        fwprintf(stderr, L"Could not remove the startup entry (error %ld)\n", status);
        return FALSE;
    }

    wprintf(L"Removed per-user startup entry: %ls\n", RUN_VALUE_NAME);
    return TRUE;
}

static BOOL launch_calculator(void) {
    wchar_t system_directory[MAX_PATH];
    wchar_t calculator_path[MAX_PATH];
    wchar_t command_line[MAX_PATH + 3];
    STARTUPINFOW startup_info;
    PROCESS_INFORMATION process_info;
    UINT system_directory_length;

    system_directory_length = GetSystemDirectoryW(system_directory, ARRAYSIZE(system_directory));
    if (system_directory_length == 0 || system_directory_length >= ARRAYSIZE(system_directory) ||
        swprintf_s(
            calculator_path,
            ARRAYSIZE(calculator_path),
            L"%ls\\calc.exe",
            system_directory
        ) < 0 ||
        swprintf_s(command_line, ARRAYSIZE(command_line), L"\"%ls\"", calculator_path) < 0) {
        fwprintf(stderr, L"Could not construct the calculator path.\n");
        return FALSE;
    }

    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    ZeroMemory(&process_info, sizeof(process_info));

    if (!CreateProcessW(
            calculator_path,
            command_line,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &startup_info,
            &process_info
        )) {
        fwprintf(stderr, L"Could not start Calculator (error %lu)\n", GetLastError());
        return FALSE;
    }

    wprintf(L"Started Calculator with PID %lu.\n", process_info.dwProcessId);
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    return TRUE;
}

int wmain(int argc, wchar_t **argv) {
    wchar_t current_path[MAX_PATH];
    wchar_t installed_path[MAX_PATH];
    DWORD current_path_length;

    if (argc > 1 && _wcsicmp(argv[1], L"--remove-startup") == 0) {
        return remove_startup_entry() ? 0 : 2;
    }

    current_path_length = GetModuleFileNameW(NULL, current_path, ARRAYSIZE(current_path));
    if (current_path_length == 0 || current_path_length >= ARRAYSIZE(current_path)) {
        fwprintf(stderr, L"Could not determine the executable path (error %lu)\n", GetLastError());
        return 3;
    }
    if (!get_install_path(installed_path, ARRAYSIZE(installed_path))) {
        return 4;
    }

    if (_wcsicmp(current_path, installed_path) != 0) {
        if (!CopyFileW(current_path, installed_path, FALSE)) {
            fwprintf(
                stderr,
                L"Could not copy the test to %ls (error %lu)\n",
                installed_path,
                GetLastError()
            );
            return 5;
        }
        wprintf(L"Copied startup test to %ls\n", installed_path);
    }

    if (!install_startup_entry(installed_path)) {
        return 6;
    }
    if (!launch_calculator()) {
        return 7;
    }

    return 0;
}
