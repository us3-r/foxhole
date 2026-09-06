#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <wchar.h>

#define URL_BUFFER_LENGTH 2048
#define DOWNLOAD_LIMIT (256ULL * 1024ULL * 1024ULL)
#define CHILD_TIMEOUT_MS 15000

typedef struct HttpRequest {
    HINTERNET session;
    HINTERNET connection;
    HINTERNET request;
} HttpRequest;

static void close_http_request(HttpRequest *handles) {
    if (handles->request != NULL) {
        WinHttpCloseHandle(handles->request);
    }
    if (handles->connection != NULL) {
        WinHttpCloseHandle(handles->connection);
    }
    if (handles->session != NULL) {
        WinHttpCloseHandle(handles->session);
    }
    ZeroMemory(handles, sizeof(*handles));
}

static BOOL open_get_request(const wchar_t *url, HttpRequest *handles, DWORD *status_code) {
    URL_COMPONENTS components;
    wchar_t host_name[256];
    wchar_t url_path[URL_BUFFER_LENGTH];
    DWORD request_flags = 0;
    DWORD status_size = sizeof(*status_code);

    ZeroMemory(handles, sizeof(*handles));
    ZeroMemory(&components, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.lpszHostName = host_name;
    components.dwHostNameLength = ARRAYSIZE(host_name);
    components.lpszUrlPath = url_path;
    components.dwUrlPathLength = ARRAYSIZE(url_path);

    if (!WinHttpCrackUrl(url, 0, 0, &components)) {
        fwprintf(stderr, L"WinHttpCrackUrl failed for %ls (error %lu)\n", url, GetLastError());
        return FALSE;
    }

    if (components.nScheme == INTERNET_SCHEME_HTTPS) {
        request_flags |= WINHTTP_FLAG_SECURE;
    } else if (components.nScheme != INTERNET_SCHEME_HTTP) {
        fwprintf(stderr, L"Only HTTP and HTTPS server URLs are supported.\n");
        return FALSE;
    }

    handles->session = WinHttpOpen(
        L"FoxholeServerDownloadTest/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (handles->session == NULL) {
        fwprintf(stderr, L"WinHttpOpen failed (error %lu)\n", GetLastError());
        return FALSE;
    }

    WinHttpSetTimeouts(handles->session, 5000, 5000, 10000, 10000);
    handles->connection = WinHttpConnect(
        handles->session,
        host_name,
        components.nPort,
        0
    );
    if (handles->connection == NULL) {
        fwprintf(stderr, L"WinHttpConnect failed (error %lu)\n", GetLastError());
        close_http_request(handles);
        return FALSE;
    }

    handles->request = WinHttpOpenRequest(
        handles->connection,
        L"GET",
        url_path[0] != L'\0' ? url_path : L"/",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        request_flags
    );
    if (handles->request == NULL) {
        fwprintf(stderr, L"WinHttpOpenRequest failed (error %lu)\n", GetLastError());
        close_http_request(handles);
        return FALSE;
    }

    if (!WinHttpSendRequest(
            handles->request,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0
        ) || !WinHttpReceiveResponse(handles->request, NULL)) {
        fwprintf(stderr, L"HTTP request failed (error %lu)\n", GetLastError());
        close_http_request(handles);
        return FALSE;
    }

    if (!WinHttpQueryHeaders(
            handles->request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            status_code,
            &status_size,
            WINHTTP_NO_HEADER_INDEX
        )) {
        fwprintf(stderr, L"Could not read HTTP status (error %lu)\n", GetLastError());
        close_http_request(handles);
        return FALSE;
    }

    return TRUE;
}

static BOOL check_server_health(const wchar_t *health_url) {
    HttpRequest handles;
    DWORD status_code = 0;

    if (!open_get_request(health_url, &handles, &status_code)) {
        return FALSE;
    }
    close_http_request(&handles);

    if (status_code != 200) {
        fwprintf(stderr, L"Health endpoint returned HTTP %lu\n", status_code);
        return FALSE;
    }

    wprintf(L"Server health check passed.\n");
    return TRUE;
}

static BOOL download_file(const wchar_t *url, const wchar_t *destination) {
    HttpRequest handles;
    DWORD status_code = 0;
    HANDLE output = INVALID_HANDLE_VALUE;
    wchar_t partial_path[MAX_PATH];
    BYTE buffer[64 * 1024];
    ULONGLONG total_bytes = 0;
    BOOL success = FALSE;

    if (swprintf_s(partial_path, ARRAYSIZE(partial_path), L"%ls.part", destination) < 0) {
        fwprintf(stderr, L"Download path is too long.\n");
        return FALSE;
    }

    if (!open_get_request(url, &handles, &status_code)) {
        return FALSE;
    }
    if (status_code != 200) {
        fwprintf(stderr, L"Download endpoint returned HTTP %lu\n", status_code);
        close_http_request(&handles);
        return FALSE;
    }

    output = CreateFileW(
        partial_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (output == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Could not create %ls (error %lu)\n", partial_path, GetLastError());
        close_http_request(&handles);
        return FALSE;
    }

    for (;;) {
        DWORD bytes_read = 0;
        DWORD bytes_written = 0;

        if (!WinHttpReadData(handles.request, buffer, sizeof(buffer), &bytes_read)) {
            fwprintf(stderr, L"Download read failed (error %lu)\n", GetLastError());
            break;
        }
        if (bytes_read == 0) {
            success = TRUE;
            break;
        }

        total_bytes += bytes_read;
        if (total_bytes > DOWNLOAD_LIMIT) {
            fwprintf(stderr, L"Download exceeded the 256 MiB test limit.\n");
            break;
        }
        if (!WriteFile(output, buffer, bytes_read, &bytes_written, NULL) ||
            bytes_written != bytes_read) {
            fwprintf(stderr, L"Could not write downloaded data (error %lu)\n", GetLastError());
            success = FALSE;
            break;
        }
    }

    if (success && !FlushFileBuffers(output)) {
        fwprintf(stderr, L"Could not flush downloaded data (error %lu)\n", GetLastError());
        success = FALSE;
    }
    CloseHandle(output);
    close_http_request(&handles);

    if (!success) {
        DeleteFileW(partial_path);
        return FALSE;
    }
    if (!MoveFileExW(partial_path, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fwprintf(stderr, L"Could not finalize the download (error %lu)\n", GetLastError());
        DeleteFileW(partial_path);
        return FALSE;
    }

    wprintf(L"Downloaded %llu bytes to %ls\n", total_bytes, destination);
    return TRUE;
}

static BOOL launch_download(const wchar_t *path) {
    STARTUPINFOW startup_info;
    PROCESS_INFORMATION process_info;
    wchar_t command_line[MAX_PATH + 3];
    DWORD wait_result;
    DWORD child_exit_code = STILL_ACTIVE;

    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    ZeroMemory(&process_info, sizeof(process_info));

    if (swprintf_s(command_line, ARRAYSIZE(command_line), L"\"%ls\"", path) < 0) {
        fwprintf(stderr, L"Launch path is too long.\n");
        return FALSE;
    }

    if (!CreateProcessW(
            path,
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
        fwprintf(stderr, L"CreateProcess failed for %ls (error %lu)\n", path, GetLastError());
        return FALSE;
    }

    wprintf(L"Started downloaded process with PID %lu.\n", process_info.dwProcessId);
    CloseHandle(process_info.hThread);

    wait_result = WaitForSingleObject(process_info.hProcess, CHILD_TIMEOUT_MS);
    if (wait_result == WAIT_TIMEOUT) {
        fwprintf(stderr, L"Downloaded process exceeded the %lu ms test limit.\n", CHILD_TIMEOUT_MS);
        TerminateProcess(process_info.hProcess, 124);
        WaitForSingleObject(process_info.hProcess, 5000);
        CloseHandle(process_info.hProcess);
        return FALSE;
    }
    if (wait_result != WAIT_OBJECT_0) {
        fwprintf(stderr, L"Could not wait for the downloaded process (error %lu)\n", GetLastError());
        CloseHandle(process_info.hProcess);
        return FALSE;
    }
    if (!GetExitCodeProcess(process_info.hProcess, &child_exit_code)) {
        fwprintf(stderr, L"Could not read the downloaded process exit code (error %lu)\n", GetLastError());
        CloseHandle(process_info.hProcess);
        return FALSE;
    }
    CloseHandle(process_info.hProcess);

    if (child_exit_code != 0) {
        fwprintf(stderr, L"Downloaded process exited with code %lu.\n", child_exit_code);
        return FALSE;
    }
    wprintf(L"Downloaded process completed successfully.\n");
    return TRUE;
}

int wmain(int argc, wchar_t **argv) {
    const wchar_t *server_base = argc > 1 ? argv[1] : L"http://127.0.0.1:8080";
    wchar_t normalized_base[URL_BUFFER_LENGTH];
    wchar_t health_url[URL_BUFFER_LENGTH];
    wchar_t download_url[URL_BUFFER_LENGTH];
    wchar_t temporary_root[MAX_PATH];
    wchar_t test_directory[MAX_PATH];
    wchar_t destination[MAX_PATH];
    size_t base_length;
    DWORD temporary_root_length;

    if (wcsncpy_s(normalized_base, ARRAYSIZE(normalized_base), server_base, _TRUNCATE) != 0) {
        fwprintf(stderr, L"Server URL is too long.\n");
        return 2;
    }
    base_length = wcslen(normalized_base);
    while (base_length > 0 && normalized_base[base_length - 1] == L'/') {
        normalized_base[--base_length] = L'\0';
    }

    if (swprintf_s(health_url, ARRAYSIZE(health_url), L"%ls/health", normalized_base) < 0 ||
        swprintf_s(
            download_url,
            ARRAYSIZE(download_url),
            L"%ls/files/test_toDownloadExe.exe",
            normalized_base
        ) < 0) {
        fwprintf(stderr, L"Constructed URL is too long.\n");
        return 2;
    }

    if (!check_server_health(health_url)) {
        return 3;
    }

    temporary_root_length = GetTempPathW(ARRAYSIZE(temporary_root), temporary_root);
    if (temporary_root_length == 0 || temporary_root_length >= ARRAYSIZE(temporary_root) ||
        swprintf_s(test_directory, ARRAYSIZE(test_directory), L"%lsFoxholeTests", temporary_root) < 0 ||
        swprintf_s(
            destination,
            ARRAYSIZE(destination),
            L"%ls\\test_toDownloadExe.exe",
            test_directory
        ) < 0) {
        fwprintf(stderr, L"Could not construct the temporary download path.\n");
        return 4;
    }

    if (!CreateDirectoryW(test_directory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        fwprintf(stderr, L"Could not create %ls (error %lu)\n", test_directory, GetLastError());
        return 4;
    }
    if (!download_file(download_url, destination)) {
        return 5;
    }
    if (!launch_download(destination)) {
        return 6;
    }

    return 0;
}
