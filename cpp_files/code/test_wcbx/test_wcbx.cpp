#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#pragma comment(lib, "advapi32.lib")

namespace {
std::wstring join(const std::wstring& root, const std::wstring& name) { return root + L"\\" + name; }
std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0'); WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), &result[0], size, nullptr, nullptr); return result;
}
class Logger {
public:
    explicit Logger(const std::wstring& path) : file_(path, std::ios::out | std::ios::trunc) {}
    bool good() const { return file_.good(); }
    void line(const std::string& value) { std::cout << value << std::endl; if (file_.good()) { file_ << value << '\n'; file_.flush(); } OutputDebugStringA((value + "\n").c_str()); }
private: std::ofstream file_;
};
bool write_text(const std::wstring& path, const std::string& text) { std::ofstream file(path, std::ios::out | std::ios::trunc | std::ios::binary); if (!file.good()) return false; file << text; return file.good(); }
int run_process(const std::wstring& executable, const std::wstring& arguments, Logger& log) {
    std::wstring command = L"\"" + executable + L"\"" + (arguments.empty() ? L"" : L" " + arguments); std::vector<wchar_t> buffer(command.begin(), command.end()); buffer.push_back(L'\0');
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) { log.line("process_failed command=" + utf8(command) + " win32_error=" + std::to_string(GetLastError())); return -1; }
    WaitForSingleObject(process.hProcess, INFINITE); DWORD code = 1; GetExitCodeProcess(process.hProcess, &code); CloseHandle(process.hThread); CloseHandle(process.hProcess); log.line("process_result exit_code=" + std::to_string(code) + " command=" + utf8(command)); return static_cast<int>(code);
}
std::wstring system_tool(const wchar_t* name) { wchar_t path[MAX_PATH] = {}; GetSystemDirectoryW(path, ARRAYSIZE(path)); return join(path, name); }
void run_file_probes(const std::wstring& root, Logger& log) {
    log.line("[1/7] files and folder probe"); CreateDirectoryW(join(root, L"FoxholeDemoFolders").c_str(), nullptr);
    const std::wstring created = join(root, L"created.txt"), renamed = join(root, L"renamed.txt"), copied = join(root, L"copied.txt"); write_text(created, "Foxhole disposable file telemetry canary\nsecond write\n"); MoveFileExW(created.c_str(), renamed.c_str(), MOVEFILE_REPLACE_EXISTING); CopyFileW(renamed.c_str(), copied.c_str(), FALSE); DeleteFileW(copied.c_str()); DeleteFileW(renamed.c_str());
    log.line("[2/7] NTFS alternate data stream probe"); const std::wstring carrier = join(root, L"ads-carrier.txt"); write_text(carrier, "Visible Foxhole ADS carrier\n"); write_text(carrier + L":foxhole-demo", "Disposable alternate stream marker\n");
}
void run_network_probes(Logger& log) {
    log.line("[3/7] native network probes"); const std::wstring system = system_tool(L""); const std::wstring tools[] = {L"ipconfig.exe", L"route.exe", L"ping.exe", L"nslookup.exe", L"curl.exe", L"netstat.exe"}; const std::wstring args[] = {L"/all", L"print", L"-n 2 -w 1000 127.0.0.1", L"example.com", L"--noproxy * --connect-timeout 3 --max-time 5 --silent --show-error --head http://example.com/", L"-ano"}; for (int i = 0; i < 6; ++i) run_process(join(system, tools[i]), args[i], log);
}
void run_process_tree(const std::wstring& root, Logger& log) {
    for (int i = 1; i <= 6; ++i) { std::ostringstream text; text << "@echo off\necho [process-tree] generation=" << i << "\n"; if (i < 6) text << "call \"" << utf8(join(root, L"process-stage-" + std::to_wstring(i + 1) + L".cmd")) << "\"\n"; else text << "exit /b 0\n"; write_text(join(root, L"process-stage-" + std::to_wstring(i) + L".cmd"), text.str()); }
    log.line("[4/7] process tree"); run_process(system_tool(L"cmd.exe"), L"/d /c call \"" + join(root, L"process-stage-1.cmd") + L"\"", log);
}
void run_runonce_probe(Logger& log) {
    log.line("[5/7] RunOnce probe"); HKEY key = nullptr; if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) { log.line("runonce=unavailable"); return; }
    const wchar_t name[] = L"FoxholeDemoOneShot_test_wcbx", data[] = L"cmd.exe /d /c exit /b 0"; const LONG result = RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(data), sizeof(data)); RegDeleteValueW(key, name); RegCloseKey(key); log.line("runonce=result=" + std::to_string(result));
}
void run_mass_probe(const std::wstring& root, Logger& log) { log.line("[6/7] disposable mass-file probe"); for (int i = 1; i <= 520; ++i) write_text(join(root, L"mass-document-" + std::to_wstring(i) + L".txt"), "Foxhole disposable mass-file canary\n"); }
void run_encryption_probe(const std::wstring& root, Logger& log) {
    log.line("[7/7] recoverable encryption probes"); write_text(join(root, L"canary-01.txt"), "Recoverable plaintext Foxhole canary 01\n"); write_text(join(root, L"canary-02.txt"), "Recoverable plaintext Foxhole canary 02\n"); CopyFileW(join(root, L"canary-01.txt").c_str(), join(root, L"canary-01.txt.encrypted").c_str(), FALSE); CopyFileW(join(root, L"canary-02.txt").c_str(), join(root, L"canary-02.txt.encrypted").c_str(), FALSE); write_text(join(root, L"README_RECOVERY.txt"), "Plaintext canaries were retained; encrypted files are disposable test copies.\n"); run_process(system_tool(L"cipher.exe"), L"/e /a \"" + join(root, L"canary-01.txt.encrypted") + L"\" \"" + join(root, L"canary-02.txt.encrypted") + L"\"", log);
}
} // namespace
int main() {
    wchar_t current[MAX_PATH] = {}; GetCurrentDirectoryW(ARRAYSIZE(current), current); const std::wstring root(current); Logger log(join(root, L"what_can_be.log")); if (!log.good()) { std::cerr << "Could not open what_can_be.log" << std::endl; return 2; }
    log.line("Foxhole native C++14 telemetry demo started"); run_file_probes(root, log); run_network_probes(log); run_process_tree(root, log); run_runonce_probe(log); run_mass_probe(root, log); run_encryption_probe(root, log); log.line("[report-log-begin] what_can_be.log"); log.line("[report-log-end] what_can_be.log"); return 0;
}
