#include <windows.h>
#include <psapi.h>
#include <regex>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

// GÜNCEL MADENCİ LİSTESİ
std::regex MINER_REGEX(
    R"(\b(xmrig|xmr-stak|minerd|cpuminer|ethminer|phoenixminer|trex|t-rex|nbminer|lolMiner|gminer|bminer|ccminer|sgminer|cgminer|cryptodredge|wildrig|kawpowminer|z-enemy|ewbf|verthash|coinhive|cryptoloot|webminepool|jsecoin|nicehash|cudo|hiveos|smos|minerstat|stratum|eth-proxy|xmr-proxy|sysupdate|kswapd0|kinsing|watchdog|donate-level|supportxmr|nanopool|f2pool|ethermine|xmrpool|moneropool|pool\.to|miner\.exe|xmrig\.exe|trex\.exe|nbminer\.exe|lolMiner\.exe|gminer\.exe|bminer\.exe|z-enemy\.exe|ewbf\.exe)\b)",
    std::regex_constants::icase
);

std::string GetProcessPath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "";

    char path[MAX_PATH] = {0};
    DWORD size = sizeof(path);
    if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        return std::string(path);
    }
    CloseHandle(hProcess);
    return "";
}

bool isSafePath(const std::string& path) {
    std::string low = path;
    std::transform(low.begin(), low.end(), low.begin(), ::tolower);

    std::vector<std::string> safePaths = {
        "\\system32\\",
        "\\syswow64\\",
        "\\windows\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\"
    };

    for (const auto& safe : safePaths) {
        if (low.find(safe) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void KillProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
}

int main() {
    // Konsol penceresini gizle (isteğe bağlı)
    // FreeConsole();

    while (true) {
        DWORD pids[1024], cbNeeded;
        if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)) {
            Sleep(10000); // 10 saniye bekle, tekrar dene
            continue;
        }

        DWORD cProcesses = cbNeeded / sizeof(DWORD);
        int blocked = 0;

        for (DWORD i = 0; i < cProcesses; i++) {
            DWORD pid = pids[i];
            if (pid < 100) continue; // Sistem süreçlerini atla

            std::string fullPath = GetProcessPath(pid);
            if (fullPath.empty()) continue;

            size_t lastSlash = fullPath.find_last_of("\\/");
            std::string fileName = (lastSlash != std::string::npos) ? fullPath.substr(lastSlash + 1) : fullPath;

            if (isSafePath(fullPath)) continue;

            if (std::regex_search(fileName, MINER_REGEX)) {
                std::cout << "[KILL] PID: " << pid << " | Path: " << fullPath << std::endl;
                KillProcess(pid);
                blocked++;
            }
        }

        std::cout << "process_amount:" << cProcesses << " | process_blocked:" << blocked << std::endl;

        // 10 saniye bekle (10.000 milisaniye)
        Sleep(10000);
    }

    return 0;
}
