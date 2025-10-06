#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <regex>
#include <string>
#include <iostream>

using namespace std;

int blocked = 0;

// Madenci regex'i (senin verdiğin, olduğu gibi)
std::regex MINER_REGEX(
    R"(\b(xmrig|xmr-stak(?:-legacy|-cpu|-opencl)?|xmrproxy(?:2)?|xmrig-(?:proxy(?:-ng|-v2)?|web|android|ios|js|go|docker|rust|dotnet|php|python|node|multi|server|fork|mod|pool|client|nicehash|gcc)|xmr-node-proxy|xmrchain-proxy|xmr-proxy-cpp|minerd(?:-wrapper|-fork|-service|-daemon)?|cpuminer(?:-opt|-multi|-jasmin|-sse2|-avx2|-arm)?|pcminer|minergate(?:-cli)?|ethminer|claymore(?:-dual|-ethereum(?:-legacy)?)?|phoenixminer(?:-legacy)?|phoenixminerproxy|t-rex(?: miner)?|trex(?:-zcoin)?|trexminer|nbminer(?:\.exe)?|kmminer|lolMiner|teamred(?:miner)?|gmine(?: r)?|gminer|ethlargement(?:proxy)?|bminer(?:\.exe)?|bfgminer(?:-alt|-xenon)?|ccminer(?:-tpruvot|-alexis|-x64|-sp-mod|-klauspost|-cryptonight(?:-lite)?)?|cudaminer(?:\.exe)?|cuda-miner|sgminer(?:-gm|-5\.0|-plx|-multi|-lyra2z|-neon|-lyra2v2|-hex|-legacy)?|cgminer|cryptodredge|wildrig(?:-multi)?|srbgminer|sr bminer(?: multi)?|kawpowminer|kaspa(?: )?miner|z-enemy(?:\.exe)?|poclbm|diablominer|ewbf(?:-miner(?:\.exe)?)?|zecminer(?:64|\.exe)?|verthash(?:-miner|-cpu)?|antminer(?:-firmware)?|braiins(?:-os|-pool)?|asic(?:miner|d|-firmware)?|bmminer(?:\.exe)?|awesome(?:-miner| miner)|minerstat(?:-agent)?|stratum(?:-miner|-proxy(?:2|3)?|-mining-proxy|-bridge(?:-proxy)?|-proxy)?|eth-proxy|ethproxy|zec-proxy|x11proxy(?:-ng)?|xmr-proxy|minerproxy(?:x)?|coinhive(?:-js|-proxy|-legacy|-fork)?|coinimp(?:-fork)?|cryptoloot(?:-js)?|webminepool(?:-fork)?|webminer(?:js)?|web-miner-service|browser-miner|browserminerjs|browsercryptominer|inbrowser-miner|inpage-miner|wasm-(?:crypto)?miner|webassembly-miner|js-(?:crypto)?miner|jsecoin|authedmine(?:-fork)?|cryptoLoot|sysupdate|systemupdate|sysup|kswapd0|kthreadd|kworker|rvms|servicehost|svchost(?:\.exe)?|svhost(?:\.exe)?|chrome_helper|chrome-helper|explorer(?:32|64|\.exe)?|node(?:js|\.exe)?|mining(?:tool(?:kit)?|suite(?:-mgr)?|-manager|-proxy)?|automin er|auto-(?:xmrig|minerd|ccminer|ethminer|gminer|trex|bminer)|nicehash(?:miner|-quickminer|-legacy|\.exe)?|cudo(?:miner(?:\.exe)?| miner)?|minerGate|MinerGate|easyminer|easymine|winminer|wineth|simplemining(?:-os)?|smos|hiveos|rav eos|raveos|rave-os|prohashing|minerwatch|minestat(?:-agent)?|poolwatch|poolchecker|poolscanner(?:-proxy|-daemon)?|minerproxy(?:ctl|d|ng)?|node-(?:cryptonote-pool|stratum-pool|open-mining-portal)|ominer|open-mining-portal|openminingportal|miningportal|pooler(?:-server|-proxy|-mgr)?|pminer(?:-eth(?:\.exe)?|64|32)?|mcminer(?:\.exe)?|mcmine(?:\.exe)?|eloominer(?:\.exe)?|miner)\b)",
    std::regex_constants::icase
);

// Süreç ismini alıp string olarak döndür
std::string GetProcessName(DWORD processID) {
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess != NULL) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
        }
        CloseHandle(hProcess);
    }

    // TCHAR -> std::string (Unicode değilse)
#ifdef UNICODE
    return std::string(szProcessName, szProcessName + wcslen(szProcessName));
#else
    return std::string(szProcessName);
#endif
}

// PID'yi taskkill ile öldür
void KillProcess(DWORD pid) {
    TCHAR cmd[256];
    _stprintf_s(cmd, _T("taskkill /F /PID %lu >nul 2>&1"), pid);
    _tsystem(cmd);
}

int main() {
    DWORD aProcesses[1024], cbNeeded;
    unsigned int cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return 1;
    }

    cProcesses = cbNeeded / sizeof(DWORD);
    blocked = 0;

    for (unsigned int i = 0; i < cProcesses; i++) {
        DWORD pid = aProcesses[i];
        if (pid == 0 || pid == 4) continue; // Idle ve System süreçlerini atla

        std::string procName = GetProcessName(pid);

        // Madenci mi?
        if (std::regex_search(procName, MINER_REGEX)) {
            wprintf(L"[KILL] PID: %lu | İsim: %hs\n", pid, procName.c_str());
            KillProcess(pid);
            blocked++;
        }
    }

    // İsteğe bağlı: payload gönder (senin için şimdilik yazdıralım)
    printf("process_amount:%u\n", cProcesses);
    printf("process_blocked:%d\n", blocked);

    return 0;
}