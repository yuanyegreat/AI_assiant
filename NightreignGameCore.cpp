#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>

// 全局变量
HANDLE hProcess = NULL;
uintptr_t moduleBase = 0;
uintptr_t gameDataManAddr = 0;
uintptr_t worldChrManAddr = 0;
// 存储函数地址: 0:Runes, 1:Murk, 2:Sigil
uintptr_t funcAddresses[3] = { 0 }; 

// --- 内部工具函数 ---
DWORD GetProcId(const char* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32First(hSnap, &procEntry)) {
            do {
                if (_stricmp(procEntry.szExeFile, procName) == 0) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

uintptr_t GetModuleBase(DWORD procId, const char* modName) {
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (_stricmp(modEntry.szModule, modName) == 0) {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

uintptr_t ScanPattern(const char* pattern, const char* mask) {
    size_t scanSize = 0x6000000; 
    std::vector<BYTE> buffer(scanSize);
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, buffer.data(), scanSize, 0)) return 0;

    size_t patternLen = strlen(mask);
    for (size_t i = 0; i < scanSize - patternLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] != '?' && pattern[j] != (char)buffer[i + j]) {
                found = false; break;
            }
        }
        if (found) return moduleBase + i;
    }
    return 0;
}

uintptr_t ResolveRip(uintptr_t addr, int offset_pos) {
    int32_t offset = 0;
    ReadProcessMemory(hProcess, (LPCVOID)(addr + offset_pos), &offset, sizeof(offset), 0);
    return addr + 7 + offset;
}

// --- 导出接口 ---
extern "C" {
    __declspec(dllexport) int Connect() {
        DWORD pid = GetProcId("nightreign.exe");
        if (pid == 0) return 0;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
        moduleBase = GetModuleBase(pid, "nightreign.exe");
        return (hProcess && moduleBase) ? 1 : 0;
    }

    __declspec(dllexport) int ScanAll() {
        if (!hProcess) return 0;
        // GameDataMan
        uintptr_t addrGDM = ScanPattern("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x05\x48\x8B\x40\x58\xC3", "xxx????xxxxxxxxxx");
        if (addrGDM) gameDataManAddr = ResolveRip(addrGDM, 3);
        // WorldChrMan
        uintptr_t addrWCM = ScanPattern("\x48\x8B\x05\x00\x00\x00\x00\x0F\x28\xF1\x48\x85\xC0", "xxx????xxxxxx");
        if (addrWCM) worldChrManAddr = ResolveRip(addrWCM, 3);
        
        return (gameDataManAddr && worldChrManAddr) ? 1 : 0;
    }

    __declspec(dllexport) int InjectAddValue(int target, int value) {
        // 这里只是示例，因为我们没有实际扫描 funcAddresses，所以这步可能会失败
        // 实际用的时候你需要把 scan_add_funcs 的逻辑也搬进来
        // 但编译原理是一样的
        return 0; 
    }
    
    __declspec(dllexport) int ReadHP() {
        if (!worldChrManAddr) return -1;
        uintptr_t wcmPtr = 0;
        ReadProcessMemory(hProcess, (LPCVOID)worldChrManAddr, &wcmPtr, 8, 0);
        if (!wcmPtr) return -1;
        uintptr_t playerBase = 0;
        ReadProcessMemory(hProcess, (LPCVOID)(wcmPtr + 0x174E8), &playerBase, 8, 0);
        if (!playerBase) return -1;
        int hp = 0;
        ReadProcessMemory(hProcess, (LPCVOID)(playerBase + 0x140), &hp, 4, 0);
        return hp;
    }
}
