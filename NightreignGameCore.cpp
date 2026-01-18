#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>

// 全局变量
HANDLE hProcess = NULL;
uintptr_t moduleBase = 0;
size_t moduleSize = 0; // 新增：自动获取的模块大小

uintptr_t gameDataManAddr = 0;
uintptr_t worldChrManAddr = 0;

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

// 修改：同时获取基址和大小
uintptr_t GetModuleInfo(DWORD procId, const char* modName) {
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (_stricmp(modEntry.szModule, modName) == 0) {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    moduleSize = modEntry.modBaseSize; // 获取真实大小！
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

// 修改：使用真实大小进行全量扫描
uintptr_t ScanPattern(const char* pattern, const char* mask) {
    if (moduleSize == 0) return 0;

    // 分块读取以节省内存 (每次读 10MB)
    // 但为了代码简单，这里演示一次性读取 (注意：如果内存不够可能会失败，但在64位系统通常没问题)
    // 更稳健的做法是分块扫描，这里我们直接读整个 buffer
    std::vector<BYTE> buffer(moduleSize);
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, buffer.data(), moduleSize, 0)) return 0;

    size_t patternLen = strlen(mask);
    for (size_t i = 0; i < moduleSize - patternLen; i++) {
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
        moduleBase = GetModuleInfo(pid, "nightreign.exe");
        return (hProcess && moduleBase && moduleSize > 0) ? 1 : 0;
    }

    __declspec(dllexport) int ScanAll() {
        if (!hProcess) return 0;

        // 1. GameDataMan (严格匹配 Python memory_core.py 的特征码)
        // Python: 48 8B 0D ?? ?? ?? ?? F3 48 0F 2C C0
        // Mask: xxx????xxxxx
        uintptr_t addrGDM = ScanPattern(
            "\x48\x8B\x0D\x00\x00\x00\x00\xF3\x48\x0F\x2C\xC0", 
            "xxx????xxxxx"
        );
        if (addrGDM) gameDataManAddr = ResolveRip(addrGDM, 3);

        // 2. WorldChrMan (严格匹配 Python memory_core.py 的特征码)
        // Python: 48 8B 05 ?? ?? ?? ?? 0F 28 F1 48 85 C0
        // Mask: xxx????xxxxxx
        uintptr_t addrWCM = ScanPattern(
            "\x48\x8B\x05\x00\x00\x00\x00\x0F\x28\xF1\x48\x85\xC0", 
            "xxx????xxxxxx"
        );
        if (addrWCM) worldChrManAddr = ResolveRip(addrWCM, 3);
        
        return (gameDataManAddr && worldChrManAddr) ? 1 : 0;
    }

    // 读取 HP (严格按照 Python memory_core.py 的偏移链)
    // Chain: WorldChrMan -> +174E8 -> +1B8 -> +0 -> +140
    __declspec(dllexport) int ReadHP() {
        if (!worldChrManAddr) return -1;

        uintptr_t ptr1 = 0;
        ReadProcessMemory(hProcess, (LPCVOID)worldChrManAddr, &ptr1, 8, 0);
        if (!ptr1) return -1;

        uintptr_t ptr2 = 0;
        // + 0x174E8
        ReadProcessMemory(hProcess, (LPCVOID)(ptr1 + 0x174E8), &ptr2, 8, 0);
        if (!ptr2) return -1;

        uintptr_t ptr3 = 0;
        // + 0x1B8
        ReadProcessMemory(hProcess, (LPCVOID)(ptr2 + 0x1B8), &ptr3, 8, 0);
        if (!ptr3) return -1;

        uintptr_t ptr4 = 0;
        // + 0x0
        ReadProcessMemory(hProcess, (LPCVOID)(ptr3 + 0), &ptr4, 8, 0);
        if (!ptr4) return -1;

        int hp = 0;
        // + 0x140
        ReadProcessMemory(hProcess, (LPCVOID)(ptr4 + 0x140), &hp, 4, 0);
        return hp;
    }
    
    // 注入功能预留接口 (保持不变)
    __declspec(dllexport) int InjectAddValue(int target, int value) { return 0; }
}
