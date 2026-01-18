#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>

// ==========================================
// 全局状态与常量
// ==========================================
HANDLE hProcess = NULL;
uintptr_t moduleBase = 0;
size_t moduleSize = 0;

uintptr_t gameDataManAddr = 0;
uintptr_t worldChrManAddr = 0;
// 0: Runes, 1: Murk, 2: Sigil
uintptr_t funcAddresses[3] = { 0 }; 

// Hook 状态结构体
struct HookInfo {
    void* caveAddr;
    uintptr_t targetAddr;
    BYTE originalBytes[16];
    int len;
    bool active;
} ohkHook = {0};

// --- 偏移量定义 ---
const uintptr_t OFFSET_PLAYER = 0x174E8;

// Stat Offsets
const uintptr_t OFF_HP_CUR = 0x140;
const uintptr_t OFF_HP_MAX = 0x144;
const uintptr_t OFF_FP_CUR = 0x150;
const uintptr_t OFF_FP_MAX = 0x154;
const uintptr_t OFF_ST_CUR = 0x15C;
const uintptr_t OFF_ST_MAX = 0x160;

// Structs
const uintptr_t OFF_CD_STRUCT = 0x148;
const uintptr_t OFF_FLAG_STRUCT = 0x60;

// Float Values
const uintptr_t OFF_ULT_CUR = 0x14;
const uintptr_t OFF_ULT_MAX = 0x18;
const uintptr_t OFF_SKILL_CUR = 0x28;
const uintptr_t OFF_SKILL_MAX = 0x2C;

// Flags
const uintptr_t OFF_GOD_FLAG = 0xF8;
const uintptr_t OFF_NO_DEAD = 0x189; // Bit 2: NoDead, Bit 4: NoFP, Bit 5: NoStamina
const uintptr_t OFF_NO_GOODS = 0x551; // Bit 7

// ==========================================
// 内部工具函数
// ==========================================

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
                    moduleSize = modEntry.modBaseSize;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

// 通用指针链读取
uintptr_t GetPtrAddr(uintptr_t base, const std::vector<uintptr_t>& offsets) {
    uintptr_t addr = base;
    uintptr_t temp = 0;
    
    // 读取基址
    ReadProcessMemory(hProcess, (LPCVOID)addr, &temp, 8, 0);
    addr = temp;
    if (addr == 0) return 0;

    // 遍历偏移
    for (size_t i = 0; i < offsets.size() - 1; ++i) {
        ReadProcessMemory(hProcess, (LPCVOID)(addr + offsets[i]), &temp, 8, 0);
        addr = temp;
        if (addr == 0) return 0;
    }

    return addr + offsets.back();
}

// 特征码扫描
uintptr_t ScanPattern(const std::vector<BYTE>& buffer, const char* pattern, const char* mask) {
    size_t patternLen = strlen(mask);
    for (size_t i = 0; i < buffer.size() - patternLen; i++) {
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

// 扫描注入函数 (Runes/Murk/Sigil)
void ScanFuncs(const std::vector<BYTE>& buffer) {
    // 1. Soul (Runes) -> "8D 04 17" check prev "8B D9"
    for (size_t i = 4; i < buffer.size() - 3; ++i) {
        if (buffer[i] == 0x8D && buffer[i+1] == 0x04 && buffer[i+2] == 0x17) {
            if (buffer[i-3] == 0x8B && buffer[i-2] == 0xD9) {
                funcAddresses[0] = moduleBase + i - 4 - 0xD;
                break;
            }
        }
    }
    // 2. Murk -> "8B 81 D0 00 00 00" check next
    for (size_t i = 0; i < buffer.size() - 15; ++i) {
        if (buffer[i]==0x8B && buffer[i+1]==0x81 && buffer[i+2]==0xD0 && buffer[i+3]==0x00) {
            if (buffer[i+7] == 0x8B && buffer[i+8] == 0xD1 && buffer[i+9] == 0xB9) {
                funcAddresses[1] = moduleBase + i - 1;
                break;
            }
        }
    }
    // 3. Sigil -> "8B 41 5C" check next
    for (size_t i = 0; i < buffer.size() - 10; ++i) {
        if (buffer[i]==0x8B && buffer[i+1]==0x41 && buffer[i+2]==0x5C) {
            if (buffer[i+4] == 0x8B && buffer[i+5] == 0xD1) {
                funcAddresses[2] = moduleBase + i - 1;
                break;
            }
        }
    }
}

// ==========================================
// 🚀 导出接口 (API)
// ==========================================
extern "C" {

    // 1. 连接游戏
    __declspec(dllexport) int Connect() {
        DWORD pid = GetProcId("nightreign.exe");
        if (pid == 0) return 0;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
        moduleBase = GetModuleInfo(pid, "nightreign.exe");
        return (hProcess && moduleBase && moduleSize > 0) ? 1 : 0;
    }

    // 2. 全量扫描
    __declspec(dllexport) int ScanAll() {
        if (!hProcess || !moduleSize) return 0;
        
        std::vector<BYTE> buffer(moduleSize);
        if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, buffer.data(), moduleSize, 0)) return 0;

        // GDM
        uintptr_t addrGDM = ScanPattern(buffer, "\x48\x8B\x0D\x00\x00\x00\x00\xF3\x48\x0F\x2C\xC0", "xxx????xxxxx");
        if (addrGDM) {
            int32_t offset = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(addrGDM + 3), &offset, 4, 0);
            gameDataManAddr = addrGDM + 7 + offset;
        }

        // WCM
        uintptr_t addrWCM = ScanPattern(buffer, "\x48\x8B\x05\x00\x00\x00\x00\x0F\x28\xF1\x48\x85\xC0", "xxx????xxxxxx");
        if (addrWCM) {
            int32_t offset = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(addrWCM + 3), &offset, 4, 0);
            worldChrManAddr = addrWCM + 7 + offset;
        }

        // Funcs
        ScanFuncs(buffer);

        return (gameDataManAddr && worldChrManAddr) ? 1 : 0;
    }

    // 3. 数值管理 (HP/FP/Stamina)
    // type: 0=HP, 1=FP, 2=Stamina
    // mode: 0=Get, 1=SetVal, 2=SetMax
    __declspec(dllexport) int ManageStat(int type, int mode, int value) {
        if (!worldChrManAddr) return -1;
        
        uintptr_t offsetCur = 0, offsetMax = 0;
        if (type == 0) { offsetCur = OFF_HP_CUR; offsetMax = OFF_HP_MAX; } 
        else if (type == 1) { offsetCur = OFF_FP_CUR; offsetMax = OFF_FP_MAX; }
        else if (type == 2) { offsetCur = OFF_ST_CUR; offsetMax = OFF_ST_MAX; }

        // Chain: WCM -> Player -> 1B8 -> 0
        std::vector<uintptr_t> chain = {OFFSET_PLAYER, 0x1B8, 0, 0}; 
        uintptr_t baseStruct = GetPtrAddr(worldChrManAddr, chain);
        if (!baseStruct) return -1;

        if (mode == 0) { // Get
            int val = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(baseStruct + offsetCur), &val, 4, 0);
            return val;
        } 
        else if (mode == 1) { // Set
            WriteProcessMemory(hProcess, (LPVOID)(baseStruct + offsetCur), &value, 4, 0);
            return 1;
        }
        else if (mode == 2) { // Recover Max
            int maxVal = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(baseStruct + offsetMax), &maxVal, 4, 0);
            WriteProcessMemory(hProcess, (LPVOID)(baseStruct + offsetCur), &maxVal, 4, 0);
            return maxVal;
        }
        return 0;
    }

    // 4. 浮点数管理 (CD/Ult)
    // type: 0=Ult, 1=Skill
    // mode: 0=Get, 1=SetVal, 2=SetMax
    __declspec(dllexport) float ManageFloat(int type, int mode, float value) {
        if (!worldChrManAddr) return -1.0f;

        std::vector<uintptr_t> chain = {OFFSET_PLAYER, 0x1B8, OFF_CD_STRUCT, 0};
        uintptr_t baseStruct = GetPtrAddr(worldChrManAddr, chain);
        if (!baseStruct) return -1.0f;

        uintptr_t offsetCur = 0, offsetMax = 0;
        if (type == 0) { offsetCur = OFF_ULT_CUR; offsetMax = OFF_ULT_MAX; }
        else if (type == 1) { offsetCur = OFF_SKILL_CUR; offsetMax = OFF_SKILL_MAX; }

        if (mode == 0) {
            float val = 0.0f;
            ReadProcessMemory(hProcess, (LPCVOID)(baseStruct + offsetCur), &val, 4, 0);
            return val;
        }
        else if (mode == 1) {
            WriteProcessMemory(hProcess, (LPVOID)(baseStruct + offsetCur), &value, 4, 0);
            return 1.0f;
        }
        else if (mode == 2) { // Set Max (or Clear)
            float maxVal = 0.0f;
            if (type == 0) ReadProcessMemory(hProcess, (LPCVOID)(baseStruct + offsetMax), &maxVal, 4, 0);
            else maxVal = 0.0f; // Skill CD clear to 0
            
            WriteProcessMemory(hProcess, (LPVOID)(baseStruct + offsetCur), &maxVal, 4, 0);
            return maxVal;
        }
        return 0.0f;
    }

    // 5. 标记管理 (GodMode/Flags)
    // type: 0=GodMode, 1=NoDead, 2=NoStamina, 3=NoFP, 4=NoGoods
    __declspec(dllexport) int SetFlag(int type, int enable) {
        if (!worldChrManAddr) return 0;
        
        uintptr_t targetAddr = 0;
        int bitPos = 0;

        if (type == 0) { // GodMode (F8)
            targetAddr = GetPtrAddr(worldChrManAddr, {OFFSET_PLAYER, OFF_FLAG_STRUCT, OFF_GOD_FLAG});
            BYTE val = enable ? 1 : 0;
            WriteProcessMemory(hProcess, (LPVOID)targetAddr, &val, 1, 0);
            return 1;
        }
        
        // Bit Flags
        if (type == 4) { // NoGoods
            targetAddr = GetPtrAddr(worldChrManAddr, {OFFSET_PLAYER, OFF_NO_GOODS});
            bitPos = 7;
        } else { // 189 Struct
            targetAddr = GetPtrAddr(worldChrManAddr, {OFFSET_PLAYER, 0x1B8, 0, OFF_NO_DEAD});
            if (type == 1) bitPos = 2; // NoDead
            else if (type == 2) bitPos = 5; // NoStamina
            else if (type == 3) bitPos = 4; // NoFP
        }

        if (!targetAddr) return 0;

        BYTE current = 0;
        ReadProcessMemory(hProcess, (LPCVOID)targetAddr, &current, 1, 0);
        
        BYTE newVal = current;
        if (enable) newVal |= (1 << bitPos);
        else newVal &= ~(1 << bitPos);

        if (newVal != current) {
            WriteProcessMemory(hProcess, (LPVOID)targetAddr, &newVal, 1, 0);
        }
        return 1;
    }

    // 6. 注入添加物品 (Runes/Murk)
    __declspec(dllexport) int InjectAddValue(int target, int value) {
        if (!hProcess || !gameDataManAddr) return 0;
        uintptr_t funcAddr = funcAddresses[target];
        if (funcAddr == 0) return -1; 

        uintptr_t gdmPtr = 0;
        ReadProcessMemory(hProcess, (LPCVOID)gameDataManAddr, &gdmPtr, 8, 0);
        if (!gdmPtr) return -2;

        uintptr_t playerDataPtr = 0;
        ReadProcessMemory(hProcess, (LPCVOID)(gdmPtr + 0x8), &playerDataPtr, 8, 0);
        if (!playerDataPtr) return -2;

        void* shellcodeAddr = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) return 0;

        // Shellcode construction
        BYTE code[64];
        int idx = 0;

        // mov rcx, playerDataPtr
        code[idx++] = 0x48; code[idx++] = 0xB9;
        *(uint64_t*)&code[idx] = playerDataPtr; idx += 8;

        // mov edx, value
        code[idx++] = 0xBA;
        *(uint32_t*)&code[idx] = value; idx += 4;

        // mov rax, funcAddr
        code[idx++] = 0x48; code[idx++] = 0xB8;
        *(uint64_t*)&code[idx] = funcAddr; idx += 8;

        // call logic
        BYTE suffix[] = {0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3};
        memcpy(&code[idx], suffix, sizeof(suffix));
        idx += sizeof(suffix);

        WriteProcessMemory(hProcess, shellcodeAddr, code, idx, 0);
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return 1;
    }

    // 7. 安全的一击必杀 (One Hit Kill)
    __declspec(dllexport) int SetOneHitKill(int enable) {
        if (!hProcess || !moduleSize || !worldChrManAddr) return 0;

        if (enable) {
            if (ohkHook.active) return 1; 

            // 1. Scan for damage instruction: 8B 80 40 01 00 00 48 83 (mov eax, [rax+140])
            std::vector<BYTE> buffer(moduleSize);
            ReadProcessMemory(hProcess, (LPCVOID)moduleBase, buffer.data(), moduleSize, 0);
            uintptr_t target = ScanPattern(buffer, "\x8B\x80\x40\x01\x00\x00\x48\x83", "xxxxxxxx");
            if (!target) return -1; // Pattern not found

            // 2. Get Player Entity for safety check
            uintptr_t playerEntity = GetPtrAddr(worldChrManAddr, {OFFSET_PLAYER, 0x1B8, 0});
            if (!playerEntity) return -2; // Player not found

            // 3. Alloc Code Cave
            void* cave = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!cave) return 0;

            // 4. Construct Shellcode
            BYTE code[128];
            int idx = 0;

            // push rbx; mov rbx, playerEntity; cmp rax, rbx; pop rbx; je +offset
            code[idx++] = 0x53; // push rbx
            code[idx++] = 0x48; code[idx++] = 0xBB; // mov rbx, ...
            *(uint64_t*)&code[idx] = playerEntity; idx += 8;
            code[idx++] = 0x48; code[idx++] = 0x39; code[idx++] = 0xD8; // cmp rax, rbx
            code[idx++] = 0x5B; // pop rbx
            code[idx++] = 0x74; code[idx++] = 0x0A; // je +10 (Skip write 0)

            // mov [rax+140], 0
            code[idx++] = 0xC7; code[idx++] = 0x80;
            *(uint32_t*)&code[idx] = 0x140; idx += 4;
            *(uint32_t*)&code[idx] = 0; idx += 4;

            // original: mov eax, [rax+140]
            code[idx++] = 0x8B; code[idx++] = 0x80;
            *(uint32_t*)&code[idx] = 0x140; idx += 4;

            // jmp back
            uintptr_t backAddr = target + 6; 
            uintptr_t caveExit = (uintptr_t)cave + idx + 5;
            int32_t jmpOffset = (int32_t)(backAddr - caveExit);
            code[idx++] = 0xE9;
            *(int32_t*)&code[idx] = jmpOffset; idx += 4;

            // Write shellcode
            WriteProcessMemory(hProcess, cave, code, idx, 0);

            // 5. Apply Hook
            BYTE patch[6];
            patch[0] = 0xE9; // JMP
            int32_t hookOffset = (int32_t)((uintptr_t)cave - (target + 5));
            *(int32_t*)&patch[1] = hookOffset;
            patch[5] = 0x90; // NOP

            // Backup & Write
            ReadProcessMemory(hProcess, (LPCVOID)target, ohkHook.originalBytes, 6, 0);
            WriteProcessMemory(hProcess, (LPVOID)target, patch, 6, 0);

            // Save state
            ohkHook.caveAddr = cave;
            ohkHook.targetAddr = target;
            ohkHook.len = 6;
            ohkHook.active = true;
            return 1;
        } else {
            if (!ohkHook.active) return 1;
            WriteProcessMemory(hProcess, (LPVOID)ohkHook.targetAddr, ohkHook.originalBytes, ohkHook.len, 0);
            VirtualFreeEx(hProcess, ohkHook.caveAddr, 0, MEM_RELEASE);
            ohkHook.active = false;
            return 1;
        }
    }
}
