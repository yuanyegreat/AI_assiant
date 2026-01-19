#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>

// ==========================================
// 全局变量
// ==========================================
HANDLE hProcess = NULL;
uintptr_t moduleBase = 0;
size_t moduleSize = 0;

uintptr_t gameDataManAddr = 0;
uintptr_t worldChrManAddr = 0;
uintptr_t csGaitemAddr = 0;
uintptr_t funcAddresses[3] = { 0 };

struct HookInfo {
    void* caveAddr;
    uintptr_t targetAddr;
    BYTE originalBytes[16];
    int len;
    bool active;
} ohkHook = {0};

const uintptr_t OFFSET_PLAYER = 0x174E8;
const uintptr_t OFF_HP_CUR = 0x140;
const uintptr_t OFF_HP_MAX = 0x144;
const uintptr_t OFF_FP_CUR = 0x150;
const uintptr_t OFF_FP_MAX = 0x154;
const uintptr_t OFF_ST_CUR = 0x15C;
const uintptr_t OFF_ST_MAX = 0x160;
const uintptr_t OFF_CD_STRUCT = 0x148;
const uintptr_t OFF_FLAG_STRUCT = 0x60;
const uintptr_t OFF_ULT_CUR = 0x14;
const uintptr_t OFF_ULT_MAX = 0x18;
const uintptr_t OFF_SKILL_CUR = 0x28;
const uintptr_t OFF_SKILL_MAX = 0x2C;
const uintptr_t OFF_GOD_FLAG = 0xF8;
const uintptr_t OFF_NO_DEAD = 0x189;
const uintptr_t OFF_NO_GOODS = 0x551;

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

uintptr_t GetPtrAddr(uintptr_t base, const std::vector<uintptr_t>& offsets) {
    uintptr_t addr = base;
    uintptr_t temp = 0;
    ReadProcessMemory(hProcess, (LPCVOID)addr, &temp, 8, 0);
    addr = temp;
    if (addr == 0) return 0;
    for (size_t i = 0; i < offsets.size() - 1; ++i) {
        ReadProcessMemory(hProcess, (LPCVOID)(addr + offsets[i]), &temp, 8, 0);
        addr = temp;
        if (addr == 0) return 0;
    }
    return addr + offsets.back();
}

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

void ScanFuncs(const std::vector<BYTE>& buffer) {
    for (size_t i = 4; i < buffer.size() - 3; ++i) {
        if (buffer[i] == 0x8D && buffer[i+1] == 0x04 && buffer[i+2] == 0x17) {
            if (buffer[i-3] == 0x8B && buffer[i-2] == 0xD9) {
                funcAddresses[0] = moduleBase + i - 4 - 0xD;
                break;
            }
        }
    }
    for (size_t i = 0; i < buffer.size() - 15; ++i) {
        if (buffer[i]==0x8B && buffer[i+1]==0x81 && buffer[i+2]==0xD0 && buffer[i+3]==0x00) {
            if (buffer[i+7] == 0x8B && buffer[i+8] == 0xD1 && buffer[i+9] == 0xB9) {
                funcAddresses[1] = moduleBase + i - 1;
                break;
            }
        }
    }
    for (size_t i = 0; i < buffer.size() - 10; ++i) {
        if (buffer[i]==0x8B && buffer[i+1]==0x41 && buffer[i+2]==0x5C) {
            if (buffer[i+4] == 0x8B && buffer[i+5] == 0xD1) {
                funcAddresses[2] = moduleBase + i - 1;
                break;
            }
        }
    }
}

// 关键修复：在目标地址附近申请内存 (解决 2GB 跳转崩溃问题)
void* AllocNear(uintptr_t targetAddr, size_t size) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t pageSize = sysInfo.dwAllocationGranularity;

    uintptr_t startAddr = (targetAddr & ~(pageSize - 1)); // 对齐
    uintptr_t minAddr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    // 向上搜寻 (1GB范围内)
    for (size_t i = 0; i < 1024; i++) {
        uintptr_t attemptAddr = startAddr + (i * pageSize);
        if (attemptAddr >= maxAddr) break;
        // 尝试申请
        void* pMem = VirtualAllocEx(hProcess, (LPVOID)attemptAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pMem) {
            // 检查距离是否在 2GB 内 (int32范围)
            int64_t diff = (int64_t)pMem - (int64_t)targetAddr;
            if (diff > -0x7FFFFFFF && diff < 0x7FFFFFFF) return pMem;
            VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        }
    }
    // 向下搜寻
    for (size_t i = 0; i < 1024; i++) {
        uintptr_t attemptAddr = startAddr - (i * pageSize);
        if (attemptAddr <= minAddr) break;
        void* pMem = VirtualAllocEx(hProcess, (LPVOID)attemptAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pMem) {
            int64_t diff = (int64_t)pMem - (int64_t)targetAddr;
            if (diff > -0x7FFFFFFF && diff < 0x7FFFFFFF) return pMem;
            VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
        }
    }
    return nullptr;
}

// ==========================================
// 🚀 导出接口
// ==========================================
extern "C" {
    __declspec(dllexport) int Connect() {
        DWORD pid = GetProcId("nightreign.exe");
        if (pid == 0) return 0;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
        moduleBase = GetModuleInfo(pid, "nightreign.exe");
        return (hProcess && moduleBase && moduleSize > 0) ? 1 : 0;
    }

    __declspec(dllexport) int ScanAll() {
        if (!hProcess || !moduleSize) return 0;
        std::vector<BYTE> buffer(moduleSize);
        if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, buffer.data(), moduleSize, 0)) return 0;

        uintptr_t addrGDM = ScanPattern(buffer, "\x48\x8B\x0D\x00\x00\x00\x00\xF3\x48\x0F\x2C\xC0", "xxx????xxxxx");
        if (addrGDM) {
            int32_t offset = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(addrGDM + 3), &offset, 4, 0);
            gameDataManAddr = addrGDM + 7 + offset;
        }

        uintptr_t addrWCM = ScanPattern(buffer, "\x48\x8B\x05\x00\x00\x00\x00\x0F\x28\xF1\x48\x85\xC0", "xxx????xxxxxx");
        if (addrWCM) {
            int32_t offset = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(addrWCM + 3), &offset, 4, 0);
            worldChrManAddr = addrWCM + 7 + offset;
        }

        ScanFuncs(buffer);
        return (gameDataManAddr && worldChrManAddr) ? 1 : 0;
    }

    __declspec(dllexport) int ManageStat(int type, int mode, int value) {
        if (!worldChrManAddr) return -1;
        uintptr_t offsetCur = 0, offsetMax = 0;
        if (type == 0) { offsetCur = OFF_HP_CUR; offsetMax = OFF_HP_MAX; }
        else if (type == 1) { offsetCur = OFF_FP_CUR; offsetMax = OFF_FP_MAX; }
        else if (type == 2) { offsetCur = OFF_ST_CUR; offsetMax = OFF_ST_MAX; }

        std::vector<uintptr_t> chain = {OFFSET_PLAYER, 0x1B8, 0, 0};
        uintptr_t baseStruct = GetPtrAddr(worldChrManAddr, chain);
        if (!baseStruct) return -1;

        if (mode == 0) {
            int val = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(baseStruct + offsetCur), &val, 4, 0);
            return val;
        }
        else if (mode == 1) {
            WriteProcessMemory(hProcess, (LPVOID)(baseStruct + offsetCur), &value, 4, 0);
            return 1;
        }
        else if (mode == 2) {
            int maxVal = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(baseStruct + offsetMax), &maxVal, 4, 0);
            WriteProcessMemory(hProcess, (LPVOID)(baseStruct + offsetCur), &maxVal, 4, 0);
            return maxVal;
        }
        return 0;
    }

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
        else if (mode == 2) {
            float maxVal = 0.0f;
            if (type == 0) ReadProcessMemory(hProcess, (LPCVOID)(baseStruct + offsetMax), &maxVal, 4, 0);
            WriteProcessMemory(hProcess, (LPVOID)(baseStruct + offsetCur), &maxVal, 4, 0);
            return maxVal;
        }
        return 0.0f;
    }

    __declspec(dllexport) int SetFlag(int type, int enable) {
        if (!worldChrManAddr) return 0;
        uintptr_t targetAddr = 0;
        int bitPos = 0;

        if (type == 0) {
            targetAddr = GetPtrAddr(worldChrManAddr, {OFFSET_PLAYER, OFF_FLAG_STRUCT, OFF_GOD_FLAG});
            BYTE val = enable ? 1 : 0;
            WriteProcessMemory(hProcess, (LPVOID)targetAddr, &val, 1, 0);
            return 1;
        }
        if (type == 4) {
            targetAddr = GetPtrAddr(worldChrManAddr, {OFFSET_PLAYER, OFF_NO_GOODS});
            bitPos = 7;
        } else {
            targetAddr = GetPtrAddr(worldChrManAddr, {OFFSET_PLAYER, 0x1B8, 0, OFF_NO_DEAD});
            if (type == 1) bitPos = 2;
            else if (type == 2) bitPos = 5;
            else if (type == 3) bitPos = 4;
        }
        if (!targetAddr) return 0;

        BYTE current = 0;
        ReadProcessMemory(hProcess, (LPCVOID)targetAddr, &current, 1, 0);
        BYTE newVal = current;
        if (enable) newVal |= (1 << bitPos);
        else newVal &= ~(1 << bitPos);
        if (newVal != current) WriteProcessMemory(hProcess, (LPVOID)targetAddr, &newVal, 1, 0);
        return 1;
    }

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

        void* shellcodeAddr = AllocNear(gdmPtr, 1024); // 尝试分配附近内存，虽然CreateRemoteThread不严格要求
        if (!shellcodeAddr) shellcodeAddr = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) return 0;

        BYTE code[64];
        int idx = 0;
        code[idx++] = 0x48; code[idx++] = 0xB9; *(uint64_t*)&code[idx] = playerDataPtr; idx += 8;
        code[idx++] = 0xBA; *(uint32_t*)&code[idx] = value; idx += 4;
        code[idx++] = 0x48; code[idx++] = 0xB8; *(uint64_t*)&code[idx] = funcAddr; idx += 8;
        BYTE suffix[] = {0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3};
        memcpy(&code[idx], suffix, sizeof(suffix));
        idx += sizeof(suffix);

        WriteProcessMemory(hProcess, shellcodeAddr, code, idx, 0);
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
        if (hThread) { WaitForSingleObject(hThread, INFINITE); CloseHandle(hThread); }
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return 1;
    }

    // ==========================================
    // ⚔️ 终极修正版: 一击必杀 (防崩溃)
    // ==========================================
    __declspec(dllexport) int SetOneHitKill(int enable) {
        if (!hProcess || !moduleSize || !worldChrManAddr) return 0;

        if (enable) {
            if (ohkHook.active) return 1;

            // 1. 扫描目标: mov eax, [rax+140] (8B 80 40 01 00 00)
            std::vector<BYTE> buffer(moduleSize);
            ReadProcessMemory(hProcess, (LPCVOID)moduleBase, buffer.data(), moduleSize, 0);
            uintptr_t target = ScanPattern(buffer, "\x8B\x80\x40\x01\x00\x00\x48\x83", "xxxxxxxx");
            if (!target) return -1;

            uintptr_t playerEntity = GetPtrAddr(worldChrManAddr, {OFFSET_PLAYER, 0x1B8, 0});
            if (!playerEntity) return -2;

            // ⚠️ 关键修复：申请内存必须在 Target 附近 (±2GB)，否则 JMP 会崩溃
            void* cave = AllocNear(target, 1024);
            if (!cave) return 0; // 申请失败

            BYTE code[128];
            int idx = 0;

            // --- Shellcode ---
            // push rbx
            code[idx++] = 0x53;
            // mov rbx, playerEntity
            code[idx++] = 0x48; code[idx++] = 0xBB; *(uint64_t*)&code[idx] = playerEntity; idx += 8;
            // cmp rax, rbx
            code[idx++] = 0x48; code[idx++] = 0x39; code[idx++] = 0xD8;
            // pop rbx
            code[idx++] = 0x5B;
            // je +10 (如果是玩家，跳过写0操作)
            code[idx++] = 0x74; code[idx++] = 0x0A;

            // mov [rax+140], 0 (写入 0 血量)
            code[idx++] = 0xC7; code[idx++] = 0x80;
            *(uint32_t*)&code[idx] = 0x140; idx += 4;
            *(uint32_t*)&code[idx] = 0; idx += 4;

            // Original: mov eax, [rax+140] (还原被覆盖的指令)
            code[idx++] = 0x8B; code[idx++] = 0x80;
            *(uint32_t*)&code[idx] = 0x140; idx += 4;

            // ⚠️ 关键修复：使用绝对跳转跳回 (Absolute Jump)
            // 防止跳回距离过远导致崩溃。格式: FF 25 00 00 00 00 [Address]
            code[idx++] = 0xFF; code[idx++] = 0x25;
            *(int32_t*)&code[idx] = 0; idx += 4; // RIP+0
            uintptr_t backAddr = target + 6; // 跳回原指令下一条
            *(uint64_t*)&code[idx] = backAddr; idx += 8;

            WriteProcessMemory(hProcess, cave, code, idx, 0);

            // --- Apply Hook ---
            BYTE patch[6];
            patch[0] = 0xE9; // JMP
            // 计算相对偏移 (现在 cave 一定在 2GB 内，所以是安全的)
            int64_t diff = (int64_t)cave - (int64_t)target - 5;
            *(int32_t*)&patch[1] = (int32_t)diff;
            patch[5] = 0x90; // NOP

            // 备份并写入
            ReadProcessMemory(hProcess, (LPCVOID)target, ohkHook.originalBytes, 6, 0);
            WriteProcessMemory(hProcess, (LPVOID)target, patch, 6, 0);

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

void InitCSGaitemAddress() {
    // 特征码：48 8D 44 24 40 48 89 44 24 50 8B 02 89 44 24 40 48 8B 0D
    // 注意：Hexinton 脚本里这里有一个 offset = 0x10 的处理，说明真正的 mov rcx, [rip+offset] 在特征码开始后的第16个字节
    // 原始特征码较长，我们取关键部分进行搜索，或者直接使用脚本里的完整码
    // 对应 Lua: {name = "CSGaitem", aob = "48 8D ... 48 8B 0D ?? ?? ?? ?? 48 85 C9", offset = 0x10}

    // 假设你有一个 AOBScan 函数，这里是伪代码逻辑，请替换为你实际的扫描函数
    // 这里的 pattern 对应 offset 0x10 处的那条指令: 48 8B 0D ...
    std::string pattern = "48 8B 0D ?? ?? ?? ?? 48 85 C9";
    uintptr_t aobResult = AOBScanModuleUnique("nightreign.exe", pattern);

    if (aobResult != 0) {
        // 解析 RIP 寻址 ( 48 8B 0D [Offset] )
        // 指令长度 7 字节
        int32_t ripOffset = 0;
        ReadProcessMemory(hProcess, (LPCVOID)(aobResult + 3), &ripOffset, sizeof(ripOffset), 0);
        csGaitemAddr = aobResult + 7 + ripOffset;
        std::cout << "CSGaitem Address: " << std::hex << csGaitemAddr << std::endl;
    } else {
        std::cerr << "Failed to find CSGaitem" << std::endl;
    }
}

// 3. 获取第一个遗物 (1st Equipped Relic) 的 Attribute 1 ID 的方法
int GetFirstRelicAttribute1() {
    if (gameDataManAddr == 0 || csGaitemAddr == 0) return -1;

    // 步骤 1: 获取 PlayerGameData 指针
    uintptr_t playerGameData = 0;
    // [GameDataMan] + 0x8
    uintptr_t ptrToPlayerGameData = 0;
    ReadProcessMemory(hProcess, (LPCVOID)gameDataManAddr, &ptrToPlayerGameData, sizeof(ptrToPlayerGameData), 0);
    ReadProcessMemory(hProcess, (LPCVOID)(ptrToPlayerGameData + 0x8), &playerGameData, sizeof(playerGameData), 0);

    if (playerGameData == 0) return -1;

    // 步骤 2: 获取第一个遗物的索引 (Index)
    // 偏移 0x2F4 对应 "1st Equipped Relic" 的索引
    int16_t relicIndex = 0;
    ReadProcessMemory(hProcess, (LPCVOID)(playerGameData + 0x2F4), &relicIndex, sizeof(relicIndex), 0);

    // 步骤 3: 从 CSGaitem 获取具体的遗物对象指针
    // Lua 逻辑: 8 + 8 * [GaitemIndex]
    // CSGaitem 本身存放了一个指针，或者直接作为基址使用，根据 Lua "readQword(CSGaitem)" 来判断
    // 通常 registerSymbol 后，直接读取符号地址的值。
    uintptr_t csGaitemBase = 0;
    ReadProcessMemory(hProcess, (LPCVOID)csGaitemAddr, &csGaitemBase, sizeof(csGaitemBase), 0);

    if (csGaitemBase == 0) return -1;

    // 计算目标指针在数组中的位置
    uintptr_t targetRelicPtrLoc = csGaitemBase + 0x8 + (relicIndex * 0x8);
    uintptr_t targetRelicAddr = 0;
    ReadProcessMemory(hProcess, (LPCVOID)targetRelicPtrLoc, &targetRelicAddr, sizeof(targetRelicAddr), 0);

    if (targetRelicAddr == 0) return -1;

    // 步骤 4: 读取 Attribute 1 ID
    // 偏移 +0x18
    int32_t attribute1ID = 0;
    ReadProcessMemory(hProcess, (LPCVOID)(targetRelicAddr + 0x18), &attribute1ID, sizeof(attribute1ID), 0);

    return attribute1ID;
}
