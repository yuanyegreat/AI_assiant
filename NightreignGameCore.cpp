#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>

// ==========================================
// 1. 配置与常量定义 (Offsets)
// ==========================================
namespace Offsets {
    // 基础偏移
    const uintptr_t PlayerBase = 0x174E8;

    // 属性偏移 (WorldChrMan -> Player -> 0x1B8 -> ...)
    const uintptr_t HP_Current = 0x140;
    const uintptr_t HP_Max     = 0x144;
    const uintptr_t FP_Current = 0x150;
    const uintptr_t FP_Max     = 0x154;
    const uintptr_t St_Current = 0x15C;
    const uintptr_t St_Max     = 0x160;

    // 冷却/大招偏移
    const uintptr_t CD_Struct  = 0x148;
    const uintptr_t Ult_Cur    = 0x14;
    const uintptr_t Ult_Max    = 0x18;
    const uintptr_t Skill_Cur  = 0x28;
    const uintptr_t Skill_Max  = 0x2C;

    // Flags
    const uintptr_t Flag_Struct = 0x60;
    const uintptr_t Flag_God    = 0xF8;
    const uintptr_t Flag_NoDead = 0x189;
    const uintptr_t Flag_NoGoods= 0x551;

    // 遗物相关
    const uintptr_t RelicIndexBase = 0x2F4; // PlayerGameData + 0x2F4
}

// 导出给 Python 的结构体
struct RelicRawData {
    int fields[16]; // 覆盖 0x18 到 0x54 (含 Debuff 的 +0x40)
};

// ==========================================
// 2. 全局游戏上下文 (GameContext)
// ==========================================
// 管理进程句柄和关键基址，避免全局变量散乱
class GameContext {
public:
    HANDLE hProcess = NULL;
    uintptr_t moduleBase = 0;
    size_t moduleSize = 0;

    // 关键基址管理器
    uintptr_t addrGameDataMan = 0;
    uintptr_t addrWorldChrMan = 0;
    uintptr_t addrCSGaitem = 0;

    // 注入用的函数地址缓存
    uintptr_t funcAddresses[3] = { 0 };

    static GameContext& Instance() {
        static GameContext instance;
        return instance;
    }

    bool IsValid() const {
        return hProcess != NULL && moduleBase != 0;
    }
};

// 简化访问宏
#define G_Ctx GameContext::Instance()

// ==========================================
// 3. 内存工具类 (MemoryUtils)
// ==========================================
class MemoryUtils {
public:
    // 获取进程ID
    static DWORD GetProcId(const char* procName) {
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

    // 获取模块基址
    static uintptr_t GetModuleInfo(DWORD procId, const char* modName, size_t& outSize) {
        uintptr_t modBaseAddr = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 modEntry;
            modEntry.dwSize = sizeof(modEntry);
            if (Module32First(hSnap, &modEntry)) {
                do {
                    if (_stricmp(modEntry.szModule, modName) == 0) {
                        modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                        outSize = modEntry.modBaseSize;
                        break;
                    }
                } while (Module32Next(hSnap, &modEntry));
            }
        }
        CloseHandle(hSnap);
        return modBaseAddr;
    }

    // 指针链读取
    static uintptr_t GetPtrAddr(uintptr_t base, const std::vector<uintptr_t>& offsets) {
        if (base == 0) return 0;
        uintptr_t addr = base;
        uintptr_t temp = 0;

        // 读取基址本身指向的值
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)addr, &temp, 8, 0);
        addr = temp;
        if (addr == 0) return 0;

        // 遍历偏移
        for (size_t i = 0; i < offsets.size() - 1; ++i) {
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(addr + offsets[i]), &temp, 8, 0);
            addr = temp;
            if (addr == 0) return 0;
        }
        return addr + offsets.back();
    }

    // 特征码扫描 (外部进程版，安全分块)
    static uintptr_t AOBScan(const std::string& pattern) {
        if (!G_Ctx.IsValid()) return 0;

        std::vector<int> patternBytes;
        std::stringstream ss(pattern);
        std::string byteStr;
        while (ss >> byteStr) {
            patternBytes.push_back((byteStr == "??" || byteStr == "?") ? -1 : std::stoi(byteStr, nullptr, 16));
        }

        const size_t CHUNK_SIZE = 1024 * 64;
        std::vector<BYTE> buffer(CHUNK_SIZE);
        size_t patternLen = patternBytes.size();

        // 兜底模块大小
        size_t scanSize = (G_Ctx.moduleSize > 0) ? G_Ctx.moduleSize : 0x4000000;

        for (size_t i = 0; i < scanSize; i += (CHUNK_SIZE - patternLen)) {
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(G_Ctx.moduleBase + i), buffer.data(), CHUNK_SIZE, &bytesRead) || bytesRead == 0)
                continue;

            for (size_t j = 0; j < bytesRead; ++j) {
                if (j + patternLen > bytesRead) break;
                bool found = true;
                for (size_t k = 0; k < patternLen; ++k) {
                    if (patternBytes[k] != -1 && buffer[j + k] != (BYTE)patternBytes[k]) {
                        found = false; break;
                    }
                }
                if (found) return G_Ctx.moduleBase + i + j;
            }
        }
        return 0;
    }

    // 本地缓冲区扫描 (用于初始化)
    static uintptr_t ScanPatternInLocalBuffer(const std::vector<BYTE>& buffer, const char* pattern, const char* mask) {
        size_t patternLen = strlen(mask);
        for (size_t i = 0; i < buffer.size() - patternLen; i++) {
            bool found = true;
            for (size_t j = 0; j < patternLen; j++) {
                if (mask[j] != '?' && pattern[j] != (char)buffer[i + j]) {
                    found = false; break;
                }
            }
            if (found) return G_Ctx.moduleBase + i;
        }
        return 0;
    }

    // 在目标附近申请内存 (用于 Hook/Shellcode)
    static void* AllocNear(uintptr_t targetAddr, size_t size) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        uintptr_t pageSize = sysInfo.dwAllocationGranularity;
        uintptr_t startAddr = (targetAddr & ~(pageSize - 1));

        // 向上和向下搜索
        for (int dir = 0; dir < 2; dir++) {
            for (size_t i = 0; i < 1024; i++) {
                uintptr_t attemptAddr = (dir == 0) ? (startAddr + i * pageSize) : (startAddr - i * pageSize);
                void* pMem = VirtualAllocEx(G_Ctx.hProcess, (LPVOID)attemptAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (pMem) {
                    int64_t diff = (int64_t)pMem - (int64_t)targetAddr;
                    if (diff > -0x7FFFFFFF && diff < 0x7FFFFFFF) return pMem;
                    VirtualFreeEx(G_Ctx.hProcess, pMem, 0, MEM_RELEASE);
                }
            }
        }
        return nullptr;
    }
};

// ==========================================
// 4. 地址扫描与管理器 (AddressScanner)
// ==========================================
class AddressScanner {
public:
    static void ScanCorePtrs(const std::vector<BYTE>& buffer) {
        // GameDataMan
        uintptr_t addrGDM = MemoryUtils::ScanPatternInLocalBuffer(buffer, "\x48\x8B\x0D\x00\x00\x00\x00\xF3\x48\x0F\x2C\xC0", "xxx????xxxxx");
        if (addrGDM) {
            int32_t offset = 0;
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(addrGDM + 3), &offset, 4, 0);
            G_Ctx.addrGameDataMan = addrGDM + 7 + offset;
        }

        // WorldChrMan
        uintptr_t addrWCM = MemoryUtils::ScanPatternInLocalBuffer(buffer, "\x48\x8B\x05\x00\x00\x00\x00\x0F\x28\xF1\x48\x85\xC0", "xxx????xxxxxx");
        if (addrWCM) {
            int32_t offset = 0;
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(addrWCM + 3), &offset, 4, 0);
            G_Ctx.addrWorldChrMan = addrWCM + 7 + offset;
        }
    }

    static void ScanFunctions(const std::vector<BYTE>& buffer) {
        // 这里保留原本的硬编码扫描逻辑
        for (size_t i = 4; i < buffer.size() - 3; ++i) {
            if (buffer[i] == 0x8D && buffer[i+1] == 0x04 && buffer[i+2] == 0x17) {
                if (buffer[i-3] == 0x8B && buffer[i-2] == 0xD9) {
                    G_Ctx.funcAddresses[0] = G_Ctx.moduleBase + i - 4 - 0xD;
                    break;
                }
            }
        }
        for (size_t i = 0; i < buffer.size() - 15; ++i) {
            if (buffer[i]==0x8B && buffer[i+1]==0x81 && buffer[i+2]==0xD0 && buffer[i+3]==0x00) {
                if (buffer[i+7] == 0x8B && buffer[i+8] == 0xD1 && buffer[i+9] == 0xB9) {
                    G_Ctx.funcAddresses[1] = G_Ctx.moduleBase + i - 1;
                    break;
                }
            }
        }
        for (size_t i = 0; i < buffer.size() - 10; ++i) {
            if (buffer[i]==0x8B && buffer[i+1]==0x41 && buffer[i+2]==0x5C) {
                if (buffer[i+4] == 0x8B && buffer[i+5] == 0xD1) {
                    G_Ctx.funcAddresses[2] = G_Ctx.moduleBase + i - 1;
                    break;
                }
            }
        }
    }

    // 独立扫描 CSGaitem (支持懒加载)
    static void ScanCSGaitem() {
        if (G_Ctx.addrCSGaitem != 0) return;

        std::string pattern = "48 8D 44 24 40 48 89 44 24 50 8B 02 89 44 24 40 48 8B 0D";
        uintptr_t aobResult = MemoryUtils::AOBScan(pattern);

        if (aobResult != 0) {
            uintptr_t instructionAddr = aobResult + 0x10;
            int32_t ripOffset = 0;
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(instructionAddr + 3), &ripOffset, sizeof(ripOffset), 0);
            G_Ctx.addrCSGaitem = instructionAddr + 7 + ripOffset;
            std::cout << "[+] CSGaitem found: " << std::hex << G_Ctx.addrCSGaitem << std::dec << std::endl;
        } else {
            std::cout << "[-] CSGaitem pattern not found." << std::endl;
        }
    }
};

// ==========================================
// 5. 玩家管理器 (PlayerManager)
// ==========================================
class PlayerManager {
public:
    // HP, FP, Stamina
    static int ManageStat(int type, int mode, int value) {
        if (!G_Ctx.addrWorldChrMan) return -1;
        uintptr_t offCur = 0, offMax = 0;

        switch(type) {
            case 0: offCur = Offsets::HP_Current; offMax = Offsets::HP_Max; break;
            case 1: offCur = Offsets::FP_Current; offMax = Offsets::FP_Max; break;
            case 2: offCur = Offsets::St_Current; offMax = Offsets::St_Max; break;
            default: return -1;
        }

        uintptr_t baseStruct = MemoryUtils::GetPtrAddr(G_Ctx.addrWorldChrMan, {Offsets::PlayerBase, 0x1B8, 0, 0});
        if (!baseStruct) return -1;

        if (mode == 0) { // Read
            int val = 0;
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(baseStruct + offCur), &val, 4, 0);
            return val;
        } else if (mode == 1) { // Write
            WriteProcessMemory(G_Ctx.hProcess, (LPVOID)(baseStruct + offCur), &value, 4, 0);
            return 1;
        } else if (mode == 2) { // Max
            int maxVal = 0;
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(baseStruct + offMax), &maxVal, 4, 0);
            WriteProcessMemory(G_Ctx.hProcess, (LPVOID)(baseStruct + offCur), &maxVal, 4, 0);
            return maxVal;
        }
        return 0;
    }

    // Ult, Skill CD
    static float ManageFloat(int type, int mode, float value) {
        if (!G_Ctx.addrWorldChrMan) return -1.0f;

        uintptr_t offCur = 0, offMax = 0;
        if (type == 0) { offCur = Offsets::Ult_Cur; offMax = Offsets::Ult_Max; }
        else { offCur = Offsets::Skill_Cur; offMax = Offsets::Skill_Max; }

        uintptr_t baseStruct = MemoryUtils::GetPtrAddr(G_Ctx.addrWorldChrMan, {Offsets::PlayerBase, 0x1B8, Offsets::CD_Struct, 0});
        if (!baseStruct) return -1.0f;

        if (mode == 0) {
            float val = 0.0f;
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(baseStruct + offCur), &val, 4, 0);
            return val;
        } else if (mode == 1) {
            WriteProcessMemory(G_Ctx.hProcess, (LPVOID)(baseStruct + offCur), &value, 4, 0);
            return 1.0f;
        } else if (mode == 2) {
            float maxVal = 0.0f;
            if(type == 0) ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(baseStruct + offMax), &maxVal, 4, 0);
            WriteProcessMemory(G_Ctx.hProcess, (LPVOID)(baseStruct + offCur), &maxVal, 4, 0);
            return maxVal;
        }
        return 0.0f;
    }

    // Flags (GodMode etc)
    static int SetFlag(int type, int enable) {
        if (!G_Ctx.addrWorldChrMan) return 0;
        uintptr_t targetAddr = 0;
        int bitPos = 0;

        if (type == 0) { // God Mode
            targetAddr = MemoryUtils::GetPtrAddr(G_Ctx.addrWorldChrMan, {Offsets::PlayerBase, Offsets::Flag_Struct, Offsets::Flag_God});
            BYTE val = enable ? 1 : 0;
            WriteProcessMemory(G_Ctx.hProcess, (LPVOID)targetAddr, &val, 1, 0);
            return 1;
        }

        // Bit Flags
        if (type == 4) { // No Consume
            targetAddr = MemoryUtils::GetPtrAddr(G_Ctx.addrWorldChrMan, {Offsets::PlayerBase, Offsets::Flag_NoGoods});
            bitPos = 7;
        } else {
            targetAddr = MemoryUtils::GetPtrAddr(G_Ctx.addrWorldChrMan, {Offsets::PlayerBase, 0x1B8, 0, Offsets::Flag_NoDead});
            if (type == 1) bitPos = 2; // No Dead
            else if (type == 2) bitPos = 5; // No Stamina
            else if (type == 3) bitPos = 4; // No FP
        }

        if (!targetAddr) return 0;
        BYTE current = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)targetAddr, &current, 1, 0);
        BYTE newVal = current;
        if (enable) newVal |= (1 << bitPos);
        else newVal &= ~(1 << bitPos);

        if (newVal != current) WriteProcessMemory(G_Ctx.hProcess, (LPVOID)targetAddr, &newVal, 1, 0);
        return 1;
    }
};

// ==========================================
// 6. 遗物/物品管理器 (InventoryManager)
// ==========================================
class InventoryManager {
public:
    static int GetAllRelics(RelicRawData* outBuffer) {
        // 确保 CSGaitem 已初始化
        AddressScanner::ScanCSGaitem();
        if (G_Ctx.addrGameDataMan == 0 || G_Ctx.addrCSGaitem == 0) return 0;

        uintptr_t ptrToPlayerGameData = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)G_Ctx.addrGameDataMan, &ptrToPlayerGameData, 8, 0);
        if (!ptrToPlayerGameData) return 0;

        uintptr_t playerGameData = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(ptrToPlayerGameData + 0x8), &playerGameData, 8, 0);
        if (!playerGameData) return 0;

        uintptr_t gaitemManager = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)G_Ctx.addrCSGaitem, &gaitemManager, 8, 0);
        if (!gaitemManager) return 0;

        // 循环读取 6 个遗物
        for (int i = 0; i < 6; i++) {
            uintptr_t indexAddr = playerGameData + Offsets::RelicIndexBase + (i * 4);
            int16_t relicIndex = -1;

            if (!ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)indexAddr, &relicIndex, 2, 0) || relicIndex < 0) {
                FillEmpty(outBuffer[i]);
                continue;
            }

            uintptr_t itemPtrLocation = gaitemManager + 0x8 + (relicIndex * 8);
            uintptr_t itemAddr = 0;
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)itemPtrLocation, &itemAddr, 8, 0);

            if (itemAddr == 0) {
                FillEmpty(outBuffer[i]);
                continue;
            }

            // 读取从 0x18 开始的 16 个整数 (覆盖到 0x54)
            if (!ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(itemAddr + 0x18), outBuffer[i].fields, sizeof(int) * 16, 0)) {
                FillEmpty(outBuffer[i]);
            }
        }
        return 1;
    }

    static int SetRelicData(int relicIndex, int fieldIndex, int value) {
        // 1. 初始化与地址检查
        AddressScanner::ScanCSGaitem();
        if (G_Ctx.addrGameDataMan == 0 || G_Ctx.addrCSGaitem == 0) return 0;

        uintptr_t ptrToPlayerGameData = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)G_Ctx.addrGameDataMan, &ptrToPlayerGameData, 8, 0);
        if (!ptrToPlayerGameData) return 0;

        uintptr_t playerGameData = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(ptrToPlayerGameData + 0x8), &playerGameData, 8, 0);
        if (!playerGameData) return 0;

        uintptr_t gaitemManager = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)G_Ctx.addrCSGaitem, &gaitemManager, 8, 0);
        if (!gaitemManager) return 0;

        // 2. 获取目标遗物的 Index
        uintptr_t indexAddr = playerGameData + Offsets::RelicIndexBase + (relicIndex * 4);
        int16_t currentRelicIndex = -1;
        if (!ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)indexAddr, &currentRelicIndex, 2, 0) || currentRelicIndex < 0) {
            return -2; // 遗物槽为空
        }

        // 3. 获取遗物实体的内存地址
        uintptr_t itemPtrLocation = gaitemManager + 0x8 + (currentRelicIndex * 8);
        uintptr_t itemAddr = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)itemPtrLocation, &itemAddr, 8, 0);
        if (itemAddr == 0) return -2;

        // 4. 计算目标字段地址并写入
        // Base = 0x18
        // Target = 0x18 + (fieldIndex * 4)
        uintptr_t targetFieldAddr = itemAddr + 0x18 + (fieldIndex * 4);

        if (WriteProcessMemory(G_Ctx.hProcess, (LPVOID)targetFieldAddr, &value, 4, 0)) {
            return 1; // 成功
        }
        return 0; // 写入失败
    }

private:
    static void FillEmpty(RelicRawData& data) {
        for(int k=0; k<16; k++) data.fields[k] = -1;
    }
};

// ==========================================
// 7. 作弊功能管理器 (CheatManager)
// ==========================================
class CheatManager {
    struct HookInfo {
        void* caveAddr;
        uintptr_t targetAddr;
        BYTE originalBytes[16];
        int len;
        bool active;
    };
    static HookInfo ohkHook;

public:
    static int InjectAddValue(int target, int value) {
        if (!G_Ctx.IsValid() || !G_Ctx.addrGameDataMan) return 0;
        uintptr_t funcAddr = G_Ctx.funcAddresses[target];
        if (funcAddr == 0) return -1;

        uintptr_t gdmPtr = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)G_Ctx.addrGameDataMan, &gdmPtr, 8, 0);
        if (!gdmPtr) return -2;

        uintptr_t playerDataPtr = 0;
        ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)(gdmPtr + 0x8), &playerDataPtr, 8, 0);
        if (!playerDataPtr) return -2;

        void* shellcodeAddr = MemoryUtils::AllocNear(gdmPtr, 1024);
        if (!shellcodeAddr) shellcodeAddr = VirtualAllocEx(G_Ctx.hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) return 0;

        BYTE code[64];
        int idx = 0;
        // mov rcx, playerDataPtr
        code[idx++] = 0x48; code[idx++] = 0xB9; *(uint64_t*)&code[idx] = playerDataPtr; idx += 8;
        // mov edx, value
        code[idx++] = 0xBA; *(uint32_t*)&code[idx] = value; idx += 4;
        // mov rax, funcAddr
        code[idx++] = 0x48; code[idx++] = 0xB8; *(uint64_t*)&code[idx] = funcAddr; idx += 8;
        // Call & cleanup
        BYTE suffix[] = {0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3};
        memcpy(&code[idx], suffix, sizeof(suffix));
        idx += sizeof(suffix);

        WriteProcessMemory(G_Ctx.hProcess, shellcodeAddr, code, idx, 0);
        HANDLE hThread = CreateRemoteThread(G_Ctx.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
        if (hThread) { WaitForSingleObject(hThread, INFINITE); CloseHandle(hThread); }
        VirtualFreeEx(G_Ctx.hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return 1;
    }

    static int SetOneHitKill(int enable) {
        if (!G_Ctx.IsValid() || !G_Ctx.addrWorldChrMan) return 0;

        if (enable) {
            if (ohkHook.active) return 1;

            std::vector<BYTE> buffer(G_Ctx.moduleSize);
            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)G_Ctx.moduleBase, buffer.data(), G_Ctx.moduleSize, 0);

            // mov eax, [rax+140]
            uintptr_t target = MemoryUtils::ScanPatternInLocalBuffer(buffer, "\x8B\x80\x40\x01\x00\x00\x48\x83", "xxxxxxxx");
            if (!target) return -1;

            uintptr_t playerEntity = MemoryUtils::GetPtrAddr(G_Ctx.addrWorldChrMan, {Offsets::PlayerBase, 0x1B8, 0});
            if (!playerEntity) return -2;

            void* cave = MemoryUtils::AllocNear(target, 1024);
            if (!cave) return 0;

            BYTE code[128];
            int idx = 0;
            // 逻辑: 检查是否是玩家，是则写入，否则正常执行
            // push rbx
            code[idx++] = 0x53;
            // mov rbx, playerEntity
            code[idx++] = 0x48; code[idx++] = 0xBB; *(uint64_t*)&code[idx] = playerEntity; idx += 8;
            // cmp rax, rbx
            code[idx++] = 0x48; code[idx++] = 0x39; code[idx++] = 0xD8;
            // pop rbx
            code[idx++] = 0x5B;
            // je +10 (Skip if player)
            code[idx++] = 0x74; code[idx++] = 0x0A;
            // mov [rax+140], 0 (Kill Enemy)
            code[idx++] = 0xC7; code[idx++] = 0x80; *(uint32_t*)&code[idx] = 0x140; idx += 4; *(uint32_t*)&code[idx] = 0; idx += 4;
            // Original Instruction
            code[idx++] = 0x8B; code[idx++] = 0x80; *(uint32_t*)&code[idx] = 0x140; idx += 4;
            // Jump Back
            code[idx++] = 0xFF; code[idx++] = 0x25; *(int32_t*)&code[idx] = 0; idx += 4;
            *(uint64_t*)&code[idx] = target + 6; idx += 8;

            WriteProcessMemory(G_Ctx.hProcess, cave, code, idx, 0);

            // Apply Hook
            BYTE patch[6];
            patch[0] = 0xE9;
            int64_t diff = (int64_t)cave - (int64_t)target - 5;
            *(int32_t*)&patch[1] = (int32_t)diff;
            patch[5] = 0x90;

            ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)target, ohkHook.originalBytes, 6, 0);
            WriteProcessMemory(G_Ctx.hProcess, (LPVOID)target, patch, 6, 0);

            ohkHook.caveAddr = cave;
            ohkHook.targetAddr = target;
            ohkHook.len = 6;
            ohkHook.active = true;
            return 1;
        } else {
            if (!ohkHook.active) return 1;
            WriteProcessMemory(G_Ctx.hProcess, (LPVOID)ohkHook.targetAddr, ohkHook.originalBytes, ohkHook.len, 0);
            VirtualFreeEx(G_Ctx.hProcess, ohkHook.caveAddr, 0, MEM_RELEASE);
            ohkHook.active = false;
            return 1;
        }
    }
};
// 初始化静态成员
CheatManager::HookInfo CheatManager::ohkHook = {0};


// ==========================================
// 8. 外部接口 (Extern "C" Exports)
// ==========================================
// 这一层保持不变，作为 Python ctypes 的接口层
extern "C" {
    __declspec(dllexport) int Connect() {
        DWORD pid = MemoryUtils::GetProcId("nightreign.exe");
        if (pid == 0) return 0;
        G_Ctx.hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
        G_Ctx.moduleBase = MemoryUtils::GetModuleInfo(pid, "nightreign.exe", G_Ctx.moduleSize);
        return G_Ctx.IsValid() ? 1 : 0;
    }

    __declspec(dllexport) int ScanAll() {
        if (!G_Ctx.IsValid()) return 0;
        std::vector<BYTE> buffer(G_Ctx.moduleSize);
        if (!ReadProcessMemory(G_Ctx.hProcess, (LPCVOID)G_Ctx.moduleBase, buffer.data(), G_Ctx.moduleSize, 0)) return 0;

        AddressScanner::ScanCorePtrs(buffer);
        AddressScanner::ScanFunctions(buffer);
        // CSGaitem 留给 GetAllRelics 懒加载，或者这里也可以加 AddressScanner::ScanCSGaitem();

        return (G_Ctx.addrGameDataMan && G_Ctx.addrWorldChrMan) ? 1 : 0;
    }

    __declspec(dllexport) int ManageStat(int type, int mode, int value) {
        return PlayerManager::ManageStat(type, mode, value);
    }

    __declspec(dllexport) float ManageFloat(int type, int mode, float value) {
        return PlayerManager::ManageFloat(type, mode, value);
    }

    __declspec(dllexport) int SetFlag(int type, int enable) {
        return PlayerManager::SetFlag(type, enable);
    }

    __declspec(dllexport) int InjectAddValue(int target, int value) {
        return CheatManager::InjectAddValue(target, value);
    }

    __declspec(dllexport) int SetOneHitKill(int enable) {
        return CheatManager::SetOneHitKill(enable);
    }

    // 遗物相关接口
    __declspec(dllexport) void InitCSGaitemAddress() {
        AddressScanner::ScanCSGaitem();
    }

    __declspec(dllexport) int GetAllRelics(RelicRawData* outBuffer) {
        return InventoryManager::GetAllRelics(outBuffer);
    }

    __declspec(dllexport) int SetRelicData(int relicIndex, int fieldIndex, int value) {
        return InventoryManager::SetRelicData(relicIndex, fieldIndex, value);
    }
}
