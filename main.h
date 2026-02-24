#include <Windows.h> 
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <string_view>
#include <vector>
#include <TlHelp32.h>
#include <memory>
#include <conio.h>
#include <stdio.h>
#include <optional>
#include <ranges>
#include <memory>
#include <stdexcept>
#include <fstream>
#include <psapi.h>
#include <map>



#pragma once

extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE hProcess, LPVOID pBaseAddress, LPVOID pBuffer, SIZE_T bytesToWrite, PSIZE_T pBytesWritten);
extern "C" NTSTATUS NTAPI NtReadVirtualMemory(HANDLE hProcess, LPVOID pBaseAddress, LPVOID pBuffer, SIZE_T bytesToRead, PSIZE_T bytesRead);
extern "C" NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE hProcess, LPVOID pBaseAddress, PULONG pBytesToProtect, ULONG newProtect, PULONG pOldProtect);

#define get_window_thread_process_id GetWindowThreadProcessId
#define find_window FindWindowA
#define close_handle CloseHandle
#define get_process_id GetProcessId
#define get_current_process GetCurrentProcess
#define ntstatus NTSTATUS
#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7
#define system_handle_information 16
#define SystemHandleInformation 16 
#define psystem_handle_information SYSTEM_HANDLE_INFORMATION*
#define status_info_length_mismatch STATUS_INFO_LENGTH_MISMATCH
#define process_handle_type ProcessHandleType
#define process_dup_handle PROCESS_DUP_HANDLE
#define process_all_access PROCESS_ALL_ACCESS
#define null 0 
#define pulong PULONG
#define ulong ULONG

using image_dos_header = IMAGE_DOS_HEADER;
using image_nt_header = IMAGE_NT_HEADERS;
using image_file_header = IMAGE_FILE_HEADER;
using image_optional_header = IMAGE_OPTIONAL_HEADER;
using boolean = BOOLEAN;
using byte = BYTE;
using dword = DWORD;
using hmodule = HMODULE;
using farproc = FARPROC;
using handle = HANDLE;
using dword_ptr = DWORD_PTR;


typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );


struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
};

struct OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
};

struct CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
};

struct SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
};

struct SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
};

typedef NTSTATUS(NTAPI* NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved
    );

typedef NTSTATUS(NTAPI* RtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled
    );

typedef NTSYSAPI NTSTATUS(NTAPI* NtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    CLIENT_ID* ClientId
    );

typedef NTSTATUS(NTAPI* NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;    
    PVOID PebBaseAddress;  
    PVOID Reserved2[2];   
    ULONG_PTR UniqueProcessId;   
    ULONG_PTR InheritedFromUniqueProcessId; 
} PROCESS_BASIC_INFORMATION;



typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessResourceManagement,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessOwnerInformation,
    ProcessWindowInformation,
    ProcessHandleInformation,
    ProcessMitigationPolicy,
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode,
    ProcessKeepAliveCount,
    ProcessRevokeFileHandles,
    ProcessWorkingSetControl,
    ProcessHandleTable,
    ProcessCheckStackExtentsMode,
    ProcessCommandLineInformation,
    ProcessProtectionInformation,
    ProcessMemoryExhaustion,
    ProcessFaultInformation,
    ProcessTelemetryIdInformation,
    ProcessCommitReleaseInformation,
    ProcessDefaultCpuSetsInformation,
    ProcessAllowedCpuSetsInformation,
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation,
    ProcessInPrivate,
    ProcessRaiseUMExceptionOnInvalidHandleClose,
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation,
    ProcessHighGraphicsPriorityInformation,
    ProcessSubsystemInformation,
    ProcessEnergyValues,
    ProcessActivityThrottleState,
    ProcessActivityThrottlePolicy,
    ProcessWin32kSyscallFilterInformation,
    ProcessDisableSystemAllowedCpuSets,
    ProcessWakeInformation,
    ProcessEnergyTrackingState,
    ProcessManageWritesToExecutableMemory,
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging,
    ProcessUptimeInformation,
    ProcessImageSection,
    ProcessDebugAuthInformation,
    ProcessSystemResourceManagement,
    ProcessSequenceNumber,
    ProcessLoaderDetour,
    ProcessSecurityDomainInformation,
    ProcessCombineSecurityDomainsInformation,
    ProcessEnableLogging,
    ProcessLeapSecondInformation,
    ProcessFiberShadowStackAllocation,
    ProcessFreeFiberShadowStackAllocation,
    ProcessAltSystemCallInformation,
    ProcessDynamicEHContinuationTargets,
    ProcessDynamicEnforcedCetCompatibleRanges,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef NTSTATUS(NTAPI* NtQueryInformationProcess)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS(NTAPI* pNtQueryInfo)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
    );



typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;



FARPROC resolve_address(_In_ const char* function_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        std::cout << "[-] " << function_name << " is null\n";
        return nullptr;
    }
    return GetProcAddress(ntdll, function_name);
}

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR dll_name);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE dll_base, LPCSTR process_name);
typedef BOOL(WINAPI* pDllMain)(HMODULE dll_base, DWORD reason, LPVOID x);
typedef BOOLEAN(WINAPIV* pRtlAddFunctionTable)(PRUNTIME_FUNCTION function_table, DWORD entry_count, DWORD64 base_address);


typedef struct {
    HMODULE dll_base;
    pLoadLibraryA load_librarya;
    pGetProcAddress get_process_address;
    pRtlAddFunctionTable rtl_add_fujnction_table;
    IMAGE_OPTIONAL_HEADER optional_header;
} injection_structure;

struct relocation_information{
    uintptr_t relocation_entries = 0;
    dword_ptr* patched_addresses;
    BASE_RELOCATION_ENTRY* rva = 0;
};




typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;                                // +0x00
    UCHAR Initialized;                           // +0x04
    PVOID SsHandle;                              // +0x08
    LIST_ENTRY InLoadOrderModuleList;            // +0x10
    LIST_ENTRY InMemoryOrderModuleList;          // +0x20
    LIST_ENTRY InInitializationOrderModuleList;  // +0x30


} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef void (*PPS_POST_PROCESS_INIT_ROUTINE)(void);
typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;



typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;               // +0x00
    LIST_ENTRY InMemoryOrderLinks;             // +0x10
    LIST_ENTRY InInitializationOrderLinks;     // +0x20
    PVOID DllBase;                             // +0x30
    PVOID EntryPoint;                          // +0x38
    ULONG SizeOfImage;                         // +0x40
    UNICODE_STRING FullDllName;                // +0x48
    UNICODE_STRING BaseDllName;                // +0x58
    ULONG Flags;                               // +0x68
    USHORT LoadCount;                          // +0x6C
    USHORT TlsIndex;                           // +0x6E
    LIST_ENTRY HashLinks;                      // +0x70
    ULONG TimeDateStamp;                       // +0x80
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


bool manual_map(_In_ std::string_view process_window_name, _In_ const char* dll_path);
