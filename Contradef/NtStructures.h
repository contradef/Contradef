#pragma once
#ifndef NT_STRUCTURES_H
#define NT_STRUCTURES_H

#include <iostream>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define NTAPI

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

#undef far
#undef near
#undef pascal

#define far
#define near

#undef FAR
#undef  NEAR
#define FAR                 far
#define NEAR                near
#ifndef CONST
#define CONST               const
#endif

typedef UINT64 HWND;   // HWND é normalmente um ponteiro ou um valor integral
typedef const char* LPCTSTR;
typedef void* HINSTANCE;
typedef void* LPVOID;
typedef void* HKEY;

typedef BOOL* PBOOL;
typedef int LONG;
typedef void* PVOID;
typedef unsigned short USHORT;
typedef USHORT* PUSHORT;
typedef unsigned char UCHAR;
typedef UCHAR* PUCHAR;
typedef int LONG;
typedef LONG NTSTATUS;
typedef wchar_t WCHAR; // Caracter de 16 bits no Windows
typedef unsigned long ULONG;
typedef ULONG* PULONG;
typedef wchar_t* PWSTR; // Ponteiro para uma string de caracteres wide (Unicode)
typedef void* HANDLE; // Um identificador para um objeto do Windows


typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef int                 INT;
typedef unsigned int        UINT;
typedef unsigned int* PUINT;


#include <cstdint>
#if defined(_WIN64)
typedef uint64_t ULONG_PTR;

typedef __int64 INT_PTR, * PINT_PTR;
typedef unsigned __int64 UINT_PTR, * PUINT_PTR;

typedef __int64 LONG_PTR, * PLONG_PTR;
typedef unsigned __int64 ULONG_PTR, * PULONG_PTR;

#define __int3264   __int64
#else
typedef uint32_t ULONG_PTR;

typedef _W64 int INT_PTR, * PINT_PTR;
typedef _W64 unsigned int UINT_PTR, * PUINT_PTR;

typedef _W64 long LONG_PTR, * PLONG_PTR;
typedef _W64 unsigned long ULONG_PTR, * PULONG_PTR;

#define __int3264   __int32
#endif

typedef ULONG_PTR DWORD_PTR, * PDWORD_PTR;

typedef ULONG_PTR SIZE_T, * PSIZE_T;
typedef LONG_PTR SSIZE_T, * PSSIZE_T;


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer; //PWSTR alterado para o tipo PVOID
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;                   // Tamanho da estrutura em bytes
    HANDLE RootDirectory;           // Handle para o diretório raiz (ou NULL)
    PUNICODE_STRING ObjectName;     // Nome do objeto (pode ser NULL)
    ULONG Attributes;               // Flags de atributos
    PVOID SecurityDescriptor;       // Descritor de segurança (ou NULL)
    PVOID SecurityQualityOfService; // Qualidade de serviço de segurança (ou NULL)
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION // Themida antianalisys, é antidebug?
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX // Themida antianalisys, é antidebug?
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2 // Themida antianalisys, é antidebug?
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE // Debug present
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION // Themida antianalisys, é antidebug?
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR // Themida antianalisys, é antidebug? Pesquisar mais
    ProcessImageFileName, // q: UNICODE_STRING // Themida antianalisys, é antidebug? Pesquisar mais e ver o processamento posterior se tem algum tratamento para nomes de arquivos ou processos 
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30 // Debug present
    ProcessDebugFlags, // qs: ULONG // Debug present
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION // Themida antianalisys, é antidebug? Pesquisar mais
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40  // Debug present
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG  // pode ser antidebug? Pesquisar mais
    ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION // Themida antianalisys, é antidebug? Pesquisar mais
    ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
    ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation, // Themida antianalisys, é antidebug? Pesquisar mais <-----------------
    ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
    ProcessAltPrefetchParam, // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
    ProcessEffectivePagePriority, // q: ULONG
    MaxProcessInfoClass
} PROCESSINFOCLASS;

///*
//classes usadas para detecção de debug e antianalise:
//    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION // Themida antianalisys, é antidebug?
//    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX // Themida antianalisys, é antidebug?
//    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2 // Themida antianalisys, é antidebug?
//    ProcessDebugPort, // q: HANDLE // Debug present
//    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION // Themida antianalisys, é antidebug?
//    ProcessWow64Information, // q: ULONG_PTR // Themida antianalisys, é antidebug? Pesquisar mais
//    ProcessImageFileName, // q: UNICODE_STRING // Themida antianalisys, é antidebug? Pesquisar mais e ver o processamento posterior se tem algum tratamento para nomes de arquivos ou processos
//    ProcessDebugObjectHandle, // q: HANDLE // 30 // Debug present
//    ProcessDebugFlags, // qs: ULONG // Debug present
//    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION // Themida antianalisys, é antidebug? Pesquisar mais
//    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40  // Debug present
//    ProcessTokenVirtualizationEnabled, // s: ULONG  // pode ser antidebug? Pesquisar mais
//    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION // Themida antianalisys, é antidebug? Pesquisar mais
//    ProcessEnclaveInformation, // Themida antianalisys, é antidebug? Pesquisar mais <-----------------
//
//*/

typedef CHAR* PCHAR, * LPCH, * PCH;

typedef wchar_t WCHAR;
typedef WCHAR* PWCHAR, * LPWCH, * PWCH;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef
VOID
(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
    VOID
    );

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, * PPEB;

// Definição da estrutura PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;  // Usando PVOID em vez de PPEB
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;


typedef double LONGLONG;
typedef double ULONGLONG;
typedef LONGLONG* PLONGLONG;
typedef ULONGLONG* PULONGLONG;
typedef LONGLONG USN;



// Memory Basic Info

#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
#define SECTION_EXTEND_SIZE          0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020 // not included in SECTION_ALL_ACCESS

#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
                            SECTION_MAP_WRITE |      \
                            SECTION_MAP_READ |       \
                            SECTION_MAP_EXECUTE |    \
                            SECTION_EXTEND_SIZE)

//
// Session Specific Access Rights.
//

#define SESSION_QUERY_ACCESS  0x0001
#define SESSION_MODIFY_ACCESS 0x0002

#define SESSION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED |  \
                            SESSION_QUERY_ACCESS |             \
                            SESSION_MODIFY_ACCESS)

// end_access
#define PAGE_NOACCESS           0x01    
#define PAGE_READONLY           0x02    
#define PAGE_READWRITE          0x04    
#define PAGE_WRITECOPY          0x08    
#define PAGE_EXECUTE            0x10    
#define PAGE_EXECUTE_READ       0x20    
#define PAGE_EXECUTE_READWRITE  0x40    
#define PAGE_EXECUTE_WRITECOPY  0x80    
#define PAGE_GUARD             0x100    
#define PAGE_NOCACHE           0x200    
#define PAGE_WRITECOMBINE      0x400    
#define PAGE_GRAPHICS_NOACCESS           0x0800    
#define PAGE_GRAPHICS_READONLY           0x1000    
#define PAGE_GRAPHICS_READWRITE          0x2000    
#define PAGE_GRAPHICS_EXECUTE            0x4000    
#define PAGE_GRAPHICS_EXECUTE_READ       0x8000    
#define PAGE_GRAPHICS_EXECUTE_READWRITE 0x10000    
#define PAGE_GRAPHICS_COHERENT          0x20000    
#define PAGE_GRAPHICS_NOCACHE           0x40000    
#define PAGE_ENCLAVE_THREAD_CONTROL 0x80000000  
#define PAGE_REVERT_TO_FILE_MAP     0x80000000  
#define PAGE_TARGETS_NO_UPDATE      0x40000000  
#define PAGE_TARGETS_INVALID        0x40000000  
#define PAGE_ENCLAVE_UNVALIDATED    0x20000000  
#define PAGE_ENCLAVE_MASK           0x10000000  
#define PAGE_ENCLAVE_DECOMMIT       (PAGE_ENCLAVE_MASK | 0) 
#define PAGE_ENCLAVE_SS_FIRST       (PAGE_ENCLAVE_MASK | 1) 
#define PAGE_ENCLAVE_SS_REST        (PAGE_ENCLAVE_MASK | 2) 
#define MEM_COMMIT                      0x00001000  
#define MEM_RESERVE                     0x00002000  
#define MEM_REPLACE_PLACEHOLDER         0x00004000  
#define MEM_RESERVE_PLACEHOLDER         0x00040000  
#define MEM_RESET                       0x00080000  
#define MEM_TOP_DOWN                    0x00100000  
#define MEM_WRITE_WATCH                 0x00200000  
#define MEM_PHYSICAL                    0x00400000  
#define MEM_ROTATE                      0x00800000  
#define MEM_DIFFERENT_IMAGE_BASE_OK     0x00800000  
#define MEM_RESET_UNDO                  0x01000000  
#define MEM_LARGE_PAGES                 0x20000000  
#define MEM_4MB_PAGES                   0x80000000  
#define MEM_64K_PAGES                   (MEM_LARGE_PAGES | MEM_PHYSICAL)  
#define MEM_UNMAP_WITH_TRANSIENT_BOOST  0x00000001  
#define MEM_COALESCE_PLACEHOLDERS       0x00000001  
#define MEM_PRESERVE_PLACEHOLDER        0x00000002  
#define MEM_DECOMMIT                    0x00004000  
#define MEM_RELEASE                     0x00008000  
#define MEM_FREE                        0x00010000  

#define MEM_PRIVATE                 0x00020000  
#define MEM_MAPPED                  0x00040000  
#define MEM_IMAGE                   0x01000000  
#define WRITE_WATCH_FLAG_RESET  0x01    

#define ENCLAVE_TYPE_SGX            0x00000001
#define ENCLAVE_TYPE_SGX2           0x00000002

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
#if defined (_WIN64)
    WORD   PartitionId;
#endif
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;


typedef struct _MEMORY_BASIC_INFORMATION32 {
    DWORD BaseAddress;
    DWORD AllocationBase;
    DWORD AllocationProtect;
    DWORD RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION32, * PMEMORY_BASIC_INFORMATION32;

#ifndef DECLSPEC_ALIGN
#if (_MSC_VER >= 1300) && !defined(MIDL_PASS)
#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#else
#define DECLSPEC_ALIGN(x)
#endif
#endif

typedef struct DECLSPEC_ALIGN(16) _MEMORY_BASIC_INFORMATION64 {
    ULONGLONG BaseAddress;
    ULONGLONG AllocationBase;
    DWORD     AllocationProtect;
    DWORD     __alignment1;
    ULONGLONG RegionSize;
    DWORD     State;
    DWORD     Protect;
    DWORD     Type;
    DWORD     __alignment2;
} MEMORY_BASIC_INFORMATION64, * PMEMORY_BASIC_INFORMATION64;
// End Memory Basic Info


// Definição do IMAGE_DATA_DIRECTORY
typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress; // Endereço virtual
    uint32_t Size;           // Tamanho
} IMAGE_DATA_DIRECTORY;

// Estrutura IMAGE_FILE_HEADER
typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;              // Identifica a arquitetura do processador
    uint16_t NumberOfSections;     // Número de seções no arquivo
    uint32_t TimeDateStamp;        // Data e hora de criação
    uint32_t PointerToSymbolTable; // Ponteiro para a tabela de símbolos (se aplicável)
    uint32_t NumberOfSymbols;      // Número de símbolos (se aplicável)
    uint16_t SizeOfOptionalHeader; // Tamanho do cabeçalho opcional
    uint16_t Characteristics;       // Características do arquivo
} IMAGE_FILE_HEADER;

// Estrutura IMAGE_OPTIONAL_HEADER
typedef struct _IMAGE_OPTIONAL_HEADER {
    uint16_t Magic;                       // Identifica o formato do cabeçalho
    uint8_t MajorLinkerVersion;           // Versão principal do vinculador
    uint8_t MinorLinkerVersion;           // Versão secundária do vinculador
    uint32_t SizeOfCode;                  // Tamanho da seção de código
    uint32_t SizeOfInitializedData;       // Tamanho da seção de dados inicializados
    uint32_t SizeOfUninitializedData;     // Tamanho da seção de dados não inicializados
    uint32_t AddressOfEntryPoint;         // Endereço do ponto de entrada
    uint32_t BaseOfCode;                  // Endereço base da seção de código
    uint32_t BaseOfData;                  // Endereço base da seção de dados (opcional)
    uint32_t ImageBase;                   // Endereço base do módulo na memória
    uint32_t SectionAlignment;             // Alinhamento das seções na memória
    uint32_t FileAlignment;                // Alinhamento das seções no arquivo
    uint16_t MajorOperatingSystemVersion; // Versão principal do sistema operacional
    uint16_t MinorOperatingSystemVersion; // Versão secundária do sistema operacional
    uint16_t MajorImageVersion;           // Versão principal da imagem
    uint16_t MinorImageVersion;           // Versão secundária da imagem
    uint16_t MajorSubsystemVersion;       // Versão principal do subsistema
    uint16_t MinorSubsystemVersion;       // Versão secundária do subsistema
    uint32_t Win32VersionValue;           // Valor da versão do Windows
    uint32_t SizeOfImage;                 // Tamanho da imagem (na memória)
    uint32_t SizeOfHeaders;               // Tamanho dos cabeçalhos
    uint32_t CheckSum;                    // Checksum do arquivo
    uint16_t Subsystem;                   // Subsistema para o qual o arquivo foi criado
    uint16_t DLLCharacteristics;          // Características do DLL
    uint32_t SizeOfStackReserve;          // Tamanho da pilha reservada
    uint32_t SizeOfStackCommit;           // Tamanho da pilha comprometida
    uint32_t SizeOfHeapReserve;           // Tamanho do heap reservado
    uint32_t SizeOfHeapCommit;            // Tamanho do heap comprometido
    uint16_t LoaderFlags;                 // Indicadores de carregamento
    uint16_t NumberOfRvaAndSizes;         // Número de RVA e tamanhos
    IMAGE_DATA_DIRECTORY DataDirectory[16]; // Diretórios de dados
} IMAGE_OPTIONAL_HEADER;



// Estrutura IMAGE_DOS_HEADER
typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;     // 0x5A4D "MZ"
    uint16_t e_cblp;      // Número de bytes no último página
    uint16_t e_cp;        // Número de páginas
    uint16_t e_crlc;      // Número de relocações
    uint16_t e_cparhdr;   // Tamanho do cabeçalho em parágrafos
    uint16_t e_minalloc;  // Tamanho mínimo da memória requerida
    uint16_t e_maxalloc;  // Tamanho máximo da memória requerida
    uint16_t e_ss;        // Número da seção de pilha
    uint16_t e_sp;        // Offset da pilha
    uint16_t e_csum;      // Checksum
    uint16_t e_ip;        // Offset do programa
    uint16_t e_cs;        // Número do segmento
    uint16_t e_lfarlc;    // Offset do cabeçalho em bytes
    uint16_t e_ovno;      // Número de número de versão
    uint16_t e_res[4];    // Reservado
    uint16_t e_oemid;     // ID do OEM
    uint16_t e_oeminfo;   // Informação do OEM
    uint16_t e_res2[10];  // Reservado
    int32_t e_lfanew;     // Offset para o cabeçalho PE
} IMAGE_DOS_HEADER;

// Estrutura IMAGE_NT_HEADERS
typedef struct _IMAGE_NT_HEADERS {
    uint32_t Signature;                // 0x00004550 "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;      // Cabeçalho do arquivo
    IMAGE_OPTIONAL_HEADER OptionalHeader; // Cabeçalho opcional
} IMAGE_NT_HEADERS;

// Estrutura IMAGE_SECTION_HEADER
typedef struct _IMAGE_SECTION_HEADER {
    uint8_t Name[8];                   // Nome da seção
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;           // Endereço virtual da seção
    uint32_t SizeOfRawData;            // Tamanho dos dados brutos
    uint32_t PointerToRawData;         // Ponteiro para os dados brutos
    uint32_t PointerToRelocations;     // Ponteiro para relocação
    uint32_t PointerToLinenumbers;     // Ponteiro para números de linha
    uint16_t NumberOfRelocations;      // Número de relocação
    uint16_t NumberOfLinenumbers;      // Número de números de linha
    uint32_t Characteristics;           // Características da seção
} IMAGE_SECTION_HEADER;
//#define IMAGE_FIRST_SECTION(ntHeader) ((IMAGE_SECTION_HEADER *)((BYTE *)(ntHeader) + sizeof(IMAGE_NT_HEADERS)))
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D      // 'MZ' em ASCII
#endif

#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE 0x00004550  // 'PE\0\0' em ASCII
#endif

//SYSTEM INFORMATION 
//typedef struct _SYSTEM_PROCESS_INFORMATION {
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    BYTE Reserved1[48];
//    UNICODE_STRING ImageName;
//    KPRIORITY BasePriority;
//    HANDLE UniqueProcessId;
//    PVOID Reserved2;
//    ULONG HandleCount;
//    ULONG SessionId;
//    PVOID Reserved3;
//    SIZE_T PeakVirtualSize;
//    SIZE_T VirtualSize;
//    ULONG Reserved4;
//    SIZE_T PeakWorkingSetSize;
//    SIZE_T WorkingSetSize;
//    PVOID Reserved5;
//    SIZE_T QuotaPagedPoolUsage;
//    PVOID Reserved6;
//    SIZE_T QuotaNonPagedPoolUsage;
//    SIZE_T PagefileUsage;
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//    LARGE_INTEGER Reserved7[6];
//} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformationObsolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPatchInformation,
    SystemVerifierFaultsInformation,
    SystemSystemPartitionInformation,
    SystemSystemDiskInformation,
    SystemProcessorPerformanceDistribution,
    SystemNumaProximityNodeInformation,
    SystemDynamicTimeZoneInformation,
    SystemCodeIntegrityInformation,
    SystemProcessorMicrocodeUpdateInformation,
    SystemProcessorBrandString,
    SystemVirtualAddressInformation,
    SystemLogicalProcessorAndGroupInformation,
    SystemProcessorCycleTimeInformation,
    SystemStoreInformation,
    SystemRegistryAppendString,
    SystemAitSamplingValue,
    SystemVhdBootInformation,
    SystemCpuQuotaInformation,
    SystemNativeBasicInformation,
    SystemErrorPortTimeouts,
    SystemLowPriorityIoInformation,
    SystemBootEntropyInformation,
    SystemVerifierCountersInformation,
    SystemPagedPoolInformationEx,
    SystemSystemPtesInformationEx,
    SystemNodeDistanceInformation,
    SystemAcpiAuditInformation,
    SystemBasicPerformanceInformation,
    SystemQueryPerformanceCounterInformation,
    SystemSessionBigPoolInformation,
    SystemBootGraphicsInformation,
    SystemScrubPhysicalMemoryInformation,
    SystemBadPageInformation,
    SystemProcessorProfileControlArea,
    SystemCombinePhysicalMemoryInformation,
    SystemEntropyInterruptTimingInformation,
    SystemConsoleInformation,
    SystemPlatformBinaryInformation,
    SystemPolicyInformation,
    SystemHypervisorProcessorCountInformation,
    SystemDeviceDataInformation,
    SystemDeviceDataEnumerationInformation,
    SystemMemoryTopologyInformation,
    SystemMemoryChannelInformation,
    SystemBootLogoInformation,
    SystemProcessorPerformanceInformationEx,
    SystemCriticalProcessErrorLogInformation,
    SystemSecureBootPolicyInformation,
    SystemPageFileInformationEx,
    SystemSecureBootInformation,
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation,
    SystemFullProcessInformation,
    SystemKernelDebuggerInformationEx,
    SystemBootMetadataInformation,
    SystemSoftRebootInformation,
    SystemElamCertificateInformation,
    SystemOfflineDumpConfigInformation,
    SystemProcessorFeaturesInformation,
    SystemRegistryReconciliationInformation,
    SystemEdidInformation,
    SystemManufacturingInformation,
    SystemEnergyEstimationConfigInformation,
    SystemHypervisorDetailInformation,
    SystemProcessorCycleStatsInformation,
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation,
    SystemKernelDebuggerFlags,
    SystemCodeIntegrityPolicyInformation,
    SystemIsolatedUserModeInformation,
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation,
    SystemAllowedCpuSetsInformation,
    SystemDmaProtectionInformation,
    SystemInterruptCpuSetsInformation,
    SystemSecureBootPolicyFullInformation,
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation,
    SystemRootSiloInformation,
    SystemCpuSetInformation,
    SystemCpuSetTagInformation,
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation,
    SystemCodeIntegrityPlatformManifestInformation,
    SystemInterruptSteeringInformation,
    SystemSuppportedProcessorArchitectures,
    SystemMemoryUsageInformation,
    SystemCodeIntegrityCertificateInformation,
    SystemPhysicalMemoryInformation,
    SystemControlFlowTransition,
    SystemKernelDebuggingAllowed,
    SystemActivityModerationExeState,
    SystemActivityModerationUserSettings,
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegrityUnlockInformation,
    SystemIntegrityQuotaInformation,
    SystemFlushInformation,
    SystemProcessorIdleMaskInformation,
    SystemSecureDumpEncryptionInformation,
    SystemWriteConstraintInformation,
    SystemKernelVaShadowInformation,
    SystemHypervisorSharedPageInformation,
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation,
    SystemFirmwarePartitionInformation,
    SystemSpeculationControlInformation,
    SystemDmaGuardPolicyInformation,
    SystemEnclaveLaunchControlInformation,
    SystemWorkloadAllowedCpuSetsInformation,
    SystemCodeIntegrityUnlockModeInformation,
    SystemLeapSecondInformation,
    SystemFlags2Information,
    SystemSecurityModelInformation,
    SystemCodeIntegritySyntheticCacheInformation,
    SystemFeatureConfigurationInformation,
    SystemFeatureConfigurationSectionInformation,
    SystemFeatureUsageSubscriptionInformation,
    SystemSecureSpeculationControlInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
//END SYSTEM INFORMATION CLASS

// THREADS
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    ThreadCpuAccountingInformation,
    ThreadSuspendCount,
    ThreadHeterogeneousCpuPolicy,
    ThreadContainerId,
    ThreadNameInformation,
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation,
    ThreadActualGroupAffinity,
    ThreadDynamicCodePolicyInfo,
    ThreadExplicitCaseSensitivity,
    ThreadWorkOnBehalfTicket,
    ThreadSubsystemInformation,
    ThreadDbgkWerReportActive,
    ThreadAttachContainer,
    MaxThreadInfoClass,
} THREADINFOCLASS;

// END THREDS

#endif // NT_STRUCTURES_H