/* ntdll.h.  Contains ntdll specific stuff not defined elsewhere.

   Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
   2009, 2010 Red Hat, Inc.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */

#ifndef _NTDLL_H
#define _NTDLL_H 1
#define STATUS_NOT_ALL_ASSIGNED       ((NTSTATUS) 0x00000106)
#define STATUS_OBJECT_NAME_EXISTS     ((NTSTATUS) 0x40000000)
#define STATUS_BUFFER_OVERFLOW        ((NTSTATUS) 0x80000005)
#define STATUS_NO_MORE_FILES          ((NTSTATUS) 0x80000006)
#ifndef STATUS_INVALID_INFO_CLASS
/* Some w32api header file defines this so we need to conditionalize this
   define to avoid warnings. */
#define STATUS_INVALID_INFO_CLASS     ((NTSTATUS) 0xc0000003)
#endif
#define STATUS_INFO_LENGTH_MISMATCH   ((NTSTATUS) 0xc0000004)
#define STATUS_INVALID_PARAMETER      ((NTSTATUS) 0xc000000d)
#define STATUS_NO_SUCH_FILE           ((NTSTATUS) 0xc000000f)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS) 0xc0000010)
#define STATUS_END_OF_FILE            ((NTSTATUS) 0xc0000011)
#define STATUS_NO_MEDIA_IN_DEVICE     ((NTSTATUS) 0xc0000013)
#define STATUS_ACCESS_DENIED          ((NTSTATUS) 0xc0000022)
#define STATUS_BUFFER_TOO_SMALL       ((NTSTATUS) 0xc0000023)
#define STATUS_OBJECT_NAME_INVALID    ((NTSTATUS) 0xc0000033)
#define STATUS_OBJECT_NAME_NOT_FOUND  ((NTSTATUS) 0xc0000034)
#define STATUS_OBJECT_PATH_NOT_FOUND  ((NTSTATUS) 0xc000003A)
#define STATUS_SHARING_VIOLATION      ((NTSTATUS) 0xc0000043)
#define STATUS_EAS_NOT_SUPPORTED      ((NTSTATUS) 0xc000004f)
#define STATUS_EA_TOO_LARGE           ((NTSTATUS) 0xc0000050)
#define STATUS_NONEXISTENT_EA_ENTRY   ((NTSTATUS) 0xc0000051)
#define STATUS_NO_EAS_ON_FILE         ((NTSTATUS) 0xc0000052)
#define STATUS_LOCK_NOT_GRANTED       ((NTSTATUS) 0xc0000055)
#define STATUS_DELETE_PENDING         ((NTSTATUS) 0xc0000056)
#define STATUS_DISK_FULL              ((NTSTATUS) 0xc000007f)
#define STATUS_WORKING_SET_QUOTA      ((NTSTATUS) 0xc00000a1)
#define STATUS_NOT_SUPPORTED          ((NTSTATUS) 0xc00000bb)
#define STATUS_BAD_NETWORK_PATH       ((NTSTATUS) 0xc00000be)
#define STATUS_INVALID_NETWORK_RESPONSE ((NTSTATUS) 0xc00000c3)
#define STATUS_BAD_NETWORK_NAME       ((NTSTATUS) 0xc00000cc)
#define STATUS_DIRECTORY_NOT_EMPTY    ((NTSTATUS) 0xc0000101)
#define STATUS_CANNOT_DELETE          ((NTSTATUS) 0xc0000121)
#define STATUS_INVALID_LEVEL          ((NTSTATUS) 0xc0000148)
#define STATUS_DLL_NOT_FOUND          ((NTSTATUS) 0xc0000135)
#define STATUS_ENTRYPOINT_NOT_FOUND   ((NTSTATUS) 0xc0000139)
#define STATUS_BAD_DLL_ENTRYPOINT     ((NTSTATUS) 0xc0000251)
#define STATUS_ILLEGAL_DLL_RELOCATION ((NTSTATUS) 0xc0000269)
/* custom status code: */
#define STATUS_ILLEGAL_DLL_PSEUDO_RELOCATION ((NTSTATUS) 0xe0000269)

#define PDI_MODULES 0x01
#define PDI_HEAPS 0x04
#define LDRP_IMAGE_DLL 0x00000004
#define WSLE_PAGE_READONLY 0x001
#define WSLE_PAGE_EXECUTE 0x002
#define WSLE_PAGE_EXECUTE_READ 0x003
#define WSLE_PAGE_READWRITE 0x004
#define WSLE_PAGE_WRITECOPY 0x005
#define WSLE_PAGE_EXECUTE_READWRITE 0x006
#define WSLE_PAGE_EXECUTE_WRITECOPY 0x007
#define WSLE_PAGE_SHARE_COUNT_MASK 0x0E0
#define WSLE_PAGE_SHAREABLE 0x100

#define FILE_SUPERSEDED     0
#define FILE_OPENED         1
#define FILE_CREATED        2
#define FILE_OVERWRITTEN    3
#define FILE_EXISTS         4
#define FILE_DOES_NOT_EXIST 5

#define FILE_WRITE_TO_END_OF_FILE      (-1LL)
#define FILE_USE_FILE_POINTER_POSITION (-2LL)

/* Device Characteristics. */
#define FILE_REMOVABLE_MEDIA           0x00000001
#define FILE_READ_ONLY_DEVICE          0x00000002
#define FILE_FLOPPY_DISKETTE           0x00000004
#define FILE_WRITE_ONCE_MEDIA          0x00000008
#define FILE_REMOTE_DEVICE             0x00000010
#define FILE_DEVICE_IS_MOUNTED         0x00000020
#define FILE_VIRTUAL_VOLUME            0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME 0x00000080
#define FILE_DEVICE_SECURE_OPEN        0x00000100

/* Transaction access rights. */
#define TRANSACTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x3F)

typedef enum _FILE_INFORMATION_CLASS
{
  FileDirectoryInformation = 1,
  FileFullDirectoryInformation, // 2
  FileBothDirectoryInformation, // 3
  FileBasicInformation, // 4 wdm
  FileStandardInformation, // 5 wdm
  FileInternalInformation, // 6
  FileEaInformation, // 7
  FileAccessInformation, // 8
  FileNameInformation, // 9
  FileRenameInformation, // 10
  FileLinkInformation, // 11
  FileNamesInformation, // 12
  FileDispositionInformation, // 13
  FilePositionInformation, // 14 wdm
  FileFullEaInformation, // 15
  FileModeInformation, // 16
  FileAlignmentInformation, // 17
  FileAllInformation, // 18
  FileAllocationInformation, // 19
  FileEndOfFileInformation, // 20 wdm
  FileAlternateNameInformation, // 21
  FileStreamInformation, // 22
  FilePipeInformation, // 23
  FilePipeLocalInformation, // 24
  FilePipeRemoteInformation, // 25
  FileMailslotQueryInformation, // 26
  FileMailslotSetInformation, // 27
  FileCompressionInformation, // 28
  FileObjectIdInformation, // 29
  FileCompletionInformation, // 30
  FileMoveClusterInformation, // 31
  FileQuotaInformation, // 32
  FileReparsePointInformation, // 33
  FileNetworkOpenInformation, // 34
  FileAttributeTagInformation, // 35
  FileTrackingInformation, // 36
  FileIdBothDirectoryInformation, // 37
  FileIdFullDirectoryInformation, // 38
  FileValidDataLengthInformation, // 39
  FileShortNameInformation, // 40
  FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_NAMES_INFORMATION
{
  ULONG  NextEntryOffset;
  ULONG  FileIndex;
  ULONG  FileNameLength;
  WCHAR  FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
  ULONG  NextEntryOffset;
  ULONG  FileIndex;
  LARGE_INTEGER  CreationTime;
  LARGE_INTEGER  LastAccessTime;
  LARGE_INTEGER  LastWriteTime;
  LARGE_INTEGER  ChangeTime;
  LARGE_INTEGER  EndOfFile;
  LARGE_INTEGER  AllocationSize;
  ULONG  FileAttributes;
  ULONG  FileNameLength;
  WCHAR  FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_BOTH_DIRECTORY_INFORMATION
{
  ULONG  NextEntryOffset;
  ULONG  FileIndex;
  LARGE_INTEGER  CreationTime;
  LARGE_INTEGER  LastAccessTime;
  LARGE_INTEGER  LastWriteTime;
  LARGE_INTEGER  ChangeTime;
  LARGE_INTEGER  EndOfFile;
  LARGE_INTEGER  AllocationSize;
  ULONG  FileAttributes;
  ULONG  FileNameLength;
  ULONG  EaSize;
  CCHAR  ShortNameLength;
  WCHAR  ShortName[12];
  WCHAR  FileName[1];
} FILE_BOTH_DIRECTORY_INFORMATION, *PFILE_BOTH_DIRECTORY_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION
{
  ULONG  NextEntryOffset;
  ULONG  FileIndex;
  LARGE_INTEGER  CreationTime;
  LARGE_INTEGER  LastAccessTime;
  LARGE_INTEGER  LastWriteTime;
  LARGE_INTEGER  ChangeTime;
  LARGE_INTEGER  EndOfFile;
  LARGE_INTEGER  AllocationSize;
  ULONG  FileAttributes;
  ULONG  FileNameLength;
  ULONG  EaSize;
  CCHAR  ShortNameLength;
  WCHAR  ShortName[12];
  LARGE_INTEGER  FileId;
  WCHAR  FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;


#define AT_EXTENDABLE_FILE 0x00002000
#define AT_ROUND_TO_PAGE 0x40000000

#define LOCK_VM_IN_WSL 1
#define LOCK_VM_IN_RAM 2

#define DIRECTORY_QUERY 1
#define DIRECTORY_TRAVERSE 2
#define DIRECTORY_CREATE_OBJECT 4
#define DIRECTORY_CREATE_SUBDIRECTORY 8
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|0x0f)

#define EVENT_QUERY_STATE 1
#define SEMAPHORE_QUERY_STATE 1

/* Specific ACCESS_MASKSs for objects created in Cygwin. */
#define CYG_SHARED_DIR_ACCESS	(DIRECTORY_QUERY \
				 | DIRECTORY_TRAVERSE \
				 | DIRECTORY_CREATE_SUBDIRECTORY \
				 | DIRECTORY_CREATE_OBJECT \
				 | READ_CONTROL)

#define CYG_MUTANT_ACCESS	(MUTANT_QUERY_STATE \
				 | SYNCHRONIZE \
				 | READ_CONTROL)

#define CYG_EVENT_ACCESS	(EVENT_QUERY_STATE \
				 | EVENT_MODIFY_STATE \
				 | SYNCHRONIZE \
				 | READ_CONTROL)

#define CYG_SEMAPHORE_ACCESS	(SEMAPHORE_QUERY_STATE \
				 | SEMAPHORE_MODIFY_STATE \
				 | SYNCHRONIZE \
				 | READ_CONTROL)

typedef ULONG KAFFINITY;

typedef enum _SYSTEM_INFORMATION_CLASS
{
  SystemBasicInformation = 0,
  SystemPerformanceInformation = 2,
  SystemTimeOfDayInformation = 3,
  SystemProcessesAndThreadsInformation = 5,
  SystemProcessorTimes = 8,
  SystemPagefileInformation = 18,
  /* There are a lot more of these... */
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION
{
  ULONG Unknown;
  ULONG MaximumIncrement;
  ULONG PhysicalPageSize;
  ULONG NumberOfPhysicalPages;
  ULONG LowestPhysicalPage;
  ULONG HighestPhysicalPage;
  ULONG AllocationGranularity;
  ULONG LowestUserAddress;
  ULONG HighestUserAddress;
  ULONG ActiveProcessors;
  UCHAR NumberProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
  ULONG NextEntryOffset;
  ULONG CurrentSize;
  ULONG TotalUsed;
  ULONG PeakUsed;
  UNICODE_STRING FileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

typedef struct __attribute__ ((aligned (8))) _SYSTEM_PROCESSOR_TIMES
{
  LARGE_INTEGER IdleTime;
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER DpcTime;
  LARGE_INTEGER InterruptTime;
  ULONG InterruptCount;
} SYSTEM_PROCESSOR_TIMES, *PSYSTEM_PROCESSOR_TIMES;

typedef LONG KPRIORITY;
typedef struct _VM_COUNTERS
{
  ULONG PeakVirtualSize;
  ULONG VirtualSize;
  ULONG PageFaultCount;
  ULONG PeakWorkingSetSize;
  ULONG WorkingSetSize;
  ULONG QuotaPeakPagedPoolUsage;
  ULONG QuotaPagedPoolUsage;
  ULONG QuotaPeakNonPagedPoolUsage;
  ULONG QuotaNonPagedPoolUsage;
  ULONG PagefileUsage;
  ULONG PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _CLIENT_ID
{
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum
{
  StateInitialized,
  StateReady,
  StateRunning,
  StateStandby,
  StateTerminated,
  StateWait,
  StateTransition,
  StateUnknown,
} THREAD_STATE;

typedef enum
{
  Executive,
  FreePage,
  PageIn,
  PoolAllocation,
  DelayExecution,
  Suspended,
  UserRequest,
  WrExecutive,
  WrFreePage,
  WrPageIn,
  WrPoolAllocation,
  WrDelayExecution,
  WrSuspended,
  WrUserRequest,
  WrEventPair,
  WrQueue,
  WrLpcReceive,
  WrLpcReply,
  WrVirtualMemory,
  WrPageOut,
  WrRendezvous,
  Spare2,
  Spare3,
  Spare4,
  Spare5,
  Spare6,
  WrKernel,
  MaximumWaitReason
} KWAIT_REASON;

typedef struct _SYSTEM_THREADS
{
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  KPRIORITY BasePriority;
  ULONG ContextSwitchCount;
  THREAD_STATE State;
  KWAIT_REASON WaitReason;
  DWORD Reserved;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES
{
  ULONG NextEntryDelta;
  ULONG ThreadCount;
  ULONG Reserved1[6];
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ProcessName;
  KPRIORITY BasePriority;
  ULONG ProcessId;
  ULONG InheritedFromProcessId;
  ULONG HandleCount;
  ULONG Reserved2[2];
  VM_COUNTERS VmCounters;
  IO_COUNTERS IoCounters;
  SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK
{
  NTSTATUS Status;
  ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
  LARGE_INTEGER IdleTime;
  LARGE_INTEGER ReadTransferCount;
  LARGE_INTEGER WriteTransferCount;
  LARGE_INTEGER OtherTransferCount;
  ULONG ReadOperationCount;
  ULONG WriteOperationCount;
  ULONG OtherOperationCount;
  ULONG AvailablePages;
  ULONG TotalCommittedPages;
  ULONG TotalCommitLimit;
  ULONG PeakCommitment;
  ULONG PageFaults;
  ULONG WriteCopyFaults;
  ULONG TransitionFaults;
  ULONG Reserved1;
  ULONG DemandZeroFaults;
  ULONG PagesRead;
  ULONG PageReadIos;
  ULONG Reserved2[2];
  ULONG PagefilePagesWritten;
  ULONG PagefilePageWriteIos;
  ULONG MappedFilePagesWritten;
  ULONG MappedFilePageWriteIos;
  ULONG PagedPoolUsage;
  ULONG NonPagedPoolUsage;
  ULONG PagedPoolAllocs;
  ULONG PagedPoolFrees;
  ULONG NonPagedPoolAllocs;
  ULONG NonPagedPoolFrees;
  ULONG TotalFreeSystemPtes;
  ULONG SystemCodePage;
  ULONG TotalSystemDriverPages;
  ULONG TotalSystemCodePages;
  ULONG SmallNonPagedLookasideListAllocateHits;
  ULONG SmallPagedLookasideListAllocateHits;
  ULONG Reserved3;
  ULONG MmSystemCachePage;
  ULONG PagedPoolPage;
  ULONG SystemDriverPage;
  ULONG FastReadNoWait;
  ULONG FastReadWait;
  ULONG FastReadResourceMiss;
  ULONG FastReadNotPossible;
  ULONG FastMdlReadNoWait;
  ULONG FastMdlReadWait;
  ULONG FastMdlReadResourceMiss;
  ULONG FastMdlReadNotPossible;
  ULONG MapDataNoWait;
  ULONG MapDataWait;
  ULONG MapDataNoWaitMiss;
  ULONG MapDataWaitMiss;
  ULONG PinMappedDataCount;
  ULONG PinReadNoWait;
  ULONG PinReadWait;
  ULONG PinReadNoWaitMiss;
  ULONG PinReadWaitMiss;
  ULONG CopyReadNoWait;
  ULONG CopyReadWait;
  ULONG CopyReadNoWaitMiss;
  ULONG CopyReadWaitMiss;
  ULONG MdlReadNoWait;
  ULONG MdlReadWait;
  ULONG MdlReadNoWaitMiss;
  ULONG MdlReadWaitMiss;
  ULONG ReadAheadIos;
  ULONG LazyWriteIos;
  ULONG LazyWritePages;
  ULONG DataFlushes;
  ULONG DataPages;
  ULONG ContextSwitches;
  ULONG FirstLevelTbFills;
  ULONG SecondLevelTbFills;
  ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct __attribute__ ((aligned(8))) _SYSTEM_TIME_OF_DAY_INFORMATION
{
  LARGE_INTEGER BootTime;
  LARGE_INTEGER CurrentTime;
  LARGE_INTEGER TimeZoneBias;
  ULONG CurrentTimeZoneId;
} SYSTEM_TIME_OF_DAY_INFORMATION, *PSYSTEM_TIME_OF_DAY_INFORMATION;

typedef enum _PROCESSINFOCLASS
{
  ProcessBasicInformation = 0,
  ProcessQuotaLimits = 1,
  ProcessVmCounters = 3,
  ProcessTimes = 4,
  ProcessSessionInformation = 24,
  ProcessWow64Information = 26
} PROCESSINFOCLASS;

typedef struct _DEBUG_BUFFER
{
  HANDLE SectionHandle;
  PVOID SectionBase;
  PVOID RemoteSectionBase;
  ULONG SectionBaseDelta;
  HANDLE EventPairHandle;
  ULONG Unknown[2];
  HANDLE RemoteThreadHandle;
  ULONG InfoClassMask;
  ULONG SizeOfInfo;
  ULONG AllocatedSize;
  ULONG SectionSize;
  PVOID ModuleInformation;
  PVOID BackTraceInformation;
  PVOID HeapInformation;
  PVOID LockInformation;
  PVOID Reserved[9];
} DEBUG_BUFFER, *PDEBUG_BUFFER;

typedef struct _DEBUG_HEAP_INFORMATION
{
  ULONG Base;
  ULONG Flags;
  USHORT Granularity;
  USHORT Unknown;
  ULONG Allocated;
  ULONG Committed;
  ULONG TagCount;
  ULONG BlockCount;
  ULONG Reserved[7];
  PVOID Tags;
  PVOID Blocks;
} DEBUG_HEAP_INFORMATION, *PDEBUG_HEAP_INFORMATION;

typedef struct _DEBUG_MODULE_INFORMATION
{
  ULONG Reserved[2];
  ULONG Base;
  ULONG Size;
  ULONG Flags;
  USHORT Index;
  USHORT Unknown;
  USHORT LoadCount;
  USHORT ModuleNameOffset;
  CHAR ImageName[256];
} DEBUG_MODULE_INFORMATION, *PDEBUG_MODULE_INFORMATION;

typedef struct _KERNEL_USER_TIMES
{
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER ExitTime;
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
  ULONG AllocationSize;
  ULONG Size;
  ULONG Flags;
  ULONG DebugFlags;
  HANDLE hConsole;
  ULONG ProcessGroup;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
  UNICODE_STRING CurrentDirectoryName;
  HANDLE CurrentDirectoryHandle;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
  PWSTR Environment;
  ULONG dwX;
  ULONG dwY;
  ULONG dwXSize;
  ULONG dwYSize;
  ULONG dwXCountChars;
  ULONG dwYCountChars;
  ULONG dwFillAttribute;
  ULONG dwFlags;
  ULONG wShowWindow;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING DesktopInfo;
  UNICODE_STRING ShellInfo;
  UNICODE_STRING RuntimeInfo;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[9];
  PVOID LoaderData;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  BYTE Reserved3[448];
  ULONG SessionId;
} PEB, *PPEB;

/* Simplifed definition, just to get the PEB pointer. */
typedef struct _TEB
{
  PVOID dummy[12];
  PPEB                    Peb;
  /* A lot more follows... */
} TEB, *PTEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
  NTSTATUS ExitStatus;
  PPEB PebBaseAddress;
  KAFFINITY AffinityMask;
  KPRIORITY BasePriority;
  ULONG UniqueProcessId;
  ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_SESSION_INFORMATION
{
  ULONG  SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS
{
  MemoryBasicInformation,
  MemoryWorkingSetList,
  MemorySectionName,
  MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_WORKING_SET_LIST
{
  ULONG NumberOfPages;
  ULONG WorkingSetList[1];
} MEMORY_WORKING_SET_LIST, *PMEMORY_WORKING_SET_LIST;

typedef struct _FILE_BASIC_INFORMATION {
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
  LARGE_INTEGER AllocationSize;
  LARGE_INTEGER EndOfFile;
  ULONG NumberOfLinks;
  BOOLEAN DeletePending;
  BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  LARGE_INTEGER AllocationSize;
  LARGE_INTEGER EndOfFile;
  ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION {
  LARGE_INTEGER FileId;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
  ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
  ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {
  BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
  LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
  LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
  ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {
  ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_LINK_INFORMATION {
  BOOLEAN ReplaceIfExists;
  HANDLE RootDirectory;
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION {
  BOOLEAN ReplaceIfExists;
  HANDLE RootDirectory;
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
  FILE_BASIC_INFORMATION     BasicInformation;
  FILE_STANDARD_INFORMATION  StandardInformation;
  FILE_INTERNAL_INFORMATION  InternalInformation;
  FILE_EA_INFORMATION        EaInformation;
  FILE_ACCESS_INFORMATION    AccessInformation;
  FILE_POSITION_INFORMATION  PositionInformation;
  FILE_MODE_INFORMATION      ModeInformation;
  FILE_ALIGNMENT_INFORMATION AlignmentInformation;
  FILE_NAME_INFORMATION      NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;

typedef struct _FILE_PIPE_LOCAL_INFORMATION
{
  ULONG NamedPipeType;
  ULONG NamedPipeConfiguration;
  ULONG MaximumInstances;
  ULONG CurrentInstances;
  ULONG InboundQuota;
  ULONG ReadDataAvailable;
  ULONG OutboundQuota;
  ULONG WriteQuotaAvailable;
  ULONG NamedPipeState;
  ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;

typedef struct _FILE_COMPRESSION_INFORMATION
{
  LARGE_INTEGER CompressedFileSize;
  USHORT CompressionFormat;
  UCHAR	CompressionUnitShift;
  UCHAR ChunkShift;
  UCHAR ClusterShift;
  UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;

typedef struct _FILE_FS_DEVICE_INFORMATION
{
  ULONG DeviceType;
  ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION
{
  ULONG FileSystemAttributes;
  ULONG MaximumComponentNameLength;
  ULONG FileSystemNameLength;
  WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION
{
  LARGE_INTEGER VolumeCreationTime;
  ULONG VolumeSerialNumber;
  ULONG VolumeLabelLength;
  BOOLEAN SupportsObjects;
  WCHAR VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _FILE_FS_SIZE_INFORMATION
{
  LARGE_INTEGER TotalAllocationUnits;
  LARGE_INTEGER AvailableAllocationUnits;
  ULONG SectorsPerAllocationUnit;
  ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;

typedef struct _FILE_FS_FULL_SIZE_INFORMATION
{
  LARGE_INTEGER TotalAllocationUnits;
  LARGE_INTEGER CallerAvailableAllocationUnits;
  LARGE_INTEGER ActualAvailableAllocationUnits;
  ULONG SectorsPerAllocationUnit;
  ULONG BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION, *PFILE_FS_FULL_SIZE_INFORMATION;

typedef struct _FILE_FS_OBJECTID_INFORMATION {
    UCHAR ObjectId[16];
    UCHAR ExtendedInfo[48];
} FILE_FS_OBJECTID_INFORMATION, *PFILE_FS_OBJECTID_INFORMATION;

typedef enum _FSINFOCLASS {
  FileFsVolumeInformation = 1,
  FileFsLabelInformation,
  FileFsSizeInformation,
  FileFsDeviceInformation,
  FileFsAttributeInformation,
  FileFsControlInformation,
  FileFsFullSizeInformation,
  FileFsObjectIdInformation,
  FileFsDriverPathInformation,
  FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
  ObjectBasicInformation = 0,
  ObjectNameInformation = 1,
  ObjectHandleInformation = 4
   // and many more
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION
{
  ULONG Attributes;
  ACCESS_MASK GrantedAccess;
  ULONG HandleCount;
  ULONG PointerCount;
  ULONG PagedPoolUsage;
  ULONG NonPagedPoolUsage;
  ULONG Reserved[3];
  ULONG NameInformationLength;
  ULONG TypeInformationLength;
  ULONG SecurityDescriptorLength;
  LARGE_INTEGER CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
  UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION;

typedef struct _DIRECTORY_BASIC_INFORMATION
{
  UNICODE_STRING ObjectName;
  UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
  ULONG   NextEntryOffset;
  UCHAR   EaNameLength;
  CHAR    EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

typedef struct _FILE_FULL_EA_INFORMATION
{
  ULONG NextEntryOffset;
  UCHAR Flags;
  UCHAR EaNameLength;
  USHORT EaValueLength;
  CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_MAILSLOT_SET_INFORMATION
{
  LARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_SET_INFORMATION, *PFILE_MAILSLOT_SET_INFORMATION;

typedef VOID NTAPI (*PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);

typedef enum _EVENT_TYPE
{
  NotificationEvent = 0,
  SynchronizationEvent
} EVENT_TYPE, *PEVENT_TYPE;

typedef struct _EVENT_BASIC_INFORMATION
{
  EVENT_TYPE EventType;
  LONG SignalState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

typedef enum _EVENT_INFORMATION_CLASS
{
  EventBasicInformation = 0
} EVENT_INFORMATION_CLASS, *PEVENT_INFORMATION_CLASS;

/* Function declarations for ntdll.dll.  These don't appear in any
   standard Win32 header.  */

#define NtCurrentProcess() ((HANDLE) 0xffffffff)
#define NtCurrentThread()  ((HANDLE) 0xfffffffe)

/* Helper macro for sync I/O with async handle. */
inline NTSTATUS
wait_pending (NTSTATUS status, HANDLE h, IO_STATUS_BLOCK &io)
{
  if (status != STATUS_PENDING)
    return status;
  WaitForSingleObject (h, INFINITE);
  return io.Status;
}

extern "C"
{
  NTSTATUS NTAPI NtAdjustPrivilegesToken (HANDLE, BOOLEAN, PTOKEN_PRIVILEGES,
					  ULONG, PTOKEN_PRIVILEGES, PULONG);
  NTSTATUS NTAPI NtClose (HANDLE);
  NTSTATUS NTAPI NtCommitTransaction (HANDLE, BOOLEAN);
  NTSTATUS NTAPI NtCreateDirectoryObject (PHANDLE, ACCESS_MASK,
					  POBJECT_ATTRIBUTES);
  NTSTATUS NTAPI NtCreateEvent (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
				EVENT_TYPE, BOOLEAN);
  NTSTATUS NTAPI NtCreateFile (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
			     PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
			     ULONG, ULONG, PVOID, ULONG);
  NTSTATUS NTAPI NtCreateMailslotFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
				      PIO_STATUS_BLOCK, ULONG, ULONG, ULONG,
				      PLARGE_INTEGER);
  NTSTATUS NTAPI NtCreateMutant (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
				 BOOLEAN);
  NTSTATUS NTAPI NtCreateSection (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
				  PLARGE_INTEGER, ULONG, ULONG, HANDLE);
  NTSTATUS NTAPI NtCreateSemaphore (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
				    LONG, LONG);
  NTSTATUS NTAPI NtCreateToken (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
				TOKEN_TYPE, PLUID, PLARGE_INTEGER, PTOKEN_USER,
				PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_OWNER,
				PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL,
				PTOKEN_SOURCE);
  NTSTATUS NTAPI NtCreateTransaction (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
				      LPGUID, HANDLE, ULONG, ULONG, ULONG,
				      PLARGE_INTEGER, PUNICODE_STRING);
  NTSTATUS NTAPI NtFsControlFile (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
				  PIO_STATUS_BLOCK, ULONG, PVOID, ULONG,
				  PVOID, ULONG);
  NTSTATUS NTAPI NtLockVirtualMemory (HANDLE, PVOID *, ULONG *, ULONG);
  NTSTATUS NTAPI NtMapViewOfSection (HANDLE, HANDLE, PVOID *, ULONG, ULONG,
				     PLARGE_INTEGER, PULONG, SECTION_INHERIT,
				     ULONG, ULONG);
  NTSTATUS NTAPI NtNotifyChangeDirectoryFile (HANDLE, HANDLE, PIO_APC_ROUTINE,
					      PVOID, PIO_STATUS_BLOCK,
					      PFILE_NOTIFY_INFORMATION, ULONG,
					      ULONG, BOOLEAN);
  NTSTATUS NTAPI NtOpenDirectoryObject (PHANDLE, ACCESS_MASK,
					POBJECT_ATTRIBUTES);
  NTSTATUS NTAPI NtOpenEvent (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
  NTSTATUS NTAPI NtOpenFile (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
			     PIO_STATUS_BLOCK, ULONG, ULONG);
  NTSTATUS NTAPI NtOpenMutant (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
  NTSTATUS NTAPI NtOpenSection (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
  NTSTATUS NTAPI NtOpenSemaphore (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
  /* WARNING!  Don't rely on the timestamp information returned by
     NtQueryAttributesFile.  Only the DOS file attribute info is reliable. */
  NTSTATUS NTAPI NtQueryAttributesFile (POBJECT_ATTRIBUTES,
					PFILE_BASIC_INFORMATION);
  NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PVOID, PVOID,
				      PIO_STATUS_BLOCK, PVOID, ULONG,
				      FILE_INFORMATION_CLASS, BOOLEAN,
				      PUNICODE_STRING, BOOLEAN);
  NTSTATUS NTAPI NtQueryDirectoryObject (HANDLE, PVOID, ULONG, BOOLEAN,
					 BOOLEAN, PULONG, PULONG);
  NTSTATUS NTAPI NtQueryEaFile (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
				BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN);
  NTSTATUS NTAPI NtQueryEvent (HANDLE, EVENT_INFORMATION_CLASS, PVOID, ULONG,
			       PULONG);
  NTSTATUS NTAPI NtQueryFullAttributesFile (POBJECT_ATTRIBUTES,
					    PFILE_NETWORK_OPEN_INFORMATION);
  NTSTATUS NTAPI NtQueryInformationFile (HANDLE, PIO_STATUS_BLOCK, PVOID,
					 ULONG, FILE_INFORMATION_CLASS);
  NTSTATUS NTAPI NtQueryInformationProcess (HANDLE, PROCESSINFOCLASS,
					    PVOID, ULONG, PULONG);
  NTSTATUS NTAPI NtQueryObject (HANDLE, OBJECT_INFORMATION_CLASS, VOID *,
				ULONG, ULONG *);
  NTSTATUS NTAPI NtQuerySystemInformation (SYSTEM_INFORMATION_CLASS,
					   PVOID, ULONG, PULONG);

  NTSTATUS WINAPI NtQuerySystemTime (PLARGE_INTEGER);

  NTSTATUS NTAPI NtQuerySecurityObject (HANDLE, SECURITY_INFORMATION,
					PSECURITY_DESCRIPTOR, ULONG, PULONG);
  NTSTATUS NTAPI NtQueryVirtualMemory (HANDLE, PVOID, MEMORY_INFORMATION_CLASS,
				       PVOID, ULONG, PULONG);
  NTSTATUS NTAPI NtQueryVolumeInformationFile (HANDLE, IO_STATUS_BLOCK *,
					       VOID *, ULONG,
					       FS_INFORMATION_CLASS);
  NTSTATUS NTAPI NtReadFile (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
			     PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER,
			     PULONG);
  NTSTATUS NTAPI NtRollbackTransaction (HANDLE, BOOLEAN);
  NTSTATUS NTAPI NtSetEaFile (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
  NTSTATUS NTAPI NtSetInformationFile (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
				       FILE_INFORMATION_CLASS);
  NTSTATUS NTAPI NtSetSecurityObject (HANDLE, SECURITY_INFORMATION,
				      PSECURITY_DESCRIPTOR);
  NTSTATUS NTAPI NtUnlockVirtualMemory (HANDLE, PVOID *, ULONG *, ULONG);
  NTSTATUS NTAPI NtUnmapViewOfSection (HANDLE, PVOID);
  NTSTATUS NTAPI NtWriteFile (HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
			      PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER,
			      PULONG);
  NTSTATUS NTAPI RtlAppendUnicodeToString (PUNICODE_STRING, PCWSTR);
  NTSTATUS NTAPI RtlAppendUnicodeStringToString (PUNICODE_STRING,
						 PUNICODE_STRING);
  VOID NTAPI RtlAcquirePebLock ();
  NTSTATUS NTAPI RtlAnsiStringToUnicodeString (PUNICODE_STRING, PANSI_STRING,
					       BOOLEAN);
  LONG NTAPI RtlCompareUnicodeString (PUNICODE_STRING, PUNICODE_STRING,
				      BOOLEAN);
  NTSTATUS NTAPI RtlConvertSidToUnicodeString (PUNICODE_STRING, PSID, BOOLEAN);
  VOID NTAPI RtlCopyUnicodeString (PUNICODE_STRING, PUNICODE_STRING);
  BOOLEAN NTAPI RtlCreateUnicodeStringFromAsciiz (PUNICODE_STRING, PCSTR);
  NTSTATUS NTAPI RtlDowncaseUnicodeString (PUNICODE_STRING, PUNICODE_STRING,
					   BOOLEAN);
  BOOLEAN NTAPI RtlEqualUnicodeString (PUNICODE_STRING, PUNICODE_STRING,
				       BOOLEAN);
  VOID NTAPI RtlFreeAnsiString (PANSI_STRING);
  VOID NTAPI RtlFreeOemString (POEM_STRING);
  VOID NTAPI RtlFreeUnicodeString (PUNICODE_STRING);
  HANDLE NTAPI RtlGetCurrentTransaction ();
  VOID NTAPI RtlInitEmptyUnicodeString (PUNICODE_STRING, PCWSTR, USHORT);
  VOID NTAPI RtlInitUnicodeString (PUNICODE_STRING, PCWSTR);
  NTSTATUS NTAPI RtlIntegerToUnicodeString (ULONG, ULONG, PUNICODE_STRING);
  ULONG NTAPI RtlIsDosDeviceName_U (PCWSTR);
  ULONG NTAPI RtlNtStatusToDosError (NTSTATUS);
  NTSTATUS NTAPI RtlOemStringToUnicodeString (PUNICODE_STRING, POEM_STRING,
					       BOOLEAN);
  BOOLEAN NTAPI RtlPrefixUnicodeString (PUNICODE_STRING, PUNICODE_STRING,
					BOOLEAN);
  VOID NTAPI RtlReleasePebLock ();
  VOID NTAPI RtlSecondsSince1970ToTime (ULONG, PLARGE_INTEGER);
  BOOLEAN NTAPI RtlSetCurrentTransaction (HANDLE);
  NTSTATUS NTAPI RtlUnicodeStringToAnsiString (PANSI_STRING, PUNICODE_STRING,
					       BOOLEAN);
  NTSTATUS NTAPI RtlUnicodeStringToOemString (PANSI_STRING, PUNICODE_STRING,
					      BOOLEAN);
  WCHAR NTAPI RtlUpcaseUnicodeChar (WCHAR);
  NTSTATUS NTAPI RtlUpcaseUnicodeString (PUNICODE_STRING, PUNICODE_STRING,
					 BOOLEAN);

  /* A few Rtl functions are either actually macros, or they just don't
     exist even though they would be a big help.  We implement them here,
     partly as inline functions. */

  /* RtlInitEmptyUnicodeString is defined as a macro in wdm.h, but that file
     is missing entirely in w32api. */
  inline
  VOID NTAPI RtlInitEmptyUnicodeString(PUNICODE_STRING dest, PCWSTR buf,
				       USHORT len)
  {
    dest->Length = 0;
    dest->MaximumLength = len;
    dest->Buffer = (PWSTR) buf;
  }
  /* Like RtlInitEmptyUnicodeString, but initialize Length to len, too.
     This is for instance useful when creating a UNICODE_STRING from an
     NtQueryInformationFile info buffer, where the length of the filename
     is known, but you can't rely on the string being 0-terminated.
     If you know it's 0-terminated, just use RtlInitUnicodeString(). */
  inline
  VOID NTAPI RtlInitCountedUnicodeString (PUNICODE_STRING dest, PCWSTR buf,
					  USHORT len)
  {
    dest->Length = dest->MaximumLength = len;
    dest->Buffer = (PWSTR) buf;
  }
  /* Split path into dirname and basename part.  This function does not
     copy anything!  It just initializes the dirname and basename
     UNICODE_STRINGs so that their Buffer members point to the right spot
     into path's Buffer, and the Length (and MaximumLength) members are set
     to match the dirname part and the basename part.
     Note that dirname's Length is set so that it also includes the trailing
     backslash.  If you don't need it, just subtract sizeof(WCHAR) from
     dirname.Length. */
  inline
  VOID NTAPI RtlSplitUnicodePath (PUNICODE_STRING path, PUNICODE_STRING dirname,
				  PUNICODE_STRING basename)
  {
    USHORT len = path->Length / sizeof (WCHAR);
    while (len > 0 && path->Buffer[--len] != L'\\')
      ;
    ++len;
    if (dirname)
      RtlInitCountedUnicodeString (dirname, path->Buffer, len * sizeof (WCHAR));
    if (basename)
      RtlInitCountedUnicodeString (basename, &path->Buffer[len],
				   path->Length - len * sizeof (WCHAR));
  }
  /* Check if prefix is a prefix of path. */
  inline
  BOOLEAN NTAPI RtlEqualUnicodePathPrefix (PUNICODE_STRING path,
					   PUNICODE_STRING prefix,
					   BOOLEAN caseinsensitive)
  {
    UNICODE_STRING p;

    RtlInitCountedUnicodeString (&p, path->Buffer,
				 prefix->Length < path->Length
				 ? prefix->Length : path->Length);
    return RtlEqualUnicodeString (&p, prefix, caseinsensitive);
  }
  /* Check if sufffix is a sufffix of path. */
  inline
  BOOL NTAPI RtlEqualUnicodePathSuffix (PUNICODE_STRING path,
					PUNICODE_STRING suffix,
					BOOLEAN caseinsensitive)
  {
    UNICODE_STRING p;

    if (suffix->Length < path->Length)
      RtlInitCountedUnicodeString (&p, (PWCHAR) ((PBYTE) path->Buffer
				       + path->Length - suffix->Length),
				   suffix->Length);
    else
      RtlInitCountedUnicodeString (&p, path->Buffer, path->Length);
    return RtlEqualUnicodeString (&p, suffix, caseinsensitive);
  }
  /* Implemented in strfuncs.cc.  Create a Hex UNICODE_STRING from a given
     64 bit integer value.  If append is TRUE, append the hex string,
     otherwise overwrite dest.  Returns either STATUS_SUCCESS, or
     STATUS_BUFFER_OVERFLOW, if the unicode buffer is too small (hasn't
     room for 16 WCHARs). */
  NTSTATUS NTAPI RtlInt64ToHexUnicodeString (ULONGLONG value,
					     PUNICODE_STRING dest,
					     BOOLEAN append);
  /* Set file attributes.  Don't change file times. */
  inline
  NTSTATUS NTAPI NtSetAttributesFile (HANDLE h, ULONG attr)
  {
    IO_STATUS_BLOCK io;
    FILE_BASIC_INFORMATION fbi;
    fbi.CreationTime.QuadPart = fbi.LastAccessTime.QuadPart =
    fbi.LastWriteTime.QuadPart = fbi.ChangeTime.QuadPart = 0LL;
    fbi.FileAttributes = attr ?: FILE_ATTRIBUTE_NORMAL;
    return NtSetInformationFile(h, &io, &fbi, sizeof fbi, FileBasicInformation);
  }
}
#endif /*_NTDLL_H*/
