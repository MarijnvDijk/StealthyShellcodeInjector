#include <minwindef.h>
#include <winternl.h>
#pragma once

#ifndef CUSTOM_H
#define CUSTOM_H

FARPROC fun001gpa(IN HMODULE hModule, IN LPCSTR lpApiName);
HMODULE fun002gmh(IN LPCWSTR szModuleName);

typedef NTSTATUS(*fnfun003qsi)(
	IN          SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT      PVOID                    SystemInformation,
	IN          ULONG                    SystemInformationLength,
	OUT			PULONG                   ReturnLength
	);

typedef NTSTATUS(*fnfun004cf)(
	OUT          PHANDLE            FileHandle,
	IN           ACCESS_MASK        DesiredAccess,
	IN           POBJECT_ATTRIBUTES ObjectAttributes,
	OUT          PIO_STATUS_BLOCK   IoStatusBlock,
	IN OPTIONAL PLARGE_INTEGER     AllocationSize,
	IN           ULONG              FileAttributes,
	IN           ULONG              ShareAccess,
	IN           ULONG              CreateDisposition,
	IN           ULONG              CreateOptions,
	IN           PVOID              EaBuffer,
	IN           ULONG              EaLength
	);

typedef HANDLE(*fnfun005cfm)(
	IN           HANDLE                hFile,
	IN OPTIONAL  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	IN           DWORD                 flProtect,
	IN           DWORD                 dwMaximumSizeHigh,
	IN           DWORD                 dwMaximumSizeLow,
	IN OPTIONAL  LPCWSTR               lpName
	);

typedef LPVOID(*fnfun006mvf)(
	IN HANDLE hFileMappingObject,
	IN DWORD  dwDesiredAccess,
	IN DWORD  dwFileOffsetHigh,
	IN DWORD  dwFileOffsetLow,
	IN SIZE_T dwNumberOfBytesToMap
	);

typedef NTSTATUS(*fnfun007ch)(
	IN HANDLE Handle
	);

typedef BOOL(*fnfun008vp)(
	IN  LPVOID lpAddress,
	IN  SIZE_T dwSize,
	IN  DWORD  flNewProtect,
	OUT PDWORD lpflOldProtect
	);

typedef NTSTATUS (*fnfun009avm)(
	IN      HANDLE    ProcessHandle,
	IN OUT  PVOID* BaseAddress,
	IN      ULONG_PTR ZeroBits,
	IN OUT  PSIZE_T   RegionSize,
	IN      ULONG     AllocationType,
	IN      ULONG     Protect
);

typedef HANDLE (*fnfun010gcp)();

typedef NTSTATUS (*fnfun011wvm)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS (*fnfun012pvm)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection);

typedef NTSTATUS(*fnfun013cte)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T StackSize OPTIONAL,
	IN SIZE_T MaximumStackSize OPTIONAL,
	IN PVOID AttributeList OPTIONAL
	);

typedef NTSTATUS (*fnfun014wfso)(
	IN HANDLE         Handle,
	IN BOOLEAN        Alertable,
	IN PLARGE_INTEGER Timeout
);

typedef NTSTATUS (*fnfun015fvm)(
	IN HANDLE               ProcessHandle,
	IN PVOID* BaseAddress,
	IN OUT PULONG           RegionSize,
	IN ULONG                FreeType);

#endif