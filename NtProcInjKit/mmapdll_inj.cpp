#include "inj.h"
#include <iostream>

//definitions

void InitUnicodeString(PUNICODE_STRING dst, LPCWSTR src) {
	dst->Length = (USHORT)(wcslen(src) * sizeof(WCHAR));
	dst->MaximumLength = dst->Length + sizeof(WCHAR);
	dst->Buffer = (PWSTR)src;
}

HMODULE FMD(LPCSTR dllName) {
	PPEB peb = (PPEB)__readgsqword(0x60);
	LIST_ENTRY* list = &peb->Ldr->InMmeoryOrderModuleList;
	for (LIST_ENTRY* p = list->Flink; p != list; p = p->Flink) {
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(p, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		WCHAR* wDllName = entry->FullDllName.Buffer;
		if (wDllName == (WCHAR*)dllName) {
			return (HMODULE)entry->DllBase;
		}
	}
	return NULL;
}

FARPROC GetProcManual(HMODULE ModuleBase, LPCSTR FuncName) {
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ModuleBase;
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)ModuleBase + dos->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ModuleBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* NameRvas = (DWORD*)((BYTE*)ModuleBase + exportDir->AddressOfNames);
	WORD* ordinals = (WORD*)((BYTE*)ModuleBase + exportDir->AddressOfNameOrdinals);
	DWORD* funcs = (DWORD*)((BYTE*)ModuleBase + exportDir->AddressOfFunctions);

	for (DWORD i = 0; exportDir->NumberOfNames; ++i) {
		LPCSTR name = (LPCSTR)((BYTE*)ModuleBase + NameRvas[i]);
		if (strcmp(name, FuncName) == 0) {
			WORD ord = ordinals[i];
			return (FARPROC)((BYTE*)ModuleBase + funcs[ord]);
		}
	}
	return NULL;
}

bool ParsePe(BYTE* Buffer, SIZE_T size, BYTE* MappedBase) {
	cout << "Starting Parse";
	IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)Buffer;
	IMAGE_NT_HEADERS64* Nt = (IMAGE_NT_HEADERS64*)(Buffer + Dos->e_lfanew);
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(Nt);
	for (int i = 0; i < Nt->FileHeader.NumberOfSections; i++, section++) {
		BYTE* dest = MappedBase + section->VirtualAddress;
		BYTE* src = Buffer + section->PointerToRawData;
		SIZE_T sizeOfRaw = section->SizeOfRawData;
		memcpy(dest, src, sizeOfRaw);
	}
	cout << "Parsed Sections";
	ULONGLONG PreferedBase = Nt->OptionalHeader.ImageBase;
	ULONGLONG Delta = (ULONGLONG)MappedBase - PreferedBase;
	if (Delta != 0) {
		cout << "Mapped Base is not at Prefered Base, Starting relocation";
		IMAGE_DATA_DIRECTORY RelocDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (RelocDir.Size == 0) {
			cout << "The file is not meant to be relocated, Aborting now.";
			return false;
		}
		IMAGE_BASE_RELOCATION* RelocPtr = (IMAGE_BASE_RELOCATION*)(MappedBase + RelocDir.VirtualAddress);
		while (RelocPtr->VirtualAddress && RelocPtr->SizeOfBlock) {
			DWORD count = (RelocPtr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD));
			WORD* RelocData = (WORD*)(RelocPtr + 1);
				for (DWORD i = 0; i < count; i++) {
					WORD entry = RelocData[i];
					WORD type = entry >> 12;
					WORD offset = entry & 0xFFF;
					
					if (type == IMAGE_REL_BASED_DIR64) {
						ULONGLONG* PatchAddr = (ULONGLONG*)(MappedBase + RelocPtr->VirtualAddress + offset);
						*PatchAddr += Delta;
					}
				}
				RelocPtr = (IMAGE_BASE_RELOCATION*)((BYTE*)RelocPtr + RelocPtr->SizeOfBlock);
		}
		return true;
	}
}

bool MmapDllNt(int PID, LPCWSTR DllName,SIZE_T FileSize) {
	UNICODE_STRING ustr;
	InitUnicodeString(&ustr,DllName);
	OBJECT_ATTRIBUTES oa = { 0 };
	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.ObjectName = &ustr;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.RootDirectory = NULL;
	oa.SecurityDescriptor = NULL;
	oa.SecurityQualityOfService = NULL;
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	ZeroMemory(&iosb, sizeof(IO_STATUS_BLOCK));
	NTSTATUS Create = Sw3NtCreateFile(&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&iosb,
		NULL, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,NULL,
		0);
	if (Create != 0) {
		cout << "Error getting File handle\n";
	}
	IO_STATUS_BLOCK iosbRead = { 0 };
	BYTE* Buffer = (BYTE*)VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!Buffer) {
		cout << "Alloc failed\n";
		return false;
	}
	NTSTATUS Read = Sw3NtReadFile(&hFile,
		NULL, NULL, NULL,
		&iosbRead,
		Buffer,
		(ULONG)FileSize,
		NULL, NULL);
	if (Read != 0) {
		VirtualFree(Buffer, 0, MEM_RELEASE);
		cout << "Reading Failed\n";
		return false;
	}
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)Buffer;
	 
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "Dos Signature Couldnt be verified, Aborting\n";
		return false;
	}
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(Buffer + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		cout << "nt Signature Couldnt Be Verified, Aborting\n";
		return false;
	}
	SIZE_T ImageSize = nt->OptionalHeader.SizeOfImage;
	BYTE* MappedBase = (BYTE*)VirtualAlloc(NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ParsePe(Buffer, ImageSize, MappedBase)) {
		cout << "A fatal error has occured when parsing PE headers\n";
	}
	IMAGE_DATA_DIRECTORY DataDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR* ImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(MappedBase + DataDir.VirtualAddress);
	while (ImportDesc->Name) {
		char* dllName = (char*)(MappedBase + ImportDesc->Name);
		HMODULE moduleBase = FMD(dllName);
		FARPROC* thunkref = (FARPROC*)(MappedBase + ImportDesc->FirstThunk);
		IMAGE_THUNK_DATA* origthunk = (IMAGE_THUNK_DATA*)(MappedBase + ImportDesc->OriginalFirstThunk);

		while (origthunk->u1.AddressOfData) {
			IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(MappedBase + origthunk->u1.AddressOfData);
			LPCSTR FuncName = (LPCSTR)importByName->Name;

			FARPROC Res = GetProcManual(moduleBase, FuncName);
			*thunkref = Res;

			++origthunk;
			++thunkref;
		}
	}
	CLIENT_ID client_id;
	client_id.UniqueProcess = (HANDLE)PID;
	client_id.UniqueThread = NULL;

	OBJECT_ATTRIBUTES objAttr;
	ZeroMemory(&objAttr, sizeof(objAttr));
	objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
	HANDLE hProc;
	NTSTATUS Open = Sw3NtOpenProcess(&hProc,
		PROCESS_ALL_ACCESS,
		&objAttr,
		&client_id);

	if (Open != 0) {
		cout << "There was an exception while opening the process\n";
		return false;
	}
	PVOID remotebase = NULL;
	ULONG_PTR ad = 0;
	NTSTATUS alloc = Sw3NtAllocateVirtualMemory(&hProc,
		&remotebase,
		ad,
		&ImageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (alloc != 0) {
		cout << "There was an exception while allocating memory\n";
		return false;
	}
	SIZE_T bytewritten;
	NTSTATUS write = Sw3NtWriteVirtualMemory(&hProc,
		remotebase,
		MappedBase,
		ImageSize,
		&bytewritten);
	if (write != 0) {
		cout << "There was an exception while writing [!] BytesWritten = " << dec << bytewritten << endl;
		return false;
	}
	ULONG old;
	NTSTATUS reprotect = Sw3NtProtectVirtualMemory(hProc,
		&remotebase,
		&ImageSize,
		PAGE_EXECUTE_READ,
		&old);
	if (reprotect != 0) {
		cout << "There was an exception changing memory protections to RW TO RX\n";
		return false;
	}
	HANDLE tHandle;
	DWORD EntryRv = nt->OptionalHeader.AddressOfEntryPoint;
	DWORD EntryPoint = ((DWORD)remotebase + EntryRv);
	LPTHREAD_START_ROUTINE RemoteDllMain = (LPTHREAD_START_ROUTINE)((BYTE*)remotebase + EntryPoint);
	NTSTATUS create = Sw3NtCreateThreadEx(&tHandle,
		THREAD_ALL_ACCESS,
		NULL,
		hProc,
		RemoteDllMain,
		remotebase,
		0, 0, 0, 0,
		NULL);
	if (create != 0) {
		cout << "There was an exception while creating the thread\n";
		return false;
	}
	WaitForSingleObject(tHandle, INFINITE);
	cout << "Thread Successfuly Ran, Freeing memory and cleaning up process\n";
	Sw3NtClose(tHandle);
	Sw3NtClose(hProc);

	SIZE_T size = 0;
	Sw3NtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&MappedBase, &size, MEM_RELEASE);
	return true;
}
