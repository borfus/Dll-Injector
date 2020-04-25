#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

DWORD search_process_list_for_pid(HANDLE process_list, char *process_name) {
	// must initialize dwSize to struct or Process32First will fail
	PROCESSENTRY32 current_process = { .dwSize = sizeof(PROCESSENTRY32) };

	if (Process32First(process_list, &current_process)) {
		while (Process32Next(process_list, &current_process)) {
			if (strcmp(current_process.szExeFile, process_name) == 0) {
				return current_process.th32ProcessID;
			}
		}
	}

	return 0;
}

DWORD get_pid(char *process_name) {
	HANDLE process_list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (process_list != NULL) {
		return search_process_list_for_pid(process_list, process_name);
	}

	return 0;
}

void inject_dll(DWORD pid, char *dll) {
	HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
	if (process == INVALID_HANDLE_VALUE) {
		printf("Failed to open PID %d, error code %d", pid, GetLastError());
		return;
	}

	// write the dll name to memory
	int namelen = strlen(dll) + 1;
	LPVOID remote_string = VirtualAllocEx(process, NULL, namelen, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(process, remote_string, dll, namelen, NULL);

	// get the address of LoadLibraryA()
	HMODULE k32 = GetModuleHandleA("Kernel32.dll");
	LPVOID func_adr = GetProcAddress(k32, "LoadLibraryA");

	// create the thread
	HANDLE thread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)func_adr, remote_string, NULL, NULL);

	printf("DLL path address: 0x%08x\n", thread);
	
	// let the thread finish and clean up
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
}

char* open_dll_file() {
	OPENFILENAME open_file_dialog;
	ZeroMemory(&open_file_dialog, sizeof(OPENFILENAME));
	char file_name[256] = { 0 };

	open_file_dialog.lStructSize = sizeof(OPENFILENAME);
	open_file_dialog.lpstrFile = file_name;
	open_file_dialog.lpstrFile[0] = '\0';
	open_file_dialog.nMaxFile = 256;
	open_file_dialog.lpstrTitle = "Choose a DLL to inject:";
	open_file_dialog.lpstrFilter = "All Files\0*.*\0DLL Files\0*.dll\0";
	open_file_dialog.nFilterIndex = 2; // choose 'DLL Files' by default

	GetOpenFileName(&open_file_dialog);

	return file_name;
}

int main(int argc, char *argv[]) {
	char process[256], dll_path[256];

	if (argc == 1) {
		printf("Process name: ");
		scanf("%s", process);
		strcpy(dll_path, open_dll_file());
	} else if (argc == 3) {
		strcpy(process, argv[1]);
		strcpy(dll_path, argv[2]);
	}
	
	DWORD pid = get_pid(process);

	if (pid) {
		printf("PID: %d\n", pid);
		inject_dll(pid, dll_path);
	}

	return 0;
}

