#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

DWORD search_process_list_for_pid(HANDLE process_list_snapshot)
{
	// must initialize dwSize to struct or Process32First will fail
	PROCESSENTRY32 current_process_in_list = { .dwSize = sizeof(PROCESSENTRY32) };

	if (Process32First(process_list_snapshot, &current_process_in_list))
	{
		do
		{
			if (!strcmp(current_process_in_list.szExeFile, process_name))
			{
				return current_process_in_list.th32ProcessID;
			}
		} while (Process32Next(process_list_snapshot, &current_process_in_list));
	}
	return 0;
}

DWORD get_pid(char *process_name)
{
	HANDLE process_list_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (process_list_snapshot != NULL)
	{
		return search_process_list_for_pid(process_list_snapshot);
	}
	return 0;
}

int main()
{
	// Dll Path and Target Process ID
	char *Dll_Path = "dll_path";
	DWORD pid = get_pid("process_name");

	if (pid)
	{
		// Handle to the target process using its pid
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

		// Allocates memory inside the target process and sets it to the path of our dll
		LPVOID pDll_Path = VirtualAllocEx(hProcess, 0, strlen(Dll_Path) + 1, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(hProcess, pDll_Path, (LPVOID)Dll_Path, strlen(Dll_Path) + 1, 0);

		// Creates a remote thread in the target process and calls LoadLibraryA from Kernel32 to load our dll
		HMODULE hKernel32 = GetModuleHandleA("Kernel32.dll");
		PVOID load_library = GetProcAddress(hKernel32, "LoadLibraryA");
		HANDLE load_thread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)load_library, pDll_Path, 0, 0);

		// Waits for the execution of our loader thread to finish
		WaitForSingleObject(load_thread, INFINITE);

		printf("Dll path address: 0x%08x\n", (int)pDll_Path);

		// Frees the dll path memory we allocated earlier
		VirtualFreeEx(hProcess, pDll_Path, strlen(Dll_Path) + 1, MEM_RELEASE);
	}

	return 0;
}
