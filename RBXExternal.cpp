
#include <Windows.h> 
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include "main.h"
#include "addresses.h"
#include <sstream>
#include <filesystem>

#include <iostream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <cstdint>
#include <mmsystem.h>
#include "Psapi.h"


#define _CRT_SECURE_NO_WARNINGS

OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security)
{
	OBJECT_ATTRIBUTES object;

	object.Length = sizeof(OBJECT_ATTRIBUTES);
	object.ObjectName = name;
	object.Attributes = attributes;
	object.RootDirectory = hRoot;
	object.SecurityDescriptor = security;

	return object;
}

SYSTEM_HANDLE_INFORMATION* hInfo; 


HANDLE procHandle = NULL;
HANDLE hProcess = NULL;
HANDLE HijackedHandle = NULL;


DWORD GetPID(LPCSTR procName)
{
	//create a process snapshot
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, false);
	if (hSnap && hSnap != INVALID_HANDLE_VALUE) //check the snapshot succeded
	{
		PROCESSENTRY32 procEntry;

		//zero the memory containing the file names
		ZeroMemory(procEntry.szExeFile, sizeof(procEntry.szExeFile));

		//repeat the loop until a name matches the desired name
		do
		{
			if (lstrcmpi(procEntry.szExeFile, procName) == NULL) {
				return procEntry.th32ProcessID;
				CloseHandle(hSnap);
			}
		} while (Process32Next(hSnap, &procEntry));


	}


}



bool IsHandleValid(HANDLE handle) //i made this to simply check if a handle is valid rather than repeating the if statments
{
	if (handle && handle != INVALID_HANDLE_VALUE)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void CleanUpAndExit(LPSTR ErrorMessage) //just a function to clean up and exit. 
{

	delete[] hInfo;

	procHandle ? CloseHandle(procHandle) : 0;

	std::cout << ErrorMessage << std::endl;

	system("pause");

}
HANDLE HijackExistingHandle(DWORD dwTargetProcessId)
{
	HMODULE Ntdll = GetModuleHandleA("ntdll"); // get the base address of ntdll.dll

	//get the address of RtlAdjustPrivilege in ntdll.dll so we can grant our process the highest permission possible
	_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(Ntdll, "RtlAdjustPrivilege");

	boolean OldPriv; //store the old privileges

	// Give our program SeDeugPrivileges whcih allows us to get a handle to every process, even the highest privileged SYSTEM level processes.
	RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv);

	//get the address of NtQuerySystemInformation in ntdll.dll so we can find all the open handles on our system
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(Ntdll, "NtQuerySystemInformation");

	//get the address of NtDuplicateObject in ntdll.dll so we can duplicate an existing handle into our cheat, basically performing the hijacking
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(Ntdll, "NtDuplicateObject");

	//get the address of NtOpenProcess in ntdll.dll so wecan create a Duplicate handle
	_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(Ntdll, "NtOpenProcess");


	//initialize the Object Attributes structure, you can just set each member to NULL rather than create a function like i did
	OBJECT_ATTRIBUTES Obj_Attribute = InitObjectAttributes(NULL, NULL, NULL, NULL);

	//clientID is a PDWORD or DWORD* of the process id to create a handle to
	CLIENT_ID clientID = { 0 };


	//the size variable is the amount of bytes allocated to store all the open handles
	DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);

	//we allocate the memory to store all the handles on the heap rather than the stack becuase of the large amount of data
	hInfo = (SYSTEM_HANDLE_INFORMATION*) new byte[size];

	//zero the memory handle info
	ZeroMemory(hInfo, size);

	//we use this for checking if the Native functions succeed
	NTSTATUS NtRet = NULL;

	do
	{
		// delete the previously allocated memory on the heap because it wasn't large enough to store all the handles
		delete[] hInfo;

		//increase the amount of memory allocated by 50%
		size *= 1.5;
		try
		{
			//set and allocate the larger size on the heap
			hInfo = (PSYSTEM_HANDLE_INFORMATION) new byte[size];



		}
		catch (std::bad_alloc) //catch a bad heap allocation.
		{


			std::cout << "Loading....\n";

		}
		Sleep(1); //sleep for the cpu

		//we continue this loop until all the handles have been stored
	} while ((NtRet = NtQuerySystemInformation(SystemHandleInformation, hInfo, size, NULL)) == STATUS_INFO_LENGTH_MISMATCH);

	//check if we got all the open handles on our system
	if (!NT_SUCCESS(NtRet))
	{
		std::cout << "Loading....\n";
		
	}


	//loop through each handle on our system, and filter out handles that are invalid or cant be hijacked
	for (unsigned int i = 0; i < hInfo->HandleCount; ++i)
	{
		//a variable to store the number of handles OUR cheat has open.
		static DWORD NumOfOpenHandles;

		//get the amount of outgoing handles OUR cheat has open
		GetProcessHandleCount(GetCurrentProcess(), &NumOfOpenHandles);

		//you can do a higher number if this is triggering false positives. Its just to make sure we dont fuck up and create thousands of handles
		
		if (NumOfOpenHandles > 50)
		{
				
			
		}

		//check if the current handle is valid, otherwise increment i and check the next handle
		if (!IsHandleValid((HANDLE)hInfo->Handles[i].Handle))
		{
			continue;
		}

		//check the handle type is 0x7 meaning a process handle so we dont hijack a file handle for example
		if (hInfo->Handles[i].ObjectTypeNumber != ProcessHandleType)
		{
			continue;
		}


		//set clientID to a pointer to the process with the handle to out target
		clientID.UniqueProcess = (DWORD*)hInfo->Handles[i].ProcessId;

		//if procHandle is open, close it
		procHandle ? CloseHandle(procHandle) : 0;

		//create a a handle with duplicate only permissions to the process with a handle to our target. NOT OUR TARGET.
		NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE, &Obj_Attribute, &clientID);
		if (!IsHandleValid(procHandle) || !NT_SUCCESS(NtRet)) //check is the funcions succeeded and check the handle is valid
		{
			continue;
		}


		//we duplicate the handle another process has to our target into our cheat with whatever permissions we want. I did all access.
		NtRet = NtDuplicateObject(procHandle, (HANDLE)hInfo->Handles[i].Handle, NtCurrentProcess, &HijackedHandle, PROCESS_ALL_ACCESS, 0, 0);
		if (!IsHandleValid(HijackedHandle) || !NT_SUCCESS(NtRet))//check is the funcions succeeded and check the handle is valid
		{
			continue;
		}

		//get the process id of the handle we duplicated and check its to our target
		if (GetProcessId(HijackedHandle) != dwTargetProcessId) {
			CloseHandle(HijackedHandle);
			continue;
		}



		hProcess = HijackedHandle;

		break;
	}



	return hProcess;

}

DWORD GetProcessIdFromName(const std::string& processName) {
	DWORD pid = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &processEntry)) {
			do {
				if (_stricmp(processEntry.szExeFile, processName.c_str()) == 0) {
					pid = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}
	return pid;
}

DWORD_PTR GetProcessBaseAddress(DWORD processID)
{
	DWORD_PTR   baseAddress = 0;
	HANDLE      processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	HMODULE* moduleArray;
	LPBYTE      moduleArrayBytes;
	DWORD       bytesRequired;

	if (processHandle)
	{
		if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired))
		{
			if (bytesRequired)
			{
				moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

				if (moduleArrayBytes)
				{
					unsigned int moduleCount;

					moduleCount = bytesRequired / sizeof(HMODULE);
					moduleArray = (HMODULE*)moduleArrayBytes;

					if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
					{
						baseAddress = (DWORD_PTR)moduleArray[0];
					}

					LocalFree(moduleArrayBytes);
				}
			}
		}

		CloseHandle(processHandle);
	}

	return baseAddress;
}


bool SuspendProcess(DWORD processId) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create thread snapshot." << std::endl;
		return false;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(snapshot, &threadEntry)) {
		std::cerr << "Failed to retrieve first thread." << std::endl;
		CloseHandle(snapshot);
		return false;
	}

	bool success = false;
	do {
		if (threadEntry.th32OwnerProcessID == processId) {
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
			if (hThread != NULL) {
				if (SuspendThread(hThread) != -1) {
					success = true;
				}
				else {
					std::cerr << "Failed to suspend thread." << std::endl;
				}
				CloseHandle(hThread);
			}
			else {
				std::cerr << "Failed to open thread." << std::endl;
			}
		}
	} while (Thread32Next(snapshot, &threadEntry));

	CloseHandle(snapshot);
	return success;
}

bool ResumeApplication(DWORD processId) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(snapshot, &threadEntry)) {
		CloseHandle(snapshot);
		return false;
	}

	bool success = false;
	do {
		if (threadEntry.th32OwnerProcessID == processId) {
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
			if (hThread != NULL) {
				if (ResumeThread(hThread) != -1) {
					success = true;
				}
				else {
				}
				CloseHandle(hThread);
			}
			else {
			}
		}
	} while (Thread32Next(snapshot, &threadEntry));

	CloseHandle(snapshot);
	return success;
}

bool isProcessRunning(DWORD pid) {
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (process == NULL) {
		return false;
	}
	DWORD exitCode;
	GetExitCodeProcess(process, &exitCode);
	CloseHandle(process);
	return (exitCode == STILL_ACTIVE);
}

DWORD GetProcessIdByName(const std::string& processName) {//lol i cant!!!
	DWORD processId = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32)) {
			do {
				if (processName == pe32.szExeFile) {
					processId = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
	return processId;
}



bool crashed( ) {
	HWND hwnd = FindWindowA(NULL, "Roblox Crash");
	return hwnd != NULL;
}

#include <WinInet.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "wininet.lib")

std::string replaceAll(std::string subject, const std::string& search,
	const std::string& replace) {
	size_t pos = 0;//dont use NULL becuz homo
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);//replace
		pos += replace.length();
	}
	return subject;
}

std::string DownloadURL(const char* URL) {//URL downloader (similar to DownloadString)
	HINTERNET interwebs = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);//cmon this is homo
	HINTERNET urlFile;
	std::string rtn;
	if (interwebs) {//if
		urlFile = InternetOpenUrlA(interwebs, URL, NULL, NULL, NULL, NULL);//open
		if (urlFile) {
			char buffer[2000];//buff deez nuts
			DWORD bytesRead;
			do {//do
				InternetReadFile(urlFile, buffer, 2000, &bytesRead);//read
				rtn.append(buffer, bytesRead);
				memset(buffer, 0, 2000);//cop
			} while (bytesRead);
			InternetCloseHandle(interwebs);
			InternetCloseHandle(urlFile);
			std::string p = replaceAll(rtn, "|n", "\r\n");
			return p;//return
		}
	}
	InternetCloseHandle(interwebs);
	std::string p = replaceAll(rtn, "|n", "\r\n");//ik spliting is gay
	return p;	


}

int main() {

	//atexit(ontheexitt);

	bool isHipHeightEnabled = false;
	SetConsoleTitleA("[-] NYXIA EXTERNAL // SPEEDSTERKAWAII");
	Sleep(2000);
	std::cout << R"(

                                                                 
b.             8 `8.`8888.      ,8' `8.`8888.      ,8'           
888o.          8  `8.`8888.    ,8'   `8.`8888.    ,8'            
Y88888o.       8   `8.`8888.  ,8'     `8.`8888.  ,8'             
.`Y888888o.    8    `8.`8888.,8'       `8.`8888.,8'              
8o. `Y888888o. 8     `8.`88888'         `8.`88888'               
8`Y8o. `Y88888o8      `8. 8888          .88.`8888.               
8   `Y8o. `Y8888       `8 8888         .8'`8.`8888.              
8      `Y8o. `Y8        8 8888        .8'  `8.`8888.             
8         `Y8o.`        8 8888       .8'    `8.`8888.            
8            `Yo        8 8888      .8'      `8.`8888.           


)"; 

	std::cout << "[-] NYXIA EXTERNAL [USER-MODE]\n";
	std::cout << "[+] FINDING ROBLOX...\n";

	int PID = GetProcessIdFromName("RobloxPlayerBeta.exe");
	if (!isProcessRunning(PID)) {
		MessageBoxA(0, "Did you forget to open roblox?\n", "Nyxia", MB_TOPMOST);
		abort();
		exit(0);
	}

	else {  }
	HANDLE hProcess = HijackExistingHandle(PID);
	if(hProcess != INVALID_HANDLE_VALUE)
	{
		std::cout << "[+] INJECTED INTO ROBLOX\n";
	}
	else {
		std::cout << "[!] EJECTED FROM ROBLOX\n"; 
	}

	uintptr_t Base = GetProcessBaseAddress(PID);
	SetWindowPos(GetConsoleWindow(), HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	
	bool isReadyforNextOff = false;
	bool isReadyforNextOn = false;

	std::stringstream ss;

	std::string DisplayName;


	std::cout << "[-] TYPE RBX DISPLAY NAME: \n"; 

	const std::string filename = "displayname.user";

	std::ifstream file(filename);
	if (file) {
		std::string line;
		while (std::getline(file, line)) {
			std::cout << "[!] SKIPPED, FOUND " << line << std::endl;
			DisplayName = line;
		}
		file.close();
	}
	else {
		std::cin >> DisplayName;

		std::ofstream file(filename);
		if (file) {
			file << DisplayName;

			file.close();
			std::cout << "[!] SAVED DISPLAY NAME" << std::endl;
		}
		else {
			std::cerr << "[+] CANT CREATE FILE" << std::endl; 
			system("PAUSE");
		}

	}

	int wss;

	std::cout << "[-] WALKSPEED VALUE [16 is default]: ";
	std::cin >> wss;


	SuspendProcess(PID);
	Sleep(1000);
	ResumeApplication(PID);

	int jp;

	std::cout << "[-] JUMPPOWER VALUE [50 is default]: ";
	std::cin >> jp;

	std::cout << "[!] WALKSPEED/JUMPPOWER WILL BE EXECUTED\n";
	std::cout << "[!] PLEASE WAIT A MOMENT\n";
	SearchMemory(DisplayName, hProcess);

	SuspendProcess(PID);
    Sleep(3000);
    ResumeApplication(PID);


	std::cout << "[+] EXECUTED TASK\n";
	std::cout << "[+] DO NOT RESET YOUR PLAYER\n";
	std::cout << "[+] EXIT THIS CONSOLE ONCE DONE\n"; 
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	//CloseHandle(hProcess);
	std::cout << "\n";
	isReadyToInject = true;

	SIZE_T bytesWritten;
	float targetjp = static_cast<float>(jp); 
	WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(JumpPower), &targetjp, sizeof(targetjp), &bytesWritten);
	float targetws = static_cast<float>(wss);
	WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(WS1), &targetws, sizeof(targetws), &bytesWritten);
	WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(WS2), &targetws, sizeof(targetws), &bytesWritten);
	
	Sleep(696969666966969);

	return 1;
}