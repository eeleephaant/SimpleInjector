#ifndef INJECTOR_INJECTOR_H
#define INJECTOR_INJECTOR_H

#include <Windows.h>
#include <TlHelp32.h>


class Injector {
private:
    static DWORD getPid(char* processName);

public:
    static void defaultInject(char* dllName, char* processName);

    static void APCInject(char *processName, char *payload, size_t payloadSize);

    static void EarlyAPCInject(char *exePath, char *payload, size_t payloadSize);

    void ManualMappingInject(char *bytecode, size_t bytecodeSize);
};


#endif //INJECTOR_INJECTOR_H
