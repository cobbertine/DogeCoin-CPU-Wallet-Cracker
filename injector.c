#define _WIN32_WINNT 0x0A00
#define CALL_TARGET_FUNCTION_NAME "callTargetFunction"
#define SET_SHARED_MEMORY_ADDRESS_FUNCTION_NAME "setSharedMemoryAddress"
#define AGENT_INTERACTION_WAIT_TIME_MS 5000
#define POLL_AGENT_STATUS_MS 1000

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "shared_constants.h"

// Returns True (1) if the thread returned within the specified waitTime, otherwise False (0)
int callRemoteFunction(HANDLE processHandle, LPTHREAD_START_ROUTINE function, LPVOID argumentAddress, int waitTime)
{
    HANDLE threadHandle = CreateRemoteThread(processHandle, 0, 0, function, argumentAddress, 0, 0);

    DWORD threadStatus = WaitForSingleObject(threadHandle, waitTime);

    CloseHandle(threadHandle);

    if(threadStatus == WAIT_OBJECT_0)
    {
        return 1;
    }
    else
    {
        return 0;
    }    
}

int main(int argc, char **argv)
{
    if(argc == 1)
    {
        printf("%s\n", "Insufficient args. Requires at least target process ID. Can also include worker ID if performing parallel operations");
        return 0;
    }

    LONG_PTR workerID = 0;

    if(argc > 2)
    {
        workerID = atoi(*(argv+2));
    }

    // Load the library here first, so we can see where ASLR is going to put it. We will keep it loaded so that ASLR doesn't move it elsewhere when the target process loads it (keeping it loaded might not be necessary).
    // ASLR understanding from: https://security.stackexchange.com/a/18557
    HMODULE dllAddress = LoadLibraryA(DLL_PATH);
    // Get the addresses of the functions we want, as we'll need it to call them again in our target process.
    FARPROC callTargetFunctionPointer = GetProcAddress(dllAddress, CALL_TARGET_FUNCTION_NAME);
    FARPROC setSharedMemoryAddress = GetProcAddress(dllAddress, SET_SHARED_MEMORY_ADDRESS_FUNCTION_NAME);

    // Get user supplied target process ID
    DWORD targetProcessId = atoi(*(argv + 1));
    // Get a handle to the target process
    HANDLE targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, targetProcessId);
    // Creates a piece of memory for the process with enough room to hold a file path (MAX_PATH as defined by Windows of 260 characters). Other flags are essential to reserve and commit the memory and make sure it's usable.
    LPVOID targetMemoryAddressForDllHandle = VirtualAllocEx(targetProcessHandle, 0, DATA_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // Write our DLL file path into the allocated memory
    WriteProcessMemory(targetProcessHandle, targetMemoryAddressForDllHandle, DLL_PATH, strlen(DLL_PATH) + 1, 0);
    // Creates a new thread in the target process calling LoadLibrary (it has to be casted, but it still works as the signature is essentially the same) and provides it with the targetMemoryAddressForDllHandle pointer which it will interpret as a char pointer to the DLL file path string. The DLL will then be loaded which we can use afterwards.
    // Thanks to how ASLR works, LoadLibrary should be in the same location in this process as it is in our target process, as the DLL that holds it has already been loaded.
    if(callRemoteFunction(targetProcessHandle, (LPTHREAD_START_ROUTINE)LoadLibraryA, targetMemoryAddressForDllHandle, AGENT_INTERACTION_WAIT_TIME_MS) == 0)
    {
        printf("%s\n", "An error has occurred and the remote process is not responding. Exiting.");
        return 1;
    }


    // Re-using the buffer used for LoadLibrary, we let the DLL know where to write its updates when it begins its task
    if(callRemoteFunction(targetProcessHandle, (LPTHREAD_START_ROUTINE)setSharedMemoryAddress, targetMemoryAddressForDllHandle, AGENT_INTERACTION_WAIT_TIME_MS) == 0)
    {
        printf("%s\n", "An error has occurred and the remote process is not responding. Exiting.");
        return 1;
    }

    // Call the DLL function which will kick off the task
    callRemoteFunction(targetProcessHandle, (LPTHREAD_START_ROUTINE)callTargetFunctionPointer, (LPVOID)workerID, 0);

    // The DLL will write the status of the task (success (1), fail (0), pending (-1)) and the total attempts made so far
    char data[DATA_BUFFER_SIZE];
    char status = PASSPHRASE_PENDING;
    long long totalAttempts = 0;

    while(status == PASSPHRASE_PENDING)            
    {
        printf("%s%lld\n", "Attempts so far: ", totalAttempts);
        Sleep(POLL_AGENT_STATUS_MS);
        // Read the shared memory
        ReadProcessMemory(targetProcessHandle, targetMemoryAddressForDllHandle, data, DATA_BUFFER_SIZE, 0);
        // Split it by the delimiter '|'
        char *newStatus = strtok(data, "|");
        // subsequent strtok calls use a null pointer when continuing to iterate over the same buffer
        char *newTotalAttempts = strtok(0, "|");
        // and convert the strings to their correct data type
        // status = 32bit signed integer
        status = atoi(newStatus);
        // totalAttempts  = 64bit signed integer
        totalAttempts = atoll(newTotalAttempts);
    }

    if(status == PASSPHRASE_FAIL)
    {
        printf("%s\n", "Correct password not found");
    }
    else if(status == PASSPHRASE_SUCCESS)
    {
        printf("%s\n", "Correct password found - check output file");
    }

    printf("%s%lld\n", "Total Attempts: ", totalAttempts);
    
    VirtualFreeEx(targetProcessHandle, targetMemoryAddressForDllHandle, 0, MEM_RELEASE);
    CloseHandle(targetProcessHandle);
    printf("%s\n", "Finished. Closing...");
    return status;
}