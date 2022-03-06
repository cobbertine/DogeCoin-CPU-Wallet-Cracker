#define _WIN32_WINNT 0x0A00
#define TARGET_APP_NAME "dogecoin-qt-patched.exe"
#define INJECTOR_APP_NAME "injector.exe"
#define WAIT_FOR_TARGET_PROCESS_TO_START_MS 7500
#define POLL_PROCESS_TIME_MS 1000

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "shared_constants.h"

typedef struct _WorkerData
{
    WINBOOL isEnabled;
    STARTUPINFOA targetStartUpInfo;
    PROCESS_INFORMATION targetProcessInformation;
    STARTUPINFOA injectorStartUpInfo;
    PROCESS_INFORMATION injectorProcessInformation;
} WorkerData;

void closeProcesses(WorkerData *workerData)
{
    if(workerData->isEnabled == TRUE)
    {
        workerData->isEnabled = FALSE;

        TerminateProcess(workerData->injectorProcessInformation.hProcess, 0);
        CloseHandle(workerData->injectorProcessInformation.hProcess);
        CloseHandle(workerData->injectorProcessInformation.hThread);  
        workerData->injectorProcessInformation.hProcess = 0;
        workerData->injectorProcessInformation.hThread = 0;        
        
        if(workerData->injectorStartUpInfo.dwFlags & STARTF_USESTDHANDLES != 0)
        {
            CloseHandle(workerData->injectorStartUpInfo.hStdInput);
            CloseHandle(workerData->injectorStartUpInfo.hStdOutput);
            CloseHandle(workerData->injectorStartUpInfo.hStdError);
            workerData->injectorStartUpInfo.hStdInput = 0;
            workerData->injectorStartUpInfo.hStdOutput = 0;
            workerData->injectorStartUpInfo.hStdError = 0;            
        }

        TerminateProcess(workerData->targetProcessInformation.hProcess, 0);
        CloseHandle(workerData->targetProcessInformation.hProcess);
        CloseHandle(workerData->targetProcessInformation.hThread);
        workerData->targetProcessInformation.hProcess = 0;
        workerData->targetProcessInformation.hThread = 0;        

        if(workerData->targetStartUpInfo.dwFlags & STARTF_USESTDHANDLES != 0)
        {
            CloseHandle(workerData->targetStartUpInfo.hStdInput);
            CloseHandle(workerData->targetStartUpInfo.hStdOutput);
            CloseHandle(workerData->targetStartUpInfo.hStdError);
            workerData->targetStartUpInfo.hStdInput = 0;
            workerData->targetStartUpInfo.hStdOutput = 0;
            workerData->targetStartUpInfo.hStdError = 0;            
        }
    }
}

int main(int argc, char **argv)
{
    if(argc == 1)
    {
        printf("%s\n", "Insufficient args. Requires # of workers desired.");
        return 0;
    }

    int workerCount = atoi(*(argv+1));

    // Set up the workers
    // Each injector will have its own ID, and therefore its own output file.

    WorkerData workerData[workerCount];

    printf("%s\n", "Launching target processes...");

    for(int i = 0; i < workerCount; i++)
    {
        workerData[i].isEnabled = FALSE;

        // Zero out the struct, just in case CreateProcess does not fill out all the data itself.
        ZeroMemory(&workerData[i].targetStartUpInfo, sizeof(workerData[i].targetStartUpInfo));
        ZeroMemory(&workerData[i].targetProcessInformation, sizeof(workerData[i].targetStartUpInfo));
        // Undocumented, but setting this cb value seems to be critical for CreateProcess to actually work.
        workerData[i].targetStartUpInfo.cb = sizeof(workerData[i].targetStartUpInfo);

        char commandLineTargetApp[MAX_PATH];
        sprintf(commandLineTargetApp, "%s", TARGET_APP_NAME);

        // Launch the target application.
        // CREATE_NEW_CONSOLE will ensure the processes has its own stdout, rather than sharing with controller
        WINBOOL isTargetAppStarted = CreateProcessA(0, commandLineTargetApp, 0, 0, 0, CREATE_NEW_CONSOLE, 0, 0, &workerData[i].targetStartUpInfo, &workerData[i].targetProcessInformation);

        if(isTargetAppStarted == FALSE)
        {
            printf("%s%d%s\n", "Worker ID #", GetLastError(), " failed to start the target application");
        }

        Sleep(WAIT_FOR_TARGET_PROCESS_TO_START_MS);
    }

    printf("%s\n", "Done.");

    printf("%s\n", "Launching injectors...");

    for(int i = 0; i < workerCount; i++)
    {
        ZeroMemory(&workerData[i].injectorStartUpInfo, sizeof(workerData[i].injectorStartUpInfo));
        ZeroMemory(&workerData[i].injectorProcessInformation, sizeof(workerData[i].injectorProcessInformation));
        workerData[i].injectorStartUpInfo.cb = sizeof(workerData[i].injectorStartUpInfo);

        char commandLineInjectorApp[DATA_BUFFER_SIZE];
        sprintf(commandLineInjectorApp, "%s%s%d%s%d", INJECTOR_APP_NAME, " ", workerData[i].targetProcessInformation.dwProcessId, " ", i);

        // Launch the injector app    
        WINBOOL isInjectorAppStarted = CreateProcessA(0, commandLineInjectorApp, 0, 0, 0, CREATE_NEW_CONSOLE, 0, 0, &workerData[i].injectorStartUpInfo, &workerData[i].injectorProcessInformation);

        if(isInjectorAppStarted == FALSE)
        {
            printf("%s%d%s\n", "Worker ID #", i, " failed to start the injector application");
        }    

        workerData[i].isEnabled = TRUE;
    }

    printf("%s\n", "Done.");

    printf("%s\n", "Waiting for results...");

    // Begin monitoring the workers
    while(1)
    {
        Sleep(POLL_PROCESS_TIME_MS);

        int activeWorkers = 0;

        for(int i = 0; i < workerCount; i++)
        {
            if(workerData[i].isEnabled == FALSE)
            {
                continue;
            }

            activeWorkers++;

            int injectorStatus = PASSPHRASE_PENDING;
            GetExitCodeProcess(workerData[i].injectorProcessInformation.hProcess, (LPDWORD)&injectorStatus);

            // If the process has ended...
            if(injectorStatus != STILL_ACTIVE)
            {
                closeProcesses(&workerData[i]);
                activeWorkers--;

                if(injectorStatus == PASSPHRASE_SUCCESS)
                {
                    printf("%s%d%s\n", "Success! Worker #", i, " has found the passphrase. Check the related output file for more info");
                    activeWorkers = 0;
                    break;
                }
                else
                {
                    printf("%s%d%s\n", "Failure. Worker #", i, " has not found the passphrase. Check the related output file for more info");
                }
            }
        }

        if(activeWorkers == 0)
        {
            for(int i = 0; i < workerCount; i++)
            {
                closeProcesses(&(workerData[i]));
            }

            printf("%s\n", "Tap Enter to close");
            getc(stdin);
            return 0;
        }
    }
}