// Compiled as a DLL

#define _WIN32_WINNT 0x0A00

// Function offsets to set up the application state and ultimately check the supplied passphrase
#define CHECK_PASSPHRASE_FUNCTION_OFFSET 0x21A560
#define CHECK_PASSPHRASE_ARG1_OFFSET 0x1F9B488

#define MODULE_ITERATOR_START 0
#define MODULE_ITERATOR_CONTINUE 1

#define PASSPHRASE_CANDIDATE_FILE_NAME "candidate_list_"
#define PASSPHRASE_CANDIDATE_FILE_EXTENSION ".txt"
#define PASSPHRASE_MAX_LENGTH 64
#define PASSPHRASE_COMMAND "walletpassphrase"
#define PASSPHRASE_COMMAND_DURATION "1"
#define PASSPHRASE_COMMAND_ALLOCATION_SIZE 32

#define OUTPUT_FILE_NAME "\\agent_output_"
#define OUTPUT_FILE_EXTENSION ".txt"
#define OUTPUT_SUCCESS "The password has been found!"
#define OUTPUT_FAIL "The password was not found."
#define OUTPUT_INFO "Total Attempts:"
#define OUTPUT_FOUND_PASSPHRASE "Correct passphrase:"

#include "shared_constants.h"

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>
#include <tlhelp32.h>
#include <shlobj.h>

// This is the function that checks the supplied passphrase and returns 1 or 0 if it's correct or not, respectively.
// The first arg is the value at the offset 0x1F9B488. This value is likely to be a pointer to something else. The assembly instruct does a QWORD move, so that is why arg1 is of type long long
// The second arg is a double pointer to the passphrase. Inside this function, it will perform an operation like (passphraseMemoryAddress - 0x18), to retrieve a value that describes the length of the passphrase. The assembly instruction does a QWORD move, hence why passphraseLength is a long long. 
// The PassphraseObject struct lays out the memory for this to work
// The remaining two args are both 0 (it is not known if they are used at all).
typedef int (*CheckPassphraseSignature) (long long arg1, void **passphrase, int firstZero, int secondZero);

typedef struct _PasssphraseObject
{
    long long passphraseLength;
    // Provides sufficient space between passphraseLength and passphrase such that the instruction (passphraseMemoryAddress - 0x18) will work
    char padding[0x10];
    char passphrase[PASSPHRASE_MAX_LENGTH];
} PassphraseObject;

HANDLE currentProcessHandle = 0;
LPVOID sharedMemoryAddress = 0;
char sharedMemoryData[DATA_BUFFER_SIZE];

int readLine(FILE *filePointer, char *outputBuffer, int outputBufferSize)
{
     int index = 0;

     while(index < outputBufferSize)
     {
         char readCharacter = fgetc(filePointer);

        if(readCharacter != EOF && readCharacter != '\n')
        {
            outputBuffer[index] = readCharacter;
        }
        else
        {
            outputBuffer[index] = '\0';
            return index == 0 ? EOF : 1;
        }

        index++;
     }
}

// Called periodically by callTargetFunction, writing the current status to shared memory.
// This piece of memory is read by the injector periodically to get the current status of this agent.
void writeStatusToSharedMemory(char status, long long totalAttempts)
{
    if(currentProcessHandle == 0)
    {
        int currentProcessId = GetCurrentProcessId();
        currentProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, currentProcessId);          
    }

    // Convert status and totalAttempts into a string, delimited by '|'
    int dataLength = sprintf(sharedMemoryData, "%d|%lld", status, totalAttempts) + 1;   
    // Write the string to shared memory
    WriteProcessMemory(currentProcessHandle, sharedMemoryAddress, sharedMemoryData, dataLength, 0);
}

// Called by the injector and tells this agent where the shared memory location is
int setSharedMemoryAddress(LPVOID address)
{
    sharedMemoryAddress = address;
    // Writes to shared memory straight away, indicating that the program is running.
    // This avoids the possibility of the injector reading arbitary data and getting the wrong status of the agent
    writeStatusToSharedMemory(PASSPHRASE_PENDING, 0);
    return 0;
}

// ASLR can change the base address of the process we're injected in. For our offsets to work, like when calling a certain function, we must know the current base address.
LPVOID getBaseAddress()
{
    // Get the full qualified name path of the process we are injected into. Output is placed in currentProcessName
    char currentProcessName[MAX_PATH];
    GetModuleFileNameA(0, currentProcessName, MAX_PATH);

    // Each process has a variety of modules loaded into it which you can get a list of. The list will also contain the main executable itself, with its base address. Determining the base address is necessary when calling certain functions when only their offsets are known.  
    // We will proceed to iterate over every module in the process we're injected into, and find the module which has the same name as currentProcessName. We will then have our base address.
    
    // Create a handle to a snapshot containing every 32bit & 64bit module (DLL) loaded in the process we're injected into.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    
    // Iterating the modules held in the snapshot is a bit strange but basically you have to call Module32First and then subsequently Module32Next. 
    // These are actually macros which expand into a function.
    typedef WINBOOL (*ModuleIterator) (HANDLE snapshot, LPMODULEENTRY32 moduleInfoPointer);
    // To make the code a bit more compact, I've placed Module32First and Module32Next in an array which I can select with an index
    ModuleIterator moduleIterators[] = {Module32First, Module32Next};
    // Start at index 0.
    char moduleIteratorIndex = MODULE_ITERATOR_START;
    // Buffer to hold the currently selected module name
    char moduleFileName[MAX_PATH];
    // The base address of our main executable
    LPVOID baseAddress = 0;

    while(1)
    {
        // Select the next available module, load the data into moduleInfo struct
        MODULEENTRY32 moduleInfo;
        moduleInfo.dwSize = sizeof(MODULEENTRY32);
        WINBOOL isSuccessful = moduleIterators[moduleIteratorIndex](snapshot, &moduleInfo);

        if(isSuccessful == TRUE)
        {
            // Sets the index to 1, only relevant on the first iteration really when we go from calling Module32First to Module32Next.
            moduleIteratorIndex = MODULE_ITERATOR_CONTINUE;

            // Get the selected module's fully qualified name
            HMODULE moduleHandle = moduleInfo.hModule;
            GetModuleFileNameA(moduleHandle, moduleFileName, MAX_PATH);

            // Compare the selected module's name with the main executable's name
            // If it's the same, then we have our module and can set the base address and break to clean up before returning.
            if(strcmp(currentProcessName, moduleFileName) == 0)
            {
                baseAddress = moduleInfo.modBaseAddr;
                break;
            }
        }
        else
        {
            break;
        }
    }

    CloseHandle(snapshot);
    snapshot = 0;
    return baseAddress;
}

// LPTHREAD_START_ROUTINE expects a function that takes 1 argument of type LPVOID. Therefore, the workerID had to be casted.
// This function is called by the injector and instructs the agent to begin its task
// The task consists of calling the function that takes in a candidate passphrase, and reading the output of that function.
// The shared memory will be updated periodically with the agent's status
int callTargetFunction(LPVOID castedWorkerID)
{
    LONG_PTR workerID = (LONG_PTR)castedWorkerID;

    // Get the base address of the process we've been injected into.  
    LPVOID baseAddress =  getBaseAddress();

    CheckPassphraseSignature checkPassphrase = (baseAddress + CHECK_PASSPHRASE_FUNCTION_OFFSET);
    long long checkPassphraseArg1 = *(long long *)(baseAddress + CHECK_PASSPHRASE_ARG1_OFFSET);

    PassphraseObject passphraseObject;
    char *passphrasePointer[sizeof(char *)];
    passphrasePointer[0] = passphraseObject.passphrase;

    char passphraseCandidateFileName[MAX_PATH];
    sprintf(passphraseCandidateFileName, "%s%lld%s", PASSPHRASE_CANDIDATE_FILE_NAME, workerID, PASSPHRASE_CANDIDATE_FILE_EXTENSION);
    FILE *passphraseCandidateFile = fopen(passphraseCandidateFileName, "r");
    char currentPassphrase[PASSPHRASE_MAX_LENGTH];

    int result = PASSPHRASE_PENDING;
    long long totalIterations = 0;

    while(1)
    {
        int fileStatus = readLine(passphraseCandidateFile, currentPassphrase, PASSPHRASE_MAX_LENGTH);

        if(fileStatus == EOF)
        {
            break;
        }

        passphraseObject.passphraseLength = sprintf(passphraseObject.passphrase, "%s", currentPassphrase);

        result = checkPassphrase(checkPassphraseArg1, (void **)passphrasePointer, 0, 0);

        totalIterations = totalIterations + 1;

        if(result == PASSPHRASE_SUCCESS)
        {
            break;
        }    
        else
        {
            writeStatusToSharedMemory(PASSPHRASE_PENDING, totalIterations);
        }
    }

    writeStatusToSharedMemory(result, totalIterations);

    LPSTR outputFilePath = calloc(MAX_PATH, sizeof(char));
    // Loads a file path string at the memory location pointed to by outputFilePath
    // example path: "C:\Users\user\Desktop"
    // CISDL values can be found at: https://docs.microsoft.com/en-us/windows/win32/shell/knownfolderid
    SHGetFolderPathA(0, CSIDL_DESKTOP, 0, 0, outputFilePath);

    // Check if there's enough space to add on the actual output file name to the returned path

    char outputFileName[MAX_PATH];
    int outputFileNameLength = sprintf(outputFileName, "%s%lld%s", OUTPUT_FILE_NAME, workerID, OUTPUT_FILE_EXTENSION);

    if(strlen(outputFilePath) + outputFileNameLength + 1 <= MAX_PATH)
    {
        strcat(outputFilePath, outputFileName);
        FILE *outputFilePointer = fopen(outputFilePath, "w");
        // Writes to the file the outcome of the program, the total iterations, and the correct passphrase (if applicable, else N/A)
        fprintf(outputFilePointer, "%s\n%s %lld\n%s %s", 
        result == PASSPHRASE_SUCCESS ? OUTPUT_SUCCESS : OUTPUT_FAIL, 
        OUTPUT_INFO, totalIterations, 
        OUTPUT_FOUND_PASSPHRASE, result == PASSPHRASE_SUCCESS ? currentPassphrase : "N/A");
        fclose(outputFilePointer);
        outputFilePointer = 0;
    }

    free(outputFilePath);     
    fclose(passphraseCandidateFile);         
    CloseHandle(currentProcessHandle);
    outputFilePath = 0;
    passphraseCandidateFile = 0;
    currentProcessHandle = 0;
    return 0;
}


// (Retrieved from Microsoft documentation. Is executed automatically on load)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
            break;
        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.   
}