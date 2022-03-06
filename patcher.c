#define ORIGINAL_EXE_NAME "dogecoin-qt.exe"
#define PATCHED_EXE_SUFFIX "-patched.exe"
#define TOTAL_CHANGES 22
#define FILE_READ_BUFFER_SIZE 1024 * 1024 * 1

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct _IntKeyValuePair
{
    int key;
    int value;
} IntKeyValuePair;

IntKeyValuePair createIntKeyValuePair(int key, int value)
{
    IntKeyValuePair intKeyValuePair;
    intKeyValuePair.key = key;
    intKeyValuePair.value = value;
    return intKeyValuePair;
}

void createPatchedExe(char *originalExeName, char *patchedExeName)
{
    IntKeyValuePair patchData[TOTAL_CHANGES];

    // This array consists of an index and a value
    // These values are related to assembly instructions which will allow the 
    // program to run multiple instances.
    // By default, it grabs a lock on some files which forbids extra instances running. 
    patchData[0] = createIntKeyValuePair(0xE93FB, 0x90); // Start Region #1
    patchData[1] = createIntKeyValuePair(0xE93FC, 0x90);
    patchData[2] = createIntKeyValuePair(0xE93FD, 0x90);
    patchData[3] = createIntKeyValuePair(0xE93FE, 0x90);
    patchData[4] = createIntKeyValuePair(0xE93FF, 0x90);
    patchData[5] = createIntKeyValuePair(0xE9400, 0x90); // End Region #1
    patchData[6] = createIntKeyValuePair(0xE952F, 0xE9); // Start Region #2
    patchData[7] = createIntKeyValuePair(0xE9530, 0xD8);
    patchData[8] = createIntKeyValuePair(0xE9531, 0xFE);
    patchData[9] = createIntKeyValuePair(0xE9532, 0xFF);
    patchData[10] = createIntKeyValuePair(0xE9534, 0x90); // End Region #2
    patchData[11] = createIntKeyValuePair(0x38AC73, 0x07); // Start Region #3
    patchData[12] = createIntKeyValuePair(0x38AC7B, 0xC0); // End Region #3
    patchData[13] = createIntKeyValuePair(0x38B95D, 0xBA); // Start Region #4
    patchData[14] = createIntKeyValuePair(0x38B95E, 0x00);
    patchData[15] = createIntKeyValuePair(0x38B95F, 0x00);
    patchData[16] = createIntKeyValuePair(0x38B960, 0x00);
    patchData[17] = createIntKeyValuePair(0x38B961, 0xC0);
    patchData[18] = createIntKeyValuePair(0x38B962, 0x90);
    patchData[19] = createIntKeyValuePair(0x38B963, 0x90);
    patchData[20] = createIntKeyValuePair(0x38B964, 0x90);
    patchData[21] = createIntKeyValuePair(0x38B965, 0x90); // End Region #4

    FILE *originalExe = fopen(originalExeName, "rb");
    FILE *patchedExe = fopen(patchedExeName, "wb");

    int originalExeFileIndex = 0;

    // While reading the file, it is likely that the buffer will need to be expanded.
    int dataBufferSizeMultiplier = 1;
    char *originalBytes = malloc(FILE_READ_BUFFER_SIZE * dataBufferSizeMultiplier * sizeof(char));

    while(1)
    {
        int originalByte = fgetc(originalExe);

        if(originalByte != EOF)
        {
            originalBytes[originalExeFileIndex++] = originalByte;

            // If the index has now reached the end of the current buffer, resize it.
            if(originalExeFileIndex == FILE_READ_BUFFER_SIZE * dataBufferSizeMultiplier)
            {
                dataBufferSizeMultiplier++;
                char *resizedOriginalBytes = malloc(FILE_READ_BUFFER_SIZE * dataBufferSizeMultiplier * sizeof(char));
                memcpy(resizedOriginalBytes, originalBytes, FILE_READ_BUFFER_SIZE * (dataBufferSizeMultiplier - 1));
                free(originalBytes);
                originalBytes = resizedOriginalBytes;
            }
        }
        else
        {
            // Once the file has been completely read into memory, begin applying the necessary patches
            for(int i = 0; i < TOTAL_CHANGES; i++)
            {
                originalBytes[patchData[i].key] = patchData[i].value;
            }

            // Finally write the file from memory onto the disk in a new file.
            for(int i = 0; i < originalExeFileIndex; i++)
            {
                fputc(originalBytes[i], patchedExe);
            }   

            free(originalBytes);
            fclose(originalExe);
            fclose(patchedExe);
            originalBytes = 0;
            originalExe = 0;
            patchedExe = 0;
            return;
        }
    } 
}

void checkExes(char *originalExeName, char *patchedExeName)
{
    FILE *originalExe = fopen(originalExeName, "rb");
    FILE *patchedExe = fopen(patchedExeName, "rb");    

    int index = 0;

    while(1)
    {
        int originalByte = fgetc(originalExe);
        int patchedByte = fgetc(patchedExe);

        if(originalByte == EOF)
        {
            printf("%s%d\n", "Total bytes read: ", index);
            fclose(originalExe);
            fclose(patchedExe);
            originalExe = 0;
            patchedExeName = 0;
            return;
        }

        if(originalByte != patchedByte)
        {
            // Format specifier:
            // | string | uppercase hex with "0x" prepended | string | uppercase hex of at least 2 numbers with "0x" prepended | string | uppercase hex of at least 2 numbers with "0x" prepended |
            printf("%s0x%X%s0x%.2X%s0x%.2X\n", "Detected byte difference at file offset ", index, ": ", originalByte, " -> ", patchedByte);
        }

        index++;
    }    
}

int main(int argc, char **argv)
{
    // We will create a new string for the patched exe, based off the original exe name.
    char originalExeName[] = ORIGINAL_EXE_NAME;
    // strtok will replace the delimiter with a null terminator
    char *originalExeNameNoExtension = strtok(originalExeName, ".");
    char patchedExeName[strlen(originalExeNameNoExtension) + strlen(PATCHED_EXE_SUFFIX) + 1];
    // Add a new string to the supplied array.
    sprintf(patchedExeName, "%s%s", originalExeNameNoExtension, PATCHED_EXE_SUFFIX);    
    // We can now undo what strtok did so we can use the original name as well.
    // (*(originalExeName + strlen(originalExeName))) = '.';
    originalExeName[strlen(originalExeName)] = '.';

    printf("%s\n", "Patching...");
    createPatchedExe(originalExeName, patchedExeName);
    printf("%s\n", "Patch done.");
    printf("%s\n", "Displaying byte differences of original and patched exe.");
    checkExes(originalExeName, patchedExeName);
    printf("%s\n", "Done.");

    return 0;
}