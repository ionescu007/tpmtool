/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    tpmtool.cpp

Abstract:

    This module implements the main command-line handling of the utility plus
    the dumping of data using a hexdump. Each command-line option is wrapped
    in a helper which then uses the TPM2.0 commands in tpmcmd.cpp.

Author:

    Alex Ionescu (@aionescu) 11-Jun-2020 - Initial version

Environment:

    Portable to any environment.

--*/

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

//
// C Headers needed for CLI Tool
//
#include <stdlib.h>
#include <string.h>
#include <io.h>

//
// Shared Library Header
//
#include "tpmtool.hpp"

void
DumpHex (
    uint8_t* Buffer,
    int32_t Size
    )
{
    char ascii[17];
    int32_t i, j;

    //
    // Taken and adapted from https://gist.github.com/ccbrown/9722406
    //
    ascii[16] = '\0';
    for (i = 0; i < Size; ++i)
    {
        fprintf(stderr, "%02X ", Buffer[i]);
        if ((Buffer[i] >= ' ') && (Buffer[i] <= '~'))
        {
            ascii[i % 16] = Buffer[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((((i + 1) % 8) == 0) || ((i + 1) == Size))
        {
            fprintf(stderr, " ");
            if ((i + 1) % 16 == 0)
            {
                fprintf(stderr, "|  %s \n", ascii);

            }
            else if ((i + 1) == Size)
            {
                ascii[((i + 1) % 16)] = '\0';
                if (((i + 1) % 16) <= 8)
                {
                    fprintf(stderr, " ");
                }

                for (j = ((i + 1) % 16); j < 16; ++j)
                {
                    fprintf(stderr, "   ");
                }
                fprintf(stderr, "|  %s \n", ascii);
            }
        }
    }
    fprintf(stderr, "\n");
}

void
PrintUsage (
    void
    )
{
    //
    // Print help block
    //
    fprintf(stderr, "TpmTool allows you to define non-volatile (NV) spaces (indices) and\n");
    fprintf(stderr, "read/write data within them. Password authentication can optionally\n");
    fprintf(stderr, "be used to protect their contents.\n\n");
    fprintf(stderr, "Usage: tpmtool [-h <size>|-r <size>|-t|-e|index] [-c <attributes> <owner> <auth> <size>|-r <offset> <size>|-w <offset> <size>|-rl|-wl|-d|-q] [password]\n");
    fprintf(stderr, "    -r    Retrieves random bytes based on the size given.\n");
    fprintf(stderr, "    -t    Reads the TPM Time Information.\n");
    fprintf(stderr, "    -h    Computes the SHA-256 hash of the data in STDIN.\n");
    fprintf(stderr, "          You can use pipes or redirection to write from a file.\n");
    fprintf(stderr, "    -e    Enumerates all NV spaces active on the TPM.\n");
    fprintf(stderr, "    -c    Create a new NV space with the given index value.\n");
    fprintf(stderr, "          Attributes can be a combination (use + for multiple) of:\n");
    fprintf(stderr, "              RL    Allow the resulting NV index to be read-locked.\n");
    fprintf(stderr, "              WL    Allow the resulting NV index to be write-locked.\n");
    fprintf(stderr, "              WO    Make the write-locked state of the NV index permanent.\n");
    fprintf(stderr, "              WA    Partial writes are not allowed into the NV index.\n");
    fprintf(stderr, "              NP    No protection against dictionary attacks.\n");
    fprintf(stderr, "              CH    Cache the resulting NV index in RAM (orderly).\n");
    fprintf(stderr, "              VL    Makes the dirty flag volatile (cleared at startup).\n");
    fprintf(stderr, "              PT    Marks the NV space as non-deletable without a policy.\n");
    fprintf(stderr, "          Owner and Auth rights can be one of R, RW, or NA.\n");
    fprintf(stderr, "          Size is limited by TPM should usually be 2048 or less.\n");
    fprintf(stderr, "    -r    Read the data stored at the given index value.\n");
    fprintf(stderr, "          Offset and size must be fit within size of the space.\n");
    fprintf(stderr, "          Data is printed to STDOUT and can be redirected to a file.\n");
    fprintf(stderr, "    -w    Write the data from STDIN into the given index value.\n");
    fprintf(stderr, "          Offset and size must be fit within size of the space.\n");
    fprintf(stderr, "          You can use pipes or redirection to write from a file.\n");
    fprintf(stderr, "    -q    Query the size, rights, and attributes of the given index.\n");
    fprintf(stderr, "          Also indicates if the index has ever been written to (dirty).\n");
    fprintf(stderr, "          Attributes are the same as shown earlier, with the addition of:\n");
    fprintf(stderr, "              LR    The index is locked against reads until reset.\n");
    fprintf(stderr, "              LW    The index is locked against writes until reset.\n");
    fprintf(stderr, "                    NOTE: If the WO attribute is set, locked forever.\n");
    fprintf(stderr, "              PO    The index was created and is owned by the platform.\n");
    fprintf(stderr, "    -qa   Query all NV spaces active on the TPM.\n");
    fprintf(stderr, "          Prints size, rights and attributes for each index.\n");
    fprintf(stderr, "    -rl   Lock the NV space at the given index value against reads.\n");
    fprintf(stderr, "          The NV space must have been created with the RL attribute.\n");
    fprintf(stderr, "    -wl   Lock the NV space at the given index value against writes.\n");
    fprintf(stderr, "          The NV space must have been created with the WL attribute.\n");
    fprintf(stderr, "    -d    Delete the NV space at the given index value.\n\n");
    fprintf(stderr, "If the index was created with a password and owner auth is NA, the\n");
    fprintf(stderr, "password must be used on any further read or write operations.\n");
}

int32_t
LockSpace (
    int32_t ArgumentCount,
    char* Arguments[],
    uintptr_t TpmHandle,
    TPM_NV_INDEX Index,
    bool Write
    )
{
    uint8_t* password;
    uint16_t passwordSize;
    TPM_RC tpmResult;

    //
    // We need at least 3 arguments, and no more than 4
    //
    if ((ArgumentCount < 3) || (ArgumentCount > 4))
    {
        PrintUsage();
        return -1;
    }

    //
    // Check if a password was entered
    //
    if (ArgumentCount == 4)
    {
        //
        // Read it and calculate its size
        //
        password = reinterpret_cast<uint8_t*>(Arguments[3]);
        passwordSize = static_cast<uint16_t>(strlen(Arguments[3]));
        if (passwordSize == 0)
        {
            fprintf(stderr, "Password %s not valid!\n", Arguments[3]);
            return -1;
        }
    }
    else
    {
        //
        // We'll use owner auth
        //
        password = nullptr;
        passwordSize = 0;
    }

    //
    // Undefine it
    //
    fprintf(stderr, "Locking NV space with index 0x%08x...\n\n", Index.Value);
    tpmResult = Write ? TpmWriteLock2(TpmHandle, Index, passwordSize, password) :
                        TpmReadLock2(TpmHandle, Index, passwordSize, password);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Locking failed with code 0x%02x\n", tpmResult);
        return -1;
    }
    fprintf(stderr, "Locking completed!\n");
    return 0;
}

int32_t
DeleteSpace (
    int32_t ArgumentCount,
    uintptr_t TpmHandle,
    TPM_NV_INDEX Index
    )
{
    TPM_RC tpmResult;

    //
    // We should only have 3 arguments
    //
    if (ArgumentCount != 3)
    {
        PrintUsage();
        return -1;
    }

    //
    // Undefine it
    //
    fprintf(stderr, "Deleting NV space with index 0x%08x...\n\n", Index.Value);
    tpmResult = TpmUndefineSpace2(TpmHandle, Index);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Undefine failed with code 0x%02x\n", tpmResult);
        return -1;
    }
    fprintf(stderr, "Undefine completed!\n");
    return 0;
}

int32_t
WriteSpace (
    int32_t ArgumentCount,
    char* Arguments[],
    uintptr_t TpmHandle,
    TPM_NV_INDEX Index
    )
{
    uint16_t dataSize;
    uint16_t offset;
    uint8_t* data;
    uint8_t* password;
    uint16_t passwordSize;
    TPM_RC tpmResult;
    size_t sizeRead;

    //
    // We need at least 5 arguments, and no more than 6
    //
    if ((ArgumentCount < 5) || (ArgumentCount > 6))
    {
        PrintUsage();
        return -1;
    }

    //
    // Read the offset and make sure it's valid
    //
    offset = static_cast<uint16_t>(strtoul(Arguments[3], nullptr, 0));
    if ((offset == 0) && (Arguments[3][0] != '0'))
    {
        fprintf(stderr, "Offset of %s bytes not permitted!\n", Arguments[3]);
        return -1;
    }

    //
    // Read the size and make sure it's valid
    //
    dataSize = static_cast<uint16_t>(strtoul(Arguments[4], nullptr, 0));
    if (dataSize == 0)
    {
        fprintf(stderr, "Size of %s bytes not permitted!\n", Arguments[4]);
        return -1;
    }
    else if (dataSize > USHRT_MAX)
    {
        fprintf(stderr, "Size of %d bytes is too large!\n", dataSize);
        return -1;
    }

    //
    // Allocate space for the data
    //
    data = reinterpret_cast<uint8_t*>(alloca(dataSize));
    memset(data, 0, dataSize);

    //
    // Read input
    //
    sizeRead = fread(data, 1, dataSize, stdin);
    if (sizeRead == 0)
    {
        fprintf(stderr, "Could not read from STDIN\n");
        return -1;
    }

    //
    // Check if a password was entered
    //
    if (ArgumentCount == 6)
    {
        //
        // Read it and calculate its size
        //
        password = reinterpret_cast<uint8_t*>(Arguments[5]);
        passwordSize = static_cast<uint16_t>(strlen(Arguments[5]));
        if (passwordSize == 0)
        {
            fprintf(stderr, "Password %s not valid!\n", Arguments[5]);
            return -1;
        }
    }
    else
    {
        //
        // We'll use owner auth
        //
        password = nullptr;
        passwordSize = 0;
    }

    //
    // Go and do the write
    //
    fprintf(stderr,
            "Writing to NV space with index 0x%08x at offset 0x%04x...\n\n",
            Index.Value,
            offset);
    DumpHex(data, dataSize);
    tpmResult = TpmNvWrite2(TpmHandle,
                            Index,
                            passwordSize,
                            password,
                            offset,
                            dataSize,
                            data);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Write failed with code 0x%02x\n", tpmResult);
        return -1;
    }
    fprintf(stderr, "Write completed!\n");
    return 0;
}

int32_t
ReadSpace (
    int32_t ArgumentCount,
    char* Arguments[],
    uintptr_t TpmHandle,
    TPM_NV_INDEX Index
    )
{
    uint16_t dataSize;
    uint16_t offset;
    uint8_t* data;
    uint8_t* password;
    uint16_t passwordSize;
    TPM_RC tpmResult;

    //
    // We need at least 5 arguments, and no more than 6
    //
    if ((ArgumentCount < 5) || (ArgumentCount > 6))
    {
        PrintUsage();
        return -1;
    }

    //
    // Read the offset and make sure it's valid
    //
    offset = static_cast<uint16_t>(strtoul(Arguments[3], nullptr, 0));
    if ((offset == 0) && (Arguments[3][0] != '0'))
    {
        fprintf(stderr, "Offset of %s bytes not permitted!\n", Arguments[3]);
        return -1;
    }

    //
    // Read the size and make sure it's valid
    //
    dataSize = static_cast<uint16_t>(strtoul(Arguments[4], nullptr, 0));
    if (dataSize == 0)
    {
        fprintf(stderr, "Size of %s bytes not permitted!\n", Arguments[4]);
        return -1;
    }
    else if (dataSize > USHRT_MAX)
    {
        fprintf(stderr, "Size of %d bytes is too large!\n", dataSize);
        return -1;
    }

    //
    // Allocate space for the data
    //
    data = reinterpret_cast<uint8_t*>(alloca(dataSize));
    memset(data, 0, dataSize);

    //
    // Check if a password was entered
    //
    if (ArgumentCount == 6)
    {
        //
        // Read it and calculate its size
        //
        password = reinterpret_cast<uint8_t*>(Arguments[5]);
        passwordSize = static_cast<uint16_t>(strlen(Arguments[5]));
        if (passwordSize == 0)
        {
            fprintf(stderr, "Password %s not valid!\n", Arguments[5]);
            return -1;
        }
    }
    else
    {
        //
        // We'll use owner auth
        //
        password = nullptr;
        passwordSize = 0;
    }

    //
    // Go and do the write
    //
    fprintf(stderr,
            "Reading 0x%04x bytes from NV space with index "
            "0x%08x at offset 0x%04x...\n\n",
            dataSize,
            Index.Value,
            offset);
    tpmResult = TpmNvRead2(TpmHandle,
                           Index,
                           passwordSize,
                           password,
                           offset,
                           dataSize,
                           data);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Read failed with code 0x%02x\n", tpmResult);
        return -1;
    }

    //
    // Print data to STDOUT and dump to STDERR
    //
    if (_isatty(_fileno(stdout)) == false)
    {
        printf("%.*s", dataSize, data);
    }
    DumpHex(data, dataSize);

    //
    // And final result
    //
    fprintf(stderr, "Read completed!\n");
    return 0;
}

int32_t
CreateSpace (
    int32_t ArgumentCount,
    char* Arguments[],
    uintptr_t TpmHandle,
    TPM_NV_INDEX Index
    )
{
    uint8_t ownerRights;
    uint8_t authRights;
    uint16_t dataSize;
    uint8_t* password;
    uint16_t passwordSize;
    uint8_t attributes;
    TPM_RC tpmResult;

    //
    // We need at least 7 arguments, and no more than 8
    //
    if ((ArgumentCount < 7) || (ArgumentCount > 8))
    {
        PrintUsage();
        return -1;
    }

    //
    // Validate owner rights
    //
    ownerRights = TpmToolNoAccess;
    if (strcmp(Arguments[3], "R") == 0)
    {
        ownerRights |= TpmToolReadAccess;
    }
    else if (strcmp(Arguments[3], "RW") == 0)
    {
        ownerRights |= TpmToolReadWriteAccess;
    }
    else if (strcmp(Arguments[3], "NA") == 0)
    {
        ownerRights = TpmToolNoAccess;
    }
    else
    {
        fprintf(stderr, "Invalid owner rights value: %s\n", Arguments[3]);
        return -1;
    }

    //
    // Validate auth rights
    //
    authRights = TpmToolNoAccess;
    if (strcmp(Arguments[4], "R") == 0)
    {
        authRights |= TpmToolReadAccess;
    }
    else if (strcmp(Arguments[4], "RW") == 0)
    {
        authRights |= TpmToolReadWriteAccess;
    }
    else if (strcmp(Arguments[4], "NA") == 0)
    {
        authRights = TpmToolNoAccess;
    }
    else
    {
        fprintf(stderr, "Invalid auth rights value: %s\n", Arguments[4]);
        return -1;
    }

    //
    // Validate attributes
    //
    attributes = 0;
    if (strstr(Arguments[5], "RL") != nullptr)
    {
        attributes |= TpmToolReadLockable;
    }
    if (strstr(Arguments[5], "WL") != nullptr)
    {
        attributes |= TpmToolWriteLockable;
    }
    if (strstr(Arguments[5], "WO") != nullptr)
    {
        attributes |= TpmToolWriteOnce;
    }
    if (strstr(Arguments[5], "WA") != nullptr)
    {
        attributes |= TpmToolWriteAll;
    }
    if (strstr(Arguments[5], "NP") != nullptr)
    {
        attributes |= TpmToolNonProtected;
    }
    if (strstr(Arguments[5], "CH") != nullptr)
    {
        attributes |= TpmToolCached;
    }
    if (strstr(Arguments[5], "VL") != nullptr)
    {
        attributes |= TpmToolWriteLocked;
    }
    if (strstr(Arguments[5], "PT") != nullptr)
    {
        attributes |= TpmToolPermanent;
    }

    //
    // Get the data size and validate
    //
    dataSize = static_cast<uint16_t>(strtoul(Arguments[6], nullptr, 0));
    if (dataSize == 0)
    {
        fprintf(stderr, "Space of %s bytes not permitted!\n", Arguments[5]);
        return -1;
    }

    //
    // Check if a password was entered
    //
    if (ArgumentCount == 8)
    {
        //
        // Read it and calculate its size
        //
        password = reinterpret_cast<uint8_t*>(Arguments[7]);
        passwordSize = static_cast<uint16_t>(strlen(Arguments[7]));
        if (passwordSize == 0)
        {
            fprintf(stderr, "Password %s not valid!\n", Arguments[7]);
            return -1;
        }
    }
    else
    {
        //
        // We'll use owner auth
        //
        password = nullptr;
        passwordSize = 0;
    }

    //
    // Define the space
    //
    fprintf(stderr,
            "Creating NV space with index 0x%08x, attributes 0x%02x "
            "and data size 0x%04x...\n\n",
            Index.Value,
            attributes,
            dataSize);
    tpmResult = TpmDefineSpace2(TpmHandle,
                                Index,
                                dataSize,
                                attributes,
                                ownerRights,
                                authRights,
                                passwordSize,
                                password);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Create failed with code 0x%02x\n", tpmResult);
        return -1;
    }
    fprintf(stderr, "Create completed!\n");
    return 0;
}

TPM_RC
QuerySpaceInternal (
    uintptr_t TpmHandle,
    TPM_NV_INDEX Index,
    uint16_t* DataSize,
    char* Attributes,
    char* OwnerRights,
    char* AuthRights,
    char* AttributeBuffer
    )
{
    uint16_t attributes;
    uint8_t ownerRights;
    uint8_t authRights;
    TPM_RC tpmResult;

    //
    // Query information on the given space
    //
    tpmResult = TpmReadPublic2(TpmHandle,
                               Index,
                               &attributes,
                               &ownerRights,
                               &authRights,
                               DataSize);

    if (tpmResult != TPM_RC_SUCCESS)
    {
        return tpmResult;
    }

    strcpy(Attributes, (attributes & TpmToolWritten) ? "dirty" : "unwritten");

    if ((ownerRights & TpmToolReadWriteAccess) == TpmToolReadWriteAccess)
    {
        strcpy(OwnerRights, "RW");
    }
    else if((ownerRights & TpmToolReadAccess) == TpmToolReadAccess)
    {
        strcpy(OwnerRights, "R");
    }
    else
    {
        strcpy(OwnerRights, "NA");
    }

    if ((authRights & TpmToolReadWriteAccess) == TpmToolReadWriteAccess)
    {
        strcpy(AuthRights, "RW");
    }
    else if ((authRights & TpmToolReadAccess) == TpmToolReadAccess)
    {
        strcpy(AuthRights, "R");
    }
    else
    {
        strcpy(AuthRights, "NA");
    }

    strcpy(AttributeBuffer, " ");
    if (attributes & TpmToolReadLockable)
    {
        strcat(AttributeBuffer, "RL+");
    }
    if (attributes & TpmToolWriteLockable)
    {
        strcat(AttributeBuffer, "WL+");
    }
    if (attributes & TpmToolWriteOnce)
    {
        strcat(AttributeBuffer, "WO+");
    }
    if (attributes & TpmToolWriteAll)
    {
        strcat(AttributeBuffer, "WA+");
    }
    if (attributes & TpmToolNonProtected)
    {
        strcat(AttributeBuffer, "NP+");
    }
    if (attributes & TpmToolCached)
    {
        strcat(AttributeBuffer, "CH+");
    }
    if (attributes & TpmToolVolatileDirtyFlag)
    {
        strcat(AttributeBuffer, "VL+");
    }
    if (attributes & TpmToolPermanent)
    {
        strcat(AttributeBuffer, "PT+");
    }

    //
    // Next, the status attributes
    //
    if (attributes & TpmToolReadLocked)
    {
        strcat(AttributeBuffer, "LR+");
    }
    if (attributes & TpmToolWriteLocked)
    {
        strcat(AttributeBuffer, "LW+");
    }
    if (attributes & TpmToolPlatformOwned)
    {
        strcat(AttributeBuffer, "PO+");
    }

    return TPM_RC_SUCCESS;
}

int32_t
QuerySpaceMinimalOutput (
    uintptr_t TpmHandle,
    TPM_NV_INDEX Index
    )
{
    uint16_t dataSize;
    TPM_RC tpmResult;
    char attributes[sizeof("unwritten")];
    char ownerRights[sizeof("NA")];
    char authRights[sizeof("NA")];
    char attributeBuffer[(12 * 3) + 1];

    tpmResult = QuerySpaceInternal(TpmHandle,
                                   Index,
                                   &dataSize,
                                   attributes,
                                   ownerRights,
                                   authRights,
                                   attributeBuffer);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        return -1;
    }

    attributeBuffer[strlen(attributeBuffer) - 1] = '\0';
    printf("0x%04x, %s, owner rights: %s, auth rights: %s, attributes:%s",
           dataSize,
           attributes,
           ownerRights,
           authRights,
           attributeBuffer);
    return 0;
}

int32_t
QuerySpace (
    int32_t ArgumentCount,
    uintptr_t TpmHandle,
    TPM_NV_INDEX Index
    )
{
    uint16_t dataSize;
    TPM_RC tpmResult;
    char attributes[sizeof("unwritten")];
    char ownerRights[sizeof("NA")];
    char authRights[sizeof("NA")];
    char attributeBuffer[(12 * 3) + 1];

    //
    // This one only takes 3 arguments
    //
    if (ArgumentCount != 3)
    {
        PrintUsage();
        return -1;
    }

    //
    // Query information on the given space
    //
    fprintf(stderr, "Querying NV space with index 0x%08x...\n\n", Index.Value);
    tpmResult = QuerySpaceInternal(TpmHandle,
                                   Index,
                                   &dataSize,
                                   attributes,
                                   ownerRights,
                                   authRights,
                                   attributeBuffer);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Query failed with code 0x%02x\n", tpmResult);
        return -1;
    }

    //
    // Dump the size and if it's been modified yet
    //
    printf("NV_PUBLIC\n");
    printf("=========\n");
    printf("Data Size    : 0x%04x [%s]\n",
            dataSize,
            attributes);

    //
    // Dump the owner and authorization rights
    //
    printf("Owner Rights : %s\n",
            ownerRights);
    printf("Auth Rights  : %s\n",
            authRights);

    //
    // Do the attributes, first with the ones set at creation
    //
    printf("Attributes   :");

    //
    // This is dirty... converts the last plus into a newline *g*
    //
    attributeBuffer[strlen(attributeBuffer) - 1] = '\n';
    printf("%s\n", attributeBuffer);

    //
    // And final result
    //
    fprintf(stderr, "Query completed!\n");
    return 0;
}

int32_t
EnumerateSpaces (
    int32_t ArgumentCount,
    uintptr_t TpmHandle,
    bool QuerySpaces
    )
{
    uint32_t handleCount;
    uint32_t i;
    uint32_t arraySize;
    TPM_NV_INDEX* handleArray;
    TPM_RC tpmResult;

    //
    // This one is special and takes no other arguments
    //
    if (ArgumentCount != 2)
    {
        PrintUsage();
        return -1;
    }

    //
    // Enumerate the NV Indices that are defined on the chip, querying only the
    // count for now.
    //
    handleCount = 0;
    tpmResult = TpmNvEnumerate2(TpmHandle, &handleCount, nullptr);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Enumeration failed with code 0x%02x\n", tpmResult);
        return -1;
    }

    //
    // Now that we know how many there are, allocate a big enough array.
    // Note that there is technically a race here, and we'll just fail if so.
    //
    arraySize = handleCount * sizeof(*handleArray);
    handleArray = reinterpret_cast<decltype(handleArray)>(alloca(arraySize));

    //
    // Do the second query, which will now return the actual NV index values
    //
    tpmResult = TpmNvEnumerate2(TpmHandle, &handleCount, handleArray);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Enumeration failed with code 0x%02x\n", tpmResult);
        return -1;
    }

    //
    // For each NV index, print its value to STDOUT
    //
    for (i = 0; i < handleCount; i++)
    {
        printf("NV index: 0x%08x\n", handleArray[i].Value);
    }
    return 0;
}

int32_t
ReadClock (
    int32_t ArgumentCount,
    uintptr_t TpmHandle
    )
{
    uint64_t timeValue;
    uint64_t clockValue;
    uint32_t resetCount;
    uint32_t restartCount;
    TPMI_YES_NO isSafe;
    TPM_RC tpmResult;

    //
    // This one is special and takes no other arguments
    //
    if (ArgumentCount != 2)
    {
        PrintUsage();
        return -1;
    }

    //
    // Send the TPM command to read the information
    //
    tpmResult = TpmReadClock(TpmHandle,
                             &timeValue,
                             &clockValue,
                             &resetCount,
                             &restartCount,
                             &isSafe);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Clock read failed with code 0x%02x\n", tpmResult);
        return -1;
    }

    //
    // Output the result back to the user
    //
    printf("Clock: %016lld\t"
            "Time: %016lld\t"
            "Resets: %08ld\t"
            "Restarts: %08ld\t"
            "Safe: %c\n",
            clockValue,
            timeValue,
            resetCount,
            restartCount,
            isSafe == 1? 'Y' : 'N');
    return 0;
}

int32_t
GetRandom (
    int32_t ArgumentCount,
    char* Arguments[],
    uintptr_t TpmHandle
    )
{
    TPM_RC tpmResult;
    uint32_t userInput;
    uint16_t requestedBytes;
    uint8_t* randomBytes;

    //
    // This one is special and takes no other arguments
    //
    if (ArgumentCount != 3)
    {
        PrintUsage();
        return -1;
    }

    //
    // Check how many random bytes the user wants
    //
    userInput = strtoul(Arguments[2], NULL, 0);
    if (userInput >= USHRT_MAX)
    {
        fprintf(stderr, "Bytes requested over 64KB\n");
        return -1;
    }

    //
    // Allocate the output buffer
    //
    requestedBytes = static_cast<uint16_t>(userInput);
    randomBytes = static_cast<uint8_t*>(_malloca(requestedBytes));

    //
    // Send the TPM command to read the information
    //
    tpmResult = TpmGetRandom(TpmHandle, &requestedBytes, randomBytes);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Random bytes failed with code 0x%02x\n", tpmResult);
        return -1;
    }

    //
    // Print the random bytes
    //
    printf("Received %d random bytes back...\n", requestedBytes);
    DumpHex(randomBytes, requestedBytes);

    //
    // Output the result back to the user
    //
    return 0;
}

int32_t
GetHash (
    int32_t ArgumentCount,
    char* Arguments[],
    uintptr_t TpmHandle
    )
{
    TPM_RC tpmResult;
    uint32_t userInput;
    uint16_t requestedBytes;
    uint8_t* data;
    uint8_t hash[32];
    size_t sizeRead;

    //
    // Three arguments are expected
    //
    if (ArgumentCount != 3)
    {
        PrintUsage();
        return -1;
    }

    //
    // Check how many random bytes the user wants
    //
    userInput = strtoul(Arguments[2], NULL, 0);
    if (userInput >= USHRT_MAX)
    {
        fprintf(stderr, "Bytes requested over 64KB\n");
        return -1;
    }

    //
    // Allocate space for the data
    //
    requestedBytes = static_cast<uint16_t>(userInput);
    data = reinterpret_cast<uint8_t*>(_malloca(requestedBytes));

    //
    // Read input
    //
    sizeRead = fread(data, 1, requestedBytes, stdin);
    if (sizeRead == 0)
    {
        fprintf(stderr, "Could not read from STDIN\n");
        return -1;
    }

    //
    // Send the TPM command to read the information
    //
    tpmResult = TpmHash(TpmHandle, requestedBytes, data, hash);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        fprintf(stderr, "Hash failed with code 0x%02x\n", tpmResult);
        return -1;
    }

    //
    // Print the random bytes
    //
    DumpHex(hash, 32);

    //
    // Output the result back to the user
    //

    return 0;
}

int32_t
main (
    int32_t ArgumentCount,
    char* Arguments[]
    )
{
    uintptr_t tpmHandle;
    bool osResult;
    TPM_NV_INDEX index;
    int32_t res;

    //
    // Banner time!
    //
    fprintf(stderr, "\nTpmTool v1.2.0 - Access TPM2.0 NV Spaces\n");
    fprintf(stderr, "Copyright (C) 2020-2021 Alex Ionescu\n");
    fprintf(stderr, "@aionescu -- www.windows-internals.com\n\n");
    if (ArgumentCount < 2)
    {
        PrintUsage();
        return -1;
    }

    //
    // First, try to get access to the chip
    //
    osResult = TpmOsOpen(&tpmHandle);
    if (osResult == false)
    {
        fprintf(stderr, "Unable to open TPM Base Stack or Resource Manager\n");
        return -1;
    }

    //
    // Assume failure until a valid command is found and executed
    //
    res = -1;

    //
    // Check for options with no other arguments
    //
    if (strcmp(Arguments[1], "-e") == 0)
    {
        res = EnumerateSpaces(ArgumentCount, tpmHandle, false);
    }
    else if (strcmp(Arguments[1], "-qa") == 0)
    {
        res = EnumerateSpaces(ArgumentCount, tpmHandle, true);
    }
    else if (strcmp(Arguments[1], "-t") == 0)
    {
        //
        // Get time info
        //
        res = ReadClock(ArgumentCount, tpmHandle);
    }
    else if (strcmp(Arguments[1], "-r") == 0)
    {
        //
        // Get random bytes
        //
        res = GetRandom(ArgumentCount, Arguments, tpmHandle);
    }
    else if (strcmp(Arguments[1], "-h") == 0)
    {
        //
        // Get hash
        //
        res = GetHash(ArgumentCount, Arguments, tpmHandle);
    }
    else
    {
        //
        // All other commands have at least 3 arguments...
        //
        if (ArgumentCount < 3)
        {
            PrintUsage();
            goto Exit;
        }

        //
        // The index is always parameter 1 and assumed hex
        //
        index.Value = strtoul(Arguments[1], NULL, 16);
        if (index.Type != TPM_HT_NV_INDEX)
        {
            fprintf(stderr, "Index type for 0x%08x is not NV\n", index.Value);
            goto Exit;
        }

        //
        // The action is in parameter 2, go and handle the options
        //
        if (strcmp(Arguments[2], "-c") == 0)
        {
            res = CreateSpace(ArgumentCount, Arguments, tpmHandle, index);
        }
        else if (strcmp(Arguments[2], "-w") == 0)
        {
            res = WriteSpace(ArgumentCount, Arguments, tpmHandle, index);
        }
        else if (strcmp(Arguments[2], "-r") == 0)
        {
            res = ReadSpace(ArgumentCount, Arguments, tpmHandle, index);
        }
        else if (strcmp(Arguments[2], "-d") == 0)
        {
            res = DeleteSpace(ArgumentCount, tpmHandle, index);
        }
        else if (strcmp(Arguments[2], "-wl") == 0)
        {
            res = LockSpace(ArgumentCount, Arguments, tpmHandle, index, true);
        }
        else if (strcmp(Arguments[2], "-rl") == 0)
        {
            res = LockSpace(ArgumentCount, Arguments, tpmHandle, index, false);
        }
        else if (strcmp(Arguments[2], "-q") == 0)
        {
            res = QuerySpace(ArgumentCount, tpmHandle, index);
        }
        else
        {
            //
            // Unrecognized action
            //
            PrintUsage();
            goto Exit;
        }
    }
Exit:
    //
    // Close the handle and return
    //
    TpmOsClose(tpmHandle);
    return res;
}
