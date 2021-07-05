/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    tpmoswin.cpp

Abstract:

    This module handles the Windows-specific functionality for accessing the
    TPM2.0 interface of the operating system. It also provides the compiler
    intrinsics for endian swapping.

Author:

    Alex Ionescu (@aionescu) 11-Jun-2020 - Initial version

Environment:

    Windows 8 and above, kernel mode (Tbs.sys) or user mode (Tbs.dll).

--*/

#include <stdint.h>
#include <Windows.h>
#include <tbs.h>
#include <intrin.h>

uint16_t
OsSwap16 (
    _In_ uint16_t Input
    )
{
    return _byteswap_ushort(Input);
}

uint32_t
OsSwap32 (
    _In_ uint32_t Input
    )
{
    return _byteswap_ulong(Input);
}

uint64_t
OsSwap64 (
    _In_ uint64_t Input
    )
{
    return _byteswap_uint64(Input);
}

bool
TpmOsIssueCommand (
    _In_ uintptr_t TpmHandle,
    _In_ uint8_t* In,
    _In_ uint32_t InLength,
    _In_ uint8_t* Out,
    _In_ uint32_t OutLength,
    _Out_opt_ uint32_t* OsResult
    )
{
    uint32_t resultLength;
    TBS_RESULT tbsResult;

    //
    // Use the TBSI stack to send the command to the TPM
    //
    resultLength = OutLength;
    tbsResult = Tbsip_Submit_Command(reinterpret_cast<TBS_HCONTEXT>(TpmHandle),
                                     TBS_COMMAND_LOCALITY_ZERO,
                                     TBS_COMMAND_PRIORITY_NORMAL,
                                     In,
                                     InLength,
                                     Out,
                                     &resultLength);
    if (tbsResult != TBS_SUCCESS)
    {
        //
        // Clear the result on failure
        //
        resultLength = 0;
    }

    //
    // Return the OS result if needed
    //
    if (OsResult != nullptr)
    {
        *OsResult = tbsResult;
    }

    //
    // Return a boolean if the TPM command was issued. The actual TPM may still
    // return an error code as part of the respone header.
    //
    return (tbsResult == TBS_SUCCESS);
}

bool
TpmOsOpen (
    _Out_ uintptr_t* TpmHandle
    )
{
    TBS_CONTEXT_PARAMS2 pContextParams;
    TBS_HCONTEXT hContext;
    TBS_RESULT tbsResult;
    bool result;

    //
    // Initialize for failure
    //
    *TpmHandle = 0;

    //
    // Request TPM 2.0 Access
    //
    pContextParams.asUINT32 = 0;
    pContextParams.version = TBS_CONTEXT_VERSION_TWO;
    pContextParams.includeTpm20 = 1;
    tbsResult = Tbsi_Context_Create(reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&pContextParams),
                                    &hContext);
    if (tbsResult != TBS_SUCCESS)
    {
        result = false;
        goto Exit;
    }

    //
    // Return a handle that can be used for further commands
    //
    *TpmHandle = reinterpret_cast<uintptr_t>(hContext);
    result = true;
Exit:
    return result;
}

bool
TpmOsClose (
    _In_ uintptr_t TpmHandle
    )
{
    TBS_RESULT tbsResult;

    //
    // Close the context handle
    //
    tbsResult = Tbsip_Context_Close(reinterpret_cast<TBS_HCONTEXT>(TpmHandle));
    return (tbsResult == TBS_SUCCESS);
}

