/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    tpmcmd.hpp

Abstract:

    This header provides helper macros that simplify the construction of some
    of the variable-sized TPM2.0 command and reply structures that are needed,
    especially when using password authentication.

Author:

    Alex Ionescu (@aionescu) 11-Jun-2020 - Initial version

Environment:

    Portable to any environment.

--*/

#pragma once
#include <type_traits> 

//
// This macro calculates the size of a variable data command made up of
// A static-size header (including TPM_CMD_HEADER)
// A dynamic-size data blob
// A dynamic-size authorization session
// A static-size footer
//
#define TpmVariableCmdSize(header, authSize, data, size, footer)    \
    ((offsetof(std::remove_reference<decltype(*header)>::type,      \
               AuthSession.Password)) +                             \
     (authSize) +                                                   \
     (offsetof(std::remove_reference<decltype(*data)>::type,        \
               Data)) +                                             \
     (size) +                                                       \
     (sizeof(*footer)))

//
// This macro calculates the size of a fixed data command made up of
// A static-size header (including TPM_CMD_HEADER)
// A dynamic-size authorization session
// A static-size footer
//
#define TpmFixedCmdSize(header, authSize, footer)                   \
    ((offsetof(std::remove_reference<decltype(*header)>::type,      \
               AuthSession.Password)) +                             \
     (authSize) +                                                   \
     (sizeof(*footer)))

//
// This macro calculates the size of an empty data command made up of
// A static-size header (including TPM_CMD_HEADER)
// A dynamic-size authorization session
//
#define TpmEmptyCmdSize(header, authSize)                           \
    ((offsetof(std::remove_reference<decltype(*header)>::type,      \
               AuthSession.Password)) +                             \
     (authSize))

//
// This macro allocates a TPM 2.0 Command Buffer on the stack
//
#define TpmpAllocateCommand(header, commandSize)                    \
    reinterpret_cast<decltype(header)>(alloca(commandSize));

//
// This macro calculates the size of a fixed data response made up of
// A static-size header (including TPM_REPLY_HEADER)
// The 32-bit parameter size
// An empty authorization response
//
#define TpmFixedResponseSize(x)                                     \
    (sizeof(*x))

//
// This macro calculates the size of a variable data response made up of
// A static-size header (including TPM_REPLY_HEADER)
// The 32-bit parameter size
// A dynamic-size data blob
// An empty authorization response
//
#define TpmVariableResponseSize(x, y)                               \
    ((offsetof(std::remove_reference<decltype(*x)>::type,           \
               Data)) +                                             \
     (y) +                                                          \
     (sizeof(TPMS_AUTH_RESPONSE_NO_NONCE)))

//
// This macro allocates a TPM 2.0 Response Buffer on the stack
//
#define TpmpAllocateResponse(x, y)                                  \
    reinterpret_cast<decltype(x)>(alloca(y));

//
// This macro returns a TPM 2.0 Result Code from a Response Buffer
//
#define TpmReadResponseCode(response)                               \
    static_cast<TPM_RC>(OsSwap32((response)->Header.ResponseCode))

//
// Internal Routines that require OS Support
//
uint16_t
OsSwap16 (
    uint16_t Input
    );

uint32_t
OsSwap32 (
    uint32_t Input
    );

bool
TpmOsIssueCommand (
    uintptr_t TpmHandle,
    uint8_t* In,
    uint32_t InLength,
    uint8_t* Out,
    uint32_t OutLength,
    uint32_t* OsResult
    );
