/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    tpmtool.hpp

Abstract:

    This header is the main header for all files part of the tool, defining its
    internal API and including the TPM2.0 Specification Header as well.

Author:

    Alex Ionescu (@aionescu) 11-Jun-2020 - Initial version

Environment:

    Portable to any environment.

--*/

#pragma once

//
// Standard C Files
//
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <malloc.h>

//
// TPM2.0 Specification Headers and Custom Structure Definitions
//
#include "tpmspec.hpp"
#include "tpmstruc.hpp"

//
// TpmTool Permission Flags for Auth/Owner Rights
//
typedef enum _TPM_TOOL_PERMISSION_FLAGS
{
    TpmToolNoAccess,
    TpmToolReadAccess,
    TpmToolWriteAccess,
    TpmToolReadWriteAccess
} TPM_TOOL_PERMISSION_FLAGS;

//
// TpmTool NV Index Attributes
//
typedef enum _TPM_TOOL_ATTRIBUTES : uint16_t
{
    //
    // Modifiable Attributes
    //
    TpmToolReadLockable = (1 << 0),
    TpmToolWriteLockable = (1 << 1),
    TpmToolWriteOnce = (1 << 2),
    TpmToolWriteAll = (1 << 3),
    TpmToolNonProtected = (1 << 4),
    TpmToolCached = (1 << 5),
    TpmToolVolatileDirtyFlag = (1 << 6),
    TpmToolPermanent = (1 << 7),
    //
    // Status variables
    //
    TpmToolReadLocked = (1 << 8),
    TpmToolWriteLocked = (1 << 9),
    TpmToolWritten = (1 << 10),
    TpmToolPlatformOwned = (1 << 11),
} TPM_TOOL_ATTRIBUTES;

//
// TpmTool API
//
bool
TpmOsOpen (
    uintptr_t* TpmHandle
    );

bool
TpmOsClose (
    uintptr_t TpmHandle
    );

TPM_RC
TpmDefineSpace2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t SpaceSize,
    uint8_t Attributes,
    uint8_t OwnerRights,
    uint8_t AuthRights,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData
    );

TPM_RC
TpmNvWrite2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData,
    uint16_t Offset,
    uint16_t DataSize,
    uint8_t* Data
    );

TPM_RC
TpmNvRead2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData,
    uint16_t Offset,
    uint16_t DataSize,
    uint8_t* Data
    );

TPM_RC
TpmUndefineSpace2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex
    );

TPM_RC
TpmReadLock2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData
    );

TPM_RC
TpmWriteLock2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData
    );

TPM_RC
TpmReadPublic2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t* Attributes,
    uint8_t* OwnerRights,
    uint8_t* AuthRights,
    uint16_t* DataSize
    );

TPM_RC
TpmNvEnumerate2 (
    uintptr_t TpmHandle,
    uint32_t* IndexCount,
    TPM_NV_INDEX* IndexArray
    );
