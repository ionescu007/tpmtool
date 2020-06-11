/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    tpmcmd.cpp

Abstract:

    This module implements the main logic for producing TPM2.0 commands and
    handling their responses, including password authentication sessions.

Author:

    Alex Ionescu (@aionescu) 11-Jun-2020 - Initial version

Environment:

    Portable to any environment.

--*/

#include "tpmtool.hpp"
#include "tpmcmd.hpp"

void
TpmpFillCommandHeader (
    PTPM_CMD_HEADER CommandHeader,
    TPM_CC CommandCode,
    TPM_ST SessionTag,
    uint32_t Size
    )
{
    //
    // Fill out the TPM Command Header
    //
    CommandHeader->SessionTag = static_cast<TPM_ST>(OsSwap16(SessionTag));
    CommandHeader->Size = OsSwap32(Size);
    CommandHeader->CommandCode = static_cast<TPM_CC>(OsSwap32(CommandCode));
}

void
TpmpFillAuthSession (
    TPMS_AUTH_COMMAND_NO_NONCE* AuthSession,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData,
    uint8_t** CommandFooter
    )
{
    uint32_t authSessionSize;
    int32_t i;

    //
    // Compute the size of the auth session, which contains the password but
    // not the size of the session itself.
    //
    authSessionSize = offsetof(TPMS_AUTH_COMMAND_NO_NONCE, Password) +
                      AuthorizationSize -
                      sizeof(AuthSession->SessionSize);

    //
    // Build a password authorization session. If there's no password this will
    // simply use the empty password and authenticate as owner.
    //
    AuthSession->SessionSize = OsSwap32(authSessionSize);
    AuthSession->SessionHandle.Value = OsSwap32(TPM_RS_PW.Value);
    AuthSession->NonceSize = OsSwap16(0);
    AuthSession->SessionAttributes.Value = 0;
    AuthSession->PasswordSize = OsSwap16(AuthorizationSize);
    for (i = 0; i < AuthorizationSize; i++)
    {
        AuthSession->Password[i] = AuthorizationData[i];
    }

    //
    // Return a pointer to the command footer following the session
    //
    if (CommandFooter != nullptr)
    {
        *CommandFooter = &AuthSession->Password[i];
    }
}

TPM_RC
TpmUndefineSpace2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex
    )
{
    TPM_NV_UNDEFINE_SPACE_CMD_HEADER* commandHeader;
    TPM_NV_UNDEFINE_SPACE_REPLY* reply;
    uint32_t commandSize;
    uint32_t replySize;
    bool osResult;

    //
    // Allocate the command
    //
    commandSize = TpmEmptyCmdSize(commandHeader, 0);
    commandHeader = TpmpAllocateCommand(commandHeader, commandSize);

    //
    // Fill out the TPM Command Header
    //
    TpmpFillCommandHeader(&commandHeader->Header,
                          TPM_CC_NV_UndefineSpace,
                          TPM_ST_SESSIONS,
                          commandSize);

    //
    // Use our owner handle
    //
    commandHeader->AuthHandle.Value = OsSwap32(TPM_RH_OWNER.Value);

    //
    // Fill in the index being deleted
    //
    commandHeader->NvIndex.Value = OsSwap32(HandleIndex.Value);

    //
    // Fill out an empty authorization session
    //
    TpmpFillAuthSession(&commandHeader->AuthSession,
                        0,
                        nullptr,
                        nullptr);

    //
    // Make space for the response
    //
    replySize = TpmFixedResponseSize(reply);
    reply = TpmpAllocateResponse(reply, replySize);

    //
    // Call the OS function
    //
    osResult = TpmOsIssueCommand(TpmHandle,
                                 reinterpret_cast<uint8_t*>(commandHeader),
                                 commandSize,
                                 reinterpret_cast<uint8_t*>(reply),
                                 replySize,
                                 nullptr);
    if (osResult == false)
    {
        return TPM_RC_FAILURE;
    }

    //
    // Return the TPM response code -- no data is returned
    //
    return TpmReadResponseCode(reply);
}

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
    )
{
    TPM_NV_DEFINE_SPACE_CMD_HEADER* commandHeader;
    TPM_NV_DEFINE_SPACE_CMD_BODY* commandData;
    TPM_NV_DEFINE_SPACE_CMD_FOOTER* commandFooter;
    TPM_NV_DEFINE_SPACE_REPLY* reply;
    uint32_t nvAttributes;
    uint32_t replySize;
    bool osResult;
    int32_t i;
    uint32_t commandSize;

    //
    // Allocate the command
    //
    commandSize = TpmVariableCmdSize(commandHeader, 0, commandData, AuthorizationSize, commandFooter);
    commandHeader = TpmpAllocateCommand(commandHeader, commandSize);

    //
    // Fill out the TPM Command Header
    //
    TpmpFillCommandHeader(&commandHeader->Header,
                          TPM_CC_NV_DefineSpace,
                          TPM_ST_SESSIONS,
                          commandSize);

    //
    // Use our owner handle
    //
    commandHeader->AuthHandle.Value = OsSwap32(TPM_RH_OWNER.Value);

    //
    // Fill out an empty authorization session
    //
    TpmpFillAuthSession(&commandHeader->AuthSession,
                        0,
                        nullptr,
                        reinterpret_cast<uint8_t**>(&commandData));

    //
    // Configure the password (if any) as the authorization data
    //
    commandData->AuthSize = OsSwap16(AuthorizationSize);
    for (i = 0; i < AuthorizationSize; i++)
    {
        commandData->Data[i] = AuthorizationData[i];
    }

    //
    // Finish up with the footer, which contains the NV_PUBLIC data
    //
    commandFooter = reinterpret_cast<decltype(commandFooter)>(&commandData->Data[i]);
    commandFooter->NvPublicSize = OsSwap16(sizeof(*commandFooter) - sizeof(commandFooter->NvPublicSize));
    commandFooter->NvIndex.Value = OsSwap32(HandleIndex.Value);
    commandFooter->NameAlg = static_cast<TPMI_ALG_HASH>(OsSwap16(TPM_ALG_SHA256));
    commandFooter->DataSize = OsSwap16(SpaceSize);
    commandFooter->AuthPolicySize = 0;

    //
    // Write the attributes by converting both the Owner/Auth rights as well as
    // the attributes the tool lets you set. Note that the read-only R/WLOCKED
    // attributes are not settable, so we don't bother checking for them.
    //
    nvAttributes = ((((OwnerRights & TpmToolReadAccess) ==
                       TpmToolReadAccess) * TPMA_NV_OWNERREAD) |
                    (((OwnerRights & TpmToolWriteAccess) ==
                       TpmToolWriteAccess) * TPMA_NV_OWNERWRITE) |
                    (((AuthRights & TpmToolReadAccess) ==
                       TpmToolReadAccess) * TPMA_NV_AUTHREAD) |
                    (((AuthRights & TpmToolWriteAccess) ==
                       TpmToolWriteAccess) * TPMA_NV_AUTHWRITE));
    nvAttributes |= ((((Attributes & TpmToolReadLockable) ==
                        TpmToolReadLockable) * TPMA_NV_READ_STCLEAR) |
                     (((Attributes & TpmToolWriteLockable) ==
                        TpmToolWriteLockable) * TPMA_NV_WRITE_STCLEAR) |
                     (((Attributes & TpmToolWriteOnce) ==
                        TpmToolWriteOnce) * TPMA_NV_WRITEDEFINE) |
                     (((Attributes & TpmToolWriteAll) ==
                        TpmToolWriteAll) * TPMA_NV_WRITEALL) |
                     (((Attributes & TpmToolNonProtected) ==
                        TpmToolNonProtected) * TPMA_NV_NO_DA) |
                     (((Attributes & TpmToolCached) ==
                        TpmToolCached) * TPMA_NV_ORDERLY) |
                     (((Attributes & TpmToolVolatileDirtyFlag) ==
                        TpmToolVolatileDirtyFlag) * TPMA_NV_CLEAR_STCLEAR) |
                     (((Attributes & TpmToolPermanent) ==
                        TpmToolPermanent) * TPMA_NV_POLICY_DELETE));
    commandFooter->Attributes = static_cast<TPMA_NV>(OsSwap32(nvAttributes));

    //
    // Make space for the response
    //
    replySize = TpmFixedResponseSize(reply);
    reply = TpmpAllocateResponse(reply, replySize);

    //
    // Call the OS function
    //
    osResult = TpmOsIssueCommand(TpmHandle,
                                 reinterpret_cast<uint8_t*>(commandHeader),
                                 commandSize,
                                 reinterpret_cast<uint8_t*>(reply),
                                 replySize,
                                 nullptr);
    if (osResult == false)
    {
        return TPM_RC_FAILURE;
    }

    //
    // Return the TPM response code -- no data is returned
    //
    return TpmReadResponseCode(reply);
}

TPM_RC
TpmNvRead2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData,
    uint16_t Offset,
    uint16_t DataSize,
    uint8_t* Data
    )
{
    TPM_NV_READ_CMD_FOOTER* commandFooter;
    TPM_NV_READ_CMD_HEADER* command;
    TPM_NV_READ_REPLY* reply;
    uint32_t commandSize;
    uint32_t replySize;
    bool osResult;
    TPM_RC tpmResult;

    //
    // Allocate the command
    //
    commandSize = TpmFixedCmdSize(command, AuthorizationSize, commandFooter);
    command = TpmpAllocateCommand(command, commandSize);

    //
    // Fill out the TPM Command Header
    //
    TpmpFillCommandHeader(&command->Header,
                          TPM_CC_NV_Read,
                          TPM_ST_SESSIONS,
                          commandSize);

    //
    // Fill in the rest of the command header
    //
    command->NvIndex.Value = OsSwap32(HandleIndex.Value);

    //
    // Check if we're doing owner or session authorization
    //
    if (AuthorizationSize == 0)
    {
        //
        // Pass in the owner pseudo-handle
        //
        command->AuthHandle.Value = OsSwap32(TPM_RH_OWNER.Value);
    }
    else
    {
        //
        // For session authentication, we authenticate against the index itself
        //
        command->AuthHandle.Value = OsSwap32(HandleIndex.Value);
    }

    //
    // Fill out the authorization session
    //
    TpmpFillAuthSession(&command->AuthSession,
                        AuthorizationSize,
                        AuthorizationData,
                        reinterpret_cast<uint8_t**>(&commandFooter));

    //
    // Now fill in the command footer
    //
    commandFooter->Offset = OsSwap16(Offset);
    commandFooter->Size = OsSwap16(DataSize);

    //
    // Make space for the response
    //
    replySize = TpmVariableResponseSize(reply, DataSize);
    reply = TpmpAllocateResponse(reply, replySize);

    //
    // Call the OS function
    //
    osResult = TpmOsIssueCommand(TpmHandle,
                                 reinterpret_cast<uint8_t*>(command),
                                 commandSize,
                                 reinterpret_cast<uint8_t*>(reply),
                                 replySize,
                                 nullptr);
    if (osResult == false)
    {
        return TPM_RC_FAILURE;
    }

    //
    // Read the response code, and copy the result back to the caller
    //
    tpmResult = TpmReadResponseCode(reply);
    if (tpmResult == TPM_RC_SUCCESS)
    {
        for (int i = 0; i < DataSize; i++)
        {
            Data[i] = reply->Data[i];
        }
    }
    return tpmResult;
}

TPM_RC
TpmNvWrite2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData,
    uint16_t Offset,
    uint16_t DataSize,
    uint8_t* Data
    )
{
    TPM_NV_WRITE_CMD_FOOTER* commandFooter;
    TPM_NV_WRITE_CMD_BODY* commandData;
    TPM_NV_WRITE_CMD_HEADER* command;
    TPM_NV_WRITE_REPLY* reply;
    uint32_t commandSize;
    uint32_t replySize;
    int32_t i;
    bool osResult;

    //
    // Allocate the command
    //
    commandSize = TpmVariableCmdSize(command, AuthorizationSize, commandData, DataSize, commandFooter);
    command = TpmpAllocateCommand(command, commandSize);

    //
    // Fill out the TPM Command Header
    //
    TpmpFillCommandHeader(&command->Header,
                          TPM_CC_NV_Write,
                          TPM_ST_SESSIONS,
                          commandSize);

    //
    // Fill in the rest of the command header
    //
    command->NvIndex.Value = OsSwap32(HandleIndex.Value);

    //
    // Check if we're doing owner or session authorization
    //
    if (AuthorizationSize == 0)
    {
        //
        // Pass in the owner pseudo-handle
        //
        command->AuthHandle.Value = OsSwap32(TPM_RH_OWNER.Value);
    }
    else
    {
        //
        // For session authentication, we authenticate against the index itself
        //
        command->AuthHandle.Value = OsSwap32(HandleIndex.Value);
    }

    //
    // Fill out the authorization session
    //
    TpmpFillAuthSession(&command->AuthSession,
                        AuthorizationSize,
                        AuthorizationData,
                        reinterpret_cast<uint8_t**>(&commandData));

    //
    // Fill out the command data
    //
    commandData->Size = OsSwap16(DataSize);
    for (i = 0; i < DataSize; i++)
    {
        commandData->Data[i] = Data[i];
    }

    //
    // Finish up with the footer
    //
    commandFooter = reinterpret_cast<decltype(commandFooter)>(&commandData->Data[i]);
    commandFooter->Offset = OsSwap16(Offset);

    //
    // Make space for the response
    //
    replySize = TpmFixedResponseSize(reply);
    reply = TpmpAllocateResponse(reply, replySize);

    //
    // Call the OS function
    //
    osResult = TpmOsIssueCommand(TpmHandle,
                                 reinterpret_cast<uint8_t*>(command),
                                 commandSize,
                                 (uint8_t*)reply,
                                 replySize,
                                 nullptr);
    if (osResult == false)
    {
        return TPM_RC_FAILURE;
    }

    //
    // Return the TPM response code -- no data is returned
    //
    return TpmReadResponseCode(reply);
}

TPM_RC
TpmpLock2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    bool WriteLock,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData
    )
{
    TPM_NV_READ_LOCK_CMD_HEADER* command;
    TPM_NV_READ_LOCK_REPLY* reply;
    uint32_t commandSize;
    uint32_t replySize;
    bool osResult;

    //
    // Allocate the command
    //
    commandSize = TpmEmptyCmdSize(command, AuthorizationSize);
    command = TpmpAllocateCommand(command, commandSize);

    //
    // Fill out the TPM Command Header
    //
    TpmpFillCommandHeader(&command->Header,
                          WriteLock ? TPM_CC_NV_WriteLock : TPM_CC_NV_ReadLock,
                          TPM_ST_SESSIONS,
                          commandSize);

    //
    // Fill in the index being locked
    //
    command->NvIndex.Value = OsSwap32(HandleIndex.Value);

    //
    // Check if we're doing owner or session authorization
    //
    if (AuthorizationSize == 0)
    {
        //
        // Pass in the owner pseudo-handle
        //
        command->AuthHandle.Value = OsSwap32(TPM_RH_OWNER.Value);
    }
    else
    {
        //
        // For session authentication, we authenticate against the index itself
        //
        command->AuthHandle.Value = OsSwap32(HandleIndex.Value);
    }

    //
    // Fill out the authorization session
    //
    TpmpFillAuthSession(&command->AuthSession,
                        AuthorizationSize,
                        AuthorizationData,
                        nullptr);

    //
    // Make space for the response
    //
    replySize = TpmFixedResponseSize(reply);
    reply = TpmpAllocateResponse(reply, replySize);

    //
    // Call the OS function
    //
    osResult = TpmOsIssueCommand(TpmHandle,
                                 reinterpret_cast<uint8_t*>(command),
                                 commandSize,
                                 reinterpret_cast<uint8_t*>(reply),
                                 replySize,
                                 nullptr);
    if (osResult == false)
    {
        return TPM_RC_FAILURE;
    }

    //
    // Return the TPM response code -- no data is returned
    //
    return TpmReadResponseCode(reply);
}

TPM_RC
TpmWriteLock2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData
    )
{
    //
    // Call the helper with the write parameter
    //
    return TpmpLock2(TpmHandle,
                     HandleIndex,
                     true,
                     AuthorizationSize,
                     AuthorizationData);
}

TPM_RC
TpmReadLock2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t AuthorizationSize,
    uint8_t* AuthorizationData
    )
{
    //
    // Call the helper with the read parameter
    //
    return TpmpLock2(TpmHandle,
                     HandleIndex,
                     false,
                     AuthorizationSize,
                     AuthorizationData);
}

TPM_RC
TpmReadPublic2 (
    uintptr_t TpmHandle,
    TPM_NV_INDEX HandleIndex,
    uint16_t* Attributes,
    uint8_t* OwnerRights,
    uint8_t* AuthRights,
    uint16_t* DataSize
    )
{
    TPM_NV_READ_PUBLIC_CMD_HEADER* command;
    TPM_NV_READ_PUBLIC_REPLY* reply;
    uint32_t commandSize;
    uint32_t replySize;
    uint32_t nvAtributes;
    bool osResult;
    TPM_RC tpmResult;

    //
    // Allocate the command
    //
    commandSize = sizeof(*command);
    command = TpmpAllocateCommand(command, commandSize);

    //
    // Fill out the TPM Command Header
    //
    TpmpFillCommandHeader(&command->Header,
                          TPM_CC_NV_ReadPublic,
                          TPM_ST_NO_SESSIONS,
                          commandSize);

    //
    // Fill in the index being read
    //
    command->NvIndex.Value = OsSwap32(HandleIndex.Value);

    //
    // Make space for the response
    //
    replySize = TpmFixedResponseSize(reply);
    reply = TpmpAllocateResponse(reply, replySize);

    //
    // Call the OS function
    //
    osResult = TpmOsIssueCommand(TpmHandle,
                                 reinterpret_cast<uint8_t*>(command),
                                 commandSize,
                                 reinterpret_cast<uint8_t*>(reply),
                                 replySize,
                                 nullptr);
    if (osResult == false)
    {
        return TPM_RC_FAILURE;
    }

    //
    // Read the response code, keep going only if we got success
    //
    tpmResult = TpmReadResponseCode(reply);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        return tpmResult;
    }

    //
    // Read the size of the variable back
    //
    *DataSize = OsSwap16(reply->NvPublic.DataSize);

    //
    // Read the attributes back
    //
    nvAtributes = OsSwap32(reply->NvPublic.Attributes);

    //
    // Convert the owner rights into our format
    //
    *OwnerRights = ((((nvAtributes & TPMA_NV_OWNERREAD) ==
                       TPMA_NV_OWNERREAD) * TpmToolReadAccess) |
                    (((nvAtributes & TPMA_NV_OWNERWRITE) ==
                       TPMA_NV_OWNERWRITE) * TpmToolWriteAccess));

    //
    // Convert the auth rights into our format
    //
    *AuthRights = ((((nvAtributes & TPMA_NV_AUTHREAD) ==
                      TPMA_NV_AUTHREAD) * TpmToolReadAccess) |
                   (((nvAtributes & TPMA_NV_AUTHWRITE) ==
                      TPMA_NV_AUTHWRITE) * TpmToolWriteAccess));

    //
    // Finally, convert the rest of the attributes
    //
    *Attributes = ((((nvAtributes & TPMA_NV_READ_STCLEAR) ==
                      TPMA_NV_READ_STCLEAR) * TpmToolReadLockable) |
                   (((nvAtributes & TPMA_NV_WRITE_STCLEAR) ==
                      TPMA_NV_WRITE_STCLEAR) * TpmToolWriteLockable) |
                   (((nvAtributes & TPMA_NV_WRITEDEFINE) ==
                      TPMA_NV_WRITEDEFINE) * TpmToolWriteOnce) |
                   (((nvAtributes & TPMA_NV_WRITEALL) ==
                       TPMA_NV_WRITEALL) * TpmToolWriteAll) |
                   (((nvAtributes & TPMA_NV_NO_DA) ==
                      TPMA_NV_NO_DA) * TpmToolNonProtected) |
                   (((nvAtributes & TPMA_NV_ORDERLY) ==
                      TPMA_NV_ORDERLY) * TpmToolCached) |
                   (((nvAtributes & TPMA_NV_CLEAR_STCLEAR) ==
                      TPMA_NV_CLEAR_STCLEAR) * TpmToolVolatileDirtyFlag) |
                   (((nvAtributes & TPMA_NV_POLICY_DELETE) ==
                      TPMA_NV_POLICY_DELETE) * TpmToolPermanent) |
                   (((nvAtributes & TPMA_NV_READLOCKED) ==
                      TPMA_NV_READLOCKED) * TpmToolReadLocked) |
                   (((nvAtributes & TPMA_NV_WRITELOCKED) ==
                      TPMA_NV_WRITELOCKED) * TpmToolWriteLocked) |
                   (((nvAtributes & TPMA_NV_WRITTEN) ==
                      TPMA_NV_WRITTEN) * TpmToolWritten) |
                   (((nvAtributes & TPMA_NV_PLATFORMCREATE) ==
                      TPMA_NV_PLATFORMCREATE) * TpmToolPlatformOwned));

    //
    // Finally, return the TPM response code
    //
    return tpmResult;
}

TPM_RC
TpmNvEnumerate2 (
    uintptr_t TpmHandle,
    uint32_t* IndexCount,
    TPM_NV_INDEX* IndexArray
    )
{
    TPM_GET_CAPABILITY_CMD_HEADER* command;
    TPM_GET_CAPABILITY_REPLY* reply;
    uint32_t commandSize;
    uint32_t replySize;
    bool osResult;
    uint32_t i;
    uint32_t handleCount;
    TPM_RC tpmResult;

    //
    // Allocate the command
    //
    commandSize = sizeof(*command);
    command = TpmpAllocateCommand(command, commandSize);

    //
    // Fill out the TPM Command Header
    //
    TpmpFillCommandHeader(&command->Header,
                          TPM_CC_GetCapability,
                          TPM_ST_NO_SESSIONS,
                          commandSize);

    //
    // Fill in the property query request
    //
    handleCount = sizeof(reply->Data.Data.Handles.Handle) /
                  sizeof(reply->Data.Data.Handles.Handle[0]);
    command->Capability = static_cast<TPM_CAP>(OsSwap32(TPM_CAP_HANDLES));
    command->Property = static_cast<TPM_PT>(OsSwap32(HR_NV_INDEX));
    command->PropertyCount = OsSwap32(handleCount);

    //
    // Make space for the response
    //
    replySize = TpmFixedResponseSize(reply);
    reply = TpmpAllocateResponse(reply, replySize);

    //
    // Call the OS function
    //
    osResult = TpmOsIssueCommand(TpmHandle,
                                 reinterpret_cast<uint8_t*>(command),
                                 commandSize,
                                 reinterpret_cast<uint8_t*>(reply),
                                 replySize,
                                 nullptr);
    if (osResult == false)
    {
        return TPM_RC_FAILURE;
    }

    //
    // Read the response code, keep going only if we got success
    //
    tpmResult = TpmReadResponseCode(reply);
    if (tpmResult != TPM_RC_SUCCESS)
    {
        return tpmResult;
    }

    //
    // Now we know how many NV handles exist. Did the caller specify a smaller
    // number?
    //
    handleCount = OsSwap32(reply->Data.Data.Handles.Count);
    if (*IndexCount < handleCount)
    {
        //
        // In this case, use the caller's number, and also let them know what
        // the true count is.
        //
        handleCount = *IndexCount;
        *IndexCount = OsSwap32(reply->Data.Data.Handles.Count);
    }

    //
    // Enumerate either all the handles, or as few as the caller asked for
    //
    for (i = 0; i < handleCount; i++)
    {
        IndexArray[i].Value = OsSwap32(reply->Data.Data.Handles.Handle[i].Value);
    }

    //
    // Finally, return the TPM response code
    //
    return tpmResult;
}
