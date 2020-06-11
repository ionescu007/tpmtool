/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    tpmstruc.hpp

Abstract:

    This header contains custom definitions for the data structures used by
    various TPM2.0 commands and replies relevant to the tool. These definitions
    are meant to allow easy construction of the relevant data structures using
    simple C/C++ code, without complex marshalling. However, they do not allow
    the utilization of the full suite of TPM2.0 command options, such as using
    session handles, using command encryption, enabling auditing, applying a
    nonce, and more.

Author:

    Alex Ionescu (@aionescu) 11-Jun-2020 - Initial version

Environment:

    Portable to any environment.

--*/

#pragma once
#pragma warning(disable:4201)
#pragma pack(push)
#pragma pack(1)

//
// Definition of the header of any TPM2.0 Command
//
typedef struct
{
    TPMI_ST_COMMAND_TAG SessionTag;
    uint32_t Size;
    TPM_CC CommandCode;
} TPM_CMD_HEADER, *PTPM_CMD_HEADER;

//
// Definition of the header of any TPM2.0 Response
//
typedef struct
{
    TPM_ST SessionTag;
    uint32_t Size;
    TPM_RC ResponseCode;
} TPM_REPLY_HEADER, *PTPM_REPLY_HEADER;
static_assert(sizeof(TPM_CMD_HEADER) == sizeof(TPM_REPLY_HEADER));

//
// Attached to any TPM2.0 Response with TPM_ST_SESSIONS when an authorization
// session with no nonce was sent.
//
typedef struct
{
    uint16_t NonceSize;
    TPMA_SESSION SessionAttributes;
    uint16_t HmacSize;
} TPMS_AUTH_RESPONSE_NO_NONCE;

//
// Attached to any TPM2.0 Command with TPM_ST_SESSIONS and an authorization
// session with no nonce but with an optional HMAC/password present.
//
typedef struct
{
    uint32_t SessionSize;
    TPMI_SH_AUTH_SESSION SessionHandle;
    uint16_t NonceSize;
    TPMA_SESSION SessionAttributes;
    uint16_t PasswordSize;
    uint8_t Password[1];
} TPMS_AUTH_COMMAND_NO_NONCE, *PTPMS_AUTH_COMMAND_NO_NONCE;

//
// NV_ReadLock
//
typedef struct
{
    TPM_CMD_HEADER Header;
    TPMI_RH_PROVISION AuthHandle;
    TPMI_RH_NV_INDEX NvIndex;
    TPMS_AUTH_COMMAND_NO_NONCE AuthSession;
} TPM_NV_READ_LOCK_CMD_HEADER, *PTPM_NV_READ_LOCK_CMD_HEADER;

typedef struct
{
    TPM_REPLY_HEADER Header;
    uint32_t ParameterSize;
    TPMS_AUTH_RESPONSE_NO_NONCE AuthSession;
} TPM_NV_READ_LOCK_REPLY, *PTPM_NV_READ_LOCK_REPLY;

//
// NV_WriteLock
//
typedef struct
{
    TPM_CMD_HEADER Header;
    TPMI_RH_PROVISION AuthHandle;
    TPMI_RH_NV_INDEX NvIndex;
    TPMS_AUTH_COMMAND_NO_NONCE AuthSession;
} TPM_NV_WRITE_LOCK_CMD_HEADER, *PTPM_NV_WRITE_LOCK_CMD_HEADER;

typedef struct
{
    TPM_REPLY_HEADER Header;
    uint32_t ParameterSize;
    TPMS_AUTH_RESPONSE_NO_NONCE AuthSession;
} TPM_NV_WRITE_LOCK_REPLY, *PTPM_NV_WRITE_LOCK_REPLY;

//
// NV_UndefineSpace
//
typedef struct
{
    TPM_CMD_HEADER Header;
    TPMI_RH_PROVISION AuthHandle;
    TPMI_RH_NV_INDEX NvIndex;
    TPMS_AUTH_COMMAND_NO_NONCE AuthSession;
} TPM_NV_UNDEFINE_SPACE_CMD_HEADER, *PTPM_NV_UNDEFINE_SPACE_CMD_HEADER;

typedef struct
{
    TPM_REPLY_HEADER Header;
    uint32_t ParameterSize;
    TPMS_AUTH_RESPONSE_NO_NONCE AuthSession;
} TPM_NV_UNDEFINE_SPACE_REPLY, *PTPM_NV_UNDEFINE_SPACE_REPLY;

//
// NV_DefineSpace
//
typedef struct
{
    TPM_CMD_HEADER Header;
    TPMI_RH_PROVISION AuthHandle;
    TPMS_AUTH_COMMAND_NO_NONCE AuthSession;
} TPM_NV_DEFINE_SPACE_CMD_HEADER, *PTPM_NV_DEFINE_SPACE_CMD_HEADER;

typedef struct
{
    uint16_t AuthSize;
    uint8_t Data[1];
} TPM_NV_DEFINE_SPACE_CMD_BODY, *PTPM_NV_DEFINE_SPACE_CMD_BODY;

typedef struct
{
    uint16_t NvPublicSize;
    TPMI_RH_NV_INDEX NvIndex;
    TPMI_ALG_HASH NameAlg;
    TPMA_NV Attributes;
    uint16_t AuthPolicySize;
    uint16_t DataSize;
} TPM_NV_DEFINE_SPACE_CMD_FOOTER, *PTPM_NV_DEFINE_SPACE_CMD_FOOTER;

typedef struct
{
    TPM_REPLY_HEADER Header;
    uint32_t ParameterSize;
    TPMS_AUTH_RESPONSE_NO_NONCE AuthSession;
} TPM_NV_DEFINE_SPACE_REPLY, *PTPM_NV_DEFINE_SPACE_REPLY;

//
// NV_ReadPublic
//
typedef struct
{
    TPM_CMD_HEADER Header;
    TPMI_RH_NV_INDEX NvIndex;
} TPM_NV_READ_PUBLIC_CMD_HEADER, *PTPM_NV_READ_PUBLIC_CMD_HEADER;

typedef struct
{
    TPM_REPLY_HEADER Header;
    TPM_NV_DEFINE_SPACE_CMD_FOOTER NvPublic;
    TPM2B_DIGEST Name;
} TPM_NV_READ_PUBLIC_REPLY, *PTPM_NV_READ_PUBLIC_REPLY;

//
// NV_Write
//
typedef struct
{
    TPM_CMD_HEADER Header;
    TPMI_RH_NV_AUTH AuthHandle;
    TPMI_RH_NV_INDEX NvIndex;
    TPMS_AUTH_COMMAND_NO_NONCE AuthSession;
    //
    // Variable Size Auth Session HMAC
    //
    // ....
    //
    // TPM_NV_WRITE_CMD_FOOTER;
} TPM_NV_WRITE_CMD_HEADER, *PTPM_NV_WRITE_CMD_HEADER;

typedef struct
{
    uint16_t Size;
    uint8_t Data[1];
} TPM_NV_WRITE_CMD_BODY, *PTPM_NV_WRITE_CMD_BODY;

typedef struct
{
    uint16_t Offset;
} TPM_NV_WRITE_CMD_FOOTER, *PTPM_NV_WRITE_CMD_FOOTER;

typedef struct
{
    TPM_REPLY_HEADER Header;
    uint32_t ParameterSize;
    TPMS_AUTH_RESPONSE_NO_NONCE AuthSession;
} TPM_NV_WRITE_REPLY, *PTPM_NV_WRITE_REPLY;

//
// NV_Read
//
typedef struct
{
    TPM_CMD_HEADER Header;
    TPMI_RH_NV_AUTH AuthHandle;
    TPMI_RH_NV_INDEX NvIndex;
    TPMS_AUTH_COMMAND_NO_NONCE AuthSession;
    //
    // Variable Size Auth Session HMAC
    //
    // ....
    //
    // TPM_NV_READ_CMD_FOOTER;
} TPM_NV_READ_CMD_HEADER, *PTPM_NV_READ_CMD_HEADER;

typedef struct
{
    uint16_t Size;
    uint16_t Offset;
} TPM_NV_READ_CMD_FOOTER, *PTPM_NV_READ_CMD_FOOTER;

typedef struct
{
    TPM_REPLY_HEADER Header;
    uint32_t ParameterSize;
    uint16_t DataSize;
    uint8_t Data[1];
    //
    // TPMS_AUTH_RESPONSE_NO_NONCE AuthSession;
    //
} TPM_NV_READ_REPLY, *PTPM_NV_READ_REPLY;

//
// Get_Capabilities
//
typedef struct
{
    TPM_CMD_HEADER Header;
    TPM_CAP Capability;
    TPM_PT Property;
    uint32_t PropertyCount;
} TPM_GET_CAPABILITY_CMD_HEADER, *PTPM_GET_CAPABILITY_CMD_HEADER;

typedef struct
{
    TPM_REPLY_HEADER Header;
    TPMI_YES_NO MoreData;
    TPMS_CAPABILITY_DATA Data;
} TPM_GET_CAPABILITY_REPLY, *PTPM_GET_CAPABILITY_REPLY;

#pragma pack(pop)

