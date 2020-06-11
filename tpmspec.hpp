/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    tpmspec.hpp

Abstract:

    This header contains a subset of the TPM2.0 Specification relevant to the
    utility, using modern C++ features instead of the C89 style of the usual
    auto-generated files that the Microsoft tools provide. Naming conventions
    are kept to allow easy referencing of the specification.

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
// TPM2.0 Session Tags
//
typedef enum _TPM_ST : uint16_t
{
    TPM_ST_NO_SESSIONS = 0x8001,
    TPM_ST_SESSIONS = 0x8002
} TPM_ST, TPMI_ST_COMMAND_TAG;

//
// TPM2.0 Command Codes
//
typedef enum _TPM_CC : uint32_t
{
    TPM_CC_NV_UndefineSpace = 0x122,
    TPM_CC_NV_WriteLock = 0x138,
    TPM_CC_NV_DefineSpace = 0x12A,
    TPM_CC_NV_Write = 0x137,
    TPM_CC_NV_Read = 0x14E,
    TPM_CC_NV_ReadLock = 0x14F,
    TPM_CC_NV_ReadPublic = 0x169,
    TPM_CC_GetCapability = 0x17A
} TPM_CC;

//
// TPM2.0 Response Codes
//
typedef enum _TPM_RC : uint32_t
{
    TPM_RC_SUCCESS = 0,
    TPM_RC_FAILURE = 0x101,
    TPM_RC_NV_RANGE = 0x146,
    TPM_RC_NV_LOCKED = 0x148,
    TPM_RC_NV_AUTHORIZATION = 0x149,
    TPM_RC_NV_UNINITIALIZED = 0x14A,
    TPM_RC_NV_DEFINED = 0x14C,
    TPM_RC_HANDLE_1 = 0x18B,
} TPM_RC;

//
// TPM2.0 Handle Types
//
typedef enum _TPM_HT : uint8_t
{
    TPM_HR_PCR,
    TPM_HT_NV_INDEX,
    TPM_HT_HMAC_SESSION,
    TPM_HT_LOADED_SESSION = TPM_HT_HMAC_SESSION,
    TPM_HT_POLICY_SESSION,
    TPM_HT_SAVED_SESSION = TPM_HT_POLICY_SESSION,
    TPM_HT_PERMANENT = 0x40,
    TPM_HT_TRANSIENT = 0x80,
    TPM_HT_PERSISTENT = 0x81
} TPM_HT;
#define HR_SHIFT               24
#define HR_NV_INDEX           (TPM_HT_NV_INDEX <<  HR_SHIFT)

//
// TPM2.0 Capabilities
//
typedef enum _TPM_CAP : uint32_t
{
    TPM_CAP_FIRST = 0,
    TPM_CAP_ALGS = TPM_CAP_FIRST,
    TPM_CAP_HANDLES
} TPM_CAP;
#define MAX_CAP_BUFFER      1024
#define MAX_CAP_DATA       (MAX_CAP_BUFFER - sizeof(TPM_CAP) - sizeof(uint32_t))
#define MAX_CAP_HANDLES    (MAX_CAP_DATA / sizeof(TPM_HANDLE))

//
// TPM Algorithm IDs
//
typedef enum _TPM_ALG_ID : uint16_t
{
    TPM_ALG_SHA256 = 0x000B
} TPM_ALG_ID, TPMI_ALG_HASH;

//
// TPM Attributes for Non Volatile Index Values
//
typedef enum _TPMA_NV : uint32_t
{
    //
    // Write Permissions
    //
    TPMA_NV_PPWRITE = 0x00000001,
    TPMA_NV_OWNERWRITE = 0x00000002,
    TPMA_NV_AUTHWRITE = 0x00000004,
    TPMA_NV_POLICYWRITE = 0x00000008,

    //
    // Types
    //
    TPMA_NV_COUNTER = 0x00000010,
    TPMA_NV_BITS = 0x00000020,
    TPMA_NV_EXTEND = 0x00000040,
    TPMA_NV_RESERVED_TYPE_1 = 0x00000080,
    TPMA_NV_RESERVED_TYPE_2 = 0x00000100,
    TPMA_NV_RESERVED_TYPE_3 = 0x00000200,

    //
    // Modify Flags
    //
    TPMA_NV_POLICY_DELETE = 0x00000400,
    TPMA_NV_WRITELOCKED = 0x00000800,
    TPMA_NV_WRITEALL = 0x00001000,
    TPMA_NV_WRITEDEFINE = 0x00002000,
    TPMA_NV_WRITE_STCLEAR = 0x00004000,
    TPMA_NV_GLOBALLOCK = 0x00008000,

    //
    // Read Permissions
    //
    TPMA_NV_PPREAD = 0x00010000,
    TPMA_NV_OWNERREAD = 0x00020000,
    TPMA_NV_AUTHREAD = 0x00040000,
    TPMA_NV_POLICYREAD = 0x00080000,

    //
    // Additional Flags
    //
    TPMA_NV_RESERVED_FLAG_1 = 0x00100000,
    TPMA_NV_RESERVED_FLAG_2 = 0x00200000,
    TPMA_NV_RESERVED_FLAG_3 = 0x00400000,
    TPMA_NV_RESERVED_FLAG_4 = 0x00800000,
    TPMA_NV_RESERVED_FLAG_5 = 0x01000000,
    TPMA_NV_NO_DA = 0x02000000,
    TPMA_NV_ORDERLY = 0x04000000,
    TPMA_NV_CLEAR_STCLEAR = 0x08000000,
    TPMA_NV_READLOCKED = 0x10000000,
    TPMA_NV_WRITTEN = 0x20000000,
    TPMA_NV_PLATFORMCREATE = 0x40000000,
    TPMA_NV_READ_STCLEAR = 0x80000000
} TPMA_NV;

//
// TPM2.0 Property Types
//
typedef enum _TPM_PT : uint32_t
{
    TPM_PT_NONE = 0x0,
    PT_FIXED = 0x100
} TPM_PT;

//
// TPM2.0 Session Attributes
//
typedef union
{
    struct
    {
        uint8_t ContinueSession : 1;
        uint8_t AuditExclusive : 1;
        uint8_t AuditReset : 1;
        uint8_t : 2;
        uint8_t Decrypt : 1;
        uint8_t Encrypt : 1;
        uint8_t Audit : 1;
    };
    uint8_t Value;
} TPMA_SESSION;

//
// TPM2.0 Yes/No Boolean
//
typedef uint8_t TPMI_YES_NO;

//
// TPM2.0 Hash Algorithm Sizes
// Only SHA-256 supported for now
//
typedef union
{
    uint8_t Sha256[32];
} TPMU_HA;

//
// Definition of a TPM2.0 Hash Agile Structure (Algorithm and Digest)
//
typedef struct
{
    TPMI_ALG_HASH HashAlg;
    TPMU_HA Digest;
} TPMT_HA;

//
// Definition of a Hash Digest Buffer, which encodes a TPM2.0 Hash Agile
//
typedef struct
{
    uint16_t BufferSize;
    TPMT_HA Buffer;
} TPM2B_DIGEST;

//
// Definition of a TPM2.0 Handle
//
typedef union
{
    struct
    {
        uint8_t Index[3];
        TPM_HT Type;
    };
    uint32_t Value;
} TPM_HANDLE, TPMI_RH_NV_INDEX, TPMI_RH_PROVISION,
  TPMI_SH_AUTH_SESSION, TPMI_RH_NV_AUTH, TPM_RH, TPM_NV_INDEX;
static_assert(sizeof(TPM_HANDLE) == sizeof(uint32_t));

//
// Architecturally Defined Permanent Handles
//
static constexpr TPM_RH TPM_RH_OWNER = { 1, 0, 0, TPM_HT_PERMANENT };
static constexpr TPM_RH TPM_RS_PW = { 9, 0, 0, TPM_HT_PERMANENT };

//
// TPM2.0 Handle List
//
typedef struct
{
    uint32_t Count;
    TPM_HANDLE Handle[MAX_CAP_HANDLES];
} TPML_HANDLE, *PTPML_HANDLE;

//
// TPM2.0 Union of capability data returned by TPM2_CC_GetCapabilities
//
typedef union
{
    TPML_HANDLE Handles;
} TPMU_CAPABILITIES, *PTPMU_CAPABILITIES;

//
// TPM2.0 Payload for each capablity returned by TPM2_CC_GetCapabilities
//
typedef struct
{
    TPM_CAP Capability;
    TPMU_CAPABILITIES Data;
} TPMS_CAPABILITY_DATA, *PTPMS_CAPABILITY_DATA;

#pragma pack(pop)

