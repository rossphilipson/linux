/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005 Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef __TCG_H__
#define __TCG_H__

// **************************** CONSTANTS *********************************

// Base types used in marshal macros
typedef unsigned char BYTE;
typedef unsigned char BOOL;
typedef unsigned char UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;

// BOOL values
#define TRUE 0x01
#define FALSE 0x00

#define TCPA_MAX_BUFFER_LENGTH 0x2000

//
// TPM_COMMAND_CODE values
#define TPM_PROTECTED_ORDINAL 0x00000000UL
#define TPM_UNPROTECTED_ORDINAL 0x80000000UL
#define TPM_CONNECTION_ORDINAL 0x40000000UL
#define TPM_VENDOR_ORDINAL 0x20000000UL

#define TPM_ORD_Extend                   (20UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_PcrRead                  (21UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetRandom                (70UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Reset                    (90UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_GetCapability            (101UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Init                     (151UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_Startup                  (153UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SHA1Start                (160UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SHA1Update               (161UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SHA1Complete             (162UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_SHA1CompleteExtend       (163UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_PCR_Re                   (200UL + TPM_PROTECTED_ORDINAL)
#define TPM_ORD_MAX                      (256UL + TPM_PROTECTED_ORDINAL)

//
// TPM_RESULT values
//
// just put in the whole table from spec 1.2

#define TPM_BASE   0x0 // The start of TPM return codes
#define TPM_VENDOR_ERROR 0x00000400 // Mask to indicate that the error code is vendor specific for vendor specific commands
#define TPM_NON_FATAL  0x00000800 // Mask to indicate that the error code is a non-fatal failure.

#define TPM_SUCCESS   TPM_BASE // Successful completion of the operation
#define TPM_AUTHFAIL      TPM_BASE + 1 // Authentication failed
#define TPM_BADINDEX      TPM_BASE + 2 // The index to a PCR, DIR or other register is incorrect
#define TPM_BAD_PARAMETER     TPM_BASE + 3 // One or more parameter is bad
#define TPM_FAIL       TPM_BASE + 9 // The operation failed
#define TPM_BAD_ORDINAL     TPM_BASE + 10 // The ordinal was unknown or inconsistenta
#define TPM_INVALID_PCR_INFO   TPM_BASE + 16 // PCR information could not be interpreted
#define TPM_RESOURCES      TPM_BASE + 21 // The TPM has insufficient internal resources to perform the requested action.
#define TPM_SHORTRANDOM     TPM_BASE + 22 // A random string was too short
#define TPM_SIZE       TPM_BASE + 23 // The TPM does not have the space to perform the operation.
#define TPM_BAD_PARAM_SIZE     TPM_BASE + 25 // The paramSize argument to the command has the incorrect value
#define TPM_SHA_ERROR      TPM_BASE + 27 // The calculation is unable to proceed because the existing SHA-1 thread has already encountered an error.
#define TPM_FAILEDSELFTEST     TPM_BASE + 28 // Self-test has failed and the TPM has shutdown.
#define TPM_AUTH2FAIL      TPM_BASE + 29 // The authorization for the second key in a 2 key function failed authorization
#define TPM_BADTAG       TPM_BASE + 30 // The tag value sent to for a command is invalid
#define TPM_IOERROR      TPM_BASE + 31 // An IO error occurred transmitting information to the TPM
#define TPM_WRONG_ENTITYTYPE   TPM_BASE + 37 // The submitted entity type is not allowed
#define TPM_BAD_PRESENCE      TPM_BASE + 45 // Either the physicalPresence or physicalPresenceLock bits have the wrong value
#define TPM_BAD_VERSION      TPM_BASE + 46 // The TPM cannot perform this version of the capability
#define TPM_NOTRESETABLE      TPM_BASE + 50 // Attempt to reset a PCR register that does not have the resettable attribute
#define TPM_NOTLOCAL       TPM_BASE + 51 // Attempt to reset a PCR register that requires locality and locality modifier not part of command transport
#define TPM_BAD_TYPE       TPM_BASE + 52 // Make identity blob not properly typed
#define TPM_INVALID_RESOURCE     TPM_BASE + 53 // When saving context identified resource type does not match actual resource
#define TPM_NOTFIPS       TPM_BASE + 54 // The TPM is attempting to execute a command only available when in FIPS mode
#define TPM_INVALID_FAMILY      TPM_BASE + 55 // The command is attempting to use an invalid family ID
#define TPM_BAD_LOCALITY      TPM_BASE + 61 // The locality is incorrect for the attempted operation
#define TPM_INVALID_STRUCTURE     TPM_BASE + 67 // The structure tag and version are invalid or inconsistenta

// TPM_STARTUP_TYPE values
#define TPM_ST_CLEAR 0x0001
#define TPM_ST_STATE 0x0002
#define TPM_ST_DEACTIVATED 0x003

// TPM_TAG values
#define TPM_TAG_PCR_INFO_LONG 0x0006
#define TPM_TAG_STORED_DATA12 0x0016
#define TPM_TAG_RQU_COMMAND 0x00c1
#define TPM_TAG_RQU_AUTH1_COMMAND 0x00c2
#define TPM_TAG_RQU_AUTH2_COMMAND 0x00c3
#define TPM_TAG_RSP_COMMAND 0x00c4
#define TPM_TAG_RSP_AUTH1_COMMAND 0x00c5
#define TPM_TAG_RSP_AUTH2_COMMAND 0x00c6

// TPM_PAYLOAD_TYPE values
#define TPM_PT_ASYM 0x01
#define TPM_PT_BIND 0x02
#define TPM_PT_MIGRATE 0x03
#define TPM_PT_MAINT 0x04
#define TPM_PT_SEAL 0x05

// TPM_ENTITY_TYPE values
#define TPM_ET_KEYHANDLE 0x0001
#define TPM_ET_OWNER 0x0002
#define TPM_ET_DATA 0x0003
#define TPM_ET_SRK 0x0004
#define TPM_ET_KEY 0x0005

/// TPM_ResourceTypes
#define TPM_RT_KEY      0x00000001
#define TPM_RT_AUTH     0x00000002
#define TPM_RT_HASH     0x00000003
#define TPM_RT_TRANS    0x00000004
#define TPM_RT_CONTEXT  0x00000005
#define TPM_RT_COUNTER  0x00000006
#define TPM_RT_DELEGATE 0x00000007
#define TPM_RT_DAA_TPM  0x00000008
#define TPM_RT_DAA_V0   0x00000009
#define TPM_RT_DAA_V1   0x0000000A

// TPM_PROTOCOL_ID values
#define TPM_PID_OIAP 0x0001
#define TPM_PID_OSAP 0x0002
#define TPM_PID_ADIP 0x0003
#define TPM_PID_ADCP 0x0004
#define TPM_PID_OWNER 0x0005

// TPM_ALGORITHM_ID values
#define TPM_ALG_RSA 0x00000001
#define TPM_ALG_SHA 0x00000004
#define TPM_ALG_HMAC 0x00000005
#define TPM_ALG_AES128 0x00000006
#define TPM_ALG_MFG1 0x00000007
#define TPM_ALG_AES192 0x00000008
#define TPM_ALG_AES256 0x00000009
#define TPM_ALG_XOR 0x0000000A

// TPM_ENC_SCHEME values
#define TPM_ES_NONE 0x0001
#define TPM_ES_RSAESPKCSv15 0x0002
#define TPM_ES_RSAESOAEP_SHA1_MGF1 0x0003

// TPM_SIG_SCHEME values
#define TPM_SS_NONE 0x0001
#define TPM_SS_RSASSAPKCS1v15_SHA1 0x0002
#define TPM_SS_RSASSAPKCS1v15_DER 0x0003

/*
 * TPM_CAPABILITY_AREA Values for TPM_GetCapability ([TPM_Part2], Section 21.1)
 */
#define TPM_CAP_ORD                     0x00000001
#define TPM_CAP_ALG                     0x00000002
#define TPM_CAP_PID                     0x00000003
#define TPM_CAP_FLAG                    0x00000004
#define TPM_CAP_PROPERTY                0x00000005
#define TPM_CAP_VERSION                 0x00000006
#define TPM_CAP_KEY_HANDLE              0x00000007
#define TPM_CAP_CHECK_LOADED            0x00000008
#define TPM_CAP_SYM_MODE                0x00000009
#define TPM_CAP_KEY_STATUS              0x0000000C
#define TPM_CAP_NV_LIST                 0x0000000D
#define TPM_CAP_MFR                     0x00000010
#define TPM_CAP_NV_INDEX                0x00000011
#define TPM_CAP_TRANS_ALG               0x00000012
#define TPM_CAP_HANDLE                  0x00000014
#define TPM_CAP_TRANS_ES                0x00000015
#define TPM_CAP_AUTH_ENCRYPT            0x00000017
#define TPM_CAP_SELECT_SIZE             0x00000018
#define TPM_CAP_DA_LOGIC                0x00000019
#define TPM_CAP_VERSION_VAL             0x0000001A

/* subCap definitions ([TPM_Part2], Section 21.2) */
#define TPM_CAP_PROP_PCR                0x00000101
#define TPM_CAP_PROP_DIR                0x00000102
#define TPM_CAP_PROP_MANUFACTURER       0x00000103
#define TPM_CAP_PROP_KEYS               0x00000104
#define TPM_CAP_PROP_MIN_COUNTER        0x00000107
#define TPM_CAP_FLAG_PERMANENT          0x00000108
#define TPM_CAP_FLAG_VOLATILE           0x00000109
#define TPM_CAP_PROP_AUTHSESS           0x0000010A
#define TPM_CAP_PROP_TRANSESS           0x0000010B
#define TPM_CAP_PROP_COUNTERS           0x0000010C
#define TPM_CAP_PROP_MAX_AUTHSESS       0x0000010D
#define TPM_CAP_PROP_MAX_TRANSESS       0x0000010E
#define TPM_CAP_PROP_MAX_COUNTERS       0x0000010F
#define TPM_CAP_PROP_MAX_KEYS           0x00000110
#define TPM_CAP_PROP_OWNER              0x00000111
#define TPM_CAP_PROP_CONTEXT            0x00000112
#define TPM_CAP_PROP_MAX_CONTEXT        0x00000113
#define TPM_CAP_PROP_FAMILYROWS         0x00000114
#define TPM_CAP_PROP_TIS_TIMEOUT        0x00000115
#define TPM_CAP_PROP_STARTUP_EFFECT     0x00000116
#define TPM_CAP_PROP_DELEGATE_ROW       0x00000117
#define TPM_CAP_PROP_MAX_DAASESS        0x00000119
#define TPM_CAP_PROP_DAASESS            0x0000011A
#define TPM_CAP_PROP_CONTEXT_DIST       0x0000011B
#define TPM_CAP_PROP_DAA_INTERRUPT      0x0000011C
#define TPM_CAP_PROP_SESSIONS           0x0000011D
#define TPM_CAP_PROP_MAX_SESSIONS       0x0000011E
#define TPM_CAP_PROP_CMK_RESTRICTION    0x0000011F
#define TPM_CAP_PROP_DURATION           0x00000120
#define TPM_CAP_PROP_ACTIVE_COUNTER     0x00000122
#define TPM_CAP_PROP_MAX_NV_AVAILABLE   0x00000123
#define TPM_CAP_PROP_INPUT_BUFFER       0x00000124

// TPM_KEY_USAGE values
#define TPM_KEY_EK 0x0000
#define TPM_KEY_SIGNING 0x0010
#define TPM_KEY_STORAGE 0x0011
#define TPM_KEY_IDENTITY 0x0012
#define TPM_KEY_AUTHCHANGE 0X0013
#define TPM_KEY_BIND 0x0014
#define TPM_KEY_LEGACY 0x0015

// TPM_AUTH_DATA_USAGE values
#define TPM_AUTH_NEVER 0x00
#define TPM_AUTH_ALWAYS 0x01

// Key Handle of owner and srk
#define TPM_OWNER_KEYHANDLE 0x40000001
#define TPM_SRK_KEYHANDLE 0x40000000

// *************************** TYPEDEFS *********************************
typedef UINT32 TPM_RESULT;
typedef UINT32 TPM_PCRINDEX;
typedef UINT32 TPM_HANDLE;
typedef TPM_HANDLE TPM_AUTHHANDLE;
typedef UINT32 TPM_COMMAND_CODE;
typedef UINT16 TPM_PROTOCOL_ID;
typedef BYTE TPM_AUTH_DATA_USAGE;
typedef UINT16 TPM_ENTITY_TYPE;
typedef UINT32 TPM_ALGORITHM_ID;
typedef UINT16 TPM_STARTUP_TYPE;
typedef UINT32 TPM_CAPABILITY_AREA;

#define TPM_DIGEST_SIZE 20  // Don't change this
typedef BYTE TPM_AUTHDATA[TPM_DIGEST_SIZE];
typedef TPM_AUTHDATA TPM_SECRET;
typedef TPM_AUTHDATA TPM_ENCAUTH;
typedef BYTE TPM_PAYLOAD_TYPE;
typedef UINT16 TPM_TAG;
typedef UINT16 TPM_STRUCTURE_TAG;

// Data Types of the TCS
typedef UINT32 TCS_AUTHHANDLE;  // Handle addressing a authorization session
typedef UINT32 TCS_CONTEXT_HANDLE; // Basic context handle

// ************************* STRUCTURES **********************************

typedef struct TPM_VERSION {
  BYTE major;
  BYTE minor;
  BYTE revMajor;
  BYTE revMinor;
} TPM_VERSION;

static const TPM_VERSION TPM_STRUCT_VER_1_1 = { 1,1,0,0 };

typedef struct TPM_CAP_VERSION_INFO {
   TPM_STRUCTURE_TAG tag;
   TPM_VERSION version;
   UINT16 specLevel;
   BYTE errataRev;
   BYTE tpmVendorID[4];
   UINT16 vendorSpecificSize;
   BYTE* vendorSpecific;
} TPM_CAP_VERSION_INFO;

typedef struct TPM_DIGEST {
  BYTE digest[TPM_DIGEST_SIZE];
} TPM_DIGEST;

typedef TPM_DIGEST TPM_PCRVALUE;
typedef TPM_DIGEST TPM_COMPOSITE_HASH;
typedef TPM_DIGEST TPM_HMAC;

typedef struct TPM_NONCE {
  BYTE nonce[TPM_DIGEST_SIZE];
} TPM_NONCE;

#endif //__TCPA_H__
