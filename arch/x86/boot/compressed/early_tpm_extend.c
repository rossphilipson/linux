/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005, Intel Corp.
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

#include <linux/init.h>
#include <linux/string.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/bootparam_utils.h>

#include "tcg.h"
#include "tpm_marshal.h"
#include "tpm_extend.h"

/* TPM1 */
TPM_RESULT TPM_Extend( TPM_PCRINDEX  pcrNum,  // in
		TPM_DIGEST* inDigest, // in
		TPM_PCRVALUE*  outDigest) // out
{
	TPM_BEGIN_CMD(TPM_ORD_Extend);

	PACK_IN(TPM_PCRINDEX, pcrNum);
	PACK_IN(TPM_DIGEST, inDigest);

	TPM_XMIT_REQ();

	UNPACK_OUT(TPM_PCRVALUE, outDigest);

	TPM_END();

abort_egress:
	return status;
}

/* TPM2 */
TPM_RC TPM2_PCR_Extend(TPM_PCRINDEX pcrNum, UINT32 count, TPMT_HA hashes[])
{
    TPM_RH sessionHandle = TPM_RS_PW;
    UINT32 i;
    TPM_BEGIN(TPM_ST_SESSIONS, TPM_CC_PCR_Extend);

    /* TPM_CC */
    ptr = pack_TPM_COMMAND_CODE(ptr, ordinal);

    /* TPMI_DH_PCR+ */
    ptr = pack_TPM_PCRINDEX(ptr, pcrNum);
    /* NULL Auth */
    ptr = pack_TPM_RH(ptr, &sessionHandle); /* handle */
    ptr = pack_UINT16(ptr, 0);              /* nonce */
    ptr = pack_BYTE(ptr, 0);                /* attributes */
    ptr = pack_UINT16(ptr, 0);              /* password size */

    /* TPML_DIGEST_VALUES */
    ptr = pack_UINT32(ptr, count);
    for ( i = 0; i < count; i++ )
    {
        ptr = pack_TPM_ALG_ID(ptr, &hashes[i].hashAlg);
        ptr = pack_BUFFER(ptr, hashes[i].digest.sha256, SHA256_DIGEST_SIZE);
    }

    TPM_TRANSMIT();
    TPM_UNPACK_VERIFY();

abort_egress:
egress:
    return status;
}

TPM_RESULT TPM_TransmitData(
		BYTE* in,
		UINT32 insize,
		BYTE* out,
		UINT32* outsize)
{
	TPM_RESULT status = TPM_SUCCESS;

	/* TODO lower edge to talk to the TPM reusing mainline TPM driver */

	return status;
}

