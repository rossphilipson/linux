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
/*
 * Copyright (c) 2014 Intel Corporation.
 *
 * Authors:
 *   Quan Xu <quan.xu@intel.com>
 *
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
// TODO licensing

#ifndef TPM_MARSHAL_H
#define TPM_MARSHAL_H

/* TPM1 */

typedef enum UnpackPtr {
	UNPACK_ALIAS,
	UNPACK_ALLOC
} UnpackPtr;

static
inline BYTE* pack_BYTE(BYTE* ptr, BYTE t) {
	ptr[0] = t;
	return ++ptr;
}

static
inline BYTE* unpack_BYTE(BYTE* ptr, BYTE* t) {
	t[0] = ptr[0];
	return ++ptr;
}

static
inline int unpack3_BYTE(BYTE* ptr, UINT32* pos, UINT32 max, BYTE *t)
{
	if (*pos + 1 > max)
		return TPM_SIZE;
	unpack_BYTE(ptr + *pos, t);
	*pos += 1;
	return 0;
}


#define pack_BOOL(p, t) pack_BYTE(p, t)
#define unpack_BOOL(p, t) unpack_BYTE(p, t)
#define unpack3_BOOL(p, x, m, t) unpack3_BYTE(p, x, m, t)
#define sizeof_BOOL(t) 1

static
inline BYTE* pack_UINT16(void* ptr, UINT16 t) {
	UINT16* p = ptr;
	*p = cpu_to_be16(t);
	return ptr + sizeof(UINT16);
}

static
inline BYTE* unpack_UINT16(void* ptr, UINT16* t) {
	UINT16* p = ptr;
	*t = be16_to_cpu(*p);
	return ptr + sizeof(UINT16);
}

static
inline int unpack3_UINT16(BYTE* ptr, UINT32* pos, UINT32 max, UINT16 *t)
{
	if (*pos + 2 > max)
		return TPM_SIZE;
	unpack_UINT16(ptr + *pos, t);
	*pos += 2;
	return 0;
}

static
inline BYTE* pack_UINT32(void* ptr, UINT32 t) {
	UINT32* p = ptr;
	*p = cpu_to_be32(t);
	return ptr + sizeof(UINT32);
}

static
inline BYTE* unpack_UINT32(void* ptr, UINT32* t) {
	UINT32* p = ptr;
	*t = be32_to_cpu(*p);
	return ptr + sizeof(UINT32);
}

static
inline int unpack3_UINT32(BYTE* ptr, UINT32* pos, UINT32 max, UINT32 *t)
{
	if (*pos + 4 > max)
		return TPM_SIZE;
	unpack_UINT32(ptr + *pos, t);
	*pos += 4;
	return 0;
}

#define sizeof_BYTE(x) 1
#define sizeof_UINT16(x) 2
#define sizeof_UINT32(x) 4

#define pack_TPM_RESULT(p, t) pack_UINT32(p, t)
#define pack_TPM_PCRINDEX(p, t) pack_UINT32(p, t)
#define pack_TPM_DIRINDEX(p, t) pack_UINT32(p, t)
#define pack_TPM_HANDLE(p, t) pack_UINT32(p, t)
#define pack_TPM_AUTHHANDLE(p, t) pack_TPM_HANDLE(p, t)
#define pack_TPM_KEY_HANDLE(p, t) pack_TPM_HANDLE(p, t)
#define pack_TPM_RESOURCE_TYPE(p, t) pack_UINT32(p, t)
#define pack_TPM_COMMAND_CODE(p, t) pack_UINT32(p, t)
#define pack_TPM_PROTOCOL_ID(p, t) pack_UINT16(p, t)
#define pack_TPM_AUTH_DATA_USAGE(p, t) pack_BYTE(p, t)
#define pack_TPM_ENTITY_TYPE(p, t) pack_UINT16(p, t)
#define pack_TPM_ALGORITHM_ID(p, t) pack_UINT32(p, t)
#define pack_TPM_KEY_USAGE(p, t) pack_UINT16(p, t)
#define pack_TPM_CAPABILITY_AREA(p, t) pack_UINT32(p, t)
#define pack_TPM_KEY_FLAGS(p, t) pack_UINT32(p, t)
#define pack_TPM_LOCALITY_SELECTION(p, t) pack_BYTE(p, t)

#define unpack_TPM_RESULT(p, t) unpack_UINT32(p, t)
#define unpack_TPM_PCRINDEX(p, t) unpack_UINT32(p, t)
#define unpack_TPM_DIRINDEX(p, t) unpack_UINT32(p, t)
#define unpack_TPM_HANDLE(p, t) unpack_UINT32(p, t)
#define unpack_TPM_AUTHHANDLE(p, t) unpack_TPM_HANDLE(p, t)
#define unpack_TPM_KEY_HANDLE(p, t) unpack_TPM_HANDLE(p, t)
#define unpack_TPM_RESOURCE_TYPE(p, t) unpack_UINT32(p, t)
#define unpack_TPM_COMMAND_CODE(p, t) unpack_UINT32(p, t)
#define unpack_TPM_PROTOCOL_ID(p, t) unpack_UINT16(p, t)
#define unpack_TPM_AUTH_DATA_USAGE(p, t) unpack_BYTE(p, t)
#define unpack_TPM_ENTITY_TYPE(p, t) unpack_UINT16(p, t)
#define unpack_TPM_ALGORITHM_ID(p, t) unpack_UINT32(p, t)
#define unpack_TPM_CAPABILITY_AREA(p, t) unpack_UINT32(p, t)
#define unpack_TPM_KEY_FLAGS(p, t) unpack_UINT32(p, t)
#define unpack_TPM_LOCALITY_SELECTION(p, t) unpack_BYTE(p, t)

#define unpack3_TPM_RESULT(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_PCRINDEX(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_DIRINDEX(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_HANDLE(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_AUTHHANDLE(p, l, m, t) unpack3_TPM_HANDLE(p, l, m, t)
#define unpack3_TPM_KEY_HANDLE(p, l, m, t) unpack3_TPM_HANDLE(p, l, m, t)
#define unpack3_TPM_RESOURCE_TYPE(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_COMMAND_CODE(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_PROTOCOL_ID(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_AUTH_DATA_USAGE(p, l, m, t) unpack3_BYTE(p, l, m, t)
#define unpack3_TPM_ENTITY_TYPE(p, l, m, t) unpack3_UINT16(p, l, m, t)
#define unpack3_TPM_ALGORITHM_ID(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_CAPABILITY_AREA(p, l, m, t) unpack3_UINT32(p, l, m, t)
#define unpack3_TPM_LOCALITY_SELECTION(p, l, m, t) unpack3_BYTE(p, l, m, t)

#define sizeof_TPM_RESULT(t) sizeof_UINT32(t)
#define sizeof_TPM_PCRINDEX(t) sizeof_UINT32(t)
#define sizeof_TPM_DIRINDEX(t) sizeof_UINT32(t)
#define sizeof_TPM_HANDLE(t) sizeof_UINT32(t)
#define sizeof_TPM_AUTHHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TCPA_HASHHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TCPA_HMACHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TCPA_ENCHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TPM_KEY_HANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TCPA_ENTITYHANDLE(t) sizeof_TPM_HANDLE(t)
#define sizeof_TPM_RESOURCE_TYPE(t) sizeof_UINT32(t)
#define sizeof_TPM_COMMAND_CODE(t) sizeof_UINT32(t)
#define sizeof_TPM_PROTOCOL_ID(t) sizeof_UINT16(t)
#define sizeof_TPM_AUTH_DATA_USAGE(t) sizeof_BYTE(t)
#define sizeof_TPM_ENTITY_TYPE(t) sizeof_UINT16(t)
#define sizeof_TPM_ALGORITHM_ID(t) sizeof_UINT32(t)
#define sizeof_TPM_KEY_USAGE(t) sizeof_UINT16(t)
#define sizeof_TPM_STARTUP_TYPE(t) sizeof_UINT16(t)
#define sizeof_TPM_CAPABILITY_AREA(t) sizeof_UINT32(t)
#define sizeof_TPM_ENC_SCHEME(t) sizeof_UINT16(t)
#define sizeof_TPM_SIG_SCHEME(t) sizeof_UINT16(t)
#define sizeof_TPM_MIGRATE_SCHEME(t) sizeof_UINT16(t)
#define sizeof_TPM_PHYSICAL_PRESENCE(t) sizeof_UINT16(t)
#define sizeof_TPM_KEY_FLAGS(t) sizeof_UINT32(t)
#define sizeof_TPM_LOCALITY_SELECTION(t) sizeof_BYTE(t)

#define pack_TPM_AUTH_HANDLE(p, t) pack_UINT32(p, t)
#define pack_TCS_CONTEXT_HANDLE(p, t) pack_UINT32(p, t)
#define pack_TCS_KEY_HANDLE(p, t) pack_UINT32(p, t)

#define unpack_TPM_AUTH_HANDLE(p, t) unpack_UINT32(p, t)
#define unpack_TCS_CONTEXT_HANDLE(p, t) unpack_UINT32(p, t)
#define unpack_TCS_KEY_HANDLE(p, t) unpack_UINT32(p, t)

#define sizeof_TPM_AUTH_HANDLE(t) sizeof_UINT32(t)
#define sizeof_TCS_CONTEXT_HANDLE(t) sizeof_UINT32(t)
#define sizeof_TCS_KEY_HANDLE(t) sizeof_UINT32(t)


static
inline BYTE* pack_BUFFER(BYTE* ptr, const BYTE* buf, UINT32 size) {
	memcpy(ptr, buf, size);
	return ptr + size;
}

static
inline BYTE* unpack_BUFFER(BYTE* ptr, BYTE* buf, UINT32 size) {
	memcpy(buf, ptr, size);
	return ptr + size;
}

static
inline int unpack3_BUFFER(BYTE* ptr, UINT32* pos, UINT32 max, BYTE* buf, UINT32 size) {
	if (*pos + size > max)
		return TPM_SIZE;
	memcpy(buf, ptr + *pos, size);
	*pos += size;
	return 0;
}

#define sizeof_BUFFER(b, s) s

static
inline BYTE* unpack_ALIAS(BYTE* ptr, BYTE** buf, UINT32 size) {
	*buf = ptr;
	return ptr + size;
}

static
inline BYTE* unpack_ALLOC(BYTE* ptr, BYTE** buf, UINT32 size) {
	if(size) {
		// TODO to keep this, set some minimal allocator routine to use to get some mem
		//*buf = malloc(size);
		memcpy(*buf, ptr, size);
	} else {
		*buf = NULL;
	}
	return ptr + size;
}

static
inline BYTE* unpack_PTR(BYTE* ptr, BYTE** buf, UINT32 size, UnpackPtr alloc) {
	if(alloc == UNPACK_ALLOC) {
		return unpack_ALLOC(ptr, buf, size);
	} else {
		return unpack_ALIAS(ptr, buf, size);
	}
}

static
inline int unpack3_PTR(BYTE* ptr, UINT32* pos, UINT32 max, BYTE** buf, UINT32 size, UnpackPtr alloc) {
	if (size > max || *pos + size > max)
		return TPM_SIZE;
	if (alloc == UNPACK_ALLOC) {
		unpack_ALLOC(ptr + *pos, buf, size);
	} else {
		unpack_ALIAS(ptr + *pos, buf, size);
	}
	*pos += size;
	return 0;
}
#define unpack3_VPTR(ptr, pos, max, buf, size, alloc) unpack3_PTR(ptr, pos, max, (void*)(buf), size, alloc)

static
inline BYTE* pack_TPM_AUTHDATA(BYTE* ptr, const TPM_AUTHDATA* d) {
	return pack_BUFFER(ptr, *d, TPM_DIGEST_SIZE);
}

static
inline BYTE* unpack_TPM_AUTHDATA(BYTE* ptr, TPM_AUTHDATA* d) {
	return unpack_BUFFER(ptr, *d, TPM_DIGEST_SIZE);
}

static
inline int unpack3_TPM_AUTHDATA(BYTE* ptr, UINT32* pos, UINT32 len, TPM_AUTHDATA* d) {
	return unpack3_BUFFER(ptr, pos, len, *d, TPM_DIGEST_SIZE);
}

#define sizeof_TPM_AUTHDATA(d) TPM_DIGEST_SIZE

#define pack_TPM_SECRET(p, t) pack_TPM_AUTHDATA(p, t)
#define pack_TPM_PAYLOAD_TYPE(p, t) pack_BYTE(p, t)
#define pack_TPM_TAG(p, t) pack_UINT16(p, t)
#define pack_TPM_STRUCTURE_TAG(p, t) pack_UINT16(p, t)

#define unpack_TPM_SECRET(p, t) unpack_TPM_AUTHDATA(p, t)
#define unpack_TPM_PAYLOAD_TYPE(p, t) unpack_BYTE(p, t)
#define unpack_TPM_TAG(p, t) unpack_UINT16(p, t)
#define unpack_TPM_STRUCTURE_TAG(p, t) unpack_UINT16(p, t)
#define unpack3_TPM_STRUCTURE_TAG(p, l, m, t) unpack3_UINT16(p, l, m, t)

#define sizeof_TPM_SECRET(t) sizeof_TPM_AUTHDATA(t)
#define sizeof_TPM_PAYLOAD_TYPE(t) sizeof_BYTE(t)
#define sizeof_TPM_TAG(t) sizeof_UINT16(t)
#define sizeof_TPM_STRUCTURE_TAG(t) sizeof_UINT16(t)

static
inline BYTE* pack_TPM_VERSION(BYTE* ptr, const TPM_VERSION* t) {
	ptr[0] = t->major;
	ptr[1] = t->minor;
	ptr[2] = t->revMajor;
	ptr[3] = t->revMinor;
	return ptr + 4;
}

static
inline BYTE* unpack_TPM_VERSION(BYTE* ptr, TPM_VERSION* t) {
	t->major = ptr[0];
	t->minor = ptr[1];
	t->revMajor = ptr[2];
	t->revMinor = ptr[3];
	return ptr + 4;
}

static
inline int unpack3_TPM_VERSION(BYTE* ptr, UINT32 *pos, UINT32 max, TPM_VERSION* t) {
	if (*pos + 4 > max)
		return TPM_SIZE;
	ptr += *pos;
	t->major = ptr[0];
	t->minor = ptr[1];
	t->revMajor = ptr[2];
	t->revMinor = ptr[3];
	*pos += 4;
	return 0;
}

static
inline BYTE* pack_TPM_DIGEST(BYTE* ptr, const TPM_DIGEST* d) {
	return pack_BUFFER(ptr, d->digest, TPM_DIGEST_SIZE);
}

static
inline BYTE* unpack_TPM_DIGEST(BYTE* ptr, TPM_DIGEST* d) {
	return unpack_BUFFER(ptr, d->digest, TPM_DIGEST_SIZE);
}

static
inline int unpack3_TPM_DIGEST(BYTE* ptr, UINT32* pos, UINT32 max, TPM_DIGEST* d) {
	return unpack3_BUFFER(ptr, pos, max, d->digest, TPM_DIGEST_SIZE);
}

#define sizeof_TPM_DIGEST(d) TPM_DIGEST_SIZE

#define pack_TPM_PCRVALUE(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_PCRVALUE(ptr, d) unpack_TPM_DIGEST(ptr, d)
#define unpack3_TPM_PCRVALUE(p...) unpack3_TPM_DIGEST(p)

#define pack_TPM_COMPOSITE_HASH(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_COMPOSITE_HASH(ptr, d) unpack_TPM_DIGEST(ptr, d)
#define unpack3_TPM_COMPOSITE_HASH(ptr, p, m, d) unpack3_TPM_DIGEST(ptr, p, m, d)
#define sizeof_TPM_COMPOSITE_HASH(d) TPM_DIGEST_SIZE

#define pack_TPM_DIRVALUE(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_DIRVALUE(ptr, d) unpack_TPM_DIGEST(ptr, d)

#define pack_TPM_HMAC(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_HMAC(ptr, d) unpack_TPM_DIGEST(ptr, d)

#define pack_TPM_CHOSENID_HASH(ptr, d) pack_TPM_DIGEST(ptr, d)
#define unpack_TPM_CHOSENID_HASH(ptr, d) unpack_TPM_DIGEST(ptr, d)

/* TODO keep these */
static
inline BYTE* pack_TPM_RQU_HEADER(BYTE* ptr,
		TPM_TAG tag,
		UINT32 size,
		TPM_COMMAND_CODE ord) {
	ptr = pack_UINT16(ptr, tag);
	ptr = pack_UINT32(ptr, size);
	return pack_UINT32(ptr, ord);
}

static
inline BYTE* unpack_TPM_RQU_HEADER(BYTE* ptr,
		TPM_TAG* tag,
		UINT32* size,
		TPM_COMMAND_CODE* ord) {
	ptr = unpack_UINT16(ptr, tag);
	ptr = unpack_UINT32(ptr, size);
	ptr = unpack_UINT32(ptr, ord);
	return ptr;
}

static
inline int unpack3_TPM_RQU_HEADER(BYTE* ptr, UINT32* pos, UINT32 max,
		TPM_TAG* tag, UINT32* size, TPM_COMMAND_CODE* ord) {
	return
		unpack3_UINT16(ptr, pos, max, tag) ||
		unpack3_UINT32(ptr, pos, max, size) ||
		unpack3_UINT32(ptr, pos, max, ord);
}

#define pack_TPM_RSP_HEADER(p, t, s, r) pack_TPM_RQU_HEADER(p, t, s, r)
#define unpack_TPM_RSP_HEADER(p, t, s, r) unpack_TPM_RQU_HEADER(p, t, s, r)
#define unpack3_TPM_RSP_HEADER(p, l, m, t, s, r) unpack3_TPM_RQU_HEADER(p, l, m, t, s, r)

/* TPM Helper Macros for common operations */
#define TCPA_MAX_BUFFER_LENGTH 0x2000

#define TPM_BEGIN_CMD(ord) \
	const TPM_COMMAND_CODE ordinal = ord; \
	TPM_RESULT status = TPM_SUCCESS; \
	BYTE _io_buffer[TCPA_MAX_BUFFER_LENGTH]; \
	UINT32 _io_bufsize_in; \
	UINT32 _io_bufsize_out; \
	do { \
		BYTE *in_buf = _io_buffer; \
		UINT32 in_pos = 6; \
		PACK_IN(UINT32, ordinal);

#define IN_PTR (in_buf + in_pos)

#define PACK_IN(type, item...) do { \
	UINT32 isize = sizeof_ ## type(item); \
	if (isize + in_pos > TCPA_MAX_BUFFER_LENGTH) { \
		status = TPM_SIZE; \
		goto abort_egress; \
	} \
	pack_ ## type (IN_PTR, item); \
	in_pos += isize; \
} while (0)

#define TPM_TAG_COMMON(req_tag) \
		_io_bufsize_in = in_pos; \
		pack_TPM_TAG(in_buf, req_tag); \
		pack_UINT32(in_buf + sizeof(TPM_TAG), in_pos); \
	} while (0); \
	_io_bufsize_out = TCPA_MAX_BUFFER_LENGTH; \
	status = TPM_TransmitData(_io_buffer, _io_bufsize_in, _io_buffer, &_io_bufsize_out); \
	if (status != TPM_SUCCESS) { \
		goto abort_egress; \
	} \
	do { \
		BYTE *out_buf = _io_buffer; \
		UINT32 out_pos = 0; \
		UINT32 out_len = _io_bufsize_out; \
		do { \
			TPM_TAG rsp_tag; \
			UINT32 rsp_len; \
			UINT32 rsp_status; \
			UNPACK_OUT(TPM_RSP_HEADER, &rsp_tag, &rsp_len, &rsp_status); \
			if (rsp_status != TPM_SUCCESS) { \
				status = rsp_status; \
				goto abort_egress; \
			} \
			if (rsp_tag != req_tag + 3 || rsp_len != out_len) { \
				status = TPM_FAIL; \
				goto abort_egress; \
			} \
		} while(0)

#define UNPACK_OUT(type, item...) do { \
		if (unpack3_ ## type (out_buf, &out_pos, TCPA_MAX_BUFFER_LENGTH, item)) { \
			status = TPM_SIZE; \
			goto abort_egress; \
		} \
	} while (0)

#define TPM_XMIT_REQ() \
	TPM_TAG_COMMON(TPM_TAG_RQU_COMMAND)

#define TPM_END() TPM_END_COMMON

#define TPM_END_COMMON \
		if (out_pos != out_len) { \
			status = TPM_SIZE; \
			goto abort_egress; \
		} \
	} while (0); \

/* TPM2 */

// Table 212 -- Logic Values
#define    YES      1
#define    NO       0
#ifndef    TRUE
#define    TRUE     1
#endif
#ifndef    FALSE
#define    FALSE    0
#endif
#ifndef    true
#define    true     1
#endif
#ifndef    false
#define    false    0
#endif
#define    SET      1
#define    CLEAR    0


// Table 214 -- Implemented Algorithms
#define    ALG_SHA1              YES
#define    ALG_HMAC              NO
#define    ALG_SHA256            YES
#define    ALG_SHA384            NO
#define    ALG_SHA512            YES

#define HASH_COUNT (ALG_SHA1+ALG_SHA256+ALG_SHA384+ALG_SHA512)

// TPM2 command code
typedef UINT32 TPM_CC;
#define    TPM_CC_FIRST                         (TPM_CC)(0x0000011F)
#define    TPM_CC_PP_FIRST                      (TPM_CC)(0x0000011F)
#define    TPM_CC_Clear                         (TPM_CC)(0x00000126)
#define    TPM_CC_ClockSet                      (TPM_CC)(0x00000128)
#define    TPM_CC_PCR_SetAuthPolicy             (TPM_CC)(0x0000012C)
#define    TPM_CC_PCR_Event                     (TPM_CC)(0x0000013C)
#define    TPM_CC_PCR_Reset                     (TPM_CC)(0x0000013D)
#define    TPM_CC_Startup                       (TPM_CC)(0x00000144)
#define    TPM_CC_Shutdown                      (TPM_CC)(0x00000145)
#define    TPM_CC_Duplicate                     (TPM_CC)(0x0000014B)
#define    TPM_CC_GetTime                       (TPM_CC)(0x0000014C)
#define    TPM_CC_GetSessionAuditDigest         (TPM_CC)(0x0000014D)
#define    TPM_CC_Create                        (TPM_CC)(0x00000153)
#define    TPM_CC_Load                          (TPM_CC)(0x00000157)
#define    TPM_CC_HMAC_Start                    (TPM_CC)(0x0000015B)
#define    TPM_CC_GetCapability                 (TPM_CC)(0x0000017A)
#define    TPM_CC_GetRandom                     (TPM_CC)(0x0000017B)
#define    TPM_CC_GetTestResult                 (TPM_CC)(0x0000017C)
#define    TPM_CC_Hash                          (TPM_CC)(0x0000017D)
#define    TPM_CC_PCR_Read                      (TPM_CC)(0x0000017E)
#define    TPM_CC_PCR_Extend                    (TPM_CC)(0x00000182)
#define    TPM_CC_PCR_SetAuthValue              (TPM_CC)(0x00000183)
#define    TPM_CC_LAST                          (TPM_CC)(0x0000018D)

//TPM_RC
typedef UINT32 TPM_RC;

// TPM_ST Constants
typedef UINT16 TPM_ST;
#define    TPM_ST_NULL                    (TPM_ST)(0X8000)
#define    TPM_ST_NO_SESSIONS             (TPM_ST)(0x8001)
#define    TPM_ST_SESSIONS                (TPM_ST)(0x8002)

// TPM Handle types
typedef UINT32 TPM2_HANDLE;
typedef UINT8 TPM_HT;

// TPM_RH Constants
typedef UINT32 TPM_RH;

#define    TPM_RH_FIRST          (TPM_RH)(0x40000000)
#define    TPM_RH_SRK            (TPM_RH)(0x40000000)
#define    TPM_RH_OWNER          (TPM_RH)(0x40000001)
#define    TPM_RS_PW             (TPM_RH)(0x40000009)
#define    TPM_RH_LOCKOUT        (TPM_RH)(0x4000000A)
#define    TPM_RH_ENDORSEMENT    (TPM_RH)(0x4000000B)
#define    TPM_RH_PLATFORM       (TPM_RH)(0x4000000C)
#define    TPM_RH_LAST           (TPM_RH)(0x4000000C)

// Table 4 -- DocumentationClarity Types <I/O>
typedef UINT32    TPM_MODIFIER_INDICATOR;
typedef UINT32    TPM_SESSION_OFFSET;
typedef UINT64    TPM_SYSTEM_ADDRESS;
typedef UINT32    TPM_SPEC;

typedef UINT32 TPMA_OBJECT;
typedef BYTE TPMA_SESSION;
typedef BYTE TPMA_LOCALITY;

// Table 37 -- TPMI_YES_NO Type <I/O>
typedef BYTE TPMI_YES_NO;

// Table 42 -- TPMI_SH_AUTH_SESSION Type <I/O>
typedef TPM2_HANDLE TPMI_SH_AUTH_SESSION;

// Table 7 -- TPM_ALG_ID
typedef UINT16 TPM_ALG_ID;

#define    TPM2_ALG_ERROR             (TPM_ALG_ID)(0x0000) // a: ; D:
#define    TPM2_ALG_FIRST             (TPM_ALG_ID)(0x0001) // a: ; D:
#define    TPM2_ALG_SHA1              (TPM_ALG_ID)(0x0004) // a: H; D:
#define    TPM2_ALG_HMAC              (TPM_ALG_ID)(0x0005) // a: H X; D:
#define    TPM2_ALG_SHA256            (TPM_ALG_ID)(0x000B) // a: H; D:
#define    TPM2_ALG_NULL              (TPM_ALG_ID)(0x0010) // a: ; D:
#define    TPM2_ALG_LAST              (TPM_ALG_ID)(0x0044)

#define    SHA1_DIGEST_SIZE      20
#define    SHA1_BLOCK_SIZE       64
#define    SHA256_DIGEST_SIZE    32
#define    SHA256_BLOCK_SIZE     64

// Table 57 -- TPMI_ALG_ASYM Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_ASYM;

// Table 56 -- TPMI_ALG_HASH Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_HASH;

// Table 58 -- TPMI_ALG_SYM Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM;

// Table 59 -- TPMI_ALG_SYM_OBJECT Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;

// Table 60 -- TPMI_ALG_SYM_MODE Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;

// Table 65 -- TPMU_HA Union <I/O,S>
typedef union {
#ifdef TPM2_ALG_SHA1
    BYTE  sha1[SHA1_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_SHA256
    BYTE  sha256[SHA256_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_SM3_256
    BYTE  sm3_256[SM3_256_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_SHA384
    BYTE  sha384[SHA384_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_SHA512
    BYTE  sha512[SHA512_DIGEST_SIZE];
#endif
#ifdef TPM2_ALG_WHIRLPOOL512
    BYTE  whirlpool[WHIRLPOOL512_DIGEST_SIZE];
#endif

} TPMU_HA;

// Table 67 -- TPM2B_DIGEST Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPMU_HA)];
} TPM2B_DIGEST;

// Table 69 -- TPM2B_NONCE Types <I/O>
typedef TPM2B_DIGEST    TPM2B_NONCE;

typedef TPM2B_DIGEST    TPM2B_DATA;

// Table 70 -- TPM2B_AUTH Types <I/O>
typedef TPM2B_DIGEST    TPM2B_AUTH;

// Table 71 -- TPM2B_OPERAND Types <I/O>
typedef TPM2B_DIGEST    TPM2B_OPERAND;

// Table 66 -- TPMT_HA Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
    TPMU_HA          digest;
} TPMT_HA;

//Table 80 -- TPM2B_NAME Structure
typedef struct {
    UINT16 size;
    BYTE name[sizeof(TPMT_HA)];
} TPM2B_NAME;

#define    IMPLEMENTATION_PCR   24
#define    PLATFORM_PCR         24
#define    PCR_SELECT_MAX       ((IMPLEMENTATION_PCR+7)/8)
#define    PCR_SELECT_NUM(x)    (uint8_t)(x/8)
#define    PCR_SELECT_VALUE(x)  (uint8_t)(0x1)<<(x%8)

// Table 80 -- TPMS_PCR_SELECTION Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hash;
    UINT8            sizeofSelect;
    BYTE             pcrSelect[PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

// Table 96 -- Definition of TPML_DIGEST Structure <I/O>
typedef struct {
    UINT32               count;
    TPM2B_DIGEST         digests[8];
} TPML_DIGEST;

// Table 97 -- TPML_PCR_SELECTION Structure <I/O>
typedef struct {
    UINT32                count;
    TPMS_PCR_SELECTION    pcrSelections[HASH_COUNT];
} TPML_PCR_SELECTION;

#define pack_TPM_BUFFER(ptr, buf, size) pack_BUFFER(ptr, buf, size)
#define unpack_TPM_BUFFER(ptr, buf, size) unpack_BUFFER(ptr, buf, size)

#define pack_TPMA_OBJECT(ptr, t)                pack_UINT32(ptr, (UINT32)(*t))
#define unpack_TPMA_OBJECT(ptr, t)              unpack_UINT32(ptr, (UINT32 *)(t))
#define pack_TPM_RH(ptr, t)                     pack_UINT32(ptr, (UINT32)(*t))
#define unpack_TPM_RH(ptr, t)                   unpack_UINT32(ptr, (UINT32 *)(t))
#define pack_TPMA_LOCALITY(ptr, locality)       pack_BYTE(ptr, (BYTE)*locality)
#define unpack_TPMA_LOCALITY(ptr, locality)     unpack_BYTE(ptr, (BYTE *)locality)
#define pack_TPM_ST(ptr, tag)                   pack_UINT16(ptr, *tag)
#define unpack_TPM_ST(ptr, tag)                 unpack_UINT16(ptr, tag)
#define pack_TPM_KEY_BITS(ptr, t)               pack_UINT16(ptr, *t)
#define unpack_TPM_KEY_BITS(ptr, t)             unpack_UINT16(ptr, t)
#define pack_TPMI_AES_KEY_BITS(ptr, t)          pack_TPM_KEY_BITS(ptr, t)
#define unpack_TPMI_AES_KEY_BITS(ptr, t)        unpack_TPM_KEY_BITS(ptr, t)
#define pack_TPMI_RSA_KEY_BITS(ptr, t)          pack_TPM_KEY_BITS(ptr, t)
#define unpack_TPMI_RSA_KEY_BITS(ptr, t)        unpack_TPM_KEY_BITS(ptr, t)
#define pack_TPM_ALG_ID(ptr, id)                pack_UINT16(ptr, *id)
#define unpack_TPM_ALG_ID(ptr, id)              unpack_UINT16(ptr, id)
#define pack_TPM_ALG_SYM(ptr, t)                pack_TPM_ALG_ID(ptr, t)
#define unpack_TPM_ALG_SYM(ptr, t)              unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_ALG_ASYM(ptr, asym)           pack_TPM_ALG_ID(ptr, asym)
#define unpack_TPMI_ALG_ASYM(ptr, asym)         unpack_TPM_ALG_ID(ptr, asym)
#define pack_TPMI_ALG_SYM_OBJECT(ptr, t)        pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_SYM_OBJECT(ptr, t)      unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_ALG_SYM_MODE(ptr, t)          pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_SYM_MODE(ptr, t)        unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_ALG_KDF(ptr, t)               pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_KDF(ptr, t)             unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_ALG_PUBLIC(ptr, t)            pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_PUBLIC(ptr, t)          unpack_TPM_ALG_ID(ptr, t)
#define pack_TPM2_HANDLE(ptr, h)                pack_UINT32(ptr, *h)
#define unpack_TPM2_HANDLE(ptr, h)              unpack_UINT32(ptr, h)
#define pack_TPMI_ALG_RSA_SCHEME(ptr, t)        pack_TPM_ALG_ID(ptr, t)
#define unpack_TPMI_ALG_RSA_SCHEME(ptr, t)      unpack_TPM_ALG_ID(ptr, t)
#define pack_TPMI_DH_OBJECT(ptr, o)             pack_TPM2_HANDLE(ptr, o)
#define unpack_TPMI_DH_OBJECT(PTR, O)           unpack_TPM2_HANDLE(ptr, o)
#define pack_TPMI_RH_HIERACHY(ptr, h)           pack_TPM2_HANDLE(ptr, h)
#define unpack_TPMI_RH_HIERACHY(ptr, h)         unpack_TPM2_HANDLE(ptr, h)
#define pack_TPMI_RH_PLATFORM(ptr, p)           pack_TPM2_HANDLE(ptr, p)
#define unpack_TPMI_RH_PLATFORM(ptr, p)         unpack_TPM2_HANDLE(ptr, p)
#define pack_TPMI_RH_OWNER(ptr, o)              pack_TPM2_HANDLE(ptr, o)
#define unpack_TPMI_RH_OWNER(ptr, o)            unpack_TPM2_HANDLE(ptr, o)
#define pack_TPMI_RH_ENDORSEMENT(ptr, e)        pack_TPM2_HANDLE(ptr, e)
#define unpack_TPMI_RH_ENDORSEMENT(ptr, e)      unpack_TPM2_HANDLE(ptr, e)
#define pack_TPMI_RH_LOCKOUT(ptr, l)            pack_TPM2_HANDLE(ptr, l)
#define unpack_TPMI_RH_LOCKOUT(ptr, l)          unpack_TPM2_HANDLE(ptr, l)

/* TPM Helper Macros for common operations */
#define TCPA_MAX_BUFFER_LENGTH 0x2000

#define TPM_BEGIN(TAG, ORD) \
    const TPM_TAG intag = TAG;\
    TPM_TAG tag = intag;\
    UINT32 paramSize;\
    const TPM_COMMAND_CODE ordinal = ORD;\
    TPM_RESULT status = TPM_SUCCESS;\
    BYTE in_buf[TCPA_MAX_BUFFER_LENGTH];\
    BYTE out_buf[TCPA_MAX_BUFFER_LENGTH];\
    UINT32 out_len = sizeof(out_buf);\
    BYTE* ptr = in_buf;\
    /* Pack the header*/\
    ptr = pack_TPM_TAG(ptr, tag);\
    ptr += sizeof(UINT32);\
    ptr = pack_TPM_COMMAND_CODE(ptr, ordinal)\

#define TPM_TRANSMIT() do {\
    /* Pack the command size */\
    paramSize = ptr - in_buf;\
    pack_UINT32(in_buf + sizeof(TPM_TAG), paramSize);\
    if ((status = TPM_TransmitData(in_buf, paramSize, out_buf, &out_len)) != TPM_SUCCESS) {\
        goto abort_egress;\
    }\
} while(0)

#include "tpm_extend.h"
#define TPM_AUTH2_VERIFY(HMACkey, auth) do {\
    ptr = unpack_TPM_AUTH_SESSION(ptr, auth);\
    if ((status = verifyAuth(&paramDigest, HMACkey, auth)) != TPM_SUCCESS) {\
        goto abort_egress;\
    }\
} while(0)

#define TPM_UNPACK_VERIFY() do { \
    ptr = out_buf;\
    ptr = unpack_TPM_RSP_HEADER(ptr, \
          &(tag), &(paramSize), &(status));\
    if ((status) != TPM_SUCCESS){ \
        goto abort_egress;\
    }\
} while(0)

#endif
