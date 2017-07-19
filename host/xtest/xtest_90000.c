/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Sigma Designs Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Author:  Tony He <tony_he@sigmadesigns.com>
 * Date:    2017/07/14
 *
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <malloc.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <tee_api_types.h>
#include <ta_teex.h>
#include <utee_defines.h>
#include <util.h>

#include <nist/186-2ecdsatestvectors.h>

#include <assert.h>

/* refer to tee_umap_attr */
#define XTEST_MAP_ATTR_CACHED	1
#define XTEST_MAP_ATTR_GLOBAL	(1 << 3)
#define XTEST_MAP_ATTR_SECURE	(1 << 4)

/* refer to tee_umap_prot */
#define XTEST_MAP_PROT_READ	1
#define XTEST_MAP_PROT_WRITE	(1 << 1)
#define XTEST_MAP_PROT_EXEC	(1 << 2)

static void xtest_tee_test_90001(ADBG_Case_t *Case_p);
static void xtest_tee_test_90002(ADBG_Case_t *Case_p);
static void xtest_tee_test_90003(ADBG_Case_t *Case_p);
static void xtest_tee_test_90004(ADBG_Case_t *Case_p);
static void xtest_tee_test_90005(ADBG_Case_t *Case_p);
static void xtest_tee_test_90006(ADBG_Case_t *Case_p);
static void xtest_tee_test_90007(ADBG_Case_t *Case_p);
static void xtest_tee_test_90008(ADBG_Case_t *Case_p);
static void xtest_tee_test_90009(ADBG_Case_t *Case_p);

ADBG_CASE_DEFINE(XTEST_TEE_90001, xtest_tee_test_90001,
		"Test TEE extension APIs Mmap/Munmap - generic");
ADBG_CASE_DEFINE(XTEST_TEE_90002, xtest_tee_test_90002,
		"Test TEE extension APIs Mmap/Munmap - stress");
ADBG_CASE_DEFINE(XTEST_TEE_90003, xtest_tee_test_90003,
		"Test TEE extension APIs Mmap/Munmap - accessible");
ADBG_CASE_DEFINE(XTEST_TEE_90004, xtest_tee_test_90004,
		"Test TEE extension API OtpWrite");
ADBG_CASE_DEFINE(XTEST_TEE_90005, xtest_tee_test_90005,
		"Test TEE extension API MemState");
ADBG_CASE_DEFINE(XTEST_TEE_90006, xtest_tee_test_90006,
		"Test TEE extension API KLGenerateKey - cipher operations with user key");
ADBG_CASE_DEFINE(XTEST_TEE_90007, xtest_tee_test_90007,
		"Test TEE extension API KLGenerateKey - consistancy");
ADBG_CASE_DEFINE(XTEST_TEE_90008, xtest_tee_test_90008,
		"Test TEE extension API KLGenerateKey - uniqueness");
ADBG_CASE_DEFINE(XTEST_TEE_90009, xtest_tee_test_90009,
		"Test TEE extension API KLGenerateKey - TSP key");

static TEE_Result ta_crypt_cmd_mmap(ADBG_Case_t *c,
				    TEEC_Session *s,
				    paddr_t pa,
				    size_t len,
				    uint32_t prot,
				    uint32_t attr,
				    void **va)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	assert((uintptr_t)pa <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)pa;
	assert(len <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)len;

	op.params[1].value.a = prot;
	op.params[1].value.b = attr;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_MMAP, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	} else {
		assert(va != NULL);
		*(uint32_t*)va = op.params[0].value.a;
	}
	return res;
}

static TEE_Result ta_crypt_cmd_munmap(ADBG_Case_t *c,
				      TEEC_Session *s,
				      void *va,
				      size_t len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	assert((uintptr_t)va <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)va;
	assert(len <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_MUNMAP, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	}

	return res;
}

static TEE_Result ta_crypt_cmd_access(ADBG_Case_t *c,
				      TEEC_Session *s,
				      paddr_t pa,
				      size_t len,
				      void *buf,
				      uint32_t attr,
				      uint32_t prot)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	assert((uintptr_t)pa <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)pa;
	assert(len <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)len;

	op.params[1].value.a = attr;	/* attributes */
	op.params[1].value.b = prot;	/* prot */

	assert((uintptr_t)buf <= UINT32_MAX);
	op.params[2].tmpref.buffer = buf;
	op.params[2].tmpref.size = len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INOUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_ACCESS, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	}

	return res;
}

static TEE_Result ta_crypt_cmd_otpwrite(ADBG_Case_t *c,
					TEEC_Session *s,
					uint32_t id,
					uint32_t prot,
					void *buf,
					size_t *plen)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = id;
	op.params[0].value.b = prot;

	assert((uintptr_t)buf <= UINT32_MAX);
	op.params[1].tmpref.buffer = buf;
	assert(plen != NULL && (uint32_t)*plen <= UINT32_MAX);
	op.params[1].tmpref.size = *plen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_OTPWRITE, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	} else {
		*plen = op.params[0].value.a;
	}

	return res;
}

static TEE_Result ta_crypt_cmd_memstate(ADBG_Case_t *c,
					TEEC_Session *s,
					paddr_t pa,
					size_t len,
					uint32_t *pstate)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	assert((uintptr_t)pa <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)pa;
	assert(len <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_MEMSTATE, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	} else {
		assert(pstate != NULL);
		*pstate = op.params[0].value.a;
	}

	return res;
}

static TEE_Result ta_crypt_cmd_set_operation_key2(ADBG_Case_t *c,
						  TEEC_Session *s,
						  TEE_OperationHandle oph,
						  TEE_ObjectHandle key1,
						  TEE_ObjectHandle key2)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	assert((uintptr_t)key1 <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)(uintptr_t)key1;

	assert((uintptr_t)key2 <= UINT32_MAX);
	op.params[1].value.a = (uint32_t)(uintptr_t)key2;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_SET_OPERATION_KEY2, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_cipher_init(ADBG_Case_t *c, TEEC_Session *s,
					    TEE_OperationHandle oph,
					    const void *iv, size_t iv_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	if (iv != NULL) {
		op.params[1].tmpref.buffer = (void *)iv;
		op.params[1].tmpref.size = iv_len;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);
	} else {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
	}

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_CIPHER_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_cipher_update(ADBG_Case_t *c, TEEC_Session *s,
					      TEE_OperationHandle oph,
					      const void *src, size_t src_len,
					      void *dst, size_t *dst_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_CIPHER_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_cipher_do_final(ADBG_Case_t *c,
						TEEC_Session *s,
						TEE_OperationHandle oph,
						const void *src,
						size_t src_len,
						void *dst,
						size_t *dst_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_CIPHER_DO_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_kl_generate_key(ADBG_Case_t *c,
						TEEC_Session *s,
						TEE_ObjectHandle o,
						uint32_t key_size,
						const TEE_Attribute *params,
						uint32_t paramCount)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	uint8_t *buf;
	size_t blen;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return res;

	assert((uintptr_t)o <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)o;
	op.params[0].value.b = key_size;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_KL_GENERATE_KEY, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	free(buf);
	return res;
}

static TEEC_Result ta_crypt_cmd_kl_generate_tsp_key(ADBG_Case_t *c,
						TEEC_Session *s,
						uint32_t index,
						uint32_t eo,
						uint32_t datum)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = index;
	op.params[0].value.b = eo;
	op.params[1].value.a = datum;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_TEEX_CMD_KL_GENERATE_TSP_KEY, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

#define XTEST_UMAP_CASE(pa, len, prot, attr, pa2, len2, prot2, attr2)	\
	{pa, len, prot, attr, TEEC_SUCCESS, pa2, len2, prot2, attr2, TEEC_SUCCESS, 0, __LINE__}

#define XTEST_UMAP_NC_CASE(pa, len, prot, attr)	\
	{pa, len, prot, (attr) & ~XTEST_MAP_ATTR_CACHED, TEEC_SUCCESS, 0, 0, 0, 0, 0, 0, __LINE__}

#define XTEST_UMAP_C_CASE(pa, len, prot, attr)	\
	{pa, len, prot, (attr) | XTEST_MAP_ATTR_CACHED, TEEC_SUCCESS, 0, 0, 0, 0, 0, 0, __LINE__}

#define XTEST_UMAP_NS_CASE(pa, len, prot, attr)	\
	{pa, len, prot, (attr) & ~XTEST_MAP_ATTR_SECURE, TEEC_SUCCESS, 0, 0, 0, 0, 0, 0, __LINE__}

#define XTEST_UMAP_S_CASE(pa, len, prot, attr)	\
	{pa, len, prot, (attr) | XTEST_MAP_ATTR_SECURE, TEEC_SUCCESS, 0, 0, 0, 0, 0, 0, __LINE__}

#define XTEST_UMAP_NG_CASE(pa, len, prot, attr)	\
	{pa, len, prot, (attr) & ~XTEST_MAP_ATTR_GLOBAL, TEEC_SUCCESS, 0, 0, 0, 0, 0, 0, __LINE__}

#define XTEST_UMAP_G_CASE(pa, len, prot, attr)	\
	{pa, len, prot, (attr) | XTEST_MAP_ATTR_GLOBAL, TEEC_SUCCESS, 0, 0, 0, 0, 0, 0, __LINE__}

#define XTEST_UMAP_NOK_CASE(pa, len, prot, attr)\
	{pa, len, prot, attr, TEEC_SUCCESS, 0, 0, 0, 0, 0, 1, __LINE__}

struct xtest_umap_case {
	uint32_t pa;
	size_t len;
	uint32_t prot;
	uint32_t attr;
	uint32_t res;
	uint32_t pa2;
	size_t len2;
	uint32_t prot2;
	uint32_t attr2;
	uint32_t res2;
	uint32_t nok;
	uint32_t line;
};

static struct xtest_umap_case umap_cases[] =
{
	XTEST_UMAP_NC_CASE(0, 0x10000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NC_CASE(0, 0x10000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NC_CASE(0, 0x12, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NC_CASE(0, 0x12, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NC_CASE(0, 0x1000000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NC_CASE(0, 0x1000000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_C_CASE(0, 0x2000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_C_CASE(0, 0x2000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_C_CASE(0, 0x12, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_C_CASE(0, 0x12, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_C_CASE(0, 0x1000000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_C_CASE(0, 0x1000000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NS_CASE(0xf000000, 0x10000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NS_CASE(0xf000000, 0x10000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NS_CASE(0xf000000, 0x12, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NS_CASE(0xf000000, 0x12, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NS_CASE(0xf000000, 0x1000000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NS_CASE(0xf000000, 0x1000000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_S_CASE(0xf000000, 0x2000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_S_CASE(0xf000000, 0x2000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_S_CASE(0xf000000, 0x12, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_S_CASE(0xf000000, 0x12, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_S_CASE(0xf000000, 0x1000000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_S_CASE(0xf000000, 0x1000000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NG_CASE(0x3f000000, 0x10000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NG_CASE(0x3f000000, 0x10000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NG_CASE(0x3f000000, 0x12, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NG_CASE(0x3f000000, 0x12, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NG_CASE(0x3f000000, 0x1000000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NG_CASE(0x3f000000, 0x1000000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_G_CASE(0x3f000000, 0x2000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_G_CASE(0x3f000000, 0x2000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_G_CASE(0x3f000000, 0x12, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_G_CASE(0x3f000000, 0x12, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_G_CASE(0x3f000000, 0x1000000, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_G_CASE(0x3f000000, 0x1000000, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),

	XTEST_UMAP_NG_CASE(0x3f000000, 0xa0001, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, XTEST_MAP_ATTR_SECURE | XTEST_MAP_ATTR_CACHED),
	XTEST_UMAP_G_CASE(0x3f000000, 0xa0001, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, XTEST_MAP_ATTR_SECURE | XTEST_MAP_ATTR_CACHED),

	XTEST_UMAP_CASE(0x1000, 0x205, XTEST_MAP_PROT_READ, 0, 0x1000, 0x205, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_CASE(0x1000, 0x205, XTEST_MAP_PROT_READ, 0, 0x1000, 0x205, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, XTEST_MAP_ATTR_CACHED),
	XTEST_UMAP_CASE(0x1000, 0x205, XTEST_MAP_PROT_READ, 0, 0x20000000, 0x100001, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, XTEST_MAP_ATTR_CACHED),

	/* I/O */
	XTEST_UMAP_NOK_CASE(0xf0000000, 0x1001, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NOK_CASE(0xf0000000, 0x1001, XTEST_MAP_PROT_READ, XTEST_MAP_ATTR_SECURE),
	XTEST_UMAP_NOK_CASE(0xffff0000, 0x2003, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NOK_CASE(0xffff0000, 0x2003, XTEST_MAP_PROT_READ, XTEST_MAP_ATTR_SECURE),

	/* share memory */
	XTEST_UMAP_NOK_CASE(0x10000000, 0x100007, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NOK_CASE(0x10000000, 0x100007, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, XTEST_MAP_ATTR_CACHED | XTEST_MAP_ATTR_SECURE),

	/* tee memory */
	XTEST_UMAP_NOK_CASE(0x10200000, 0x100007, XTEST_MAP_PROT_READ, 0),
	XTEST_UMAP_NOK_CASE(0x10200000, 0x100007, XTEST_MAP_PROT_READ, XTEST_MAP_ATTR_SECURE),
	XTEST_UMAP_NOK_CASE(0x10f00000, 0xc000d, XTEST_MAP_PROT_READ | XTEST_MAP_PROT_WRITE, 0),
	XTEST_UMAP_NOK_CASE(0x10f00000, 0xc000d, XTEST_MAP_PROT_WRITE, XTEST_MAP_ATTR_SECURE),
};

static void xtest_tee_test_90001(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	void *va, *va2;
	uint32_t pa, prot, attr;
	size_t size, size2;
	size_t n;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(umap_cases); n++) {
		Do_ADBG_BeginSubCase(c, "Umap case %d line %d",
				     (int)n, (int)umap_cases[n].line);

		va = va2 = NULL;
		pa = umap_cases[n].pa;
		size = umap_cases[n].len;
		prot = umap_cases[n].prot;
		attr = umap_cases[n].attr;

		if (umap_cases[n].nok) {
			if (!ADBG_EXPECT_NOT(c, TEEC_SUCCESS,
				ta_crypt_cmd_mmap(c, &session,
				pa, size, prot, attr, &va)) ||
			    !ADBG_EXPECT_POINTER(c, NULL, va))
				goto out;

			if (umap_cases[n].len2 != 0) {
				pa = umap_cases[n].pa2;
				size = umap_cases[n].len2;
				prot = umap_cases[n].prot2;
				attr = umap_cases[n].attr2;

				if (!ADBG_EXPECT_NOT(c, TEEC_SUCCESS,
					ta_crypt_cmd_mmap(c, &session,
					pa, size, prot, attr, &va2)) ||
				    !ADBG_EXPECT_POINTER(c, NULL, va2))
					goto out;
			}
		} else {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_mmap(c, &session,
				pa, size, prot, attr, &va)) ||
			    !ADBG_EXPECT_NOT_NULL(c, va))
				goto out;

			if (umap_cases[n].len2 != 0) {
				pa = umap_cases[n].pa2;
				size2 = umap_cases[n].len2;
				prot = umap_cases[n].prot2;
				attr = umap_cases[n].attr2;

				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_mmap(c, &session,
					pa, size2, prot, attr, &va2)) ||
				    !ADBG_EXPECT_NOT_NULL(c, va2))
					goto out;

				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_munmap(c, &session,
						va2, size2)))
					goto out;
			}

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_munmap(c, &session,
					va, size)))
				goto out;
		}

		Do_ADBG_EndSubCase(c, NULL);
	}

out:
	TEEC_CloseSession(&session);
}

static void xtest_tee_test_90002(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	void *va, *va2;
	uint32_t pa, prot, attr;
	size_t size, size2;
	size_t n, k;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(umap_cases); n++) {
		Do_ADBG_BeginSubCase(c, "Umap stress case %d line %d",
				     (int)n, (int)umap_cases[n].line);

		if (umap_cases[n].nok)
			goto next;

		va = va2 = NULL;
		pa = umap_cases[n].pa;
		size = umap_cases[n].len;
		prot = umap_cases[n].prot;
		attr = umap_cases[n].attr;

		/* repeat 1000 times for each */
		for (k = 0; k < 1000; k++) {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_mmap(c, &session,
				pa, size, prot, attr, &va)) ||
			    !ADBG_EXPECT_NOT_NULL(c, va))
				goto out;

			if (umap_cases[n].len2 != 0) {
				pa = umap_cases[n].pa2;
				size2 = umap_cases[n].len2;
				prot = umap_cases[n].prot2;
				attr = umap_cases[n].attr2;

				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_mmap(c, &session,
					pa, size2, prot, attr, &va2)) ||
				    !ADBG_EXPECT_NOT_NULL(c, va2))
					goto out;

				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_munmap(c, &session,
						va2, size2)))
					goto out;
			}

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_munmap(c, &session,
					va, size)))
				goto out;
		}
next:
		Do_ADBG_EndSubCase(c, NULL);
	}

out:
	TEEC_CloseSession(&session);
}

/* RW 4k@UMAP_RW_ADDR */
#ifdef CFG_UMAP_RW_ADDR
#define UMAP_RW_ADDR CFG_UMAP_RW_ADDR
#else
#define UMAP_RW_ADDR 0xE000000	/*Video Codec buffer*/
#endif

struct xtest_umap_rw_case {
	uint32_t pa;
	size_t len;
	uint32_t attr;
	uint32_t line;
};

#define XTEST_UMAP_RW_CASE(pa, len, at)	\
	{pa, len, at, __LINE__}
static struct xtest_umap_rw_case umap_rw_cases[] =
{
	XTEST_UMAP_RW_CASE(UMAP_RW_ADDR, 0x1000, 0),
	XTEST_UMAP_RW_CASE(UMAP_RW_ADDR, 0x1000, XTEST_MAP_ATTR_CACHED),
	XTEST_UMAP_RW_CASE(UMAP_RW_ADDR, 0x1000, XTEST_MAP_ATTR_SECURE),
	XTEST_UMAP_RW_CASE(UMAP_RW_ADDR, 0x1000, XTEST_MAP_ATTR_GLOBAL),
};

static void xtest_tee_test_90003(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	uint32_t pa, attr;
	size_t size;
	size_t n, k;
	uint8_t *buf1 = NULL, *buf2 = NULL;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(umap_rw_cases); n++) {
		Do_ADBG_BeginSubCase(c, "Umap r/w case %d line %d",
				     (int)n, (int)umap_rw_cases[n].line);

		pa = umap_rw_cases[n].pa;
		size = umap_rw_cases[n].len;
		attr = umap_rw_cases[n].attr;

		if (!(buf1 = malloc(size))) {
			Do_ADBG_Log("malloc buf failed");
			goto out;
		}

		if (!(buf2 = malloc(size))) {
			Do_ADBG_Log("malloc buf2 failed");
			goto out;
		}

		/* init buffer */
		memset(buf2, 0, size);
		for (k = 0; k < size; k++) {
			buf1[k] = (((size - k - n - 1) & 7) << 4) | ((k + n) & 7);
		}

		/* write */
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_access(c, &session,
			pa, size, buf1, attr, XTEST_MAP_PROT_WRITE)))
			goto out;

		/* read */
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_access(c, &session,
			pa, size, buf2, attr, XTEST_MAP_PROT_READ)))
			goto out;

		(void)ADBG_EXPECT_BUFFER(c, buf1,
					 size, buf2, size);

		free(buf1); buf1 = NULL;
		free(buf2); buf2 = NULL;

		Do_ADBG_EndSubCase(c, NULL);
	}

out:
	if (buf1 != NULL)
		free(buf1);
	if (buf2 != NULL)
		free(buf2);
	TEEC_CloseSession(&session);
}

/* refer to tee_otp_id */
#define XTEST_OTP_KEY_0		0
#define XTEST_OTP_KEY_1		1
#define XTEST_OTP_KEY_2		2
#define XTEST_OTP_KEY_3		3
#define XTEST_OTP_KEY_4		4
#define XTEST_OTP_KEY_5		5
#define XTEST_OTP_KEY_RSA	6

/* refer to tee_otp_prot */
#define XTEST_OTP_PROT_NONE	0
#define XTEST_OTP_PROT_NRD	1
#define XTEST_OTP_PROT_NWR	2
#define XTEST_OTP_PROT_NRDWR	3

struct xtest_otp_case {
	uint32_t id;
	uint32_t prot;
	bool nok;
	uint32_t line;
};

#define XTEST_OTP_SELFTEST	(1 << 31)	/* refer to TEE_OTP_PROT_SELFTEST */
#define XTEST_OTP_CASE(id, prot)	\
	{id, (prot) | XTEST_OTP_SELFTEST, false, __LINE__}

#define XTEST_OTP_NOK_CASE(id, prot)	\
	{id, (prot) | XTEST_OTP_SELFTEST, true, __LINE__}

static struct xtest_otp_case otp_cases[] =
{
	XTEST_OTP_CASE(XTEST_OTP_KEY_0, XTEST_OTP_PROT_NONE),
	XTEST_OTP_CASE(XTEST_OTP_KEY_0, XTEST_OTP_PROT_NRDWR),
	XTEST_OTP_CASE(XTEST_OTP_KEY_1, XTEST_OTP_PROT_NONE),
	XTEST_OTP_CASE(XTEST_OTP_KEY_1, XTEST_OTP_PROT_NRDWR),
	XTEST_OTP_CASE(XTEST_OTP_KEY_2, XTEST_OTP_PROT_NONE),
	XTEST_OTP_CASE(XTEST_OTP_KEY_2, XTEST_OTP_PROT_NRDWR),
	XTEST_OTP_CASE(XTEST_OTP_KEY_3, XTEST_OTP_PROT_NONE),
	XTEST_OTP_CASE(XTEST_OTP_KEY_3, XTEST_OTP_PROT_NRDWR),
	XTEST_OTP_CASE(XTEST_OTP_KEY_4, XTEST_OTP_PROT_NONE),
	XTEST_OTP_CASE(XTEST_OTP_KEY_4, XTEST_OTP_PROT_NRDWR),
	XTEST_OTP_CASE(XTEST_OTP_KEY_5, XTEST_OTP_PROT_NONE),
	XTEST_OTP_CASE(XTEST_OTP_KEY_5, XTEST_OTP_PROT_NRDWR),
	XTEST_OTP_CASE(XTEST_OTP_KEY_RSA, XTEST_OTP_PROT_NONE),
	XTEST_OTP_CASE(XTEST_OTP_KEY_RSA, XTEST_OTP_PROT_NRDWR),

	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_0, 0x4),
	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_1, 0x5),
	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_2, 0x8),
	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_3, 0xa),
	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_4, 0xc),
	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_5, 0xe),
	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_RSA, 0xf),
	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_0 - 1, XTEST_OTP_PROT_NONE),
	XTEST_OTP_NOK_CASE(XTEST_OTP_KEY_RSA + 1, XTEST_OTP_PROT_NONE),
};

static void xtest_tee_test_90004(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	uint8_t buf[16];
	size_t n, len;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(otp_cases); n++) {
		Do_ADBG_BeginSubCase(c, "otp case %d line %d",
				     (int)n, (int)otp_cases[n].line);

		memset(buf, 0, sizeof(buf));
		len = sizeof(buf);
		if (otp_cases[n].nok) {
			if (!ADBG_EXPECT_NOT(c, TEEC_SUCCESS,
				ta_crypt_cmd_otpwrite(c, &session,
				otp_cases[n].id, otp_cases[n].prot, buf, &len)))
				goto out;
		} else {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_otpwrite(c, &session,
				otp_cases[n].id, otp_cases[n].prot, buf, &len)))
				goto out;
		}

		Do_ADBG_EndSubCase(c, NULL);
	}

out:
	TEEC_CloseSession(&session);
}

struct xtest_mstate_case {
	uint32_t pa;
	uint32_t len;
	uint32_t state;
	uint32_t line;
};

#define XTEST_MSTATE_CASE(pa, len, st)	\
	{pa, len, st, __LINE__}

static struct xtest_mstate_case mstate_cases[] =
{
	XTEST_MSTATE_CASE(0, 0x100000, 0x1f),	/* ndram0: srwxnrwx */
	XTEST_MSTATE_CASE(0x10000000, 0x200000, 0x1f),	/* shmem: srwxnrwx */
	XTEST_MSTATE_CASE(0x10200000, 0x200000, 0x9),	/* teemem: srwxn--- */
};

static void xtest_tee_test_90005(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	size_t n;
	uint32_t state;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(mstate_cases); n++) {
		Do_ADBG_BeginSubCase(c, "Mstate case %d line %d",
				     (int)n, (int)mstate_cases[n].line);

		state = 0;
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_memstate(c, &session,
			mstate_cases[n].pa, mstate_cases[n].len, &state)))
			goto out;

		if (!ADBG_EXPECT_TEEC_RESULT(c,
			mstate_cases[n].state, state))
			goto out;

		Do_ADBG_EndSubCase(c, NULL);
	}

out:
	TEEC_CloseSession(&session);
}

/* generated with scripts/crypt_aes_cbc_nopad.pl */
static const uint8_t ciph_data_aes_key1[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
};

static const uint8_t ciph_data_des_key1[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 /* 01234567 */
};

static const uint8_t ciph_data_des_key2[] = {
	0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
};


static const uint8_t ciph_data_des3_key1[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* 12345678 */
};

static const uint8_t ciph_data_des3_key2[] = {
	0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
	0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
	0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
};

static const uint8_t ciph_data_des2_key1[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
};

static const uint8_t ciph_data_in1[] = {
	0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, /* 23456789 */
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, /* ABCDEF01 */
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, /* 3456789A */
	0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, /* BCDEF012 */
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, /* 456789AB */
	0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, /* CDEF0123 */
};

static const uint8_t ciph_data_in3[] = {
	0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, /* 23456789 */
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, /* ABCDEF01 */
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, /* 3456789A */
	0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, /* BCDEF012 */
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, /* 456789AB */
	0x43, 0x44, 0x45, 0x46, 0x30,                   /* CDEF0    */
};

static const uint8_t ciph_data_128_iv1[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* 12345678 */
	0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, /* 9ABCDEF0 */
};

static const uint8_t ciph_data_64_iv1[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* 12345678 */
};

static const uint8_t ciph_data_in2[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

static const uint8_t ciph_data_aes_ecb_nopad_out1[] = {
	0xA5, 0xBE, 0x14, 0xD5, 0x01, 0x05, 0x24, 0x48, /* ......$H */
	0x58, 0x1A, 0x6B, 0x82, 0xD4, 0x41, 0xD2, 0xB3, /* X.k..A.. */
	0xBB, 0xF9, 0xAE, 0x37, 0x94, 0xAC, 0x18, 0x50, /* ...7...P */
	0x87, 0x09, 0xCC, 0x3F, 0x43, 0xD2, 0xC2, 0xB7, /* ...?C... */
	0xD7, 0x6F, 0x84, 0x07, 0xB4, 0x78, 0xCE, 0x34, /* .o...x.4 */
	0x48, 0xC9, 0x16, 0x86, 0x42, 0xB8, 0xFF, 0xCF, /* H...B... */
};

static const uint8_t ciph_data_aes_cbc_nopad_out1[] = {
	0x8D, 0x9F, 0x88, 0xD8, 0xAF, 0x9F, 0xC1, 0x3B, /* .......; */
	0x02, 0x15, 0x43, 0x6A, 0x8C, 0x1E, 0x34, 0x5C, /* ..Cj..4\ */
	0x83, 0xF4, 0x85, 0x3E, 0x43, 0x0F, 0xE5, 0x5F, /* ...>C.._ */
	0x81, 0x4C, 0xC0, 0x28, 0x3F, 0xD9, 0x98, 0x53, /* .L.(?..S */
	0xB1, 0x44, 0x51, 0x38, 0x21, 0xAB, 0x10, 0xCE, /* .DQ8!... */
	0xC2, 0xEC, 0x65, 0x54, 0xDD, 0x5C, 0xEA, 0xDC, /* ..eT.\.. */
};

static const uint8_t ciph_data_aes_ctr_out1[] = {
	0xD2, 0xDD, 0x11, 0xA8, 0xF7, 0xB0, 0xAE, 0x55, /* .......U */
	0xBE, 0x61, 0x7A, 0xE6, 0xA1, 0x6C, 0x79, 0xF4, /* .az..ly. */
	0x62, 0x51, 0x7B, 0xE9, 0x7C, 0xA0, 0x31, 0x0C, /* bQ{.|.1. */
	0x24, 0x15, 0x70, 0x7F, 0x47, 0x37, 0x69, 0xE0, /* $.p.G7i. */
	0x24, 0xC3, 0x29, 0xCD, 0xF2, 0x26, 0x69, 0xFF, /* $.)..&i. */
	0x72, 0x0E, 0x3C, 0xD1, 0xA1, 0x2F, 0x5D, 0x33, /* r.<../]3 */
};

static const uint8_t ciph_data_aes_ctr_out2[] = {
	0xD2, 0xDD, 0x11, 0xA8, 0xF7, 0xB0, 0xAE, 0x55, /* .......U */
	0xBE, 0x61, 0x7A, 0xE6, 0xA1, 0x6C, 0x79, 0xF4, /* .az..ly. */
	0x62, 0x51, 0x7B, 0xE9, 0x7C, 0xA0, 0x31, 0x0C, /* bQ{.|.1. */
	0x24, 0x15, 0x70, 0x7F, 0x47, 0x37, 0x69, 0xE0, /* $.p.G7i. */
	0x24, 0xC3, 0x29, 0xCD, 0xF2, 0x26, 0x69, 0xFF, /* $.)..&i. */
	0x72, 0x0E, 0x3C, 0xD1, 0xA1,                   /* r.<..    */
};

static const uint8_t ciph_data_aes_cbc_vect1_key[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
};

static const uint8_t ciph_data_aes_cbc_vect1_iv[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
};

static const uint8_t ciph_data_aes_cbc_vect1_ptx[] = {
	0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x62, /* Cipher b */
	0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x63, 0x68, 0x61, /* lock cha */
	0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x43, /* ining (C */
	0x42, 0x43, 0x29, 0x20, 0x69, 0x73, 0x20, 0x61, /* BC) is a */
	0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x20, /*  common  */
	0x63, 0x68, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, /* chaining */
	0x20, 0x6D, 0x6F, 0x64, 0x65, 0x20, 0x69, 0x6E, /*  mode in */
	0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x74, /*  which t */
	0x68, 0x65, 0x20, 0x70, 0x72, 0x65, 0x76, 0x69, /* he previ */
	0x6F, 0x75, 0x73, 0x20, 0x62, 0x6C, 0x6F, 0x63, /* ous bloc */
	0x6B, 0x27, 0x73, 0x20, 0x63, 0x69, 0x70, 0x68, /* k's ciph */
	0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x20, 0x69, /* ertext i */
	0x73, 0x20, 0x78, 0x6F, 0x72, 0x65, 0x64, 0x20, /* s xored  */
	0x77, 0x69, 0x74, 0x68, 0x20, 0x74, 0x68, 0x65, /* with the */
	0x20, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6E, 0x74, /*  current */
	0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x27, 0x73, /*  block's */
	0x20, 0x70, 0x6C, 0x61, 0x69, 0x6E, 0x74, 0x65, /*  plainte */
	0x78, 0x74, 0x20, 0x62, 0x65, 0x66, 0x6F, 0x72, /* xt befor */
	0x65, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, /* e encryp */
	0x74, 0x69, 0x6F, 0x6E, 0x2E, 0x2E, 0x2E, 0x2E, /* tion.... */
};

static const uint8_t ciph_data_aes_cbc_vect1_ctx[] = {
	0xDD, 0x16, 0xC3, 0x47, 0x69, 0xEC, 0xF5, 0x86, /* ...Gi... */
	0x20, 0xB4, 0xF7, 0xE3, 0xB9, 0x36, 0xE8, 0xAC, /*  ....6.. */
	0xC9, 0xA2, 0x11, 0x71, 0x3B, 0x10, 0x9D, 0x45, /* ...q;..E */
	0xCA, 0xE2, 0x49, 0xA6, 0x4E, 0x56, 0x07, 0xC5, /* ..I.NV.. */
	0xCE, 0xA3, 0x14, 0xB5, 0x30, 0x1B, 0x63, 0xBB, /* ....0.c. */
	0x2D, 0x6F, 0xE9, 0xCA, 0x0B, 0x00, 0x31, 0x3F, /* -o....1? */
	0xA4, 0x9A, 0x39, 0xE1, 0xC8, 0xD2, 0x24, 0x95, /* ..9...$. */
	0x14, 0xE9, 0xD2, 0x43, 0xE8, 0xA8, 0x1E, 0x0A, /* ...C.... */
	0xFE, 0x9D, 0x4F, 0xF5, 0xBB, 0x16, 0xB9, 0x54, /* ..O....T */
	0x78, 0x07, 0x94, 0x05, 0x8E, 0x47, 0xC3, 0xCB, /* x....G.. */
	0x7C, 0xEC, 0xF4, 0xF8, 0xF2, 0xA4, 0x59, 0x6E, /* |.....Yn */
	0xED, 0xAD, 0x7F, 0x62, 0xAF, 0x89, 0xA8, 0x5B, /* ...b...[ */
	0x75, 0xD4, 0x73, 0xE3, 0xBA, 0x9F, 0x9A, 0xD2, /* u.s..... */
	0x0F, 0xFD, 0x3C, 0xE6, 0xC6, 0xA4, 0xD6, 0x6C, /* ..<....l */
	0x6A, 0x09, 0xE2, 0x16, 0xB0, 0x8C, 0x69, 0x3C, /* j.....i< */
	0xC8, 0x1C, 0xE4, 0x3E, 0x86, 0x4D, 0xB0, 0x2B, /* ...>.M.+ */
	0x29, 0xA0, 0x5A, 0xA3, 0x67, 0xBA, 0xDC, 0x11, /* ).Z.g... */
	0x08, 0x5E, 0x69, 0xB4, 0x6F, 0xA5, 0xE2, 0xB8, /* .^i.o... */
	0xC9, 0x6E, 0x83, 0x7E, 0x35, 0xC8, 0xA7, 0xA0, /* .n.~5... */
	0x33, 0xA3, 0xB1, 0x4B, 0x5A, 0x92, 0x51, 0x2E, /* 3..KZ.Q. */
};

/* AES-CTS test vectors from http://tools.ietf.org/html/rfc3962
 * and http://tools.ietf.org/html/draft-raeburn-krb-rijndael-krb-02 */
static const uint8_t ciph_data_aes_cts_vect1_key[] = {
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
};

static const uint8_t ciph_data_aes_cts_vect1_iv[16] = {
	0x00
};

static const uint8_t ciph_data_aes_cts_vect1_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20
};

static const uint8_t ciph_data_aes_cts_vect1_ctx[] = {
	0xc6, 0x35, 0x35, 0x68, 0xf2, 0xbf, 0x8c, 0xb4,
	0xd8, 0xa5, 0x80, 0x36, 0x2d, 0xa7, 0xff, 0x7f,
	0x97
};

#define ciph_data_aes_cts_vect2_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect2_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect2_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20
};

static const uint8_t ciph_data_aes_cts_vect2_ctx[] = {
	0xfc, 0x00, 0x78, 0x3e, 0x0e, 0xfd, 0xb2, 0xc1,
	0xd4, 0x45, 0xd4, 0xc8, 0xef, 0xf7, 0xed, 0x22,
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5
};

#define ciph_data_aes_cts_vect3_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect3_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect3_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
};

static const uint8_t ciph_data_aes_cts_vect3_ctx[] = {
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
};

#define ciph_data_aes_cts_vect4_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect4_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect4_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c,
};

static const uint8_t ciph_data_aes_cts_vect4_ctx[] = {
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0xb3, 0xff, 0xfd, 0x94, 0x0c, 0x16, 0xa1, 0x8c,
	0x1b, 0x55, 0x49, 0xd2, 0xf8, 0x38, 0x02, 0x9e,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5,
};

#define ciph_data_aes_cts_vect5_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect5_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect5_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20,
};

static const uint8_t ciph_data_aes_cts_vect5_ctx[] = {
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
	0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
};

#define ciph_data_aes_cts_vect6_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect6_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect6_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20,
	0x61, 0x6e, 0x64, 0x20, 0x77, 0x6f, 0x6e, 0x74,
	0x6f, 0x6e, 0x20, 0x73, 0x6f, 0x75, 0x70, 0x2e,
};

static const uint8_t ciph_data_aes_cts_vect6_ctx[] = {
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
	0x48, 0x07, 0xef, 0xe8, 0x36, 0xee, 0x89, 0xa5,
	0x26, 0x73, 0x0d, 0xbc, 0x2f, 0x7b, 0xc8, 0x40,
	0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
	0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8,
};

static const uint8_t ciph_data_des_ecb_nopad_out1[] = {
	0x46, 0x2B, 0x91, 0xA8, 0x55, 0xE6, 0x7E, 0x75, /* F+..U.~u */
	0x5E, 0x53, 0xF4, 0x8F, 0x29, 0x41, 0x4E, 0xEF, /* ^S..)AN. */
	0x32, 0x1B, 0x58, 0x42, 0x9B, 0xB4, 0x3A, 0x1F, /* 2.XB..:. */
	0x9A, 0xEA, 0xA4, 0xB4, 0xCD, 0xE9, 0x87, 0x7C, /* .......| */
	0xC0, 0x05, 0x34, 0xED, 0x86, 0x3C, 0x2A, 0x81, /* ..4..<.. */
	0x5E, 0x93, 0x0E, 0x86, 0xA9, 0xBB, 0x80, 0xFF, /* ^....... */
};

static const uint8_t ciph_data_des_ecb_nopad_out2[] = {
	0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05
};

static const uint8_t ciph_data_des_cbc_nopad_out1[] = {
	0xAD, 0xD6, 0xD6, 0x3E, 0x88, 0xD0, 0xDD, 0xD4, /* ...>.... */
	0x9A, 0x93, 0x95, 0xA0, 0x86, 0x22, 0x5B, 0x9E, /* ....."[. */
	0x84, 0x0C, 0x6F, 0x12, 0x04, 0x11, 0x6F, 0xD4, /* ..o...o. */
	0x12, 0x29, 0xC6, 0x78, 0x0C, 0xFB, 0x58, 0x5B, /* .).x..X[ */
	0x66, 0x82, 0x0E, 0x52, 0xDC, 0x25, 0x16, 0x51, /* f..R.%.Q */
	0x69, 0xDF, 0xFE, 0x4E, 0x11, 0x1D, 0x9D, 0x08, /* i..N.... */
};

static const uint8_t ciph_data_des3_ecb_nopad_out1[] = {
	0xA7, 0x46, 0xEC, 0xA8, 0x6A, 0x7F, 0x4A, 0xF1, /* .F..j.J. */
	0x44, 0x60, 0x37, 0x3B, 0x7F, 0x76, 0xE5, 0xFF, /* D`7;.v.. */
	0xC1, 0xE7, 0xA5, 0x04, 0x9C, 0x29, 0x5C, 0xA5, /* .....)\. */
	0xDD, 0xC8, 0xEE, 0x36, 0x1F, 0x48, 0xE0, 0xA9, /* ...6.H.. */
	0x82, 0x2D, 0x53, 0x84, 0x49, 0x69, 0x78, 0xFA, /* .-S.Iix. */
	0x23, 0x69, 0x1D, 0xF7, 0x08, 0x38, 0x44, 0x05, /* #i...8D. */
};

static const uint8_t ciph_data_des3_cbc_nopad_out1[] = {
	0x18, 0x09, 0xEB, 0x98, 0xE4, 0x58, 0x72, 0x11, /* .....Xr. */
	0x30, 0x58, 0xAB, 0x38, 0xB0, 0xC9, 0x2B, 0xED, /* 0X.8..+. */
	0xDA, 0xC5, 0xE8, 0xA9, 0xF6, 0x8A, 0xA7, 0x80, /* ........ */
	0xBE, 0x54, 0x1F, 0x63, 0xF6, 0xEE, 0xA2, 0x4C, /* .T.c...L */
	0x7C, 0xEB, 0x84, 0x7D, 0xDA, 0xCA, 0x1E, 0xB2, /* |..}.... */
	0xED, 0x5E, 0x96, 0xB8, 0x01, 0x4B, 0x77, 0x02, /* .^...Kw. */
};

static const uint8_t ciph_data_des2_ecb_nopad_out1[] = {
	0xAB, 0x12, 0xB6, 0xE2, 0x4A, 0x3A, 0x26, 0x14, /* ....J:&. */
	0xF0, 0x7D, 0x23, 0xD0, 0x55, 0xDF, 0x5C, 0x16, /* .}#.U.\. */
	0x43, 0x59, 0x1E, 0x44, 0x01, 0x76, 0xD7, 0x50, /* CY.D.v.P */
	0x44, 0xC0, 0x15, 0xDF, 0x2E, 0x7F, 0x8B, 0xC5, /* D....... */
	0xFF, 0x8B, 0x87, 0xFE, 0x33, 0xD7, 0xCB, 0x2C, /* ....3.., */
	0xDA, 0x79, 0x6F, 0xA4, 0x05, 0x2B, 0x30, 0xCE, /* .yo..+0. */
};

static const uint8_t ciph_data_des2_cbc_nopad_out1[] = {
	0x47, 0x2F, 0xB1, 0x83, 0xC4, 0xBB, 0x93, 0x16, /* G/...... */
	0x73, 0xF9, 0xAD, 0x6F, 0x00, 0xF9, 0xCB, 0x4A, /* s..o...J */
	0x0F, 0x4F, 0x75, 0x75, 0xFB, 0x39, 0x0B, 0xFC, /* .Ouu.9.. */
	0x9F, 0x48, 0x52, 0xAD, 0xA2, 0x75, 0x2C, 0xF1, /* .HR..u, . */
	0x7D, 0xC3, 0x8F, 0x16, 0xCF, 0xC9, 0x76, 0x29, /* }.....v) */
	0x1A, 0xBF, 0xB3, 0xD9, 0x10, 0x7E, 0xAA, 0x49, /* .....~.I */
};

struct xtest_ciph_case {
	uint32_t algo;
	uint32_t mode;
	uint32_t key_type;
	const uint8_t *key1;
	size_t key1_len;
	const uint8_t *key2;
	size_t key2_len;
	const uint8_t *iv;
	size_t iv_len;
	size_t in_incr;
	const uint8_t *in;
	size_t in_len;
	const uint8_t *out;
	size_t out_len;
	size_t line;
};

#define XTEST_CIPH_CASE_NO_IV(algo, key_type, key, in_incr, ptx, ctx) \
	{ (algo), TEE_MODE_ENCRYPT, (key_type), (key), ARRAY_SIZE(key), \
	  NULL, 0, NULL, 0, \
	  (in_incr), (ptx), ARRAY_SIZE(ptx), (ctx), ARRAY_SIZE(ctx), \
	  __LINE__ }, \
	{ (algo), TEE_MODE_DECRYPT, (key_type), (key), ARRAY_SIZE(key), \
	  NULL, 0, NULL, 0, \
	  (in_incr), (ctx), ARRAY_SIZE(ctx), (ptx), ARRAY_SIZE(ptx), __LINE__ }

#define XTEST_CIPH_CASE(algo, key_type, key, iv, in_incr, ptx, ctx) \
	{ (algo), TEE_MODE_ENCRYPT, (key_type), (key), ARRAY_SIZE(key), \
	  NULL, 0, iv, ARRAY_SIZE(iv), (in_incr), (ptx), ARRAY_SIZE(ptx), \
	  (ctx), ARRAY_SIZE(ctx), __LINE__ }, \
	{ (algo), TEE_MODE_DECRYPT, (key_type), (key), ARRAY_SIZE(key), \
	  NULL, 0, iv, ARRAY_SIZE(iv), (in_incr), (ctx), ARRAY_SIZE(ctx),  \
	  (ptx), ARRAY_SIZE(ptx), __LINE__ }

#define XTEST_CIPH_CASE_AES_XTS(vect, in_incr) \
	{ TEE_ALG_AES_XTS, TEE_MODE_ENCRYPT, TEE_TYPE_AES, \
	  ciph_data_aes_xts_ ## vect ## _key1, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _key1), \
	  ciph_data_aes_xts_ ## vect ## _key2, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _key2), \
	  ciph_data_aes_xts_ ## vect ## _iv, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _iv), \
	  (in_incr), \
	  ciph_data_aes_xts_ ## vect ## _ptx, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _ptx), \
	  ciph_data_aes_xts_ ## vect ## _ctx, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _ctx), __LINE__ }, \
	{ TEE_ALG_AES_XTS, TEE_MODE_DECRYPT, TEE_TYPE_AES, \
	  ciph_data_aes_xts_ ## vect ## _key1, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _key1), \
	  ciph_data_aes_xts_ ## vect ## _key2, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _key2), \
	  ciph_data_aes_xts_ ## vect ## _iv, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _iv), \
	  (in_incr), \
	  ciph_data_aes_xts_ ## vect ## _ctx, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _ctx), \
	  ciph_data_aes_xts_ ## vect ## _ptx, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _ptx), __LINE__ }

#define XTEST_CIPH_CASE_AES_CBC(vect, in_incr) \
	XTEST_CIPH_CASE(TEE_ALG_AES_CBC_NOPAD, TEE_TYPE_AES, \
			ciph_data_aes_cbc_ ## vect ## _key, \
			ciph_data_aes_cbc_ ## vect ## _iv, \
			(in_incr), ciph_data_aes_cbc_ ## vect ## _ptx, \
			ciph_data_aes_cbc_ ## vect ## _ctx)

#define XTEST_CIPH_CASE_AES_CTS(vect, in_incr) \
	XTEST_CIPH_CASE(TEE_ALG_AES_CTS, TEE_TYPE_AES, \
			ciph_data_aes_cts_ ## vect ## _key, \
			ciph_data_aes_cts_ ## vect ## _iv, \
			(in_incr), ciph_data_aes_cts_ ## vect ## _ptx, \
			ciph_data_aes_cts_ ## vect ## _ctx)

static const struct xtest_ciph_case ciph_cases[] = {
	/* AES */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_AES_ECB_NOPAD, TEE_TYPE_AES,
			      ciph_data_aes_key1, 11, ciph_data_in1,
			      ciph_data_aes_ecb_nopad_out1),
	XTEST_CIPH_CASE(TEE_ALG_AES_CBC_NOPAD, TEE_TYPE_AES,
			ciph_data_aes_key1, ciph_data_128_iv1, 11,
			ciph_data_in1,
			ciph_data_aes_cbc_nopad_out1),
	XTEST_CIPH_CASE(TEE_ALG_AES_CTR, TEE_TYPE_AES,
			ciph_data_aes_key1, ciph_data_128_iv1, 13,
			ciph_data_in1,
			ciph_data_aes_ctr_out1),
	XTEST_CIPH_CASE(TEE_ALG_AES_CTR, TEE_TYPE_AES,
			ciph_data_aes_key1, ciph_data_128_iv1, 13,
			ciph_data_in3,
			ciph_data_aes_ctr_out2),

	XTEST_CIPH_CASE_AES_CBC(vect1, 11),

	/* AES-CTS */
	XTEST_CIPH_CASE_AES_CTS(vect1, 13),
	XTEST_CIPH_CASE_AES_CTS(vect2, 14),
	XTEST_CIPH_CASE_AES_CTS(vect3, 11),
	XTEST_CIPH_CASE_AES_CTS(vect4, 9),
	XTEST_CIPH_CASE_AES_CTS(vect5, 7),
	XTEST_CIPH_CASE_AES_CTS(vect6, 17),
	XTEST_CIPH_CASE_AES_CTS(vect6, 0x20),

	/* DES */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES_ECB_NOPAD, TEE_TYPE_DES,
			      ciph_data_des_key1, 14, ciph_data_in1,
			      ciph_data_des_ecb_nopad_out1),
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES_ECB_NOPAD, TEE_TYPE_DES,
			      ciph_data_des_key2, 3, ciph_data_in2,
			      ciph_data_des_ecb_nopad_out2),
	XTEST_CIPH_CASE(TEE_ALG_DES_CBC_NOPAD, TEE_TYPE_DES,
			ciph_data_des_key1, ciph_data_64_iv1, 15, ciph_data_in1,
			ciph_data_des_cbc_nopad_out1),

	/* DES3 */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES3_ECB_NOPAD, TEE_TYPE_DES3,
			      ciph_data_des3_key1, 11, ciph_data_in1,
			      ciph_data_des3_ecb_nopad_out1),
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES3_ECB_NOPAD, TEE_TYPE_DES3,
			      ciph_data_des3_key2, 3, ciph_data_in2,
			      ciph_data_des_ecb_nopad_out2),
	XTEST_CIPH_CASE(TEE_ALG_DES3_CBC_NOPAD, TEE_TYPE_DES3,
			ciph_data_des3_key1, ciph_data_64_iv1, 11,
			ciph_data_in1,
			ciph_data_des3_cbc_nopad_out1),

	/* DES2 */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES3_ECB_NOPAD, TEE_TYPE_DES3,
			      ciph_data_des2_key1, 11, ciph_data_in1,
			      ciph_data_des2_ecb_nopad_out1),
	XTEST_CIPH_CASE(TEE_ALG_DES3_CBC_NOPAD, TEE_TYPE_DES3,
			ciph_data_des2_key1, ciph_data_64_iv1, 11,
			ciph_data_in1,
			ciph_data_des2_cbc_nopad_out1),
};

static void xtest_tee_test_90006(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	TEE_OperationHandle op;
	TEE_ObjectHandle key1_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle key2_handle = TEE_HANDLE_NULL;
	uint8_t out[2048];
	size_t out_size;
	size_t out_offs;
	uint32_t ret_orig;
	size_t n;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(ciph_cases); n++) {
		TEE_Attribute key_attr;
		size_t key_size;
		size_t op_key_size;


		Do_ADBG_BeginSubCase(c, "Cipher case %d algo 0x%x line %d",
				     (int)n, (unsigned int)ciph_cases[n].algo,
				     (int)ciph_cases[n].line);

		key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
		key_attr.content.ref.buffer = (void *)ciph_cases[n].key1;
		key_attr.content.ref.length = ciph_cases[n].key1_len;

		key_size = key_attr.content.ref.length * 8;
		if (ciph_cases[n].key_type == TEE_TYPE_DES ||
		    ciph_cases[n].key_type == TEE_TYPE_DES3)
			/* Exclude parity in bit size of key */
			key_size -= key_size / 8;

		op_key_size = key_size;
		if (ciph_cases[n].key2 != NULL)
			op_key_size *= 2;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op,
				ciph_cases[n].algo, ciph_cases[n].mode,
				op_key_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				ciph_cases[n].key_type, key_size,
				&key1_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_kl_generate_key(c, &session,
				key1_handle, ciph_cases[n].key1_len * 8, NULL, 0))) /*cant use 'key_size' here*/
			goto out;

		if (ciph_cases[n].key2 != NULL) {
			key_attr.content.ref.buffer =
				(void *)ciph_cases[n].key2;
			key_attr.content.ref.length = ciph_cases[n].key2_len;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_transient_object(c,
					&session, ciph_cases[n].key_type,
					key_attr.content.ref.length * 8,
					&key2_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_populate_transient_object(c,
					&session, key2_handle, &key_attr, 1)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key2(c, &session, op,
					key1_handle, key2_handle)))
				goto out;
		} else {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					key1_handle)))
				goto out;
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				key1_handle)))
			goto out;
		key1_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				key2_handle)))
			goto out;
		key2_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_init(c, &session, op,
				ciph_cases[n].iv, ciph_cases[n].iv_len)))
			goto out;

		out_offs = 0;
		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_update(c, &session, op,
				ciph_cases[n].in, ciph_cases[n].in_incr, out,
				&out_size)))
			goto out;

		out_offs += out_size;
		out_size = sizeof(out) - out_offs;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_do_final(c, &session, op,
				ciph_cases[n].in + ciph_cases[n].in_incr,
				ciph_cases[n].in_len - ciph_cases[n].in_incr,
				out + out_offs,
				&out_size)))
			goto out;

		out_offs += out_size;

		/*ignore result whatever*/

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;

		Do_ADBG_EndSubCase(c, NULL);
	}
out:
	TEEC_CloseSession(&session);
}

static void xtest_tee_test_90007(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	uint32_t algo, mode;
	uint32_t key_type, key_size;
	TEE_OperationHandle op;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	uint8_t input[32] = "this is for gkl key test";
	uint8_t output[32];
	uint8_t temp[32];
	uint8_t *in, *out;
	size_t in_size, out_size;
	size_t n;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
					&ret_orig)))
		return;

	algo = TEE_ALG_AES_ECB_NOPAD;
	key_type = TEE_TYPE_AES;
	key_size = 128;

	for (n = 0; n < 2; n++) {
		if (0 == n) {
			/* encrypt */
			mode = TEE_MODE_ENCRYPT;
			in = input;
			out = output;
			in_size = sizeof(input);
			out_size = sizeof(output);
		} else {
			/* decrypt*/
			mode = TEE_MODE_DECRYPT;
			in = output;
			out = temp;
			in_size = out_size;
			out_size = sizeof(temp);
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op,
				algo, mode, key_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				key_type, key_size, &key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_kl_generate_key(c, &session,
				key_handle, key_size, NULL, 0)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, &session, op,
				key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				key_handle)))
			goto out;
		key_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_init(c, &session, op,
				NULL, 0)))
			goto out;

		memset(out, 0, out_size);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_do_final(c, &session, op,
				in, in_size, out, &out_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;
	}

	/*check result*/
	(void)ADBG_EXPECT_BUFFER(c, input, sizeof(input), temp, out_size);

out:
	TEEC_CloseSession(&session);
}

static void xtest_tee_test_90008(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	uint32_t algo, mode;
	uint32_t key_type, key_size;
	TEE_OperationHandle op;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	uint8_t input[32] = "this is for gkl key test";
	uint8_t output[32];
	uint8_t temp[32];
	uint8_t *in, *out;
	size_t in_size, out_size;
	size_t n;

	algo = TEE_ALG_AES_ECB_NOPAD;
	key_type = TEE_TYPE_AES;
	key_size = 128;

	for (n = 0; n < 2; n++) {
		if (0 == n) {
			/* encrypt */
			mode = TEE_MODE_ENCRYPT;
			in = input;
			out = output;
			in_size = sizeof(input);
			out_size = sizeof(output);

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
							&ret_orig)))
				return;
		} else {
			/* decrypt*/
			mode = TEE_MODE_DECRYPT;
			in = output;
			out = temp;
			in_size = out_size;
			out_size = sizeof(temp);

			TEEC_CloseSession(&session);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				xtest_teec_open_session(&session, &teex2_ta_uuid, NULL,
							&ret_orig)))
				return;
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op,
				algo, mode, key_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				key_type, key_size, &key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_kl_generate_key(c, &session,
				key_handle, key_size, NULL, 0)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, &session, op,
				key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				key_handle)))
			goto out;
		key_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_init(c, &session, op,
				NULL, 0)))
			goto out;

		memset(out, 0, out_size);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_do_final(c, &session, op,
				in, in_size, out, &out_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;
	}

	/*check result*/
	(void)ADBG_EXPECT(c, sizeof(input), out_size);
	(void)ADBG_EXPECT_TRUE(c, !!memcmp(input, temp, out_size));
out:
	TEEC_CloseSession(&session);
}

static void xtest_tee_test_90009(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &teex_ta_uuid, NULL,
					&ret_orig)))
		return;

	/* decrypt key */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_kl_generate_tsp_key(c, &session,
			20, 0, 0)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_kl_generate_tsp_key(c, &session,
			20, 1, 0)))
		goto out;

	/* encrypt key */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_kl_generate_tsp_key(c, &session,
			22, 0, 0)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_kl_generate_tsp_key(c, &session,
			22, 1, 0)))
		goto out;

out:
	TEEC_CloseSession(&session);
}
