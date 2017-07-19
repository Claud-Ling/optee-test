/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Sigma Designs Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Author:  Tony He <tony_he@sigmadesigns.com>
 * Date:    2017/07/14
 *
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h> /*TEE_Cachexxx*/
#include <tee_api_ext.h>
#include <types_ext.h>	/*paddr_t*/
#include <utee_types.h>	/*PROT, ATTR*/
#include <util.h>	/*ROUNDDOWN*/
#include <string.h>
#include <trace.h>
#include "teex_taf.h"

#define ASSERT_PARAM_TYPE(pt)                    \
do {                                             \
	if ((pt) != param_type)                  \
		return TEE_ERROR_BAD_PARAMETERS; \
} while (0)

#define VAL2HANDLE(v) (void *)(uintptr_t)(v)

#define MAP_PAGE_SHIFT	12	/* 4kB */
#define MAP_PAGE_SIZE	(1 << MAP_PAGE_SHIFT)
#define MAP_PAGE_MASK	(MAP_PAGE_SIZE - 1)

static void* ta_mmap(paddr_t pa, size_t len, uint32_t prot, uint32_t attr, uint32_t *err)
{
	TEE_Result res;
	paddr_t pa_align;
	size_t len_align;
	void *va = NULL;

	pa_align = ROUNDDOWN(pa, MAP_PAGE_SIZE);
	len_align = len + pa - pa_align;
	va = TEE_Mmap(pa_align, len_align, prot, attr, &res);
	if (err)
		*err = res;
	return ((va != NULL) ? (void*)((vaddr_t)va + pa - pa_align) : NULL);
}

static TEE_Result ta_munmap(void *addr, size_t len)
{
	TEE_Result res __maybe_unused;
	vaddr_t va, va_align;
	size_t len_align;

	va = (vaddr_t)addr;
	va_align = ROUNDDOWN(va, MAP_PAGE_SIZE);
	len_align = len + va - va_align;
	return TEE_Munmap((void *)va_align, len_align);
}

TEE_Result ta_entry_mmap(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	paddr_t pa;
	size_t len;
	uint32_t prot, attr;
	void *va;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INOUT,
			   TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	pa = params[0].value.a,
	len = params[0].value.b;
	prot = params[1].value.a;
	attr = params[1].value.b;

	va = ta_mmap(pa, len, prot, attr, &res);

	params[0].value.a = (uint32_t)(uintptr_t)va;
	return res;
}

TEE_Result ta_entry_munmap(uint32_t param_type, TEE_Param params[4])
{
	size_t len;
	void *va;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	va = (void*)(uintptr_t)params[0].value.a,
	len = params[0].value.b;

	return ta_munmap(va, len);
}

TEE_Result ta_entry_access(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	paddr_t pa;
	size_t len;
	uint32_t prot, attr;
	void *va;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INOUT,
			   TEE_PARAM_TYPE_NONE));

	pa = params[0].value.a,
	len = params[0].value.b;
	attr = params[1].value.a;
	prot = params[1].value.b;

	if (params[2].memref.size != len)
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("memory [%lx, %zx] '%s | %s | %s | %s'", pa, len,
		((prot & (TEE_MAP_PROT_READ | TEE_MAP_PROT_WRITE)) ==
		 (TEE_MAP_PROT_READ | TEE_MAP_PROT_WRITE)) ? "RDWR" :
		 ((prot & TEE_MAP_PROT_WRITE) ? "Write" : "Read"),
		(attr & TEE_MAP_ATTR_CACHED) ? "Cached" : "Noncache",
		(attr & TEE_MAP_ATTR_SECURE) ? "Secure" : "Normal",
		(attr & TEE_MAP_ATTR_GLOBAL) ? "Global" : "nG");

	va = ta_mmap(pa, len, prot, attr, &res);
	if (va == NULL) {
		EMSG("TEE_Mmap error 0x%08x", res);
		return res;
	}

	if (prot & TEE_MAP_PROT_WRITE) {
		/*write*/
		memcpy(va, params[2].memref.buffer, params[2].memref.size);
		if (attr & TEE_MAP_ATTR_CACHED) {
			/*write to ddr*/
			res = TEE_CacheFlush(va, len);
			FMSG("result 0x%08x", res);
		}
	} else {
		/*read*/
		if (attr & TEE_MAP_ATTR_CACHED) {
			/*read from ddr*/
			res = TEE_CacheInvalidate(va, len);
			FMSG("result 0x%08x", res);
		}
		memcpy(params[2].memref.buffer, va, params[2].memref.size);
	}

	res = ta_munmap(va, len);
	FMSG("result 0x%08x", res);
	return res;
}

TEE_Result ta_entry_copy(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	paddr_t pa, dst;
	size_t len;
	uint32_t prot, attr;
	void *va, *vdst;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT,
			   TEE_PARAM_TYPE_NONE));

	pa = params[0].value.a,
	len = params[0].value.b;
	dst = params[1].value.a;
	attr = params[1].value.b;

	if (params[2].memref.size > len)
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("memcpy(%lx, %lx, %zx) '%s | %s | %s'", dst, pa, len,
		(attr & TEE_MAP_ATTR_CACHED) ? "Cached" : "Noncache",
		(attr & TEE_MAP_ATTR_SECURE) ? "Secure" : "Normal",
		(attr & TEE_MAP_ATTR_GLOBAL) ? "Global" : "nG");

	prot = TEE_MAP_PROT_READ;
	va = ta_mmap(pa, len, prot, attr, &res);
	if (va == NULL) {
		EMSG("TEE_Mmap error 0x%08x", res);
		return res;
	}

	prot = TEE_MAP_PROT_WRITE | TEE_MAP_PROT_READ;
	vdst = ta_mmap(dst, len, prot, attr, &res);
	if (vdst == NULL) {
		EMSG("TEE_Mmap error 0x%08x", res);
		goto map_error;
	}

	if (attr & TEE_MAP_ATTR_CACHED) {
		/*load from ddr*/
		res = TEE_CacheInvalidate(va, len);
		FMSG("result 0x%08x", res);
	}
	memcpy(vdst, va, len);
	if (attr & TEE_MAP_ATTR_CACHED) {
		/*write to ddr*/
		res = TEE_CacheClean(vdst, len);
		FMSG("result 0x%08x", res);
	}
	memcpy(params[2].memref.buffer, vdst, params[2].memref.size);

	res = ta_munmap(vdst, len);
	FMSG("result 0x%08x", res);
map_error:
	res = ta_munmap(va, len);
	FMSG("result 0x%08x", res);
	return res;
}

TEE_Result ta_entry_cmp(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	paddr_t pa, pa2;
	size_t len;
	uint32_t prot, attr;
	void *va, *va2;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INOUT,
			   TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	pa = params[0].value.a,
	len = params[0].value.b;
	pa2 = params[1].value.a;
	attr = params[1].value.b;

	FMSG("memcmp(%lx, %lx, %zx) '%s | %s | %s'", pa, pa2, len,
		(attr & TEE_MAP_ATTR_CACHED) ? "Cached" : "Noncache",
		(attr & TEE_MAP_ATTR_SECURE) ? "Secure" : "Normal",
		(attr & TEE_MAP_ATTR_GLOBAL) ? "Global" : "nG");

	prot = TEE_MAP_PROT_READ;
	va = ta_mmap(pa, len, prot, attr, &res);
	if (va == NULL) {
		EMSG("TEE_Mmap error 0x%08x", res);
		return res;
	}

	prot = TEE_MAP_PROT_READ;
	va2 = ta_mmap(pa2, len, prot, attr, &res);
	if (va2 == NULL) {
		EMSG("TEE_Mmap error 0x%08x", res);
		goto map_error;
	}

	if (attr & TEE_MAP_ATTR_CACHED) {
		/*load from ddr*/
		res = TEE_CacheInvalidate(va, len);
		FMSG("result 0x%08x", res);
		res = TEE_CacheInvalidate(va2, len);
		FMSG("result 0x%08x", res);
	}

	params[0].value.a = memcmp(va, va2, len);

	res = ta_munmap(va2, len);
	FMSG("result 0x%08x", res);
map_error:
	res = ta_munmap(va, len);
	FMSG("result 0x%08x", res);
	return res;
}

TEE_Result ta_entry_otpwrite(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	uint32_t id, size, prot;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INOUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	id = params[0].value.a;
	prot = params[0].value.b;
	size = params[1].memref.size;

	FMSG("otp_write(%d, %p, %x, %08x)", id,
		params[1].memref.buffer, size, prot);

	res = TEE_OtpWrite(id, params[1].memref.buffer, &size, prot);
	if (TEE_SUCCESS == res)
		params[0].value.a = size;

	return res;
}

TEE_Result ta_entry_getmstate(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	paddr_t pa;
	uint32_t size, state;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INOUT,
			   TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	pa = params[0].value.a;
	size = params[0].value.b;

	FMSG("mem_state(%08lx, %zx)", pa, size);

	res = TEE_MemState(pa, size, &state);
	if (TEE_SUCCESS == res)
		params[0].value.a = state;

	return res;
}

struct attr_packed {
	uint32_t id;
	uint32_t a;
	uint32_t b;
};

static TEE_Result unpack_attrs(const uint8_t *buf, size_t blen,
			       TEE_Attribute **attrs, uint32_t *attr_count)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute *a = NULL;
	const struct attr_packed *ap;
	size_t num_attrs = 0;
	const size_t num_attrs_size = sizeof(uint32_t);

	if (blen == 0)
		goto out;

	if (((uintptr_t)buf & 0x3) != 0 || blen < num_attrs_size)
		return TEE_ERROR_BAD_PARAMETERS;
	num_attrs = *(uint32_t *) (void *)buf;
	if ((blen - num_attrs_size) < (num_attrs * sizeof(*ap)))
		return TEE_ERROR_BAD_PARAMETERS;
	ap = (const struct attr_packed *)(const void *)(buf + num_attrs_size);

	if (num_attrs > 0) {
		size_t n;

		a = TEE_Malloc(num_attrs * sizeof(TEE_Attribute), 0);
		if (!a)
			return TEE_ERROR_OUT_OF_MEMORY;
		for (n = 0; n < num_attrs; n++) {
			uintptr_t p;

			a[n].attributeID = ap[n].id;
#define TEE_ATTR_BIT_VALUE		  (1 << 29)
			if (ap[n].id & TEE_ATTR_BIT_VALUE) {
				a[n].content.value.a = ap[n].a;
				a[n].content.value.b = ap[n].b;
				continue;
			}

			a[n].content.ref.length = ap[n].b;
			p = (uintptr_t)ap[n].a;
			if (p) {
				if ((p + a[n].content.ref.length) > blen) {
					res = TEE_ERROR_BAD_PARAMETERS;
					goto out;
				}
				p += (uintptr_t)buf;
			}
			a[n].content.ref.buffer = (void *)p;
		}
	}

	res = TEE_SUCCESS;
out:
	if (res == TEE_SUCCESS) {
		*attrs = a;
		*attr_count = num_attrs;
	} else {
		TEE_Free(a);
	}
	return res;
}

TEE_Result ta_entry_kl_generate_key(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	TEE_Attribute *attrs;
	uint32_t attr_count;
	tee_kl_param kp;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	kp.ukey.obj = VAL2HANDLE(params[0].value.a);
	kp.ukey.keySize = params[0].value.b;
	res = TEE_KLGenerateKey(KL_USER_KEY, &kp, attrs, attr_count);
	TEE_Free(attrs);
	return res;
}

TEE_Result ta_entry_kl_generate_tsp_key(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	tee_kl_param kp;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	kp.tsp.index = params[0].value.a;
	kp.tsp.eo = params[0].value.b;
	kp.tsp.datum = params[1].value.a;
	res = TEE_KLGenerateKey(KL_TSP_KEY, &kp, NULL, 0);
	return res;
}
