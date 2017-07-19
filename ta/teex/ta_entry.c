/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017-2020, Sigma Designs Inc.
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

#include <tee_ta_api.h>
#include <ta_teex.h>
#include <cryp_taf.h>
#include <teex_taf.h>
#include <trace.h>

static TEE_Result set_global(uint32_t param_types, TEE_Param params[4]);
static TEE_Result get_global(uint32_t param_types, TEE_Param params[4]);
static int _globalvalue;

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes,
				    TEE_Param pParams[4],
				    void **ppSessionContext)
{
	(void)nParamTypes;
	(void)pParams;
	(void)ppSessionContext;
	return TEE_SUCCESS;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext)
{
	(void)pSessionContext;
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[4])
{
	(void)pSessionContext;

	switch (nCommandID) {
	case TA_TEEX_CMD_ALLOCATE_OPERATION:
		return ta_entry_allocate_operation(nParamTypes, pParams);

	case TA_TEEX_CMD_FREE_OPERATION:
		return ta_entry_free_operation(nParamTypes, pParams);

	case TA_TEEX_CMD_GET_OPERATION_INFO:
		return ta_entry_get_operation_info(nParamTypes, pParams);

	case TA_TEEX_CMD_RESET_OPERATION:
		return ta_entry_reset_operation(nParamTypes, pParams);

	case TA_TEEX_CMD_SET_OPERATION_KEY:
		return ta_entry_set_operation_key(nParamTypes, pParams);

	case TA_TEEX_CMD_SET_OPERATION_KEY2:
		return ta_entry_set_operation_key2(nParamTypes, pParams);

	case TA_TEEX_CMD_COPY_OPERATION:
		return ta_entry_copy_operation(nParamTypes, pParams);

	case TA_TEEX_CMD_CIPHER_INIT:
		return ta_entry_cipher_init(nParamTypes, pParams);

	case TA_TEEX_CMD_CIPHER_UPDATE:
		return ta_entry_cipher_update(nParamTypes, pParams);

	case TA_TEEX_CMD_CIPHER_DO_FINAL:
		return ta_entry_cipher_do_final(nParamTypes, pParams);

	case TA_TEEX_CMD_ALLOCATE_TRANSIENT_OBJECT:
		return ta_entry_allocate_transient_object(nParamTypes, pParams);

	case TA_TEEX_CMD_FREE_TRANSIENT_OBJECT:
		return ta_entry_free_transient_object(nParamTypes, pParams);

	case TA_TEEX_CMD_RESET_TRANSIENT_OBJECT:
		return ta_entry_reset_transient_object(nParamTypes, pParams);

	case TA_TEEX_CMD_POPULATE_TRANSIENT_OBJECT:
		return ta_entry_populate_transient_object(nParamTypes, pParams);

	case TA_TEEX_CMD_COPY_OBJECT_ATTRIBUTES:
		return ta_entry_copy_object_attributes(nParamTypes, pParams);

	case TA_TEEX_CMD_GET_OBJECT_BUFFER_ATTRIBUTE:
		return ta_entry_get_object_buffer_attribute(nParamTypes,
							    pParams);
	case TA_TEEX_CMD_GET_OBJECT_VALUE_ATTRIBUTE:
		return ta_entry_get_object_value_attribute(nParamTypes,
							   pParams);
	case TA_TEEX_CMD_SETGLOBAL:
		return set_global(nParamTypes, pParams);

	case TA_TEEX_CMD_GETGLOBAL:
		return get_global(nParamTypes, pParams);

	case TA_TEEX_CMD_MMAP:
		return ta_entry_mmap(nParamTypes, pParams);

	case TA_TEEX_CMD_MUNMAP:
		return ta_entry_munmap(nParamTypes, pParams);

	case TA_TEEX_CMD_ACCESS:
		return ta_entry_access(nParamTypes, pParams);

	case TA_TEEX_CMD_COPY:
		return ta_entry_copy(nParamTypes, pParams);

	case TA_TEEX_CMD_CMP:
		return ta_entry_cmp(nParamTypes, pParams);

	case TA_TEEX_CMD_OTPWRITE:
		return ta_entry_otpwrite(nParamTypes, pParams);

	case TA_TEEX_CMD_MEMSTATE:
		return ta_entry_getmstate(nParamTypes, pParams);

	case TA_TEEX_CMD_KL_GENERATE_KEY:
		return ta_entry_kl_generate_key(nParamTypes, pParams);

	case TA_TEEX_CMD_KL_GENERATE_TSP_KEY:
		return ta_entry_kl_generate_tsp_key(nParamTypes, pParams);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result set_global(uint32_t param_types, TEE_Param params[4])
{
	int i;

	/* Param 0 is a memref, input/output */
	if (TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(param_types, 0))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Other parameters must be of type TEE_PARAM_TYPE_NONE */
	for (i = 1; i < 4; i++) {
		if (TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(param_types, i))
			return TEE_ERROR_BAD_PARAMETERS;
	}

	_globalvalue = params[0].value.a;
	return TEE_SUCCESS;
}

static TEE_Result get_global(uint32_t param_types, TEE_Param params[4])
{
	int i;

	/* Param 0 is a memref, input/output */
	if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(param_types, 0))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Other parameters must be of type TEE_PARAM_TYPE_NONE */
	for (i = 1; i < 4; i++) {
		if (TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(param_types, i))
			return TEE_ERROR_BAD_PARAMETERS;
	}

	params[0].value.a = _globalvalue;
	return TEE_SUCCESS;
}
