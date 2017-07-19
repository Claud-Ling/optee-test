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

#ifndef TEEX_TAF_H
#define TEEX_TAF_H

#include <tee_api.h>

#ifndef ASM
TEE_Result ta_entry_mmap(uint32_t param_types,
			 TEE_Param params[4]);

TEE_Result ta_entry_munmap(uint32_t param_types,
			   TEE_Param params[4]);

TEE_Result ta_entry_access(uint32_t param_types,
			   TEE_Param params[4]);

TEE_Result ta_entry_copy(uint32_t param_types,
			 TEE_Param params[4]);

TEE_Result ta_entry_cmp(uint32_t param_types,
			TEE_Param params[4]);

TEE_Result ta_entry_otpwrite(uint32_t param_type,
			     TEE_Param params[4]);

TEE_Result ta_entry_getmstate(uint32_t param_type,
			      TEE_Param params[4]);

TEE_Result ta_entry_kl_generate_key(uint32_t param_type,
				    TEE_Param params[4]);

TEE_Result ta_entry_kl_generate_tsp_key(uint32_t param_type,
					TEE_Param params[4]);

#endif /*!ASM*/
#endif /*TEEX_TAF_H */
