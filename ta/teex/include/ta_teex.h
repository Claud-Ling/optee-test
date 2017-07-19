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
 * INTERRUPTION) HOGWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Author:  Tony He <tony_he@sigmadesigns.com>
 * Date:    2017/07/14
 *
 */

#ifndef TA_TEEX_H
#define TA_TEEX_H

/* This UUID is generated with the ITU-T UUID generator at
   http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_TEEX_UUID { 0x43150923, 0xd5c1, 0x4d1a, \
	{ 0xa4, 0xbe, 0x32, 0x7a, 0x7d, 0xd2, 0x31, 0xd4 } }
#define TA_TEEX2_UUID { 0xae8cba7c, 0x15c4, 0x44e6, \
	{ 0xb0, 0x65, 0x3d, 0xa7, 0x22, 0x4b, 0xe8, 0xb1 } }

#define TA_TEEX_CMD_SHA224             1
#define TA_TEEX_CMD_SHA256             2
#define TA_TEEX_CMD_AES256ECB_ENC      3
#define TA_TEEX_CMD_AES256ECB_DEC      4

/*
 * TEE_Result TEE_AllocateOperation(TEE_OperationHandle *operation,
 *              uint32_t algorithm, uint32_t mode, uint32_t maxKeySize);
 * in/out   params[0].value.a = operation
 * in/out   params[0].value.b = algorithm
 * in       params[1].value.a = mode
 * in       params[2].value.b = maxKeySize
 */
#define TA_TEEX_CMD_ALLOCATE_OPERATION 5

/*
 * void TEE_FreeOperation(TEE_OperationHandle operation);
 * in       params[0].value.a = operation
 */
#define TA_TEEX_CMD_FREE_OPERATION     6

/*
 * void TEE_GetOperationInfo(TEE_OperationHandle operation,
 *              TEE_OperationInfo* operationInfo);
 * in       params[0].value.a = operation
 * out      params[1].memref  = operationInfo
 */
#define TA_TEEX_CMD_GET_OPERATION_INFO 7

/*
 * void TEE_ResetOperation(TEE_OperationHandle operation);
 * in       params[0].value.a = operation
 */
#define TA_TEEX_CMD_RESET_OPERATION    8

/*
 * TEE_Result TEE_SetOperationKey(TEE_OperationHandle operation,
 *              TEE_ObjectHandle key);
 * in       params[0].value.a = operation
 * in       params[0].value.b = key
 */
#define TA_TEEX_CMD_SET_OPERATION_KEY  9

/*
 * TEE_Result TEE_SetOperationKey2(TEE_OperationHandle operation,
 *              TEE_ObjectHandle key1, TEE_ObjectHandle key2);
 * in       params[0].value.a = operation
 * in       params[0].value.b = key1
 * in       params[0].value.a = key2
 */
#define TA_TEEX_CMD_SET_OPERATION_KEY2 10

/*
 * void TEE_CopyOperation(TEE_OperationHandle dstOperation,
 *              TEE_OperationHandle srcOperation);
 * in       params[0].value.a = dstOperation
 * in       params[0].value.b = srcOperation
 */
#define TA_TEEX_CMD_COPY_OPERATION     11

/*
 * void TEE_DigestUpdate(TEE_OperationHandle operation,
 *              void *chunk, size_t chunkSize);
 * in       params[0].value.a = operation
 * in       params[1].memref = chunk
 */
#define TA_TEEX_CMD_DIGEST_UPDATE      12

/*
 * TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation,
 *              const void *chunk, size_t chunkLen,
 *              void *hash, size_t *hashLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = chunk
 * out      params[2].memref = hash
 */
#define TA_TEEX_CMD_DIGEST_DO_FINAL    13

/*
 * void TEE_CipherInit(TEE_OperationHandle operation, const void *IV,
 *              size_t IVLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = IV
 */
#define TA_TEEX_CMD_CIPHER_INIT        14

/*
 * TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation,
 *              const void *srcData, size_t srcLen,
 *              void *destData, size_t *destLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = srcData
 * out      params[2].memref = dstData
 */
#define TA_TEEX_CMD_CIPHER_UPDATE      15

/*
 * TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
 *              const void *srcData, size_t srcLen,
 *              void *destData, size_t *destLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = srcData
 * out      params[2].memref = destData
 */
#define TA_TEEX_CMD_CIPHER_DO_FINAL    16

/*
 * void TEE_MACInit(TEE_OperationHandle operation,
 *              const void *IV, size_t IVLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = IV
 */
#define TA_TEEX_CMD_MAC_INIT           17

/*
 * void TEE_MACUpdate(TEE_OperationHandle operation,
 *              const void *chunk, size_t chunkSize);
 * in       params[0].value.a = operation
 * in       params[1].memref = chunk
 */
#define TA_TEEX_CMD_MAC_UPDATE         18

/*
 * TEE_Result TEE_MACFinalCompute(TEE_OperationHandle operation,
 *              const void *message, size_t messageLen,
 *              void *mac, size_t *macLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = message
 * out      params[2].memref = mac
 */
#define TA_TEEX_CMD_MAC_FINAL_COMPUTE  19

/*
 * TEE_Result TEE_MACFinalCompare(TEE_OperationHandle operation,
 *              const void *message, size_t messageLen,
 *              const void *mac, size_t *macLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = message
 * in       params[2].memref = mac
 */
#define TA_TEEX_CMD_MAC_FINAL_COMPARE  20

/*
 * TEE_Result TEE_AllocateTransientObject(TEE_ObjectType objectType,
 *              uint32_t maxObjectSize, TEE_ObjectHandle* object);
 * in       params[0].value.a = objectType
 * in       params[0].value.b = maxObjectSize
 * out      params[1].value.a = object;
 */
#define TA_TEEX_CMD_ALLOCATE_TRANSIENT_OBJECT  21

/*
 * void TEE_FreeTransientObject(TEE_ObjectHandle object);
 * in       params[0].value.a = object
 */
#define TA_TEEX_CMD_FREE_TRANSIENT_OBJECT      22

/*
 * void TEE_ResetTransientObject(TEE_ObjectHandle object);
 * in       params[0].value.a = object
 */
#define TA_TEEX_CMD_RESET_TRANSIENT_OBJECT     23

/*
 * TEE_Result TEE_PopulateTransientObject(TEE_ObjectHandle object,
 *              TEE_Attribute *attrs, uint32_t attrCount);
 * in       params[0].value.a = object
 * in       params[1].memref = attrs
 */
#define TA_TEEX_CMD_POPULATE_TRANSIENT_OBJECT  24

/*
 * void TEE_CopyObjectAttributes(TEE_ObjectHandle destObject,
 *              TEE_ObjectHandle srcObject);
 * in       params[0].value.a = destObject
 * in       params[0].value.b = srcObject
 */
#define TA_TEEX_CMD_COPY_OBJECT_ATTRIBUTES     25

/*
 * TEE_Result TEE_GenerateKey(TEE_ObjectHandle object, uint32_t keySize,
 *              TEE_Attribute *params, uint32_t paramCount);
 * in       params[0].value.a = object
 * in       params[0].value.b = keySize
 * in       params[1].memref = params
 */
#define TA_TEEX_CMD_GENERATE_KEY               26

/*
 * TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
 *              const TEE_Attribute *params, uint32_t paramCount,
 *              const void *srcData, size_t srcLen, void *destData,
 *              size_t *destLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = params
 * in       params[2].memref = srcData
 * out      params[3].memref = destData
 */
#define TA_TEEX_CMD_ASYMMETRIC_ENCRYPT         27

/*
 * TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
 *              const TEE_Attribute *params, uint32_t paramCount,
 *              const void *srcData, size_t srcLen, void *destData,
 *              size_t *destLen)
 * in       params[0].value.a = operation
 * in       params[1].memref = params
 * in       params[2].memref = srcData
 * out      params[3].memref = destData
 */
#define TA_TEEX_CMD_ASYMMETRIC_DECRYPT         28

/*
 * TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
 *              const TEE_Attribute *params, uint32_t paramCount,
 *              const void *digest, size_t digestLen, void *signature,
 *              size_t *signatureLen)
 * in       params[0].value.a = operation
 * in       params[1].memref = params
 * in       params[2].memref = digest
 * out      params[3].memref = signature
 */
#define TA_TEEX_CMD_ASYMMETRIC_SIGN_DIGEST     29

/*
 * TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
 *              const TEE_Attribute *params, uint32_t paramCount,
 *              const void *digest, size_t digestLen, const void *signature,
 *              size_t signatureLen)
 * in       params[0].value.a = operation
 * in       params[1].memref = params
 * in       params[2].memref = digest
 * in       params[3].memref = signature
 */
#define TA_TEEX_CMD_ASYMMETRIC_VERIFY_DIGEST   30

/*
 * void TEE_DeriveKey(TEE_OperationHandle operation,
 *              const TEE_Attribute *params, uint32_t paramCount,
 *              TEE_ObjectHandle derivedKey)
 * in       params[0].value.a = operation
 * in       params[1].memref = params
 * in       params[0].value.b = derivedKey
 */
#define TA_TEEX_CMD_DERIVE_KEY                 31

/*
 * void TEE_RandomNumberGenerate(void *randomBuffer, size_t randomBufferLen);
 * out      params[0].memref = randomBuffer
 */
#define TA_TEEX_CMD_RANDOM_NUMBER_GENEREATE    32

/*
 * TEE_Result TEE_AEInit(TEE_OperationHandle operation,
 *              const void* nonce, size_t nonceLen,
 *              uint32_t tagLen, uint32_t AADLen, uint32_t payloadLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = nonce
 * in       params[0].value.b = tagLen
 * in       params[2].value.a = AADLen
 * in       params[2].value.b = payloadLen
 */
#define TA_TEEX_CMD_AE_INIT                    33

/*
 * void TEE_AEUpdateAAD(TEE_OperationHandle operation,
 *              void* AADdata, size_t AADdataLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = AADdata
 */
#define TA_TEEX_CMD_AE_UPDATE_AAD              34

/*
 * TEE_Result TEE_AEUpdate(TEE_OperationHandle operation,
 *              const void* srcData, size_t srcLen,
 *              void* destData, size_t *destLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = srcData
 * out      params[2].memref = destData
 */
#define TA_TEEX_CMD_AE_UPDATE                  35

/*
 * TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
 *              const void* srcData, size_t srcLen,
 *              void* destData, size_t* destLen,
 *              void* tag, size_t* tagLen);
 * in       params[0].value[0].a = operation
 * in       params[1].memref = srcData
 * out      params[2].memref = destData
 * out      params[3].memref = tag
 */
#define TA_TEEX_CMD_AE_ENCRYPT_FINAL           36

/*
 * TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
 *              const void* srcData, size_t srcLen,
 *              void* destData, size_t *destLen,
 *              const void* tag, size_t tagLen);
 * in       params[0].value.a = operation
 * in       params[1].memref = srcData
 * out      params[2].memref = destData
 * in       params[3].memref = tag
 */
#define TA_TEEX_CMD_AE_DECRYPT_FINAL           37

/*
 * TEE_Result TEE_GetObjectBufferAttribute(TEE_ObjectHandle object,
 *              uint32_t attributeID, void* buffer, size_t* size);
 * in      params[0].value.a = object
 * in      params[0].value.b = attributeID
 * out     params[1].memrefs = buffer
 */
#define TA_TEEX_CMD_GET_OBJECT_BUFFER_ATTRIBUTE 38

/*
 * TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object,
 *              uint32_t attributeID, void* buffer, size_t* size);
 * in      params[0].value.a = object
 * in      params[0].value.b = attributeID
 * out     params[1].value.a = value a
 * out     params[1].value.b = value b
 */
#define TA_TEEX_CMD_GET_OBJECT_VALUE_ATTRIBUTE 39

/* To set or get a global value */
#define TA_TEEX_CMD_SETGLOBAL     40
#define TA_TEEX_CMD_GETGLOBAL     41

/*
 * teex test cmds
 */

/*
 * in/out   params[0].value.a = pa/va
 * in       params[0].value.b = len
 * in       params[1].value.a = prot
 * in       params[1].value.b = attr
 */
#define TA_TEEX_CMD_MMAP		100

/*
 * in       params[0].value.a = va
 * in       params[0].value.b = len
 */
#define TA_TEEX_CMD_MUNMAP		101

/*
 * in       params[0].value.a = pa
 * in       params[0].value.b = len
 * in       params[1].value.a = attr
 * in       params[1].value.b = prot
 * in/out   params[2].memref = data
 */
#define TA_TEEX_CMD_ACCESS		102

/*
 * in       params[0].value.a = pa
 * in       params[0].value.b = len
 * in       params[1].value.a = dst
 * in       params[1].value.b = attr
 * out      params[2].memref = data
 */
#define TA_TEEX_CMD_COPY		103

/*
 * in/out   params[0].value.a = pa/result
 * in       params[0].value.b = len
 * in       params[1].value.a = pa2
 * in       params[1].value.b = attr
 */
#define TA_TEEX_CMD_CMP			104

/*
 * in/out   params[0].value.a = id/size
 * in       params[0].value.b = prot
 * in       params[1].memref = data
 */
#define TA_TEEX_CMD_OTPWRITE		105

/*
 * in       params[0].value.a = pa
 * in       params[0].value.b = size
 */
#define TA_TEEX_CMD_MEMSTATE		106

/*
 * in       params[0].value.a = object
 * in       params[0].value.b = keySize
 * in       params[1].memref = params
 */
#define TA_TEEX_CMD_KL_GENERATE_KEY	107
/*
 * in       params[0].value.a = index
 * in       params[0].value.b = eo
 * in       params[1].value.a = datum
 */
#define TA_TEEX_CMD_KL_GENERATE_TSP_KEY	108

#endif /*TA_TEEX_H */
