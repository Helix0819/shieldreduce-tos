#ifndef STOREENCLAVE_T_H__
#define STOREENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "constVar.h"
#include "chunkStructure.h"
#include "stdbool.h"
#include "sgx_key_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void Ecall_Init_Upload(int indexType);
void Ecall_Destroy_Upload(void);
void Ecall_Init_Restore(void);
void Ecall_Destroy_Restore(void);
void Ecall_ProcRecipeBatch(uint8_t* recipeBuffer, size_t recipeNum, ResOutSGX_t* resOutSGX);
void Ecall_ProcRecipeTailBatch(ResOutSGX_t* resOutSGX);
void Ecall_ProcChunkBatch(SendMsgBuffer_t* recvChunkBuffer, UpOutSGX_t* upOutSGX);
void Ecall_ProcTailChunkBatch(UpOutSGX_t* upOutSGX);
void Ecall_Init_Client(uint32_t clientID, int type, int optType, uint8_t* encMasterKey, void** sgxClient);
void Ecall_Destroy_Client(void* sgxClient);
sgx_status_t Ecall_Enclave_RA_Init(sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status);
sgx_status_t Ecall_Enclave_RA_Close(sgx_ra_context_t ctx);
void Ecall_Get_RA_Key_Hash(sgx_ra_context_t ctx, sgx_ra_key_type_t type);
void Ecall_Session_Key_Exchange(uint8_t* publicKeyBuffer, uint32_t clientID);
void Ecall_Enclave_Init(EnclaveConfig_t* enclaveConfig);
void Ecall_Enclave_Destroy(void);
void Ecall_GetEnclaveInfo(EnclaveInfo_t* info);
void Ecall_ProcOffline(SendMsgBuffer_t* recvChunkBuffer, UpOutSGX_t* upOutSGX);
void Ecall_GetOfflineInfo(EnclaveInfo_t* info);
void Ecall_UpdateOnlineInfo(void);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL Ocall_SGX_Exit_Error(const char* error_msg);
sgx_status_t SGX_CDECL Ocall_Printf(const char* str);
sgx_status_t SGX_CDECL Ocall_PrintfBinary(const uint8_t* buffer, size_t len);
sgx_status_t SGX_CDECL Ocall_WriteContainer(void* outClient);
sgx_status_t SGX_CDECL Ocall_WriteDeltaContainer(void* outClient);
sgx_status_t SGX_CDECL Ocall_UpdateIndexStoreBuffer(bool* ret, const char* key, size_t keySize, const uint8_t* buffer, size_t bufferSize);
sgx_status_t SGX_CDECL Ocall_UpdateIndexStoreSF(bool* ret, const char* key, size_t keySize, const uint8_t* buffer, size_t bufferSize);
sgx_status_t SGX_CDECL Ocall_ReadIndexStore(bool* ret, const char* key, size_t keySize, uint8_t** retVal, size_t* expectedRetValSize, void* outClient);
sgx_status_t SGX_CDECL Ocall_ReadIndexStoreBatch(bool* ret, const char* key, size_t keySize, uint8_t** retVal, size_t* expectedRetValSize, void* outClient);
sgx_status_t SGX_CDECL Ocall_InitWriteSealedFile(bool* ret, const char* sealedFileName);
sgx_status_t SGX_CDECL Ocall_CloseWriteSealedFile(const char* sealedFileName);
sgx_status_t SGX_CDECL Ocall_WriteSealedData(const char* sealedFileName, uint8_t* sealedDataBuffer, size_t sealedDataSize);
sgx_status_t SGX_CDECL Ocall_InitReadSealedFile(uint64_t* fileSize, const char* sealedFileName);
sgx_status_t SGX_CDECL Ocall_CloseReadSealedFile(const char* sealedFileName);
sgx_status_t SGX_CDECL Ocall_ReadSealedData(const char* sealedFileName, uint8_t* dataBuffer, uint32_t sealedDataSize);
sgx_status_t SGX_CDECL Ocall_GetCurrentTime(uint64_t* retTime);
sgx_status_t SGX_CDECL Ocall_GetReqContainers(void* outClient);
sgx_status_t SGX_CDECL Ocall_SendRestoreData(void* outClient);
sgx_status_t SGX_CDECL Ocall_QueryOutIndex(void* outClient);
sgx_status_t SGX_CDECL Ocall_UpdateOutIndex(void* outClient);
sgx_status_t SGX_CDECL Ocall_UpdateFileRecipe(void* outClient);
sgx_status_t SGX_CDECL Ocall_CreateUUID(uint8_t* id, size_t len);
sgx_status_t SGX_CDECL Ocall_QueryBaseIndex(void* outClient);
sgx_status_t SGX_CDECL Ocall_FreeContainer(void* outClient);
sgx_status_t SGX_CDECL Ocall_QueryOutBasechunk(void* outClient);
sgx_status_t SGX_CDECL Ocall_getRefContainer(void* outClient);
sgx_status_t SGX_CDECL Ocall_QueryDeltaIndex(void* outClient);
sgx_status_t SGX_CDECL Ocall_UpdateDeltaIndex(void* outClient, size_t chunkNum);
sgx_status_t SGX_CDECL Ocall_GetAllDeltaIndex(void* outClient);
sgx_status_t SGX_CDECL Ocall_UpdateDeltaIndexOnly(void* outClient, size_t chunkNum);
sgx_status_t SGX_CDECL Ocall_LocalInsert(void* outClient, size_t chunkNum);
sgx_status_t SGX_CDECL Ocall_GetLocal(void* outClient);
sgx_status_t SGX_CDECL Ocall_Localrevise(void* outClient);
sgx_status_t SGX_CDECL Ocall_SaveColdContainer(const char* containerID, uint8_t* containerBody, size_t currentSize, bool* delta_flag);
sgx_status_t SGX_CDECL Ocall_GetCold(void* outClient);
sgx_status_t SGX_CDECL Ocall_ColdInsert(void* outClient);
sgx_status_t SGX_CDECL Ocall_Coldrevise(void* outClient);
sgx_status_t SGX_CDECL Ocall_OFFline_updateIndex(void* outClient, size_t keySize);
sgx_status_t SGX_CDECL Ocall_OneRecipe(void* outClient);
sgx_status_t SGX_CDECL Ocall_OneContainer(void* outClient);
sgx_status_t SGX_CDECL Ocall_SavehotContainer(const char* containerID, uint8_t* containerBody, size_t currentSize);
sgx_status_t SGX_CDECL Ocall_SavehotBaseContainer(const char* containerID, uint8_t* containerBody, size_t currentSize);
sgx_status_t SGX_CDECL Ocall_OneDeltaContainer(void* outClient);
sgx_status_t SGX_CDECL Ocall_OneColdContainer(void* outClient, bool* delta_flag);
sgx_status_t SGX_CDECL Ocall_CleanLocalIndex(void);
sgx_status_t SGX_CDECL Ocall_GetMergeContainer(void* outClient);
sgx_status_t SGX_CDECL Ocall_CleanMerge(void* outClient);
sgx_status_t SGX_CDECL Ocall_GetMergePair(void* outClient, uint8_t* containerID, uint32_t* size);
sgx_status_t SGX_CDECL Ocall_MergeContent(void* outClient, uint8_t* containerBody, size_t currentSize);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
