#include "storeEnclave_u.h"
#include <errno.h>

typedef struct ms_Ecall_Init_Upload_t {
	int ms_indexType;
} ms_Ecall_Init_Upload_t;

typedef struct ms_Ecall_ProcRecipeBatch_t {
	uint8_t* ms_recipeBuffer;
	size_t ms_recipeNum;
	ResOutSGX_t* ms_resOutSGX;
} ms_Ecall_ProcRecipeBatch_t;

typedef struct ms_Ecall_ProcRecipeTailBatch_t {
	ResOutSGX_t* ms_resOutSGX;
} ms_Ecall_ProcRecipeTailBatch_t;

typedef struct ms_Ecall_ProcChunkBatch_t {
	SendMsgBuffer_t* ms_recvChunkBuffer;
	UpOutSGX_t* ms_upOutSGX;
} ms_Ecall_ProcChunkBatch_t;

typedef struct ms_Ecall_ProcTailChunkBatch_t {
	UpOutSGX_t* ms_upOutSGX;
} ms_Ecall_ProcTailChunkBatch_t;

typedef struct ms_Ecall_Init_Client_t {
	uint32_t ms_clientID;
	int ms_type;
	int ms_optType;
	uint8_t* ms_encMasterKey;
	void** ms_sgxClient;
} ms_Ecall_Init_Client_t;

typedef struct ms_Ecall_Destroy_Client_t {
	void* ms_sgxClient;
} ms_Ecall_Destroy_Client_t;

typedef struct ms_Ecall_Enclave_RA_Init_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t ms_key;
	int ms_b_pse;
	sgx_ra_context_t* ms_ctx;
	sgx_status_t* ms_pse_status;
} ms_Ecall_Enclave_RA_Init_t;

typedef struct ms_Ecall_Enclave_RA_Close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ctx;
} ms_Ecall_Enclave_RA_Close_t;

typedef struct ms_Ecall_Get_RA_Key_Hash_t {
	sgx_ra_context_t ms_ctx;
	sgx_ra_key_type_t ms_type;
} ms_Ecall_Get_RA_Key_Hash_t;

typedef struct ms_Ecall_Session_Key_Exchange_t {
	uint8_t* ms_publicKeyBuffer;
	uint32_t ms_clientID;
} ms_Ecall_Session_Key_Exchange_t;

typedef struct ms_Ecall_Enclave_Init_t {
	EnclaveConfig_t* ms_enclaveConfig;
} ms_Ecall_Enclave_Init_t;

typedef struct ms_Ecall_GetEnclaveInfo_t {
	EnclaveInfo_t* ms_info;
} ms_Ecall_GetEnclaveInfo_t;

typedef struct ms_Ecall_ProcOffline_t {
	SendMsgBuffer_t* ms_recvChunkBuffer;
	UpOutSGX_t* ms_upOutSGX;
} ms_Ecall_ProcOffline_t;

typedef struct ms_Ecall_GetOfflineInfo_t {
	EnclaveInfo_t* ms_info;
} ms_Ecall_GetOfflineInfo_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_Ocall_SGX_Exit_Error_t {
	const char* ms_error_msg;
} ms_Ocall_SGX_Exit_Error_t;

typedef struct ms_Ocall_Printf_t {
	const char* ms_str;
} ms_Ocall_Printf_t;

typedef struct ms_Ocall_PrintfBinary_t {
	const uint8_t* ms_buffer;
	size_t ms_len;
} ms_Ocall_PrintfBinary_t;

typedef struct ms_Ocall_WriteContainer_t {
	void* ms_outClient;
} ms_Ocall_WriteContainer_t;

typedef struct ms_Ocall_WriteDeltaContainer_t {
	void* ms_outClient;
} ms_Ocall_WriteDeltaContainer_t;

typedef struct ms_Ocall_UpdateIndexStoreBuffer_t {
	bool* ms_ret;
	const char* ms_key;
	size_t ms_keySize;
	const uint8_t* ms_buffer;
	size_t ms_bufferSize;
} ms_Ocall_UpdateIndexStoreBuffer_t;

typedef struct ms_Ocall_UpdateIndexStoreSF_t {
	bool* ms_ret;
	const char* ms_key;
	size_t ms_keySize;
	const uint8_t* ms_buffer;
	size_t ms_bufferSize;
} ms_Ocall_UpdateIndexStoreSF_t;

typedef struct ms_Ocall_ReadIndexStore_t {
	bool* ms_ret;
	const char* ms_key;
	size_t ms_keySize;
	uint8_t** ms_retVal;
	size_t* ms_expectedRetValSize;
	void* ms_outClient;
} ms_Ocall_ReadIndexStore_t;

typedef struct ms_Ocall_ReadIndexStoreBatch_t {
	bool* ms_ret;
	const char* ms_key;
	size_t ms_keySize;
	uint8_t** ms_retVal;
	size_t* ms_expectedRetValSize;
	void* ms_outClient;
} ms_Ocall_ReadIndexStoreBatch_t;

typedef struct ms_Ocall_InitWriteSealedFile_t {
	bool* ms_ret;
	const char* ms_sealedFileName;
} ms_Ocall_InitWriteSealedFile_t;

typedef struct ms_Ocall_CloseWriteSealedFile_t {
	const char* ms_sealedFileName;
} ms_Ocall_CloseWriteSealedFile_t;

typedef struct ms_Ocall_WriteSealedData_t {
	const char* ms_sealedFileName;
	uint8_t* ms_sealedDataBuffer;
	size_t ms_sealedDataSize;
} ms_Ocall_WriteSealedData_t;

typedef struct ms_Ocall_InitReadSealedFile_t {
	uint64_t* ms_fileSize;
	const char* ms_sealedFileName;
} ms_Ocall_InitReadSealedFile_t;

typedef struct ms_Ocall_CloseReadSealedFile_t {
	const char* ms_sealedFileName;
} ms_Ocall_CloseReadSealedFile_t;

typedef struct ms_Ocall_ReadSealedData_t {
	const char* ms_sealedFileName;
	uint8_t* ms_dataBuffer;
	uint32_t ms_sealedDataSize;
} ms_Ocall_ReadSealedData_t;

typedef struct ms_Ocall_GetCurrentTime_t {
	uint64_t* ms_retTime;
} ms_Ocall_GetCurrentTime_t;

typedef struct ms_Ocall_GetReqContainers_t {
	void* ms_outClient;
} ms_Ocall_GetReqContainers_t;

typedef struct ms_Ocall_SendRestoreData_t {
	void* ms_outClient;
} ms_Ocall_SendRestoreData_t;

typedef struct ms_Ocall_QueryOutIndex_t {
	void* ms_outClient;
} ms_Ocall_QueryOutIndex_t;

typedef struct ms_Ocall_UpdateOutIndex_t {
	void* ms_outClient;
} ms_Ocall_UpdateOutIndex_t;

typedef struct ms_Ocall_UpdateFileRecipe_t {
	void* ms_outClient;
} ms_Ocall_UpdateFileRecipe_t;

typedef struct ms_Ocall_CreateUUID_t {
	uint8_t* ms_id;
	size_t ms_len;
} ms_Ocall_CreateUUID_t;

typedef struct ms_Ocall_QueryBaseIndex_t {
	void* ms_outClient;
} ms_Ocall_QueryBaseIndex_t;

typedef struct ms_Ocall_FreeContainer_t {
	void* ms_outClient;
} ms_Ocall_FreeContainer_t;

typedef struct ms_Ocall_QueryOutBasechunk_t {
	void* ms_outClient;
} ms_Ocall_QueryOutBasechunk_t;

typedef struct ms_Ocall_getRefContainer_t {
	void* ms_outClient;
} ms_Ocall_getRefContainer_t;

typedef struct ms_Ocall_QueryDeltaIndex_t {
	void* ms_outClient;
} ms_Ocall_QueryDeltaIndex_t;

typedef struct ms_Ocall_UpdateDeltaIndex_t {
	void* ms_outClient;
	size_t ms_chunkNum;
} ms_Ocall_UpdateDeltaIndex_t;

typedef struct ms_Ocall_GetAllDeltaIndex_t {
	void* ms_outClient;
} ms_Ocall_GetAllDeltaIndex_t;

typedef struct ms_Ocall_UpdateDeltaIndexOnly_t {
	void* ms_outClient;
	size_t ms_chunkNum;
} ms_Ocall_UpdateDeltaIndexOnly_t;

typedef struct ms_Ocall_LocalInsert_t {
	void* ms_outClient;
	size_t ms_chunkNum;
} ms_Ocall_LocalInsert_t;

typedef struct ms_Ocall_GetLocal_t {
	void* ms_outClient;
} ms_Ocall_GetLocal_t;

typedef struct ms_Ocall_Localrevise_t {
	void* ms_outClient;
} ms_Ocall_Localrevise_t;

typedef struct ms_Ocall_SaveColdContainer_t {
	const char* ms_containerID;
	uint8_t* ms_containerBody;
	size_t ms_currentSize;
	bool* ms_delta_flag;
} ms_Ocall_SaveColdContainer_t;

typedef struct ms_Ocall_GetCold_t {
	void* ms_outClient;
} ms_Ocall_GetCold_t;

typedef struct ms_Ocall_ColdInsert_t {
	void* ms_outClient;
} ms_Ocall_ColdInsert_t;

typedef struct ms_Ocall_Coldrevise_t {
	void* ms_outClient;
} ms_Ocall_Coldrevise_t;

typedef struct ms_Ocall_OFFline_updateIndex_t {
	void* ms_outClient;
	size_t ms_keySize;
} ms_Ocall_OFFline_updateIndex_t;

typedef struct ms_Ocall_OneRecipe_t {
	void* ms_outClient;
} ms_Ocall_OneRecipe_t;

typedef struct ms_Ocall_OneContainer_t {
	void* ms_outClient;
} ms_Ocall_OneContainer_t;

typedef struct ms_Ocall_SavehotContainer_t {
	const char* ms_containerID;
	uint8_t* ms_containerBody;
	size_t ms_currentSize;
} ms_Ocall_SavehotContainer_t;

typedef struct ms_Ocall_SavehotBaseContainer_t {
	const char* ms_containerID;
	uint8_t* ms_containerBody;
	size_t ms_currentSize;
} ms_Ocall_SavehotBaseContainer_t;

typedef struct ms_Ocall_OneDeltaContainer_t {
	void* ms_outClient;
} ms_Ocall_OneDeltaContainer_t;

typedef struct ms_Ocall_OneColdContainer_t {
	void* ms_outClient;
	bool* ms_delta_flag;
} ms_Ocall_OneColdContainer_t;

typedef struct ms_Ocall_GetMergeContainer_t {
	void* ms_outClient;
} ms_Ocall_GetMergeContainer_t;

typedef struct ms_Ocall_CleanMerge_t {
	void* ms_outClient;
} ms_Ocall_CleanMerge_t;

typedef struct ms_Ocall_GetMergePair_t {
	void* ms_outClient;
	uint8_t* ms_containerID;
	uint32_t* ms_size;
} ms_Ocall_GetMergePair_t;

typedef struct ms_Ocall_MergeContent_t {
	void* ms_outClient;
	uint8_t* ms_containerBody;
	size_t ms_currentSize;
} ms_Ocall_MergeContent_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SGX_Exit_Error(void* pms)
{
	ms_Ocall_SGX_Exit_Error_t* ms = SGX_CAST(ms_Ocall_SGX_Exit_Error_t*, pms);
	Ocall_SGX_Exit_Error(ms->ms_error_msg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_Printf(void* pms)
{
	ms_Ocall_Printf_t* ms = SGX_CAST(ms_Ocall_Printf_t*, pms);
	Ocall_Printf(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_PrintfBinary(void* pms)
{
	ms_Ocall_PrintfBinary_t* ms = SGX_CAST(ms_Ocall_PrintfBinary_t*, pms);
	Ocall_PrintfBinary(ms->ms_buffer, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_WriteContainer(void* pms)
{
	ms_Ocall_WriteContainer_t* ms = SGX_CAST(ms_Ocall_WriteContainer_t*, pms);
	Ocall_WriteContainer(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_WriteDeltaContainer(void* pms)
{
	ms_Ocall_WriteDeltaContainer_t* ms = SGX_CAST(ms_Ocall_WriteDeltaContainer_t*, pms);
	Ocall_WriteDeltaContainer(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateIndexStoreBuffer(void* pms)
{
	ms_Ocall_UpdateIndexStoreBuffer_t* ms = SGX_CAST(ms_Ocall_UpdateIndexStoreBuffer_t*, pms);
	Ocall_UpdateIndexStoreBuffer(ms->ms_ret, ms->ms_key, ms->ms_keySize, ms->ms_buffer, ms->ms_bufferSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateIndexStoreSF(void* pms)
{
	ms_Ocall_UpdateIndexStoreSF_t* ms = SGX_CAST(ms_Ocall_UpdateIndexStoreSF_t*, pms);
	Ocall_UpdateIndexStoreSF(ms->ms_ret, ms->ms_key, ms->ms_keySize, ms->ms_buffer, ms->ms_bufferSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_ReadIndexStore(void* pms)
{
	ms_Ocall_ReadIndexStore_t* ms = SGX_CAST(ms_Ocall_ReadIndexStore_t*, pms);
	Ocall_ReadIndexStore(ms->ms_ret, ms->ms_key, ms->ms_keySize, ms->ms_retVal, ms->ms_expectedRetValSize, ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_ReadIndexStoreBatch(void* pms)
{
	ms_Ocall_ReadIndexStoreBatch_t* ms = SGX_CAST(ms_Ocall_ReadIndexStoreBatch_t*, pms);
	Ocall_ReadIndexStoreBatch(ms->ms_ret, ms->ms_key, ms->ms_keySize, ms->ms_retVal, ms->ms_expectedRetValSize, ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_InitWriteSealedFile(void* pms)
{
	ms_Ocall_InitWriteSealedFile_t* ms = SGX_CAST(ms_Ocall_InitWriteSealedFile_t*, pms);
	Ocall_InitWriteSealedFile(ms->ms_ret, ms->ms_sealedFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_CloseWriteSealedFile(void* pms)
{
	ms_Ocall_CloseWriteSealedFile_t* ms = SGX_CAST(ms_Ocall_CloseWriteSealedFile_t*, pms);
	Ocall_CloseWriteSealedFile(ms->ms_sealedFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_WriteSealedData(void* pms)
{
	ms_Ocall_WriteSealedData_t* ms = SGX_CAST(ms_Ocall_WriteSealedData_t*, pms);
	Ocall_WriteSealedData(ms->ms_sealedFileName, ms->ms_sealedDataBuffer, ms->ms_sealedDataSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_InitReadSealedFile(void* pms)
{
	ms_Ocall_InitReadSealedFile_t* ms = SGX_CAST(ms_Ocall_InitReadSealedFile_t*, pms);
	Ocall_InitReadSealedFile(ms->ms_fileSize, ms->ms_sealedFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_CloseReadSealedFile(void* pms)
{
	ms_Ocall_CloseReadSealedFile_t* ms = SGX_CAST(ms_Ocall_CloseReadSealedFile_t*, pms);
	Ocall_CloseReadSealedFile(ms->ms_sealedFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_ReadSealedData(void* pms)
{
	ms_Ocall_ReadSealedData_t* ms = SGX_CAST(ms_Ocall_ReadSealedData_t*, pms);
	Ocall_ReadSealedData(ms->ms_sealedFileName, ms->ms_dataBuffer, ms->ms_sealedDataSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetCurrentTime(void* pms)
{
	ms_Ocall_GetCurrentTime_t* ms = SGX_CAST(ms_Ocall_GetCurrentTime_t*, pms);
	Ocall_GetCurrentTime(ms->ms_retTime);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetReqContainers(void* pms)
{
	ms_Ocall_GetReqContainers_t* ms = SGX_CAST(ms_Ocall_GetReqContainers_t*, pms);
	Ocall_GetReqContainers(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SendRestoreData(void* pms)
{
	ms_Ocall_SendRestoreData_t* ms = SGX_CAST(ms_Ocall_SendRestoreData_t*, pms);
	Ocall_SendRestoreData(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_QueryOutIndex(void* pms)
{
	ms_Ocall_QueryOutIndex_t* ms = SGX_CAST(ms_Ocall_QueryOutIndex_t*, pms);
	Ocall_QueryOutIndex(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateOutIndex(void* pms)
{
	ms_Ocall_UpdateOutIndex_t* ms = SGX_CAST(ms_Ocall_UpdateOutIndex_t*, pms);
	Ocall_UpdateOutIndex(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateFileRecipe(void* pms)
{
	ms_Ocall_UpdateFileRecipe_t* ms = SGX_CAST(ms_Ocall_UpdateFileRecipe_t*, pms);
	Ocall_UpdateFileRecipe(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_CreateUUID(void* pms)
{
	ms_Ocall_CreateUUID_t* ms = SGX_CAST(ms_Ocall_CreateUUID_t*, pms);
	Ocall_CreateUUID(ms->ms_id, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_QueryBaseIndex(void* pms)
{
	ms_Ocall_QueryBaseIndex_t* ms = SGX_CAST(ms_Ocall_QueryBaseIndex_t*, pms);
	Ocall_QueryBaseIndex(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_FreeContainer(void* pms)
{
	ms_Ocall_FreeContainer_t* ms = SGX_CAST(ms_Ocall_FreeContainer_t*, pms);
	Ocall_FreeContainer(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_QueryOutBasechunk(void* pms)
{
	ms_Ocall_QueryOutBasechunk_t* ms = SGX_CAST(ms_Ocall_QueryOutBasechunk_t*, pms);
	Ocall_QueryOutBasechunk(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_getRefContainer(void* pms)
{
	ms_Ocall_getRefContainer_t* ms = SGX_CAST(ms_Ocall_getRefContainer_t*, pms);
	Ocall_getRefContainer(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_QueryDeltaIndex(void* pms)
{
	ms_Ocall_QueryDeltaIndex_t* ms = SGX_CAST(ms_Ocall_QueryDeltaIndex_t*, pms);
	Ocall_QueryDeltaIndex(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateDeltaIndex(void* pms)
{
	ms_Ocall_UpdateDeltaIndex_t* ms = SGX_CAST(ms_Ocall_UpdateDeltaIndex_t*, pms);
	Ocall_UpdateDeltaIndex(ms->ms_outClient, ms->ms_chunkNum);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetAllDeltaIndex(void* pms)
{
	ms_Ocall_GetAllDeltaIndex_t* ms = SGX_CAST(ms_Ocall_GetAllDeltaIndex_t*, pms);
	Ocall_GetAllDeltaIndex(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateDeltaIndexOnly(void* pms)
{
	ms_Ocall_UpdateDeltaIndexOnly_t* ms = SGX_CAST(ms_Ocall_UpdateDeltaIndexOnly_t*, pms);
	Ocall_UpdateDeltaIndexOnly(ms->ms_outClient, ms->ms_chunkNum);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_LocalInsert(void* pms)
{
	ms_Ocall_LocalInsert_t* ms = SGX_CAST(ms_Ocall_LocalInsert_t*, pms);
	Ocall_LocalInsert(ms->ms_outClient, ms->ms_chunkNum);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetLocal(void* pms)
{
	ms_Ocall_GetLocal_t* ms = SGX_CAST(ms_Ocall_GetLocal_t*, pms);
	Ocall_GetLocal(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_Localrevise(void* pms)
{
	ms_Ocall_Localrevise_t* ms = SGX_CAST(ms_Ocall_Localrevise_t*, pms);
	Ocall_Localrevise(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SaveColdContainer(void* pms)
{
	ms_Ocall_SaveColdContainer_t* ms = SGX_CAST(ms_Ocall_SaveColdContainer_t*, pms);
	Ocall_SaveColdContainer(ms->ms_containerID, ms->ms_containerBody, ms->ms_currentSize, ms->ms_delta_flag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetCold(void* pms)
{
	ms_Ocall_GetCold_t* ms = SGX_CAST(ms_Ocall_GetCold_t*, pms);
	Ocall_GetCold(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_ColdInsert(void* pms)
{
	ms_Ocall_ColdInsert_t* ms = SGX_CAST(ms_Ocall_ColdInsert_t*, pms);
	Ocall_ColdInsert(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_Coldrevise(void* pms)
{
	ms_Ocall_Coldrevise_t* ms = SGX_CAST(ms_Ocall_Coldrevise_t*, pms);
	Ocall_Coldrevise(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_OFFline_updateIndex(void* pms)
{
	ms_Ocall_OFFline_updateIndex_t* ms = SGX_CAST(ms_Ocall_OFFline_updateIndex_t*, pms);
	Ocall_OFFline_updateIndex(ms->ms_outClient, ms->ms_keySize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_OneRecipe(void* pms)
{
	ms_Ocall_OneRecipe_t* ms = SGX_CAST(ms_Ocall_OneRecipe_t*, pms);
	Ocall_OneRecipe(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_OneContainer(void* pms)
{
	ms_Ocall_OneContainer_t* ms = SGX_CAST(ms_Ocall_OneContainer_t*, pms);
	Ocall_OneContainer(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SavehotContainer(void* pms)
{
	ms_Ocall_SavehotContainer_t* ms = SGX_CAST(ms_Ocall_SavehotContainer_t*, pms);
	Ocall_SavehotContainer(ms->ms_containerID, ms->ms_containerBody, ms->ms_currentSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SavehotBaseContainer(void* pms)
{
	ms_Ocall_SavehotBaseContainer_t* ms = SGX_CAST(ms_Ocall_SavehotBaseContainer_t*, pms);
	Ocall_SavehotBaseContainer(ms->ms_containerID, ms->ms_containerBody, ms->ms_currentSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_OneDeltaContainer(void* pms)
{
	ms_Ocall_OneDeltaContainer_t* ms = SGX_CAST(ms_Ocall_OneDeltaContainer_t*, pms);
	Ocall_OneDeltaContainer(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_OneColdContainer(void* pms)
{
	ms_Ocall_OneColdContainer_t* ms = SGX_CAST(ms_Ocall_OneColdContainer_t*, pms);
	Ocall_OneColdContainer(ms->ms_outClient, ms->ms_delta_flag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_CleanLocalIndex(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	Ocall_CleanLocalIndex();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetMergeContainer(void* pms)
{
	ms_Ocall_GetMergeContainer_t* ms = SGX_CAST(ms_Ocall_GetMergeContainer_t*, pms);
	Ocall_GetMergeContainer(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_CleanMerge(void* pms)
{
	ms_Ocall_CleanMerge_t* ms = SGX_CAST(ms_Ocall_CleanMerge_t*, pms);
	Ocall_CleanMerge(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetMergePair(void* pms)
{
	ms_Ocall_GetMergePair_t* ms = SGX_CAST(ms_Ocall_GetMergePair_t*, pms);
	Ocall_GetMergePair(ms->ms_outClient, ms->ms_containerID, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_MergeContent(void* pms)
{
	ms_Ocall_MergeContent_t* ms = SGX_CAST(ms_Ocall_MergeContent_t*, pms);
	Ocall_MergeContent(ms->ms_outClient, ms->ms_containerBody, ms->ms_currentSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[58];
} ocall_table_storeEnclave = {
	58,
	{
		(void*)storeEnclave_Ocall_SGX_Exit_Error,
		(void*)storeEnclave_Ocall_Printf,
		(void*)storeEnclave_Ocall_PrintfBinary,
		(void*)storeEnclave_Ocall_WriteContainer,
		(void*)storeEnclave_Ocall_WriteDeltaContainer,
		(void*)storeEnclave_Ocall_UpdateIndexStoreBuffer,
		(void*)storeEnclave_Ocall_UpdateIndexStoreSF,
		(void*)storeEnclave_Ocall_ReadIndexStore,
		(void*)storeEnclave_Ocall_ReadIndexStoreBatch,
		(void*)storeEnclave_Ocall_InitWriteSealedFile,
		(void*)storeEnclave_Ocall_CloseWriteSealedFile,
		(void*)storeEnclave_Ocall_WriteSealedData,
		(void*)storeEnclave_Ocall_InitReadSealedFile,
		(void*)storeEnclave_Ocall_CloseReadSealedFile,
		(void*)storeEnclave_Ocall_ReadSealedData,
		(void*)storeEnclave_Ocall_GetCurrentTime,
		(void*)storeEnclave_Ocall_GetReqContainers,
		(void*)storeEnclave_Ocall_SendRestoreData,
		(void*)storeEnclave_Ocall_QueryOutIndex,
		(void*)storeEnclave_Ocall_UpdateOutIndex,
		(void*)storeEnclave_Ocall_UpdateFileRecipe,
		(void*)storeEnclave_Ocall_CreateUUID,
		(void*)storeEnclave_Ocall_QueryBaseIndex,
		(void*)storeEnclave_Ocall_FreeContainer,
		(void*)storeEnclave_Ocall_QueryOutBasechunk,
		(void*)storeEnclave_Ocall_getRefContainer,
		(void*)storeEnclave_Ocall_QueryDeltaIndex,
		(void*)storeEnclave_Ocall_UpdateDeltaIndex,
		(void*)storeEnclave_Ocall_GetAllDeltaIndex,
		(void*)storeEnclave_Ocall_UpdateDeltaIndexOnly,
		(void*)storeEnclave_Ocall_LocalInsert,
		(void*)storeEnclave_Ocall_GetLocal,
		(void*)storeEnclave_Ocall_Localrevise,
		(void*)storeEnclave_Ocall_SaveColdContainer,
		(void*)storeEnclave_Ocall_GetCold,
		(void*)storeEnclave_Ocall_ColdInsert,
		(void*)storeEnclave_Ocall_Coldrevise,
		(void*)storeEnclave_Ocall_OFFline_updateIndex,
		(void*)storeEnclave_Ocall_OneRecipe,
		(void*)storeEnclave_Ocall_OneContainer,
		(void*)storeEnclave_Ocall_SavehotContainer,
		(void*)storeEnclave_Ocall_SavehotBaseContainer,
		(void*)storeEnclave_Ocall_OneDeltaContainer,
		(void*)storeEnclave_Ocall_OneColdContainer,
		(void*)storeEnclave_Ocall_CleanLocalIndex,
		(void*)storeEnclave_Ocall_GetMergeContainer,
		(void*)storeEnclave_Ocall_CleanMerge,
		(void*)storeEnclave_Ocall_GetMergePair,
		(void*)storeEnclave_Ocall_MergeContent,
		(void*)storeEnclave_sgx_oc_cpuidex,
		(void*)storeEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)storeEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)storeEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)storeEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)storeEnclave_u_sgxssl_ftime,
		(void*)storeEnclave_pthread_wait_timeout_ocall,
		(void*)storeEnclave_pthread_create_ocall,
		(void*)storeEnclave_pthread_wakeup_ocall,
	}
};
sgx_status_t Ecall_Init_Upload(sgx_enclave_id_t eid, int indexType)
{
	sgx_status_t status;
	ms_Ecall_Init_Upload_t ms;
	ms.ms_indexType = indexType;
	status = sgx_ecall(eid, 0, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Destroy_Upload(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_Init_Restore(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_Destroy_Restore(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_ProcRecipeBatch(sgx_enclave_id_t eid, uint8_t* recipeBuffer, size_t recipeNum, ResOutSGX_t* resOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcRecipeBatch_t ms;
	ms.ms_recipeBuffer = recipeBuffer;
	ms.ms_recipeNum = recipeNum;
	ms.ms_resOutSGX = resOutSGX;
	status = sgx_ecall(eid, 4, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcRecipeTailBatch(sgx_enclave_id_t eid, ResOutSGX_t* resOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcRecipeTailBatch_t ms;
	ms.ms_resOutSGX = resOutSGX;
	status = sgx_ecall(eid, 5, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcChunkBatch(sgx_enclave_id_t eid, SendMsgBuffer_t* recvChunkBuffer, UpOutSGX_t* upOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcChunkBatch_t ms;
	ms.ms_recvChunkBuffer = recvChunkBuffer;
	ms.ms_upOutSGX = upOutSGX;
	status = sgx_ecall(eid, 6, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcTailChunkBatch(sgx_enclave_id_t eid, UpOutSGX_t* upOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcTailChunkBatch_t ms;
	ms.ms_upOutSGX = upOutSGX;
	status = sgx_ecall(eid, 7, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Init_Client(sgx_enclave_id_t eid, uint32_t clientID, int type, int optType, uint8_t* encMasterKey, void** sgxClient)
{
	sgx_status_t status;
	ms_Ecall_Init_Client_t ms;
	ms.ms_clientID = clientID;
	ms.ms_type = type;
	ms.ms_optType = optType;
	ms.ms_encMasterKey = encMasterKey;
	ms.ms_sgxClient = sgxClient;
	status = sgx_ecall(eid, 8, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Destroy_Client(sgx_enclave_id_t eid, void* sgxClient)
{
	sgx_status_t status;
	ms_Ecall_Destroy_Client_t ms;
	ms.ms_sgxClient = sgxClient;
	status = sgx_ecall(eid, 9, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Enclave_RA_Init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status)
{
	sgx_status_t status;
	ms_Ecall_Enclave_RA_Init_t ms;
	ms.ms_key = key;
	ms.ms_b_pse = b_pse;
	ms.ms_ctx = ctx;
	ms.ms_pse_status = pse_status;
	status = sgx_ecall(eid, 10, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Ecall_Enclave_RA_Close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t ctx)
{
	sgx_status_t status;
	ms_Ecall_Enclave_RA_Close_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 11, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Ecall_Get_RA_Key_Hash(sgx_enclave_id_t eid, sgx_ra_context_t ctx, sgx_ra_key_type_t type)
{
	sgx_status_t status;
	ms_Ecall_Get_RA_Key_Hash_t ms;
	ms.ms_ctx = ctx;
	ms.ms_type = type;
	status = sgx_ecall(eid, 12, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Session_Key_Exchange(sgx_enclave_id_t eid, uint8_t* publicKeyBuffer, uint32_t clientID)
{
	sgx_status_t status;
	ms_Ecall_Session_Key_Exchange_t ms;
	ms.ms_publicKeyBuffer = publicKeyBuffer;
	ms.ms_clientID = clientID;
	status = sgx_ecall(eid, 13, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Enclave_Init(sgx_enclave_id_t eid, EnclaveConfig_t* enclaveConfig)
{
	sgx_status_t status;
	ms_Ecall_Enclave_Init_t ms;
	ms.ms_enclaveConfig = enclaveConfig;
	status = sgx_ecall(eid, 14, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Enclave_Destroy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 15, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_GetEnclaveInfo(sgx_enclave_id_t eid, EnclaveInfo_t* info)
{
	sgx_status_t status;
	ms_Ecall_GetEnclaveInfo_t ms;
	ms.ms_info = info;
	status = sgx_ecall(eid, 16, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcOffline(sgx_enclave_id_t eid, SendMsgBuffer_t* recvChunkBuffer, UpOutSGX_t* upOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcOffline_t ms;
	ms.ms_recvChunkBuffer = recvChunkBuffer;
	ms.ms_upOutSGX = upOutSGX;
	status = sgx_ecall(eid, 17, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_GetOfflineInfo(sgx_enclave_id_t eid, EnclaveInfo_t* info)
{
	sgx_status_t status;
	ms_Ecall_GetOfflineInfo_t ms;
	ms.ms_info = info;
	status = sgx_ecall(eid, 18, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_UpdateOnlineInfo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 19, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 20, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 21, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 22, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

