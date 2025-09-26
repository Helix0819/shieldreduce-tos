#include "storeEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_Ecall_Init_Upload(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_Init_Upload_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_Init_Upload_t* ms = SGX_CAST(ms_Ecall_Init_Upload_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	Ecall_Init_Upload(ms->ms_indexType);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Destroy_Upload(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	Ecall_Destroy_Upload();
	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Init_Restore(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	Ecall_Init_Restore();
	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Destroy_Restore(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	Ecall_Destroy_Restore();
	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_ProcRecipeBatch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_ProcRecipeBatch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_ProcRecipeBatch_t* ms = SGX_CAST(ms_Ecall_ProcRecipeBatch_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_recipeBuffer = ms->ms_recipeBuffer;
	ResOutSGX_t* _tmp_resOutSGX = ms->ms_resOutSGX;



	Ecall_ProcRecipeBatch(_tmp_recipeBuffer, ms->ms_recipeNum, _tmp_resOutSGX);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_ProcRecipeTailBatch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_ProcRecipeTailBatch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_ProcRecipeTailBatch_t* ms = SGX_CAST(ms_Ecall_ProcRecipeTailBatch_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	ResOutSGX_t* _tmp_resOutSGX = ms->ms_resOutSGX;



	Ecall_ProcRecipeTailBatch(_tmp_resOutSGX);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_ProcChunkBatch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_ProcChunkBatch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_ProcChunkBatch_t* ms = SGX_CAST(ms_Ecall_ProcChunkBatch_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	SendMsgBuffer_t* _tmp_recvChunkBuffer = ms->ms_recvChunkBuffer;
	UpOutSGX_t* _tmp_upOutSGX = ms->ms_upOutSGX;



	Ecall_ProcChunkBatch(_tmp_recvChunkBuffer, _tmp_upOutSGX);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_ProcTailChunkBatch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_ProcTailChunkBatch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_ProcTailChunkBatch_t* ms = SGX_CAST(ms_Ecall_ProcTailChunkBatch_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	UpOutSGX_t* _tmp_upOutSGX = ms->ms_upOutSGX;



	Ecall_ProcTailChunkBatch(_tmp_upOutSGX);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Init_Client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_Init_Client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_Init_Client_t* ms = SGX_CAST(ms_Ecall_Init_Client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_encMasterKey = ms->ms_encMasterKey;
	void** _tmp_sgxClient = ms->ms_sgxClient;



	Ecall_Init_Client(ms->ms_clientID, ms->ms_type, ms->ms_optType, _tmp_encMasterKey, _tmp_sgxClient);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Destroy_Client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_Destroy_Client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_Destroy_Client_t* ms = SGX_CAST(ms_Ecall_Destroy_Client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_sgxClient = ms->ms_sgxClient;



	Ecall_Destroy_Client(_tmp_sgxClient);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Enclave_RA_Init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_Enclave_RA_Init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_Enclave_RA_Init_t* ms = SGX_CAST(ms_Ecall_Enclave_RA_Init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_ctx = ms->ms_ctx;
	size_t _len_ctx = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_ctx = NULL;
	sgx_status_t* _tmp_pse_status = ms->ms_pse_status;
	size_t _len_pse_status = sizeof(sgx_status_t);
	sgx_status_t* _in_pse_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ctx, _len_ctx);
	CHECK_UNIQUE_POINTER(_tmp_pse_status, _len_pse_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ctx != NULL && _len_ctx != 0) {
		if ((_in_ctx = (sgx_ra_context_t*)malloc(_len_ctx)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ctx, 0, _len_ctx);
	}
	if (_tmp_pse_status != NULL && _len_pse_status != 0) {
		if ((_in_pse_status = (sgx_status_t*)malloc(_len_pse_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pse_status, 0, _len_pse_status);
	}

	ms->ms_retval = Ecall_Enclave_RA_Init(ms->ms_key, ms->ms_b_pse, _in_ctx, _in_pse_status);
	if (_in_ctx) {
		if (memcpy_s(_tmp_ctx, _len_ctx, _in_ctx, _len_ctx)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pse_status) {
		if (memcpy_s(_tmp_pse_status, _len_pse_status, _in_pse_status, _len_pse_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ctx) free(_in_ctx);
	if (_in_pse_status) free(_in_pse_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Enclave_RA_Close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_Enclave_RA_Close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_Enclave_RA_Close_t* ms = SGX_CAST(ms_Ecall_Enclave_RA_Close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = Ecall_Enclave_RA_Close(ms->ms_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Get_RA_Key_Hash(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_Get_RA_Key_Hash_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_Get_RA_Key_Hash_t* ms = SGX_CAST(ms_Ecall_Get_RA_Key_Hash_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	Ecall_Get_RA_Key_Hash(ms->ms_ctx, ms->ms_type);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Session_Key_Exchange(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_Session_Key_Exchange_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_Session_Key_Exchange_t* ms = SGX_CAST(ms_Ecall_Session_Key_Exchange_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_publicKeyBuffer = ms->ms_publicKeyBuffer;



	Ecall_Session_Key_Exchange(_tmp_publicKeyBuffer, ms->ms_clientID);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Enclave_Init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_Enclave_Init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_Enclave_Init_t* ms = SGX_CAST(ms_Ecall_Enclave_Init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	EnclaveConfig_t* _tmp_enclaveConfig = ms->ms_enclaveConfig;



	Ecall_Enclave_Init(_tmp_enclaveConfig);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_Enclave_Destroy(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	Ecall_Enclave_Destroy();
	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_GetEnclaveInfo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_GetEnclaveInfo_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_GetEnclaveInfo_t* ms = SGX_CAST(ms_Ecall_GetEnclaveInfo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	EnclaveInfo_t* _tmp_info = ms->ms_info;



	Ecall_GetEnclaveInfo(_tmp_info);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_ProcOffline(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_ProcOffline_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_ProcOffline_t* ms = SGX_CAST(ms_Ecall_ProcOffline_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	SendMsgBuffer_t* _tmp_recvChunkBuffer = ms->ms_recvChunkBuffer;
	UpOutSGX_t* _tmp_upOutSGX = ms->ms_upOutSGX;



	Ecall_ProcOffline(_tmp_recvChunkBuffer, _tmp_upOutSGX);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_GetOfflineInfo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_Ecall_GetOfflineInfo_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_Ecall_GetOfflineInfo_t* ms = SGX_CAST(ms_Ecall_GetOfflineInfo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	EnclaveInfo_t* _tmp_info = ms->ms_info;



	Ecall_GetOfflineInfo(_tmp_info);


	return status;
}

static sgx_status_t SGX_CDECL sgx_Ecall_UpdateOnlineInfo(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	Ecall_UpdateOnlineInfo();
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}

	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
	if (_in_g_a) {
		if (memcpy_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}

	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[23];
} g_ecall_table = {
	23,
	{
		{(void*)(uintptr_t)sgx_Ecall_Init_Upload, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Destroy_Upload, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Init_Restore, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Destroy_Restore, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_ProcRecipeBatch, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_ProcRecipeTailBatch, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_ProcChunkBatch, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_ProcTailChunkBatch, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Init_Client, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Destroy_Client, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Enclave_RA_Init, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Enclave_RA_Close, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Get_RA_Key_Hash, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Session_Key_Exchange, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Enclave_Init, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_Enclave_Destroy, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_GetEnclaveInfo, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_ProcOffline, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_GetOfflineInfo, 0, 0},
		{(void*)(uintptr_t)sgx_Ecall_UpdateOnlineInfo, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[58][23];
} g_dyn_entry_table = {
	58,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL Ocall_SGX_Exit_Error(const char* error_msg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error_msg = error_msg ? strlen(error_msg) + 1 : 0;

	ms_Ocall_SGX_Exit_Error_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_SGX_Exit_Error_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(error_msg, _len_error_msg);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error_msg != NULL) ? _len_error_msg : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_SGX_Exit_Error_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_SGX_Exit_Error_t));
	ocalloc_size -= sizeof(ms_Ocall_SGX_Exit_Error_t);

	if (error_msg != NULL) {
		ms->ms_error_msg = (const char*)__tmp;
		if (_len_error_msg % sizeof(*error_msg) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, error_msg, _len_error_msg)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_error_msg);
		ocalloc_size -= _len_error_msg;
	} else {
		ms->ms_error_msg = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_Printf(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_Ocall_Printf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_Printf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_Printf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_Printf_t));
	ocalloc_size -= sizeof(ms_Ocall_Printf_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_PrintfBinary(const uint8_t* buffer, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = len;

	ms_Ocall_PrintfBinary_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_PrintfBinary_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_PrintfBinary_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_PrintfBinary_t));
	ocalloc_size -= sizeof(ms_Ocall_PrintfBinary_t);

	if (buffer != NULL) {
		ms->ms_buffer = (const uint8_t*)__tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_WriteContainer(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_WriteContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_WriteContainer_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_WriteContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_WriteContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_WriteContainer_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_WriteDeltaContainer(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_WriteDeltaContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_WriteDeltaContainer_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_WriteDeltaContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_WriteDeltaContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_WriteDeltaContainer_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_UpdateIndexStoreBuffer(bool* ret, const char* key, size_t keySize, const uint8_t* buffer, size_t bufferSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ret = sizeof(bool);
	size_t _len_key = keySize;
	size_t _len_buffer = bufferSize;

	ms_Ocall_UpdateIndexStoreBuffer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_UpdateIndexStoreBuffer_t);
	void *__tmp = NULL;

	void *__tmp_ret = NULL;

	CHECK_ENCLAVE_POINTER(ret, _len_ret);
	CHECK_ENCLAVE_POINTER(key, _len_key);
	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ret != NULL) ? _len_ret : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (key != NULL) ? _len_key : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_UpdateIndexStoreBuffer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_UpdateIndexStoreBuffer_t));
	ocalloc_size -= sizeof(ms_Ocall_UpdateIndexStoreBuffer_t);

	if (ret != NULL) {
		ms->ms_ret = (bool*)__tmp;
		__tmp_ret = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, ret, _len_ret)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ret);
		ocalloc_size -= _len_ret;
	} else {
		ms->ms_ret = NULL;
	}
	
	if (key != NULL) {
		ms->ms_key = (const char*)__tmp;
		if (_len_key % sizeof(*key) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, key, _len_key)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_key);
		ocalloc_size -= _len_key;
	} else {
		ms->ms_key = NULL;
	}
	
	ms->ms_keySize = keySize;
	if (buffer != NULL) {
		ms->ms_buffer = (const uint8_t*)__tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	ms->ms_bufferSize = bufferSize;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (ret) {
			if (memcpy_s((void*)ret, _len_ret, __tmp_ret, _len_ret)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_UpdateIndexStoreSF(bool* ret, const char* key, size_t keySize, const uint8_t* buffer, size_t bufferSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ret = sizeof(bool);
	size_t _len_key = keySize;
	size_t _len_buffer = bufferSize;

	ms_Ocall_UpdateIndexStoreSF_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_UpdateIndexStoreSF_t);
	void *__tmp = NULL;

	void *__tmp_ret = NULL;

	CHECK_ENCLAVE_POINTER(ret, _len_ret);
	CHECK_ENCLAVE_POINTER(key, _len_key);
	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ret != NULL) ? _len_ret : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (key != NULL) ? _len_key : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_UpdateIndexStoreSF_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_UpdateIndexStoreSF_t));
	ocalloc_size -= sizeof(ms_Ocall_UpdateIndexStoreSF_t);

	if (ret != NULL) {
		ms->ms_ret = (bool*)__tmp;
		__tmp_ret = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, ret, _len_ret)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ret);
		ocalloc_size -= _len_ret;
	} else {
		ms->ms_ret = NULL;
	}
	
	if (key != NULL) {
		ms->ms_key = (const char*)__tmp;
		if (_len_key % sizeof(*key) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, key, _len_key)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_key);
		ocalloc_size -= _len_key;
	} else {
		ms->ms_key = NULL;
	}
	
	ms->ms_keySize = keySize;
	if (buffer != NULL) {
		ms->ms_buffer = (const uint8_t*)__tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	ms->ms_bufferSize = bufferSize;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (ret) {
			if (memcpy_s((void*)ret, _len_ret, __tmp_ret, _len_ret)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_ReadIndexStore(bool* ret, const char* key, size_t keySize, uint8_t** retVal, size_t* expectedRetValSize, void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ret = sizeof(bool);
	size_t _len_key = keySize;
	size_t _len_retVal = sizeof(uint8_t*);
	size_t _len_expectedRetValSize = sizeof(size_t);

	ms_Ocall_ReadIndexStore_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_ReadIndexStore_t);
	void *__tmp = NULL;

	void *__tmp_ret = NULL;
	void *__tmp_retVal = NULL;
	void *__tmp_expectedRetValSize = NULL;

	CHECK_ENCLAVE_POINTER(ret, _len_ret);
	CHECK_ENCLAVE_POINTER(key, _len_key);
	CHECK_ENCLAVE_POINTER(retVal, _len_retVal);
	CHECK_ENCLAVE_POINTER(expectedRetValSize, _len_expectedRetValSize);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ret != NULL) ? _len_ret : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (key != NULL) ? _len_key : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (retVal != NULL) ? _len_retVal : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (expectedRetValSize != NULL) ? _len_expectedRetValSize : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_ReadIndexStore_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_ReadIndexStore_t));
	ocalloc_size -= sizeof(ms_Ocall_ReadIndexStore_t);

	if (ret != NULL) {
		ms->ms_ret = (bool*)__tmp;
		__tmp_ret = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, ret, _len_ret)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ret);
		ocalloc_size -= _len_ret;
	} else {
		ms->ms_ret = NULL;
	}
	
	if (key != NULL) {
		ms->ms_key = (const char*)__tmp;
		if (_len_key % sizeof(*key) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, key, _len_key)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_key);
		ocalloc_size -= _len_key;
	} else {
		ms->ms_key = NULL;
	}
	
	ms->ms_keySize = keySize;
	if (retVal != NULL) {
		ms->ms_retVal = (uint8_t**)__tmp;
		__tmp_retVal = __tmp;
		if (_len_retVal % sizeof(*retVal) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_retVal, 0, _len_retVal);
		__tmp = (void *)((size_t)__tmp + _len_retVal);
		ocalloc_size -= _len_retVal;
	} else {
		ms->ms_retVal = NULL;
	}
	
	if (expectedRetValSize != NULL) {
		ms->ms_expectedRetValSize = (size_t*)__tmp;
		__tmp_expectedRetValSize = __tmp;
		if (_len_expectedRetValSize % sizeof(*expectedRetValSize) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_expectedRetValSize, 0, _len_expectedRetValSize);
		__tmp = (void *)((size_t)__tmp + _len_expectedRetValSize);
		ocalloc_size -= _len_expectedRetValSize;
	} else {
		ms->ms_expectedRetValSize = NULL;
	}
	
	ms->ms_outClient = outClient;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (ret) {
			if (memcpy_s((void*)ret, _len_ret, __tmp_ret, _len_ret)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (retVal) {
			if (memcpy_s((void*)retVal, _len_retVal, __tmp_retVal, _len_retVal)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (expectedRetValSize) {
			if (memcpy_s((void*)expectedRetValSize, _len_expectedRetValSize, __tmp_expectedRetValSize, _len_expectedRetValSize)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_ReadIndexStoreBatch(bool* ret, const char* key, size_t keySize, uint8_t** retVal, size_t* expectedRetValSize, void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ret = sizeof(bool);
	size_t _len_key = keySize;
	size_t _len_retVal = sizeof(uint8_t*);
	size_t _len_expectedRetValSize = sizeof(size_t);

	ms_Ocall_ReadIndexStoreBatch_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_ReadIndexStoreBatch_t);
	void *__tmp = NULL;

	void *__tmp_ret = NULL;
	void *__tmp_retVal = NULL;
	void *__tmp_expectedRetValSize = NULL;

	CHECK_ENCLAVE_POINTER(ret, _len_ret);
	CHECK_ENCLAVE_POINTER(key, _len_key);
	CHECK_ENCLAVE_POINTER(retVal, _len_retVal);
	CHECK_ENCLAVE_POINTER(expectedRetValSize, _len_expectedRetValSize);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ret != NULL) ? _len_ret : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (key != NULL) ? _len_key : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (retVal != NULL) ? _len_retVal : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (expectedRetValSize != NULL) ? _len_expectedRetValSize : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_ReadIndexStoreBatch_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_ReadIndexStoreBatch_t));
	ocalloc_size -= sizeof(ms_Ocall_ReadIndexStoreBatch_t);

	if (ret != NULL) {
		ms->ms_ret = (bool*)__tmp;
		__tmp_ret = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, ret, _len_ret)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ret);
		ocalloc_size -= _len_ret;
	} else {
		ms->ms_ret = NULL;
	}
	
	if (key != NULL) {
		ms->ms_key = (const char*)__tmp;
		if (_len_key % sizeof(*key) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, key, _len_key)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_key);
		ocalloc_size -= _len_key;
	} else {
		ms->ms_key = NULL;
	}
	
	ms->ms_keySize = keySize;
	if (retVal != NULL) {
		ms->ms_retVal = (uint8_t**)__tmp;
		__tmp_retVal = __tmp;
		if (_len_retVal % sizeof(*retVal) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_retVal, 0, _len_retVal);
		__tmp = (void *)((size_t)__tmp + _len_retVal);
		ocalloc_size -= _len_retVal;
	} else {
		ms->ms_retVal = NULL;
	}
	
	if (expectedRetValSize != NULL) {
		ms->ms_expectedRetValSize = (size_t*)__tmp;
		__tmp_expectedRetValSize = __tmp;
		if (_len_expectedRetValSize % sizeof(*expectedRetValSize) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_expectedRetValSize, 0, _len_expectedRetValSize);
		__tmp = (void *)((size_t)__tmp + _len_expectedRetValSize);
		ocalloc_size -= _len_expectedRetValSize;
	} else {
		ms->ms_expectedRetValSize = NULL;
	}
	
	ms->ms_outClient = outClient;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (ret) {
			if (memcpy_s((void*)ret, _len_ret, __tmp_ret, _len_ret)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (retVal) {
			if (memcpy_s((void*)retVal, _len_retVal, __tmp_retVal, _len_retVal)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (expectedRetValSize) {
			if (memcpy_s((void*)expectedRetValSize, _len_expectedRetValSize, __tmp_expectedRetValSize, _len_expectedRetValSize)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_InitWriteSealedFile(bool* ret, const char* sealedFileName)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ret = sizeof(bool);
	size_t _len_sealedFileName = sealedFileName ? strlen(sealedFileName) + 1 : 0;

	ms_Ocall_InitWriteSealedFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_InitWriteSealedFile_t);
	void *__tmp = NULL;

	void *__tmp_ret = NULL;

	CHECK_ENCLAVE_POINTER(ret, _len_ret);
	CHECK_ENCLAVE_POINTER(sealedFileName, _len_sealedFileName);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ret != NULL) ? _len_ret : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealedFileName != NULL) ? _len_sealedFileName : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_InitWriteSealedFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_InitWriteSealedFile_t));
	ocalloc_size -= sizeof(ms_Ocall_InitWriteSealedFile_t);

	if (ret != NULL) {
		ms->ms_ret = (bool*)__tmp;
		__tmp_ret = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, ret, _len_ret)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ret);
		ocalloc_size -= _len_ret;
	} else {
		ms->ms_ret = NULL;
	}
	
	if (sealedFileName != NULL) {
		ms->ms_sealedFileName = (const char*)__tmp;
		if (_len_sealedFileName % sizeof(*sealedFileName) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealedFileName, _len_sealedFileName)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealedFileName);
		ocalloc_size -= _len_sealedFileName;
	} else {
		ms->ms_sealedFileName = NULL;
	}
	
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (ret) {
			if (memcpy_s((void*)ret, _len_ret, __tmp_ret, _len_ret)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_CloseWriteSealedFile(const char* sealedFileName)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealedFileName = sealedFileName ? strlen(sealedFileName) + 1 : 0;

	ms_Ocall_CloseWriteSealedFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_CloseWriteSealedFile_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealedFileName, _len_sealedFileName);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealedFileName != NULL) ? _len_sealedFileName : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_CloseWriteSealedFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_CloseWriteSealedFile_t));
	ocalloc_size -= sizeof(ms_Ocall_CloseWriteSealedFile_t);

	if (sealedFileName != NULL) {
		ms->ms_sealedFileName = (const char*)__tmp;
		if (_len_sealedFileName % sizeof(*sealedFileName) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealedFileName, _len_sealedFileName)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealedFileName);
		ocalloc_size -= _len_sealedFileName;
	} else {
		ms->ms_sealedFileName = NULL;
	}
	
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_WriteSealedData(const char* sealedFileName, uint8_t* sealedDataBuffer, size_t sealedDataSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealedFileName = sealedFileName ? strlen(sealedFileName) + 1 : 0;
	size_t _len_sealedDataBuffer = sealedDataSize;

	ms_Ocall_WriteSealedData_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_WriteSealedData_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealedFileName, _len_sealedFileName);
	CHECK_ENCLAVE_POINTER(sealedDataBuffer, _len_sealedDataBuffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealedFileName != NULL) ? _len_sealedFileName : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealedDataBuffer != NULL) ? _len_sealedDataBuffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_WriteSealedData_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_WriteSealedData_t));
	ocalloc_size -= sizeof(ms_Ocall_WriteSealedData_t);

	if (sealedFileName != NULL) {
		ms->ms_sealedFileName = (const char*)__tmp;
		if (_len_sealedFileName % sizeof(*sealedFileName) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealedFileName, _len_sealedFileName)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealedFileName);
		ocalloc_size -= _len_sealedFileName;
	} else {
		ms->ms_sealedFileName = NULL;
	}
	
	if (sealedDataBuffer != NULL) {
		ms->ms_sealedDataBuffer = (uint8_t*)__tmp;
		if (_len_sealedDataBuffer % sizeof(*sealedDataBuffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealedDataBuffer, _len_sealedDataBuffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealedDataBuffer);
		ocalloc_size -= _len_sealedDataBuffer;
	} else {
		ms->ms_sealedDataBuffer = NULL;
	}
	
	ms->ms_sealedDataSize = sealedDataSize;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_InitReadSealedFile(uint64_t* fileSize, const char* sealedFileName)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fileSize = sizeof(uint64_t);
	size_t _len_sealedFileName = sealedFileName ? strlen(sealedFileName) + 1 : 0;

	ms_Ocall_InitReadSealedFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_InitReadSealedFile_t);
	void *__tmp = NULL;

	void *__tmp_fileSize = NULL;

	CHECK_ENCLAVE_POINTER(fileSize, _len_fileSize);
	CHECK_ENCLAVE_POINTER(sealedFileName, _len_sealedFileName);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fileSize != NULL) ? _len_fileSize : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealedFileName != NULL) ? _len_sealedFileName : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_InitReadSealedFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_InitReadSealedFile_t));
	ocalloc_size -= sizeof(ms_Ocall_InitReadSealedFile_t);

	if (fileSize != NULL) {
		ms->ms_fileSize = (uint64_t*)__tmp;
		__tmp_fileSize = __tmp;
		if (_len_fileSize % sizeof(*fileSize) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, fileSize, _len_fileSize)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fileSize);
		ocalloc_size -= _len_fileSize;
	} else {
		ms->ms_fileSize = NULL;
	}
	
	if (sealedFileName != NULL) {
		ms->ms_sealedFileName = (const char*)__tmp;
		if (_len_sealedFileName % sizeof(*sealedFileName) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealedFileName, _len_sealedFileName)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealedFileName);
		ocalloc_size -= _len_sealedFileName;
	} else {
		ms->ms_sealedFileName = NULL;
	}
	
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (fileSize) {
			if (memcpy_s((void*)fileSize, _len_fileSize, __tmp_fileSize, _len_fileSize)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_CloseReadSealedFile(const char* sealedFileName)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealedFileName = sealedFileName ? strlen(sealedFileName) + 1 : 0;

	ms_Ocall_CloseReadSealedFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_CloseReadSealedFile_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealedFileName, _len_sealedFileName);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealedFileName != NULL) ? _len_sealedFileName : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_CloseReadSealedFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_CloseReadSealedFile_t));
	ocalloc_size -= sizeof(ms_Ocall_CloseReadSealedFile_t);

	if (sealedFileName != NULL) {
		ms->ms_sealedFileName = (const char*)__tmp;
		if (_len_sealedFileName % sizeof(*sealedFileName) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealedFileName, _len_sealedFileName)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealedFileName);
		ocalloc_size -= _len_sealedFileName;
	} else {
		ms->ms_sealedFileName = NULL;
	}
	
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_ReadSealedData(const char* sealedFileName, uint8_t* dataBuffer, uint32_t sealedDataSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealedFileName = sealedFileName ? strlen(sealedFileName) + 1 : 0;
	size_t _len_dataBuffer = sealedDataSize;

	ms_Ocall_ReadSealedData_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_ReadSealedData_t);
	void *__tmp = NULL;

	void *__tmp_dataBuffer = NULL;

	CHECK_ENCLAVE_POINTER(sealedFileName, _len_sealedFileName);
	CHECK_ENCLAVE_POINTER(dataBuffer, _len_dataBuffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealedFileName != NULL) ? _len_sealedFileName : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dataBuffer != NULL) ? _len_dataBuffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_ReadSealedData_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_ReadSealedData_t));
	ocalloc_size -= sizeof(ms_Ocall_ReadSealedData_t);

	if (sealedFileName != NULL) {
		ms->ms_sealedFileName = (const char*)__tmp;
		if (_len_sealedFileName % sizeof(*sealedFileName) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealedFileName, _len_sealedFileName)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealedFileName);
		ocalloc_size -= _len_sealedFileName;
	} else {
		ms->ms_sealedFileName = NULL;
	}
	
	if (dataBuffer != NULL) {
		ms->ms_dataBuffer = (uint8_t*)__tmp;
		__tmp_dataBuffer = __tmp;
		if (_len_dataBuffer % sizeof(*dataBuffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_dataBuffer, 0, _len_dataBuffer);
		__tmp = (void *)((size_t)__tmp + _len_dataBuffer);
		ocalloc_size -= _len_dataBuffer;
	} else {
		ms->ms_dataBuffer = NULL;
	}
	
	ms->ms_sealedDataSize = sealedDataSize;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (dataBuffer) {
			if (memcpy_s((void*)dataBuffer, _len_dataBuffer, __tmp_dataBuffer, _len_dataBuffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_GetCurrentTime(uint64_t* retTime)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_retTime = sizeof(uint64_t);

	ms_Ocall_GetCurrentTime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_GetCurrentTime_t);
	void *__tmp = NULL;

	void *__tmp_retTime = NULL;

	CHECK_ENCLAVE_POINTER(retTime, _len_retTime);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (retTime != NULL) ? _len_retTime : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_GetCurrentTime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_GetCurrentTime_t));
	ocalloc_size -= sizeof(ms_Ocall_GetCurrentTime_t);

	if (retTime != NULL) {
		ms->ms_retTime = (uint64_t*)__tmp;
		__tmp_retTime = __tmp;
		if (_len_retTime % sizeof(*retTime) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, retTime, _len_retTime)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_retTime);
		ocalloc_size -= _len_retTime;
	} else {
		ms->ms_retTime = NULL;
	}
	
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retTime) {
			if (memcpy_s((void*)retTime, _len_retTime, __tmp_retTime, _len_retTime)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_GetReqContainers(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_GetReqContainers_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_GetReqContainers_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_GetReqContainers_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_GetReqContainers_t));
	ocalloc_size -= sizeof(ms_Ocall_GetReqContainers_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_SendRestoreData(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_SendRestoreData_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_SendRestoreData_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_SendRestoreData_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_SendRestoreData_t));
	ocalloc_size -= sizeof(ms_Ocall_SendRestoreData_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_QueryOutIndex(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_QueryOutIndex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_QueryOutIndex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_QueryOutIndex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_QueryOutIndex_t));
	ocalloc_size -= sizeof(ms_Ocall_QueryOutIndex_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_UpdateOutIndex(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_UpdateOutIndex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_UpdateOutIndex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_UpdateOutIndex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_UpdateOutIndex_t));
	ocalloc_size -= sizeof(ms_Ocall_UpdateOutIndex_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_UpdateFileRecipe(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_UpdateFileRecipe_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_UpdateFileRecipe_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_UpdateFileRecipe_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_UpdateFileRecipe_t));
	ocalloc_size -= sizeof(ms_Ocall_UpdateFileRecipe_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_CreateUUID(uint8_t* id, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_id = len;

	ms_Ocall_CreateUUID_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_CreateUUID_t);
	void *__tmp = NULL;

	void *__tmp_id = NULL;

	CHECK_ENCLAVE_POINTER(id, _len_id);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (id != NULL) ? _len_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_CreateUUID_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_CreateUUID_t));
	ocalloc_size -= sizeof(ms_Ocall_CreateUUID_t);

	if (id != NULL) {
		ms->ms_id = (uint8_t*)__tmp;
		__tmp_id = __tmp;
		if (_len_id % sizeof(*id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_id, 0, _len_id);
		__tmp = (void *)((size_t)__tmp + _len_id);
		ocalloc_size -= _len_id;
	} else {
		ms->ms_id = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (id) {
			if (memcpy_s((void*)id, _len_id, __tmp_id, _len_id)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_QueryBaseIndex(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_QueryBaseIndex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_QueryBaseIndex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_QueryBaseIndex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_QueryBaseIndex_t));
	ocalloc_size -= sizeof(ms_Ocall_QueryBaseIndex_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_FreeContainer(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_FreeContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_FreeContainer_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_FreeContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_FreeContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_FreeContainer_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_QueryOutBasechunk(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_QueryOutBasechunk_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_QueryOutBasechunk_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_QueryOutBasechunk_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_QueryOutBasechunk_t));
	ocalloc_size -= sizeof(ms_Ocall_QueryOutBasechunk_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_getRefContainer(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_getRefContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_getRefContainer_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_getRefContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_getRefContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_getRefContainer_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_QueryDeltaIndex(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_QueryDeltaIndex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_QueryDeltaIndex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_QueryDeltaIndex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_QueryDeltaIndex_t));
	ocalloc_size -= sizeof(ms_Ocall_QueryDeltaIndex_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_UpdateDeltaIndex(void* outClient, size_t chunkNum)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_UpdateDeltaIndex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_UpdateDeltaIndex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_UpdateDeltaIndex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_UpdateDeltaIndex_t));
	ocalloc_size -= sizeof(ms_Ocall_UpdateDeltaIndex_t);

	ms->ms_outClient = outClient;
	ms->ms_chunkNum = chunkNum;
	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_GetAllDeltaIndex(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_GetAllDeltaIndex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_GetAllDeltaIndex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_GetAllDeltaIndex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_GetAllDeltaIndex_t));
	ocalloc_size -= sizeof(ms_Ocall_GetAllDeltaIndex_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_UpdateDeltaIndexOnly(void* outClient, size_t chunkNum)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_UpdateDeltaIndexOnly_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_UpdateDeltaIndexOnly_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_UpdateDeltaIndexOnly_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_UpdateDeltaIndexOnly_t));
	ocalloc_size -= sizeof(ms_Ocall_UpdateDeltaIndexOnly_t);

	ms->ms_outClient = outClient;
	ms->ms_chunkNum = chunkNum;
	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_LocalInsert(void* outClient, size_t chunkNum)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_LocalInsert_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_LocalInsert_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_LocalInsert_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_LocalInsert_t));
	ocalloc_size -= sizeof(ms_Ocall_LocalInsert_t);

	ms->ms_outClient = outClient;
	ms->ms_chunkNum = chunkNum;
	status = sgx_ocall(30, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_GetLocal(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_GetLocal_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_GetLocal_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_GetLocal_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_GetLocal_t));
	ocalloc_size -= sizeof(ms_Ocall_GetLocal_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(31, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_Localrevise(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_Localrevise_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_Localrevise_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_Localrevise_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_Localrevise_t));
	ocalloc_size -= sizeof(ms_Ocall_Localrevise_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_SaveColdContainer(const char* containerID, uint8_t* containerBody, size_t currentSize, bool* delta_flag)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_containerID = containerID ? strlen(containerID) + 1 : 0;
	size_t _len_containerBody = currentSize;
	size_t _len_delta_flag = sizeof(bool);

	ms_Ocall_SaveColdContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_SaveColdContainer_t);
	void *__tmp = NULL;

	void *__tmp_delta_flag = NULL;

	CHECK_ENCLAVE_POINTER(containerID, _len_containerID);
	CHECK_ENCLAVE_POINTER(containerBody, _len_containerBody);
	CHECK_ENCLAVE_POINTER(delta_flag, _len_delta_flag);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (containerID != NULL) ? _len_containerID : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (containerBody != NULL) ? _len_containerBody : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (delta_flag != NULL) ? _len_delta_flag : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_SaveColdContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_SaveColdContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_SaveColdContainer_t);

	if (containerID != NULL) {
		ms->ms_containerID = (const char*)__tmp;
		if (_len_containerID % sizeof(*containerID) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, containerID, _len_containerID)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_containerID);
		ocalloc_size -= _len_containerID;
	} else {
		ms->ms_containerID = NULL;
	}
	
	if (containerBody != NULL) {
		ms->ms_containerBody = (uint8_t*)__tmp;
		if (_len_containerBody % sizeof(*containerBody) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, containerBody, _len_containerBody)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_containerBody);
		ocalloc_size -= _len_containerBody;
	} else {
		ms->ms_containerBody = NULL;
	}
	
	ms->ms_currentSize = currentSize;
	if (delta_flag != NULL) {
		ms->ms_delta_flag = (bool*)__tmp;
		__tmp_delta_flag = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, delta_flag, _len_delta_flag)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_delta_flag);
		ocalloc_size -= _len_delta_flag;
	} else {
		ms->ms_delta_flag = NULL;
	}
	
	status = sgx_ocall(33, ms);

	if (status == SGX_SUCCESS) {
		if (delta_flag) {
			if (memcpy_s((void*)delta_flag, _len_delta_flag, __tmp_delta_flag, _len_delta_flag)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_GetCold(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_GetCold_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_GetCold_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_GetCold_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_GetCold_t));
	ocalloc_size -= sizeof(ms_Ocall_GetCold_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(34, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_ColdInsert(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_ColdInsert_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_ColdInsert_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_ColdInsert_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_ColdInsert_t));
	ocalloc_size -= sizeof(ms_Ocall_ColdInsert_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(35, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_Coldrevise(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_Coldrevise_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_Coldrevise_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_Coldrevise_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_Coldrevise_t));
	ocalloc_size -= sizeof(ms_Ocall_Coldrevise_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(36, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_OFFline_updateIndex(void* outClient, size_t keySize)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_OFFline_updateIndex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_OFFline_updateIndex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_OFFline_updateIndex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_OFFline_updateIndex_t));
	ocalloc_size -= sizeof(ms_Ocall_OFFline_updateIndex_t);

	ms->ms_outClient = outClient;
	ms->ms_keySize = keySize;
	status = sgx_ocall(37, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_OneRecipe(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_OneRecipe_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_OneRecipe_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_OneRecipe_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_OneRecipe_t));
	ocalloc_size -= sizeof(ms_Ocall_OneRecipe_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(38, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_OneContainer(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_OneContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_OneContainer_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_OneContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_OneContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_OneContainer_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(39, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_SavehotContainer(const char* containerID, uint8_t* containerBody, size_t currentSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_containerID = containerID ? strlen(containerID) + 1 : 0;
	size_t _len_containerBody = currentSize;

	ms_Ocall_SavehotContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_SavehotContainer_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(containerID, _len_containerID);
	CHECK_ENCLAVE_POINTER(containerBody, _len_containerBody);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (containerID != NULL) ? _len_containerID : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (containerBody != NULL) ? _len_containerBody : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_SavehotContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_SavehotContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_SavehotContainer_t);

	if (containerID != NULL) {
		ms->ms_containerID = (const char*)__tmp;
		if (_len_containerID % sizeof(*containerID) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, containerID, _len_containerID)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_containerID);
		ocalloc_size -= _len_containerID;
	} else {
		ms->ms_containerID = NULL;
	}
	
	if (containerBody != NULL) {
		ms->ms_containerBody = (uint8_t*)__tmp;
		if (_len_containerBody % sizeof(*containerBody) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, containerBody, _len_containerBody)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_containerBody);
		ocalloc_size -= _len_containerBody;
	} else {
		ms->ms_containerBody = NULL;
	}
	
	ms->ms_currentSize = currentSize;
	status = sgx_ocall(40, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_SavehotBaseContainer(const char* containerID, uint8_t* containerBody, size_t currentSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_containerID = containerID ? strlen(containerID) + 1 : 0;
	size_t _len_containerBody = currentSize;

	ms_Ocall_SavehotBaseContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_SavehotBaseContainer_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(containerID, _len_containerID);
	CHECK_ENCLAVE_POINTER(containerBody, _len_containerBody);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (containerID != NULL) ? _len_containerID : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (containerBody != NULL) ? _len_containerBody : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_SavehotBaseContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_SavehotBaseContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_SavehotBaseContainer_t);

	if (containerID != NULL) {
		ms->ms_containerID = (const char*)__tmp;
		if (_len_containerID % sizeof(*containerID) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, containerID, _len_containerID)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_containerID);
		ocalloc_size -= _len_containerID;
	} else {
		ms->ms_containerID = NULL;
	}
	
	if (containerBody != NULL) {
		ms->ms_containerBody = (uint8_t*)__tmp;
		if (_len_containerBody % sizeof(*containerBody) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, containerBody, _len_containerBody)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_containerBody);
		ocalloc_size -= _len_containerBody;
	} else {
		ms->ms_containerBody = NULL;
	}
	
	ms->ms_currentSize = currentSize;
	status = sgx_ocall(41, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_OneDeltaContainer(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_OneDeltaContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_OneDeltaContainer_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_OneDeltaContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_OneDeltaContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_OneDeltaContainer_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(42, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_OneColdContainer(void* outClient, bool* delta_flag)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_delta_flag = sizeof(bool);

	ms_Ocall_OneColdContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_OneColdContainer_t);
	void *__tmp = NULL;

	void *__tmp_delta_flag = NULL;

	CHECK_ENCLAVE_POINTER(delta_flag, _len_delta_flag);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (delta_flag != NULL) ? _len_delta_flag : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_OneColdContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_OneColdContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_OneColdContainer_t);

	ms->ms_outClient = outClient;
	if (delta_flag != NULL) {
		ms->ms_delta_flag = (bool*)__tmp;
		__tmp_delta_flag = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, delta_flag, _len_delta_flag)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_delta_flag);
		ocalloc_size -= _len_delta_flag;
	} else {
		ms->ms_delta_flag = NULL;
	}
	
	status = sgx_ocall(43, ms);

	if (status == SGX_SUCCESS) {
		if (delta_flag) {
			if (memcpy_s((void*)delta_flag, _len_delta_flag, __tmp_delta_flag, _len_delta_flag)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_CleanLocalIndex(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(44, NULL);

	return status;
}
sgx_status_t SGX_CDECL Ocall_GetMergeContainer(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_GetMergeContainer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_GetMergeContainer_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_GetMergeContainer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_GetMergeContainer_t));
	ocalloc_size -= sizeof(ms_Ocall_GetMergeContainer_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(45, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_CleanMerge(void* outClient)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Ocall_CleanMerge_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_CleanMerge_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_CleanMerge_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_CleanMerge_t));
	ocalloc_size -= sizeof(ms_Ocall_CleanMerge_t);

	ms->ms_outClient = outClient;
	status = sgx_ocall(46, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_GetMergePair(void* outClient, uint8_t* containerID, uint32_t* size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_containerID = 7;
	size_t _len_size = sizeof(uint32_t);

	ms_Ocall_GetMergePair_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_GetMergePair_t);
	void *__tmp = NULL;

	void *__tmp_containerID = NULL;
	void *__tmp_size = NULL;

	CHECK_ENCLAVE_POINTER(containerID, _len_containerID);
	CHECK_ENCLAVE_POINTER(size, _len_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (containerID != NULL) ? _len_containerID : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (size != NULL) ? _len_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_GetMergePair_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_GetMergePair_t));
	ocalloc_size -= sizeof(ms_Ocall_GetMergePair_t);

	ms->ms_outClient = outClient;
	if (containerID != NULL) {
		ms->ms_containerID = (uint8_t*)__tmp;
		__tmp_containerID = __tmp;
		if (_len_containerID % sizeof(*containerID) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, containerID, _len_containerID)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_containerID);
		ocalloc_size -= _len_containerID;
	} else {
		ms->ms_containerID = NULL;
	}
	
	if (size != NULL) {
		ms->ms_size = (uint32_t*)__tmp;
		__tmp_size = __tmp;
		if (_len_size % sizeof(*size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, size, _len_size)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_size);
		ocalloc_size -= _len_size;
	} else {
		ms->ms_size = NULL;
	}
	
	status = sgx_ocall(47, ms);

	if (status == SGX_SUCCESS) {
		if (containerID) {
			if (memcpy_s((void*)containerID, _len_containerID, __tmp_containerID, _len_containerID)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (size) {
			if (memcpy_s((void*)size, _len_size, __tmp_size, _len_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_MergeContent(void* outClient, uint8_t* containerBody, size_t currentSize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_containerBody = currentSize;

	ms_Ocall_MergeContent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_MergeContent_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(containerBody, _len_containerBody);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (containerBody != NULL) ? _len_containerBody : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_MergeContent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_MergeContent_t));
	ocalloc_size -= sizeof(ms_Ocall_MergeContent_t);

	ms->ms_outClient = outClient;
	if (containerBody != NULL) {
		ms->ms_containerBody = (uint8_t*)__tmp;
		if (_len_containerBody % sizeof(*containerBody) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, containerBody, _len_containerBody)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_containerBody);
		ocalloc_size -= _len_containerBody;
	} else {
		ms->ms_containerBody = NULL;
	}
	
	ms->ms_currentSize = currentSize;
	status = sgx_ocall(48, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(49, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(50, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(51, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(52, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(53, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(54, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_timeout = timeout;
	status = sgx_ocall(55, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(56, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(57, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

