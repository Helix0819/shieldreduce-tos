#include "../../include/ecallOffline.h"

int skip_num = 0;

void OFFLineBackward::Insert_local(string oldchunkhash, string newchunkhash)
{
    local_basemap[oldchunkhash] = newchunkhash;
    return;
}

OFFLineBackward::OFFLineBackward()
{
    // Allocate memory for the temporary containers
    tmpOldContainer = (uint8_t *)malloc(MAX_CONTAINER_SIZE);
    tmpNewContainer = (uint8_t *)malloc(MAX_CONTAINER_SIZE);
    tmpDeltaContainer = (uint8_t *)malloc(MAX_CONTAINER_SIZE);
    // tmpUseContainer = (uint8_t *)malloc(MAX_CONTAINER_SIZE);
    // tmpColdContainer = (uint8_t*)malloc(MAX_CONTAINER_SIZE);
}

OFFLineBackward::~OFFLineBackward()
{
    free(tmpOldContainer);
    free(tmpNewContainer);
    free(tmpDeltaContainer);
    // free(tmpUseContainer);
    // free(tmpColdContainer);
}

void OFFLineBackward::Print()
{
    int basechunk_num = 0;

    for (unordered_map<string, vector<string>>::iterator it = delta_map.begin(); it != delta_map.end(); it++)
    {
        basechunk_num += it->second.size();
    }

    // Enclave::Logging("deltamap", "delta map size is %d\n", basechunk_num);
}

void OFFLineBackward::Easy_update(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_)
{
    // 声明相关临时变量

    // Enclave::Logging("DEBUG", "easy update begin\n");
    EnclaveClient *sgxClient = (EnclaveClient *)upOutSGX->sgxClient;
    EVP_CIPHER_CTX *cipherCtx = sgxClient->_cipherCtx;
    OutQueryEntry_t *outEntry = upOutSGX->outQuery->outQueryBase;
    uint32_t processBufferCount = 0;
    badDelta = 0;
    // coldNewContainer_ = sgxClient->offline_coldNewContainer_;
    BaseLink_ = sgxClient->BaseLinkOffline_;
    psHTable_ = &(sgxClient->psHTableOffline_);
    psHTable2_ = sgxClient->psHTable2Offline_;
    cutEdelta_ = sgxClient->cutEdeltaOffline_;
    uint8_t *old_basechunksf = sgxClient->oldBasechunkSf_;
    uint8_t *new_basechunksf = sgxClient->newBasechunkSf_;
    uint8_t *tmp_basechunksf = sgxClient->tmpBasechunkSf_;
    old_recipe_ = sgxClient->oldRecipe_;
    new_recipe_ = sgxClient->newRecipe_;
    delta_recipe_ = sgxClient->deltaRecipe_;
    tmp_recipe_ = sgxClient->tmpRecipe_;
    offline_mergeNewContainer_ = sgxClient->offline_mergeNewContainer_;
    offline_mergeRecipeEnc_ = sgxClient->offline_mergeRecipeEnc_;
    offline_mergeRecipeDec_ = sgxClient->offline_mergeRecipeDec_;
    offline_oldChunkDecrypt_ = sgxClient->offline_oldChunkDecrypt_;
    offline_newChunkDecrypt_ = sgxClient->offline_newChunkDecrypt_;
    offline_oldChunkDecompression_ = sgxClient->offline_oldChunkDecompression_;
    offline_newChunkDecompression_ = sgxClient->offline_newChunkDecompression_;
    offline_deltaSFBuffer_ = sgxClient->offline_deltaSFBuffer_;
    offline_deltaIVBuffer_ = sgxClient->offline_deltaIVBuffer_;
    offline_deltaFPBuffer_ = sgxClient->offline_deltaFPBuffer_;
    offline_outRecipeBuffer_ = sgxClient->offline_outRecipeBuffer_;
    offline_oldIVBuffer_ = sgxClient->offline_oldIVBuffer_;
    offline_newIVBuffer_ = sgxClient->offline_newIVBuffer_;
    offline_tmpUniqueBuffer_ = sgxClient->offline_tmpUniqueBuffer_;
    offline_plainNewDeltaChunkBuffer_ = sgxClient->offline_plainNewDeltaChunkBuffer_;
    offline_newDeltaChunkEnc_ = sgxClient->offline_newDeltaChunkEnc_;
    offline_oldDeltaChunkDec_ = sgxClient->offline_oldDeltaChunkDec_;
    offline_oldDeltaChunkEnc_ = sgxClient->offline_oldDeltaChunkEnc_;
    encOldChunkBuffer_ = sgxClient->offline_encOldChunkBuffer_;
    encNewChunkBuffer_ = sgxClient->offline_encNewChunkBuffer_;
    offline_lz4CompressBuffer_ = sgxClient->offline_lz4CompressBuffer_;

    size_t counter = 0;
    string old_basechunkhash;
    old_basechunkhash.resize(CHUNK_HASH_SIZE, 0);
    string new_basechunkhash;
    new_basechunkhash.resize(CHUNK_HASH_SIZE, 0);
    string tmpNewChunkHash;
    tmpNewChunkHash.resize(CHUNK_HASH_SIZE, 0);

    // RecipeEntry_t* old_recipe = (RecipeEntry_t*)malloc(sizeof(RecipeEntry_t)); // store recipe for data chunk
    // if(!old_recipe)
    // {
    //     Enclave::Logging("malloc", "old recipe\n");
    // }
    // RecipeEntry_t* new_recipe = (RecipeEntry_t*)malloc(sizeof(RecipeEntry_t)); // store recipe for new base chunk
    // if(!new_recipe)
    // {
    //     Enclave::Logging("malloc", "new recipe\n");
    // }

    // uint8_t* old_basechunksf;
    // old_basechunksf = (uint8_t*)malloc(3*CHUNK_HASH_SIZE);
    // uint8_t* old_basechunkfp;
    // uint8_t* new_basechunksf;
    // new_basechunksf = (uint8_t*)malloc(3*CHUNK_HASH_SIZE);
    // uint8_t* new_basechunkfp;

    uint8_t *old_container;
    size_t old_container_size;
    // char* old_basecontainerID = (char*)malloc(CONTAINER_ID_LENGTH);
    string old_basecontainerID;
    old_basecontainerID.resize(CONTAINER_ID_LENGTH, 0);

    string optimal_basecontainerID;
    optimal_basecontainerID.resize(CONTAINER_ID_LENGTH, 0);

    uint8_t *new_container;
    size_t new_container_size;
    // char* new_basecontainerID = (char*)malloc(CONTAINER_ID_LENGTH);
    string new_basecontainerID;
    new_basecontainerID.resize(CONTAINER_ID_LENGTH, 0);

    pair<uint32_t, uint32_t> basepair;  // user for updating cold_basemap
    pair<uint32_t, uint32_t> deltapair; // same with above
    pair<uint32_t, uint32_t> optimalpair;

    string delta_chunkhash; // TODO
    delta_chunkhash.resize(CHUNK_HASH_SIZE, 0);
    // RecipeEntry_t* delta_recipe = (RecipeEntry_t*)malloc(sizeof(RecipeEntry_t)); // store recipe for delta chunk
    // if(!delta_recipe)
    // {
    //     Enclave::Logging("malloc", "delta recipe\n");
    // }
    uint8_t *delta_container;
    size_t delta_contaienr_size;

    uint8_t *old_basechunkFP;

    uint8_t *backbuffer = upOutSGX->test_buffer;
    /*     for(int i = 0;i<CHUNK_HASH_SIZE;i++){
            Enclave::Logging("DEBUG", "02x\n",backbuffer[0]);
        }
     */

    uint32_t backnum;
    GreeyOfflineSize = _offlineCurrBackup_size * GREEDY_THRESHOLD;
    uint64_t _onlineBackup_size = _offlineCurrBackup_size;

    // Enclave::Logging("DEBUG", "in\n");
    Ocall_GetLocal(upOutSGX->outClient);
    _offline_Ocall++;
    memcpy(&backnum, backbuffer, sizeof(uint32_t));
    Enclave::Logging("DEBUG", "out map size:%d\n", backnum);
    backbuffer += sizeof(uint32_t);

    while (backnum != 0)
    {
        for (int i = 0; i < backnum; i++)
        {
            string old_basechunkstr;
            string new_basechunkstr;
            old_basechunkstr.assign((char *)backbuffer, CHUNK_HASH_SIZE);
            backbuffer += CHUNK_HASH_SIZE;
            new_basechunkstr.assign((char *)backbuffer, CHUNK_HASH_SIZE);
            backbuffer += CHUNK_HASH_SIZE;
            local_basemap[old_basechunkstr] = new_basechunkstr;
        }
        backbuffer = upOutSGX->test_buffer;
        Ocall_GetLocal(upOutSGX->outClient);
        _offline_Ocall++;
        memcpy(&backnum, backbuffer, sizeof(uint32_t));
        // Enclave::Logging("DEBUG", "next batch size:%d\n",backnum);
        backbuffer += sizeof(uint32_t);

        if (local_basemap.size() != 0)
        {
            // Enclave::Logging("DEBUG", "local base map size is %d\n", local_basemap.size());
            for (unordered_map<string, string>::iterator it = local_basemap.begin(); it != local_basemap.end(); it++)
            {
                extension_sampledFeatureCounts_.clear();
                extension_chunkFeatures_.clear();
                if (GreeyOfflineSize >= _offlineCurrBackup_size)
                {
                    old_basechunkhash = it->first;
                    memcpy(&outEntry->chunkHash, (uint8_t *)&old_basechunkhash[0], CHUNK_HASH_SIZE);
                    Ocall_OneRecipe(upOutSGX->outClient);
                    cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)old_recipe_);
                    memcpy(old_basechunksf, &old_recipe_->superfeature, 3 * CHUNK_HASH_SIZE);
                    memcpy((uint8_t *)&outEntry->superfeature, old_basechunksf, 3 * CHUNK_HASH_SIZE);
                    Ocall_OFFline_updateIndex(upOutSGX->outClient, 0);

                    new_basechunkhash = it->second;
                    memcpy(&outEntry->chunkHash, (uint8_t *)&new_basechunkhash[0], CHUNK_HASH_SIZE);
                    Ocall_OneRecipe(upOutSGX->outClient);
                    cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)new_recipe_);
                    memcpy(new_basechunksf, &new_recipe_->superfeature, 3 * CHUNK_HASH_SIZE);
                    memcpy((uint8_t *)&outEntry->superfeature, new_basechunksf, 3 * CHUNK_HASH_SIZE);
                    Ocall_OFFline_updateIndex(upOutSGX->outClient, 1);

                    memset(upOutSGX->process_buffer, 0, 100000 * CHUNK_HASH_SIZE);
                    memcpy(upOutSGX->process_buffer, (uint8_t *)&old_basechunkhash[0], CHUNK_HASH_SIZE);
                    Ocall_QueryDeltaIndex(upOutSGX->outClient);

#if (QUICK_CHECK == 1)
                    uint8_t *Coldbuffer = upOutSGX->out_buffer;
                    uint32_t delete_offset = old_recipe->offset;
                    uint32_t delete_length = old_recipe->length +
                                             4 * CHUNK_HASH_SIZE + sizeof(RecipeEntry_t) + CRYPTO_BLOCK_SIZE;
                    memcpy(Coldbuffer, old_recipe->containerName, CONTAINER_ID_LENGTH);
                    Coldbuffer += CONTAINER_ID_LENGTH;
                    memcpy(Coldbuffer, &delete_offset, sizeof(uint32_t));
                    Coldbuffer += sizeof(uint32_t);
                    memcpy(Coldbuffer, &delete_length, sizeof(uint32_t));
                    Ocall_ColdInsert(upOutSGX->outClient);
                    // _offline_Ocall++;
#endif

                    _offline_Ocall++;
                    continue;
                }

                // Enclave::Logging("DEBUG", "Backup OnlineSize: %d, GreedyThresold: %f, GreedySize: %d, OfflineSize: %d\n",_onlineBackup_size,Greedy_thresold,GreeyOfflineSize,_offlineCurrBackup_size);

                // Enclave::Logging("debug", "Base begin\n");
                old_basechunkhash = it->first;
                // Get old chunk recipe
                memcpy(&outEntry->chunkHash, (uint8_t *)&old_basechunkhash[0], CHUNK_HASH_SIZE);
                Ocall_OneRecipe(upOutSGX->outClient);
                cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)old_recipe_);
                // Get old container
                // Enclave::Logging("DEBUG", "old container id is %s\n", old_recipe->containerName);
                // Enclave::Logging("DEBUG", "old recipe offset is %d\n", old_recipe->offset);
                memcpy(&outEntry->chunkAddr.containerName, old_recipe_->containerName, CONTAINER_ID_LENGTH);
                if (old_recipe_->deltaFlag == NO_DELTA)
                {
                    tmpBaseContainerID.assign((char *)old_recipe_->containerName, CONTAINER_ID_LENGTH);
                    curHotBaseContainerID.assign((char *)hot_base_container.containerID, CONTAINER_ID_LENGTH);
                    if (tmpBaseContainerID == curHotBaseContainerID)
                    {
                        memcpy(tmpOldContainer, hot_base_container.body, MAX_CONTAINER_SIZE);
                    }
                    else
                    {
                        // Enclave::Logging(myName_.c_str(), "load base container 1\n");
                        Ocall_OneContainer(upOutSGX->outClient);
                        if (outEntry->offlineFlag == false)
                        {
                            continue;
                        }
                        memcpy(tmpOldContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                    }
                }
                else
                {
                    tmpDeltaContainerID.assign((char *)old_recipe_->containerName, CONTAINER_ID_LENGTH);
                    curHotDeltaContainerID.assign((char *)hot_container.containerID, CONTAINER_ID_LENGTH);
                    if (tmpDeltaContainerID == curHotDeltaContainerID)
                    {
                        memcpy(tmpOldContainer, hot_container.body, MAX_CONTAINER_SIZE);
                    }
                    else
                    {
                        // Enclave::Logging(myName_.c_str(), "load delta container 1\n");
                        Ocall_OneDeltaContainer(upOutSGX->outClient);
                        if (outEntry->offlineFlag == false)
                        {
                            continue;
                        }
                        memcpy(tmpOldContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                    }
                }
                // Ocall_OneContainer(upOutSGX->outClient);
                // memcpy(tmpOldContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                old_container = tmpOldContainer;
                old_basecontainerID.assign((char *)&old_recipe_->containerName, CONTAINER_ID_LENGTH);
                // Get old chunk sf
                // old_basechunksf = GetChunk_SF(old_container, old_recipe);
                memcpy(old_basechunksf, &old_recipe_->superfeature, 3 * CHUNK_HASH_SIZE);
                memcpy((uint8_t *)&outEntry->superfeature, old_basechunksf, 3 * CHUNK_HASH_SIZE);

                /*         for(int i = 0;i<CHUNK_HASH_SIZE;i++){
                            Enclave::Logging("DEBUG", "%02x\n", old_basechunkFP[i]);
                            Enclave::Logging("DEBUG", "%02x\n", old_basechunkhash[i]);

                        } */

                // update sf index: remove old basechunksf

                Ocall_OFFline_updateIndex(upOutSGX->outClient, 0);

                // Enclave::Logging("DEBUG", "Old BaseChunk load finished\n");

                _offline_Ocall++;

                new_basechunkhash = it->second;
                // Get new chunk recipe
                memcpy(&outEntry->chunkHash, (uint8_t *)&new_basechunkhash[0], CHUNK_HASH_SIZE);
                Ocall_OneRecipe(upOutSGX->outClient);
                cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)new_recipe_);
                // Get new container
                memcpy(&outEntry->chunkAddr.containerName, new_recipe_->containerName, CONTAINER_ID_LENGTH);
                // Enclave::Logging(myName_.c_str(), "new base size is %d\n", new_recipe_->length);
                // new can be delta or base
                if (new_recipe_->deltaFlag == NO_DELTA)
                {
                    tmpBaseContainerID.assign((char *)new_recipe_->containerName, CONTAINER_ID_LENGTH);
                    curHotBaseContainerID.assign((char *)hot_base_container.containerID, CONTAINER_ID_LENGTH);
                    if (tmpBaseContainerID == curHotBaseContainerID)
                    {
                        memcpy(tmpNewContainer, hot_base_container.body, MAX_CONTAINER_SIZE);
                    }
                    else
                    {
                        // Enclave::Logging(myName_.c_str(), "load base container 2\n");
                        // PrintBinaryArray((uint8_t *)&new_basechunkhash[0], 4, true);
                        // Enclave::Logging(myName_.c_str(), "%02X\n", new_basechunkhash[0]);
                        Ocall_OneContainer(upOutSGX->outClient);
                        if (outEntry->offlineFlag == false)
                        {
                            badDelta++;
                            // Enclave::Logging("DEBUG", "bad delta num: %d\n", badDelta);
                            continue;
                        }
                        memcpy(tmpNewContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                    }
                }
                else
                {
                    // Enclave::Logging(myName_.c_str(), "new is delta\n");
                    tmpDeltaContainerID.assign((char *)new_recipe_->containerName, CONTAINER_ID_LENGTH);
                    curHotDeltaContainerID.assign((char *)hot_container.containerID, CONTAINER_ID_LENGTH);
                    if (tmpDeltaContainerID == curHotDeltaContainerID)
                    {
                        memcpy(tmpNewContainer, hot_container.body, MAX_CONTAINER_SIZE);
                    }
                    else
                    {
                        // Enclave::Logging(myName_.c_str(), "load delta container 2\n");
                        Ocall_OneDeltaContainer(upOutSGX->outClient);
                        if (outEntry->offlineFlag == false)
                        {
                            badDelta++;
                            // Enclave::Logging("DEBUG", "bad delta num: %d\n", badDelta);
                            continue;
                        }
                        memcpy(tmpNewContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                    }
                }
                _offline_Ocall++;
                // Ocall_OneContainer(upOutSGX->outClient);
                // if (outEntry->offlineFlag == false)
                // {
                //     skip_num++;
                //     // Enclave::Logging("DEBUG", "skip total num: %d\n", skip_num);
                //     continue;
                // }
                // memcpy(tmpNewContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                new_container = tmpNewContainer;
                new_basecontainerID.assign((char *)&new_recipe_->containerName, CONTAINER_ID_LENGTH);
                // Get new chunk sf
                new_basechunksf = GetChunk_SF(new_container, new_recipe_);

                // memcpy(new_basechunksf, &new_recipe_->superfeature, 3 * CHUNK_HASH_SIZE);
                // memcpy((uint8_t *)&outEntry->superfeature, new_basechunksf, 3 * CHUNK_HASH_SIZE);

                // update sf index: remove old basechunksf
                // memcpy((uint8_t *)&outEntry->superfeature, new_basechunksf, 3 * CHUNK_HASH_SIZE);
                // Ocall_OFFline_updateIndex(upOutSGX->outClient, 1);

                // _offline_Ocall++;

                // Enclave::Logging("DEBUG", "New BaseChunk load finished\n");

                // Enclave::Logging("debug", "Base chunk process begin\n");

                // Get original chunk content & update code base map
                uint8_t *old_chunk_content_crypt = GetChunk_content_buffer(old_container, old_recipe_, true, basepair, encOldChunkBuffer_);
                uint8_t *new_chunk_content_crypt = GetChunk_content_buffer(new_container, new_recipe_, false, basepair, encNewChunkBuffer_);

                uint8_t *old_chunk_IV = GetChunk_IV(old_container, old_recipe_, offline_oldIVBuffer_);
                uint8_t *new_chunk_IV = GetChunk_IV(new_container, new_recipe_, offline_newIVBuffer_);

                size_t old_chunk_size = old_recipe_->length;
                size_t new_chunk_size = new_recipe_->length;

                // Enclave::Logging("debug", "content iv\n");

                uint8_t *old_chunk_content_decrypt = offline_oldChunkDecrypt_;
                uint8_t *new_chunk_content_decrypt = offline_newChunkDecrypt_;

                // uint8_t* old_chunk_content_decrypt = (uint8_t *)malloc(MAX_CHUNK_SIZE); // store old chunk content after decryptyion
                // if(!old_chunk_content_decrypt)
                // {
                //     Enclave::Logging("malloc", "old_chunk_content_decrypt\n");
                // }
                // uint8_t* new_chunk_content_decrypt = (uint8_t *)malloc(MAX_CHUNK_SIZE); // store new chunk content after decryptyion
                // if(!new_chunk_content_decrypt)
                // {
                //     Enclave::Logging("malloc", "new_chunk_content_decrypt\n");
                // }
                cryptoObj_->DecryptionWithKeyIV(cipherCtx, old_chunk_content_crypt, old_chunk_size, // decrpytion
                                                Enclave::enclaveKey_, old_chunk_content_decrypt, old_chunk_IV);
                cryptoObj_->DecryptionWithKeyIV(cipherCtx, new_chunk_content_crypt, new_chunk_size,
                                                Enclave::enclaveKey_, new_chunk_content_decrypt, new_chunk_IV);

                // uint8_t *old_chunk_content_decompression = (uint8_t *)malloc(MAX_CHUNK_SIZE); // store old chunk content after decompression
                // uint8_t *new_chunk_content_decompression = (uint8_t *)malloc(MAX_CHUNK_SIZE); // store new chunk content after decompression
                uint8_t *old_chunk_content_decompression = offline_oldChunkDecompression_;
                uint8_t *new_chunk_content_decompression = offline_newChunkDecompression_;

                // Enclave::Logging("debug", "decrypt decompress\n");

                uint8_t *old_chunk;
                uint8_t *new_chunk;

                int old_refchunksize = LZ4_decompress_safe((char *)old_chunk_content_decrypt, (char *)old_chunk_content_decompression, old_chunk_size, MAX_CHUNK_SIZE);
                // int old_refchunksize = LZ4_decompress_fast((char*)old_chunk_content_decrypt, (char*)old_chunk_content_decompression, old_chunk_size);
                if (old_refchunksize < 0)
                {
                    // old_refchunksize < 0 means chunk didn't do compression
                    old_refchunksize = old_chunk_size;
                    old_chunk = old_chunk_content_decrypt;
                }
                else
                {
                    old_chunk = old_chunk_content_decompression;
                }
                // Enclave::Logging("DEBUG", "Old BaseChunk decompression finished\n");

                bool delta_flag = true; // TODO

                int new_refchunksize = LZ4_decompress_safe((char *)new_chunk_content_decrypt, (char *)new_chunk_content_decompression, new_chunk_size, MAX_CHUNK_SIZE);
                // // int new_refchunksize = LZ4_decompress_fast((char*)new_chunk_content_decrypt, (char*)new_chunk_content_decompression, new_chunk_size);
                if (new_refchunksize < 0)
                {
                    // old_refchunksize < 0 means chunk didn't do compression
                    new_refchunksize = new_chunk_size;
                    new_chunk = new_chunk_content_decrypt;
                }
                else
                {
                    new_chunk = new_chunk_content_decompression;
                }
                // Enclave::Logging("DEBUG", "New BaseChunk decompression finished\n");

                // Enclave::Logging("debug", "Base mark\n");

                memset(upOutSGX->process_buffer, 0, 100000 * CHUNK_HASH_SIZE);
                memcpy(upOutSGX->process_buffer, (uint8_t *)&old_basechunkhash[0], CHUNK_HASH_SIZE);
                Ocall_QueryDeltaIndex(upOutSGX->outClient);
                int delta_index_num = upOutSGX->deltaInfo->QueryNum;
                if (delta_index_num != 0)
                {
                    for (int i = 0; i < delta_index_num; i++)
                    {
                        string tmpDelta;
                        tmpDelta.assign((char *)upOutSGX->process_buffer + (i + 1) * CHUNK_HASH_SIZE, CHUNK_HASH_SIZE);
                        Insert_delta(old_basechunkhash, tmpDelta);
                    }
                }

                vector<string> candidateGroup;
                string optimalBaseChunkHash;
                candidateGroup.push_back(old_basechunkhash);
                candidateGroup.push_back(new_basechunkhash);
                auto delta_it = delta_map.find(old_basechunkhash);
                // Enclave::Logging("DEBUG","delta map size is %d\n", delta_map[old_basechunkhash].size());
                // counter += delta_map[old_basechunkhash].size();
                // select new basechunk for delta chunk
                if (delta_it != delta_map.end())
                {
                    candidateGroup.insert(candidateGroup.end(), delta_it->second.begin(), delta_it->second.end());
                }
                Ocall_GetCurrentTime(&_startTimeOffline);
                optimalBaseChunkHash = SelectOptimalBaseChunk(candidateGroup, upOutSGX, cryptoObj_, old_chunk, old_refchunksize, new_chunk, new_refchunksize);
                Ocall_GetCurrentTime(&_endTimeOffline);
                selectOptimalBaseTime += (_endTimeOffline - _startTimeOffline);
                selectOptimalBaseCount++;
                // if (optimalBaseChunkHash != new_basechunkhash)
                // {
                //     Enclave::Logging("DEBUG", "unlike backward\n");
                // }
                Enclave::Logging(myName_.c_str(), "select optimal base chunk done\n");
                // load optimal new base chunk
                memcpy(&outEntry->chunkHash, (uint8_t *)&optimalBaseChunkHash[0], CHUNK_HASH_SIZE);
                Ocall_OneRecipe(upOutSGX->outClient);
                cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)new_recipe_);
                // Enclave::Logging(myName_.c_str(), "2 new base size is %d", new_recipe_->length);
                // Get new container
                memcpy(&outEntry->chunkAddr.containerName, new_recipe_->containerName, CONTAINER_ID_LENGTH);
                uint8_t *optimal_chunk;
                uint8_t *optimal_chunk_IV;
                uint8_t *optimal_chunk_SF;
                uint8_t *optimal_chunk_FP;
                uint8_t *optimal_chunk_content_crypt;
                uint8_t *optimal_chunk_content_decrypt;
                uint8_t *optimal_chunk_content_decompression;
                int optimal_chunk_size = new_recipe_->length;
                // Enclave::Logging(myName_.c_str(), "optimal chunk size is %d\n", optimal_chunk_size);
                int optimal_refchunksize;
                optimal_basecontainerID.assign((char *)&new_recipe_->containerName, CONTAINER_ID_LENGTH);
                if (new_recipe_->deltaFlag == NO_DELTA)
                {
                    // Enclave::Logging("debug", "optimal is base\n");
                    tmpBaseContainerID.assign((char *)new_recipe_->containerName, CONTAINER_ID_LENGTH);
                    curHotBaseContainerID.assign((char *)hot_base_container.containerID, CONTAINER_ID_LENGTH);
                    if (tmpBaseContainerID == curHotBaseContainerID)
                    {
                        memcpy(tmpNewContainer, hot_base_container.body, MAX_CONTAINER_SIZE);
                    }
                    else
                    {
                        Ocall_OneContainer(upOutSGX->outClient);
                        if (outEntry->offlineFlag == false)
                        {
                            badDelta++;
                            // Enclave::Logging("DEBUG", "bad delta num: %d\n", badDelta);
                            continue;
                        }
                        memcpy(tmpNewContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                    }
                    // Ocall_OneContainer(upOutSGX->outClient);
                    // memcpy(tmpNewContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                    optimal_chunk_content_crypt = GetChunk_content_buffer(tmpNewContainer, new_recipe_, true, optimalpair, encNewChunkBuffer_);
                    optimal_chunk_IV = GetChunk_IV(tmpNewContainer, new_recipe_, offline_newIVBuffer_);
                    optimal_chunk_SF = GetChunk_SF(tmpNewContainer, new_recipe_);
                    optimal_chunk_FP = GetChunk_FP(tmpNewContainer, new_recipe_);
                    optimal_chunk_content_decrypt = offline_newChunkDecrypt_;
                    cryptoObj_->DecryptionWithKeyIV(cipherCtx, optimal_chunk_content_crypt, optimal_chunk_size, Enclave::enclaveKey_, optimal_chunk_content_decrypt, optimal_chunk_IV);
                    optimal_chunk_content_decompression = offline_newChunkDecompression_;
                    optimal_refchunksize = LZ4_decompress_safe((char *)optimal_chunk_content_decrypt, (char *)optimal_chunk_content_decompression, optimal_chunk_size, MAX_CHUNK_SIZE);
                    // Enclave::Logging("DEBUG", "optimal BaseChunk decompression finished, ref size is %d\n", optimal_refchunksize);
                    if (optimal_refchunksize < 0)
                    {
                        // old_refchunksize < 0 means chunk didn't do compression
                        optimal_refchunksize = optimal_chunk_size;
                        optimal_chunk = optimal_chunk_content_decrypt;
                    }
                    else
                    {
                        optimal_chunk = optimal_chunk_content_decompression;
                    }

                    if (optimalBaseChunkHash == old_basechunkhash)
                    {
                        uint8_t *Coldbuffer = upOutSGX->out_buffer;
                        memcpy(Coldbuffer, &optimal_basecontainerID[0], CONTAINER_ID_LENGTH);
                        Coldbuffer += CONTAINER_ID_LENGTH;
                        memcpy(Coldbuffer, &optimalpair.first, sizeof(uint32_t));
                        Coldbuffer += sizeof(uint32_t);
                        memcpy(Coldbuffer, &optimalpair.second, sizeof(uint32_t));
                        Ocall_ColdInsert(upOutSGX->outClient);
                        _offline_Ocall++;
                    }
                }
                else
                {
                    // Enclave::Logging("debug", "optimal is delta\n");
                    Ocall_OneDeltaContainer(upOutSGX->outClient);
                    memcpy(tmpNewContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                    optimal_chunk_content_crypt = GetChunk_content_buffer(tmpNewContainer, new_recipe_, true, optimalpair, encNewChunkBuffer_);
                    optimal_chunk_IV = GetChunk_IV(tmpNewContainer, new_recipe_, offline_newIVBuffer_);
                    optimal_chunk_SF = GetChunk_SF(tmpNewContainer, new_recipe_);
                    optimal_chunk_FP = GetChunk_FP(tmpNewContainer, new_recipe_);
                    optimal_chunk_content_decrypt = offline_newChunkDecrypt_;
                    cryptoObj_->DecryptionWithKeyIV(cipherCtx, optimal_chunk_content_crypt, optimal_chunk_size, Enclave::enclaveKey_, optimal_chunk_content_decrypt, optimal_chunk_IV);
                    optimal_chunk_content_decompression = offline_newChunkDecompression_;
                    size_t tmp_delta_size;
                    uint8_t *tmpDecodeChunk = ed3_decode_buffer(optimal_chunk_content_decrypt, optimal_chunk_size, old_chunk, old_refchunksize, optimal_chunk_content_decompression, &tmp_delta_size);
                    optimal_refchunksize = tmp_delta_size;
                    optimal_chunk = optimal_chunk_content_decompression;
                    _deltaChunkNum--;
                    _baseChunkNum++;
                    if (optimalBaseChunkHash == old_basechunkhash)
                    {
                        uint8_t *Coldbuffer = upOutSGX->out_buffer;
                        memcpy(Coldbuffer, &optimal_basecontainerID[0], CONTAINER_ID_LENGTH);
                        Coldbuffer += CONTAINER_ID_LENGTH;
                        memcpy(Coldbuffer, &optimalpair.first, sizeof(uint32_t));
                        Coldbuffer += sizeof(uint32_t);
                        memcpy(Coldbuffer, &optimalpair.second, sizeof(uint32_t));
                        Ocall_ColdInsert(upOutSGX->outClient);
                        _offline_Ocall++;
                    }
                }
                // Enclave::Logging("DEBUG", "optimal ref size is: %d\n", optimal_refchunksize);
                Enclave::Logging(myName_.c_str(), "load optimal base chunk done\n");
                memcpy(new_basechunksf, &new_recipe_->superfeature, 3 * CHUNK_HASH_SIZE);
                memcpy((uint8_t *)&outEntry->superfeature, new_basechunksf, 3 * CHUNK_HASH_SIZE);
                Ocall_OFFline_updateIndex(upOutSGX->outClient, 1);
                _offline_Ocall++;
                Enclave::Logging(myName_.c_str(), "update optimal base chunk index store done\n");
                // if (delta_it != delta_map.end() && optimalBaseChunkHash != old_basechunkhash) // exist in delta map
                if (delta_it != delta_map.end())
                {
                    // Enclave::Logging("debug", "Delta begin\n");
                    // Enclave::Logging("DEBUG", "processing delta chunk begin\n");
                    for (size_t i = 0; i < delta_map[old_basechunkhash].size(); i++)
                    {
                        if (delta_map[old_basechunkhash][i] == optimalBaseChunkHash)
                            continue;
                        bool tmp_delta_flag = true;
                        // Get delta chunk recipe
                        delta_chunkhash = delta_map[old_basechunkhash][i];
                        memcpy(&outEntry->chunkHash, (uint8_t *)&delta_chunkhash[0], CHUNK_HASH_SIZE);
                        Ocall_OneRecipe(upOutSGX->outClient);
                        // Enclave::Logging("DEBUG", "Get delta chunk recipe\n");
                        cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)delta_recipe_);
                        //  Get delta chunk container
                        string delta_containerID;
                        delta_containerID.resize(CONTAINER_ID_LENGTH, 0);
                        delta_containerID.assign((char *)&delta_recipe_->containerName, CONTAINER_ID_LENGTH);
                        memcpy(&outEntry->chunkAddr.containerName, delta_recipe_->containerName, CONTAINER_ID_LENGTH);
                        // Enclave::Logging("DEBUG", "delta recipe container name is %s\n", delta_containerID.c_str());
#if (CONTAINER_SEPARATE == 1)
                        if (delta_recipe_->deltaFlag == NO_DELTA)
                        {
                            Ocall_OneContainer(upOutSGX->outClient);
                        }
                        else
                        {
                            Ocall_OneDeltaContainer(upOutSGX->outClient);
                        }
                        // Ocall_OneDeltaContainer(upOutSGX->outClient);
#else
                        Ocall_OneContainer(upOutSGX->outClient);
#endif
                        _offline_Ocall++;
                        memcpy(tmpDeltaContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                        delta_container = tmpDeltaContainer;
                        // Enclave::Logging("DEBUG", "Get delta chunk container\n");
                        //  Get delta chunk fp & sf & Iv
                        uint8_t *delta_fp = GetChunk_FP(delta_container, delta_recipe_);
                        uint8_t *delta_sf = GetChunk_SF(delta_container, delta_recipe_);
                        uint8_t *delta_iv = GetChunk_IV(delta_container, delta_recipe_, offline_deltaIVBuffer_);
                        // Enclave::Logging("DEBUG", "Get delta chunk fp sf iv\n");
                        //  Get delta chunk content
                        uint8_t *delta_chunk_content_crypt = GetChunk_content_buffer(delta_container, delta_recipe_, true, deltapair, offline_oldDeltaChunkEnc_);
                        // uint8_t* delta_chunk_content_decrypt = (uint8_t*)malloc(MAX_CHUNK_SIZE);
                        uint8_t *delta_chunk_content_decrypt = offline_oldDeltaChunkDec_;
                        size_t delta_size = delta_recipe_->length;
                        cryptoObj_->DecryptionWithKeyIV(cipherCtx, delta_chunk_content_crypt, delta_size,
                                                        Enclave::enclaveKey_, delta_chunk_content_decrypt, delta_iv);
                        // Enclave::Logging("DEBUG", "Get delta chunk content\n");

                        uint8_t *new_delta_content;
                        size_t new_chunk_size = 0;
                        // Get new delta chunk: do delta compression based on new basechunk
                        if (delta_recipe_->deltaFlag == NO_DELTA)
                        {
                            new_delta_content = GetNew_deltachunk(delta_chunk_content_decrypt, delta_size, old_chunk, old_refchunksize, optimal_chunk, optimal_refchunksize, &new_chunk_size, tmp_delta_flag, true);
                        }
                        else
                        {
                            new_delta_content = GetNew_deltachunk(delta_chunk_content_decrypt, delta_size, old_chunk, old_refchunksize, optimal_chunk, optimal_refchunksize, &new_chunk_size, tmp_delta_flag, false);
                        }
                        // new_delta_content = GetNew_deltachunk(delta_chunk_content_decrypt, delta_size, old_chunk, old_refchunksize, optimal_chunk, optimal_refchunksize, &new_chunk_size, tmp_delta_flag);
                        // Enclave::Logging("DEBUG", "Get new delta chunk\n");
                        // Enclave::Logging("DELTAFLAG5", "tmp delta flag is %d\n", tmp_delta_flag);
                        if (tmp_delta_flag) // update delta map
                        {
                            // update statics
                            if (delta_recipe_->deltaFlag == NO_DELTA)
                            {
                                memcpy(tmp_basechunksf, &delta_recipe_->superfeature, 3 * CHUNK_HASH_SIZE);
                                memcpy((uint8_t *)&outEntry->superfeature, tmp_basechunksf, 3 * CHUNK_HASH_SIZE);
                                Ocall_OFFline_updateIndex(upOutSGX->outClient, 0);
                            }
                            delta_recipe_->deltaFlag = DELTA;
                            delta_recipe_->length = new_chunk_size;
                            memcpy(delta_recipe_->basechunkHash, (uint8_t *)&optimalBaseChunkHash[0], CHUNK_HASH_SIZE);
                            // encrpyt before insert into container
                            uint8_t *delta_content_crypt = offline_newDeltaChunkEnc_;
                            // uint8_t* delta_content_crypt = (uint8_t*)malloc(MAX_CHUNK_SIZE);
                            cryptoObj_->EncryptWithKeyIV(cipherCtx, new_delta_content, new_chunk_size, Enclave::enclaveKey_,
                                                         delta_content_crypt, delta_iv);
                            // update container
                            InsertHot_container(delta_content_crypt, delta_recipe_, delta_fp, delta_sf, delta_iv);

                            // uint8_t* outRecipe = (uint8_t*)malloc(sizeof(RecipeEntry_t));
                            uint8_t *outRecipe = offline_outRecipeBuffer_;
                            cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)delta_recipe_, sizeof(RecipeEntry_t), Enclave::indexQueryKey_,
                                                  outRecipe);
                            bool status;
                            // Ocall_UpdateIndexStoreBuffer(&status, &delta_chunkhash[0], CHUNK_HASH_SIZE, (uint8_t*)&outRecipe, sizeof(RecipeEntry_t));
                            // memcpy(&outEntry->chunkAddr, outRecipe, sizeof(RecipeEntry_t));

                            status = UpdateIndexStore(delta_chunkhash, (char *)outRecipe, sizeof(RecipeEntry_t));

                            // free(outRecipe);
                            // if(!status)
                            // Enclave::Logging("debug","update index failed\n");

                            // Insert_delta(new_basechunkhash, delta_chunkhash); /2222222

                            // if (processBufferCount == 5000)
                            // {
                            //   Ocall_UpdateDeltaIndex(upOutSGX->outClient, 5000);
                            //   processBufferCount = 0;
                            //   _offline_Ocall++;
                            // }
                            // memcpy(upOutSGX->process_buffer + processBufferCount * CHUNK_HASH_SIZE * 2,
                            //   (uint8_t*)&new_basechunkhash[0], CHUNK_HASH_SIZE);
                            // memcpy(upOutSGX->process_buffer + processBufferCount * CHUNK_HASH_SIZE + CHUNK_HASH_SIZE,
                            //   (uint8_t*)&delta_chunkhash[0], CHUNK_HASH_SIZE);
                            // processBufferCount++;

                            memset(upOutSGX->process_buffer, 0, 100000 * CHUNK_HASH_SIZE);
                            memcpy(upOutSGX->process_buffer, (uint8_t *)&optimalBaseChunkHash[0], CHUNK_HASH_SIZE);
                            memcpy(upOutSGX->process_buffer + CHUNK_HASH_SIZE, (uint8_t *)&delta_chunkhash[0], CHUNK_HASH_SIZE);
                            Ocall_UpdateDeltaIndex(upOutSGX->outClient, 1);
                            _offline_Ocall++;

                            uint8_t *Coldbuffer = upOutSGX->out_buffer;
                            memcpy(Coldbuffer, &delta_containerID[0], CONTAINER_ID_LENGTH);
                            Coldbuffer += CONTAINER_ID_LENGTH;
                            memcpy(Coldbuffer, &deltapair.first, sizeof(uint32_t));
                            Coldbuffer += sizeof(uint32_t);
                            memcpy(Coldbuffer, &deltapair.second, sizeof(uint32_t));
                            Ocall_ColdInsert(upOutSGX->outClient);

                            _offline_Ocall++;

                            // cold_basemap[delta_containerID].push_back(deltapair);
                            //  free(delta_content_crypt);
                        }
                        else
                        {
                            delta_flag = tmp_delta_flag;
                        }

                        // free(delta_chunk_content_crypt);
                        // free(delta_chunk_content_decrypt);
                        // free(new_delta_content);
                        // free(delta_fp);
                        // free(delta_sf);
                        // free(delta_iv);
                    }
                    delta_map.erase(it->first);
                }
                delta_flag = true; // TODO
                // Enclave::Logging(myName_.c_str(), "total delta num is %d\n", _deltaChunkNum);
                if (optimalBaseChunkHash != old_basechunkhash)
                {
                    // Enclave::Logging("debug", "Base process\n");
                    // Enclave::Logging(myName_.c_str(), "old chunk edelta with optimal base chunk\n");
                    uint8_t *new_delta_content;
                    size_t new_delta_size;
                    // Enclave::Logging("debug", "xdelta begin\n");
                    new_delta_content = ed3_encode_buffer(old_chunk, old_refchunksize, optimal_chunk, optimal_refchunksize, offline_plainNewDeltaChunkBuffer_, &new_delta_size);
                    // Enclave::Logging("debug", "xdelta end\n");
                    //  uint8_t* recc_chunk;
                    //  size_t recc_size;
                    //  recc_chunk = ed3_decode(new_delta_content, new_delta_size, new_chunk, new_refchunksize, &recc_size);
                    if (new_delta_size > old_refchunksize)
                    {
                        // Enclave::Logging("debug", "NO delta!!! base_recc_chunk_size: 111");
                        delta_flag = false;
                    }
                    else
                    {
                        _offlineCompress_size -= old_chunk_size;
                        _offlineCurrBackup_size -= old_chunk_size;
                        _offlineCompress_size += new_delta_size;
                        _offlineCurrBackup_size += new_delta_size;
                        _offlinedeltaChunkNum++;
                        _deltaChunkNum++;
                        _baseChunkNum--;
                        _deltaDataSize += new_delta_size;
                        _baseDataSize -= old_chunk_size;
                        _Offline_DeltaSaveSize += (old_refchunksize - new_delta_size);
                        _lz4SaveSize -= (old_refchunksize - old_chunk_size);
                        _DeltaSaveSize += (old_refchunksize - new_delta_size);
                        _offlineDeltanum++;
                    }
                    // free(recc_chunk);

                    // Enclave::Logging("debug", " de xdelta end\n");
                    if (delta_flag)
                    {

                        old_recipe_->length = new_delta_size;
                        old_recipe_->deltaFlag = DELTA;
                        // Enclave::Logging("debug", " 1\n");
                        memcpy(&old_recipe_->basechunkHash, (uint8_t *)&optimalBaseChunkHash[0], CHUNK_HASH_SIZE);
                        // Enclave::Logging("debug", " 2\n");
                        uint8_t *new_delta_content_crypt = offline_newDeltaChunkEnc_;
                        // uint8_t* new_delta_content_crypt = (uint8_t*)malloc(MAX_CHUNK_SIZE);
                        if (!new_delta_content_crypt)
                        {
                            Enclave::Logging("malloc", "new_delta_content_crypt\n");
                        }
                        // Enclave::Logging("debug", " 3\n");
                        cryptoObj_->EncryptWithKeyIV(cipherCtx, new_delta_content, new_delta_size, Enclave::enclaveKey_,
                                                     new_delta_content_crypt, old_chunk_IV);
                        // Enclave::Logging("debug", " 4\n");
                        InsertHot_container(new_delta_content_crypt, old_recipe_, (uint8_t *)&old_basechunkhash[0], old_basechunksf, old_chunk_IV);
                        // Enclave::Logging("debug", " 5\n");
                        //  uint8_t* outRecipe = (uint8_t*)malloc(sizeof(RecipeEntry_t));
                        uint8_t *outRecipe = offline_outRecipeBuffer_;
                        // Enclave::Logging("debug", " 6\n");
                        cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)old_recipe_, sizeof(RecipeEntry_t), Enclave::indexQueryKey_,
                                              outRecipe);
                        // Enclave::Logging("debug", " 7\n");
                        bool status;

                        // Ocall_UpdateIndexStoreBuffer(&status, &old_basechunkhash[0], CHUNK_HASH_SIZE, (uint8_t*)&outRecipe, sizeof(RecipeEntry_t));
                        // Enclave::Logging("debug", " 8\n");
                        //  memcpy(&outEntry->chunkAddr, outRecipe, sizeof(RecipeEntry_t));

                        status = UpdateIndexStore(old_basechunkhash, (char *)outRecipe, sizeof(RecipeEntry_t));

                        // Enclave::Logging("debug", " 9\n");
                        //  free(outRecipe);

                        // if (processBufferCount == 5000)
                        // {
                        //   Ocall_UpdateDeltaIndex(upOutSGX->outClient, 5000);
                        //   processBufferCount = 0;
                        //   _offline_Ocall++;
                        // }
                        // memcpy(upOutSGX->process_buffer + processBufferCount * CHUNK_HASH_SIZE * 2,
                        //   (uint8_t*)&new_basechunkhash[0], CHUNK_HASH_SIZE);
                        // memcpy(upOutSGX->process_buffer + processBufferCount * CHUNK_HASH_SIZE + CHUNK_HASH_SIZE,
                        //   (uint8_t*)&delta_chunkhash[0], CHUNK_HASH_SIZE);
                        // processBufferCount++;

                        memset(upOutSGX->process_buffer, 0, 100000 * CHUNK_HASH_SIZE);
                        memcpy(upOutSGX->process_buffer, (uint8_t *)&optimalBaseChunkHash[0], CHUNK_HASH_SIZE);
                        memcpy(upOutSGX->process_buffer + CHUNK_HASH_SIZE, (uint8_t *)&old_basechunkhash[0], CHUNK_HASH_SIZE);
                        Ocall_UpdateDeltaIndex(upOutSGX->outClient, 1);
                        _offline_Ocall++;

                        // Insert_delta(new_basechunkhash, old_basechunkhash);
                        // uint8_t *Coldbuffer = upOutSGX->out_buffer;
                        // memcpy(Coldbuffer, &old_basecontainerID[0], CONTAINER_ID_LENGTH);
                        // Coldbuffer += CONTAINER_ID_LENGTH;
                        // memcpy(Coldbuffer, &basepair.first, sizeof(uint32_t));
                        // Coldbuffer += sizeof(uint32_t);
                        // memcpy(Coldbuffer, &basepair.second, sizeof(uint32_t));

                        // Ocall_ColdInsert(upOutSGX->outClient);
                        // _offline_Ocall++;
                        // cold_basemap[old_basecontainerID].push_back(basepair);
                        // Enclave::Logging("debug", " 10\n");
                        //  free(new_delta_content_crypt);
                        //  free(new_delta_content);
                    }
                }
                delta_flag = true;
                if (new_basechunkhash != optimalBaseChunkHash)
                {
                    // load newchunk
                    Enclave::Logging(myName_.c_str(), "new chunk edelta with optimal base chunk\n");
                    memcpy(&outEntry->chunkHash, (uint8_t *)&new_basechunkhash[0], CHUNK_HASH_SIZE);
                    Ocall_OneRecipe(upOutSGX->outClient);
                    _offline_Ocall++;
                    cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)tmp_recipe_);
                    memcpy(&outEntry->chunkAddr.containerName, tmp_recipe_->containerName, CONTAINER_ID_LENGTH);
                    if (tmp_recipe_->deltaFlag == NO_DELTA)
                    {
                        tmpBaseContainerID.assign((char *)tmp_recipe_->containerName, CONTAINER_ID_LENGTH);
                        curHotBaseContainerID.assign((char *)hot_base_container.containerID, CONTAINER_ID_LENGTH);
                        if (tmpBaseContainerID == curHotBaseContainerID)
                        {
                            memcpy(tmpUseContainer, hot_base_container.body, MAX_CONTAINER_SIZE);
                        }
                        else
                        {
                            // Enclave::Logging(myName_.c_str(), "load base container 2\n");
                            Ocall_OneContainer(upOutSGX->outClient);
                            if (outEntry->offlineFlag == false)
                            {
                                badDelta++;
                                Enclave::Logging("DEBUG", "bad delta num: %d\n", badDelta);
                                continue;
                            }
                            memcpy(tmpUseContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                        }
                    }
                    else
                    {
                        tmpDeltaContainerID.assign((char *)tmp_recipe_->containerName, CONTAINER_ID_LENGTH);
                        curHotDeltaContainerID.assign((char *)hot_container.containerID, CONTAINER_ID_LENGTH);
                        if (tmpDeltaContainerID == curHotDeltaContainerID)
                        {
                            memcpy(tmpUseContainer, hot_container.body, MAX_CONTAINER_SIZE);
                        }
                        else
                        {
                            // Enclave::Logging(myName_.c_str(), "load delta container\n");
                            Ocall_OneDeltaContainer(upOutSGX->outClient);
                            // if (outEntry->offlineFlag == false)
                            // {
                            //     badDelta++;
                            //     // Enclave::Logging("DEBUG", "bad delta num: %d\n", badDelta);
                            //     continue;
                            // }
                            memcpy(tmpUseContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
                        }
                    }
                    _offline_Ocall++;
                    uint8_t *tmp_chunk_content_crypt = GetChunk_content_buffer(tmpUseContainer, tmp_recipe_, false, basepair, encOldChunkBuffer_);
                    uint8_t *tmp_chunk_iv = GetChunk_IV(tmpUseContainer, tmp_recipe_, offline_oldIVBuffer_);
                    uint8_t *tmp_chunk_sf = GetChunk_SF(tmpUseContainer, tmp_recipe_);
                    uint8_t *tmp_chunk_fp = GetChunk_FP(tmpUseContainer, tmp_recipe_);
                    size_t tmp_chunk_size = tmp_recipe_->length;
                    uint8_t *tmp_chunkcontent_decrypt = offline_oldDeltaChunkDec_;
                    cryptoObj_->DecryptionWithKeyIV(cipherCtx, tmp_chunk_content_crypt, tmp_chunk_size, Enclave::enclaveKey_, tmp_chunkcontent_decrypt, tmp_chunk_iv);
                    // Enclave::Logging(myName_.c_str(), "decrypt old chunk done\n");
                    uint8_t *tmp_chunk_content_decompress = offline_newDeltaChunkEnc_;
                    int tmp_refchunksize = LZ4_decompress_safe((char *)tmp_chunkcontent_decrypt, (char *)tmp_chunk_content_decompress, tmp_chunk_size, MAX_CHUNK_SIZE);
                    // Enclave::Logging(myName_.c_str(), "old chunk size is %d, ref size is %d\n", tmp_chunk_size, tmp_refchunksize);
                    uint8_t *tmpchunk;
                    if (tmp_refchunksize < 0)
                    {
                        tmp_refchunksize = tmp_chunk_size;
                        tmpchunk = tmp_chunkcontent_decrypt;
                    }
                    else
                    {
                        tmpchunk = tmp_chunk_content_decompress;
                    }
                    // Get new container
                    // Enclave::Logging("debug", "Base process\n");
                    uint8_t *new_delta_content;
                    size_t new_delta_size;
                    // Enclave::Logging("debug", "xdelta begin\n");
                    // Enclave::Logging(myName_.c_str(), "old chunk edelta with optimal base chunk size is %d, ref size is %d\n", optimal_chunk_size, optimal_refchunksize);

                    new_delta_content = ed3_encode_buffer(tmpchunk, tmp_refchunksize, optimal_chunk, optimal_refchunksize, offline_plainNewDeltaChunkBuffer_, &new_delta_size);
                    // Enclave::Logging("debug", "edelta end\n");
                    // Enclave::Logging("debug", "xdelta end\n");
                    //  uint8_t* recc_chunk;
                    //  size_t recc_size;
                    //  recc_chunk = ed3_decode(new_delta_content, new_delta_size, new_chunk, new_refchunksize, &recc_size);
                    if (new_delta_size > tmp_refchunksize)
                    {
                        // Enclave::Logging("debug", "NO delta!!! base_recc_chunk_size: %d\n",recc_size);
                        delta_flag = false;
                    }
                    else
                    {
                        _offlineCompress_size -= tmp_chunk_size;
                        _offlineCurrBackup_size -= tmp_chunk_size;
                        _offlineCompress_size += new_delta_size;
                        _offlineCurrBackup_size += new_delta_size;
                        _offlinedeltaChunkNum++;
                        _deltaChunkNum++;
                        _baseChunkNum--;
                        _deltaDataSize += new_delta_size;
                        _baseDataSize -= tmp_chunk_size;
                        _Offline_DeltaSaveSize += (tmp_refchunksize - new_delta_size);
                        _lz4SaveSize -= (tmp_refchunksize - tmp_chunk_size);
                        _DeltaSaveSize += (tmp_refchunksize - new_delta_size);
                        _offlineDeltanum++;
                    }
                    // free(recc_chunk);

                    // Enclave::Logging("debug", " de xdelta end\n");
                    if (delta_flag)
                    {

                        old_recipe_->length = new_delta_size;
                        old_recipe_->deltaFlag = DELTA;
                        // Enclave::Logging("debug", " 1\n");
                        memcpy(&old_recipe_->basechunkHash, (uint8_t *)&optimalBaseChunkHash[0], CHUNK_HASH_SIZE);
                        // Enclave::Logging("debug", " 2\n");
                        uint8_t *new_delta_content_crypt = offline_newDeltaChunkEnc_;
                        // uint8_t* new_delta_content_crypt = (uint8_t*)malloc(MAX_CHUNK_SIZE);
                        if (!new_delta_content_crypt)
                        {
                            Enclave::Logging("malloc", "new_delta_content_crypt\n");
                        }
                        // Enclave::Logging("debug", " 3\n");
                        cryptoObj_->EncryptWithKeyIV(cipherCtx, new_delta_content, new_delta_size, Enclave::enclaveKey_,
                                                     new_delta_content_crypt, old_chunk_IV);
                        // Enclave::Logging("debug", " 4\n");
                        InsertHot_container(new_delta_content_crypt, old_recipe_, (uint8_t *)&new_basechunkhash[0], tmp_chunk_sf, tmp_chunk_iv);
                        // Enclave::Logging("debug", " 5\n");
                        //  uint8_t* outRecipe = (uint8_t*)malloc(sizeof(RecipeEntry_t));
                        uint8_t *outRecipe = offline_outRecipeBuffer_;
                        // Enclave::Logging("debug", " 6\n");
                        cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)old_recipe_, sizeof(RecipeEntry_t), Enclave::indexQueryKey_,
                                              outRecipe);
                        // Enclave::Logging("debug", " 7\n");
                        bool status;

                        // Ocall_UpdateIndexStoreBuffer(&status, &old_basechunkhash[0], CHUNK_HASH_SIZE, (uint8_t*)&outRecipe, sizeof(RecipeEntry_t));
                        // Enclave::Logging("debug", " 8\n");
                        //  memcpy(&outEntry->chunkAddr, outRecipe, sizeof(RecipeEntry_t));

                        status = UpdateIndexStore(new_basechunkhash, (char *)outRecipe, sizeof(RecipeEntry_t));

                        // Enclave::Logging("debug", " 9\n");
                        //  free(outRecipe);

                        // if (processBufferCount == 5000)
                        // {
                        //   Ocall_UpdateDeltaIndex(upOutSGX->outClient, 5000);
                        //   processBufferCount = 0;
                        //   _offline_Ocall++;
                        // }
                        // memcpy(upOutSGX->process_buffer + processBufferCount * CHUNK_HASH_SIZE * 2,
                        //   (uint8_t*)&new_basechunkhash[0], CHUNK_HASH_SIZE);
                        // memcpy(upOutSGX->process_buffer + processBufferCount * CHUNK_HASH_SIZE + CHUNK_HASH_SIZE,
                        //   (uint8_t*)&delta_chunkhash[0], CHUNK_HASH_SIZE);
                        // processBufferCount++;

                        memset(upOutSGX->process_buffer, 0, 100000 * CHUNK_HASH_SIZE);
                        memcpy(upOutSGX->process_buffer, (uint8_t *)&optimalBaseChunkHash[0], CHUNK_HASH_SIZE);
                        memcpy(upOutSGX->process_buffer + CHUNK_HASH_SIZE, (uint8_t *)&new_basechunkhash[0], CHUNK_HASH_SIZE);
                        Ocall_UpdateDeltaIndex(upOutSGX->outClient, 1);
                        _offline_Ocall++;

                        // Insert_delta(new_basechunkhash, old_basechunkhash);
                        // uint8_t *Coldbuffer = upOutSGX->out_buffer;
                        // memcpy(Coldbuffer, &old_basecontainerID[0], CONTAINER_ID_LENGTH);
                        // Coldbuffer += CONTAINER_ID_LENGTH;
                        // memcpy(Coldbuffer, &basepair.first, sizeof(uint32_t));
                        // Coldbuffer += sizeof(uint32_t);
                        // memcpy(Coldbuffer, &basepair.second, sizeof(uint32_t));

                        // Ocall_ColdInsert(upOutSGX->outClient);
                        // _offline_Ocall++;
                        // cold_basemap[old_basecontainerID].push_back(basepair);
                        // Enclave::Logging("debug", " 10\n");
                        //  free(new_delta_content_crypt);
                        //  free(new_delta_content);
                    }
                }

                // update optimal base chunk
                if (optimalBaseChunkHash != new_basechunkhash && optimalBaseChunkHash != old_basechunkhash)
                {
                    Enclave::Logging(myName_.c_str(), "update optimal base chunk\n");
                    uint8_t *compressdata = offline_lz4CompressBuffer_;
                    int optimal_chunk_compress_size = LZ4_compress_default((char *)optimal_chunk, (char *)compressdata, optimal_refchunksize, MAX_CHUNK_SIZE);
                    uint8_t *finalData;
                    size_t finalSize;
                    if (optimal_chunk_compress_size > 0)
                    {
                        finalData = compressdata;
                        finalSize = optimal_chunk_compress_size;
                    }
                    else
                    {
                        finalData = optimal_chunk;
                        finalSize = optimal_chunk_size;
                    }

                    new_recipe_->length = finalSize;
                    new_recipe_->deltaFlag = NO_DELTA;
                    uint8_t *encryptData = offline_newDeltaChunkEnc_;
                    cryptoObj_->EncryptWithKeyIV(cipherCtx, finalData, finalSize, Enclave::enclaveKey_, encryptData, optimal_chunk_IV);
                    InsertHotBase_container(encryptData, new_recipe_, (uint8_t *)optimal_chunk_FP, (uint8_t *)optimal_chunk_SF, (uint8_t *)optimal_chunk_IV);
                    // update recipe
                    uint8_t *outRecipe = offline_outRecipeBuffer_;
                    cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)new_recipe_, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, outRecipe);
                    bool status = UpdateIndexStore(optimalBaseChunkHash, (char *)outRecipe, sizeof(RecipeEntry_t));
                    _offlineCompress_size -= optimal_chunk_size;
                    _offlineCurrBackup_size -= optimal_chunk_size;
                    _offlineCompress_size += finalSize;
                    _offlineCurrBackup_size += finalSize;
                    _deltaChunkNum--;
                    _baseChunkNum++;
                    _baseDataSize += finalSize;
                    _deltaDataSize -= optimal_chunk_size;
                    _lz4SaveSize += (optimal_refchunksize - optimal_chunk_size);
                    _DeltaSaveSize -= (optimal_refchunksize - optimal_chunk_size);
                }
                // uint8_t *compressdata = offline_lz4CompressBuffer_;
                // int optimal_chunk_compress_size = LZ4_compress_default((char *)optimal_chunk, (char *)compressdata, optimal_refchunksize, MAX_CHUNK_SIZE);
                // uint8_t *finalData;
                // size_t finalSize;
                // if (optimal_chunk_compress_size > 0)
                // {
                //     finalData = compressdata;
                //     finalSize = optimal_chunk_compress_size;
                // }
                // else
                // {
                //     finalData = optimal_chunk;
                //     finalSize = optimal_chunk_size;
                // }

                // new_recipe_->length = finalSize;
                // new_recipe_->deltaFlag = NO_DELTA;
                // uint8_t *encryptData = offline_newDeltaChunkEnc_;
                // cryptoObj_->EncryptWithKeyIV(cipherCtx, finalData, finalSize, Enclave::enclaveKey_, encryptData, optimal_chunk_IV);
                // InsertHotBase_container(encryptData, new_recipe_, (uint8_t *)optimal_chunk_FP, (uint8_t *)optimal_chunk_SF, (uint8_t *)optimal_chunk_IV);
                // // update recipe
                // uint8_t *outRecipe = offline_outRecipeBuffer_;
                // cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)new_recipe_, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, outRecipe);
                // bool status = UpdateIndexStore(optimalBaseChunkHash, (char *)outRecipe, sizeof(RecipeEntry_t));
                // _offlineCompress_size -= optimal_chunk_size;
                // _offlineCurrBackup_size -= optimal_chunk_size;
                // _offlineCompress_size += finalSize;
                // _offlineCurrBackup_size += finalSize;

                // Enclave::Logging("debug", "Base end\n");
                // free(old_chunk_content_crypt);
                // free(old_chunk_IV);
                // free(new_chunk_IV);
                // free(old_chunk_content_decrypt);
                // free(old_chunk_content_decompression);
                // free(new_chunk_content_crypt);
                // free(new_chunk_content_decrypt);
                // free(new_chunk_content_decompression);
            }
            // local_basemap.clear();
        }
        // Enclave::Logging("debug", "Cold begin\n");
        local_basemap.clear();
    }
    // if(processBufferCount != 0)
    // {
    //   Ocall_UpdateDeltaIndex(upOutSGX->outClient, processBufferCount);
    //   processBufferCount = 0;
    //   _offline_Ocall++;
    // }
    Enclave::Logging("debug", "Hot update\n");
    if (hot_container.currentSize != 0)
    {
        Ocall_SavehotContainer(&hot_container.containerID[0], hot_container.body, hot_container.currentSize);
        _offline_Ocall++;
    }
    Enclave::Logging("debug", "Hot base update\n");
    if (hot_base_container.currentSize != 0)
    {
        Ocall_SavehotBaseContainer(&hot_base_container.containerID[0], hot_base_container.body, hot_base_container.currentSize);
        _offline_Ocall++;
    }
    Enclave::Logging("debug", "Cold update\n");
    // Ocall_Coldrevise(upOutSGX->outClient);
    // _offline_Ocall++;
    // uint8_t *Coldbuffer = upOutSGX->out_buffer;
    // Ocall_GetCold(upOutSGX->outClient);
    // _offline_Ocall++;
    // uint32_t ColdContainernum;
    // memcpy(&ColdContainernum, Coldbuffer, sizeof(uint32_t));
    // Coldbuffer += sizeof(uint32_t);

    // while (ColdContainernum > 0)
    // {
    //     Enclave::Logging("DEBUG", "cold map size:%d\n", ColdContainernum);
    //     for (int i = 0; i < ColdContainernum; i++)
    //     {
    //         string ColdContainerID;
    //         ColdContainerID.assign((char *)Coldbuffer, CONTAINER_ID_LENGTH);
    //         Enclave::Logging("DEBUG", "cold containerID :%s\n", ColdContainerID.c_str());
    //         Coldbuffer += CONTAINER_ID_LENGTH;
    //         uint32_t Coldnum;
    //         memcpy(&Coldnum, Coldbuffer, sizeof(uint32_t));
    //         Coldbuffer += sizeof(uint32_t);
    //         Enclave::Logging("DEBUG", "cold num:%d\n", Coldnum);
    //         for (int j = 0; j < Coldnum; j++)
    //         {
    //             pair<uint32_t, uint32_t> coldpair;
    //             uint32_t coldoffset;
    //             uint32_t coldlength;
    //             memcpy(&coldoffset, Coldbuffer, sizeof(uint32_t));
    //             Coldbuffer += sizeof(uint32_t);
    //             Enclave::Logging("DEBUG", "offset:%d\n", coldoffset);
    //             memcpy(&coldlength, Coldbuffer, sizeof(uint32_t));
    //             Coldbuffer += sizeof(uint32_t);
    //             Enclave::Logging("DEBUG", "length:%d\n", coldlength);
    //             coldpair = {coldoffset, coldlength};
    //             cold_basemap[ColdContainerID].push_back(coldpair);
    //         }
    //     }
    //     Ocall_GetCold(upOutSGX->outClient);
    //     _offline_Ocall++;
    //     Coldbuffer = upOutSGX->out_buffer;
    //     memcpy(&ColdContainernum, Coldbuffer, sizeof(uint32_t));
    //     Coldbuffer += sizeof(uint32_t);
    //     Enclave::Logging("DEBUG", "next cold map size:%d\n", ColdContainernum);
    //     for (unordered_map<string, vector<pair<uint32_t, uint32_t>>>::iterator it = cold_basemap.begin(); it != cold_basemap.end(); it++)
    //     {
    //         Update_cold_container(upOutSGX, it->first, it->second, cryptoObj_, cipherCtx);
    //         _offlineDeletenum++;
    //         Enclave::Logging("DEBUG", "Cold Container done:%s\n", it->first.c_str());
    //     }

    //     cold_basemap.clear();
    // }

#if (IS_MERGE_CONTAINER == 1)

    this->MergeContainer(upOutSGX, cryptoObj_, cipherCtx);

#endif

    Print();

    delta_map.clear();
    Ocall_GetCurrentTime(&_startTimeOffline);
    Ocall_GetCurrentTime(&_endTimeOffline);
    _testOcallTimeOffline += (_endTimeOffline - _startTimeOffline);
    _testOcallCountOffline++;
    // free(old_basechunksf);
    // free(new_basechunksf);
    // free(old_recipe);
    // free(new_recipe);
    // free(delta_recipe);
    // Enclave::Logging("debug", "Cold end\n");
    // Enclave::Logging(myName_.c_str(), "bad delta num is %d\n", badDelta);
    return;
}

void OFFLineBackward::MergeContainer(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_, EVP_CIPHER_CTX *cipherCtx)
{
    EnclaveClient *sgxClient = (EnclaveClient *)upOutSGX->sgxClient;
    uint32_t offset = 0;
    uint8_t *containerBuffer = offline_mergeNewContainer_;
    RecipeEntry_t *tmpRecipeEncrypt = offline_mergeRecipeEnc_;
    // tmpRecipeEncrypt = (RecipeEntry_t*)malloc(sizeof(RecipeEntry_t));
    RecipeEntry_t *tmpRecipeDecrypt = offline_mergeRecipeDec_;
    // tmpRecipeDecrypt = (RecipeEntry_t*)malloc(sizeof(RecipeEntry_t));
    uint8_t *containerPtr = upOutSGX->mergeContainer->body;
    uint32_t firstContainerSize;
    uint32_t secondContainerSize;
    string tmpHashStr;

    Ocall_GetMergeContainer(upOutSGX->outClient);
    _offline_Ocall++;

    while (upOutSGX->jobDoneFlag != 1)
    {

        uint8_t containerID[7];
        Ocall_GetMergePair(upOutSGX->outClient, containerID, &firstContainerSize);
        _offline_Ocall++;
        secondContainerSize = upOutSGX->outQuery->outQueryBase->containersize;

        // Enclave::Logging("DEBUG", "before print\n");
        // Enclave::Logging("DEBUG", "%d\n", (int)containerPtr[0]);

        if (upOutSGX->jobDoneFlag == 1)
        {
            Enclave::Logging("DEBUG", "merge done\n");
            break;
        }
        // string containerIDStr;
        // containerIDStr.assign((char*)containerID, CONTAINER_ID_LENGTH);
        // Enclave::Logging("DEBUG", "ID: %s\n", containerIDStr.c_str());
        offset = 0;
        while (offset < secondContainerSize)
        {
            // Enclave::Logging("DEBUG", "process one chunk\n");
            // modify recipe entry
            memcpy((uint8_t *)tmpRecipeDecrypt, containerPtr + offset, sizeof(RecipeEntry_t));
            // Enclave::Logging("DEBUG", "copy recipe ready\n");
            tmpRecipeDecrypt->offset = tmpRecipeDecrypt->offset + firstContainerSize;
            // Enclave::Logging("DEBUG", "modify offset ready\n");
            memcpy(tmpRecipeDecrypt->containerName, containerID, CONTAINER_ID_LENGTH);
            // Enclave::Logging("DEBUG", "modify ID ready\n");
            tmpHashStr.assign((char *)(containerPtr + offset + sizeof(RecipeEntry_t)), CHUNK_HASH_SIZE);
            // Enclave::Logging("DEBUG", "FP: %d %d\n", (int)tmpHashStr.c_str()[0], (int)tmpHashStr.c_str()[1]);

            // copy recipe entry
            memcpy(containerBuffer + offset, tmpRecipeDecrypt, sizeof(RecipeEntry_t));
            offset += sizeof(RecipeEntry_t);
            // Enclave::Logging("DEBUG", "copy recipe entry succ.\n");
            // Enclave::Logging("DEBUG", "in merge, offset: %u, copy length: %u, total length: %u.\n",
            //     offset, tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE, secondContainerSize);
            // copy content
            memcpy(containerBuffer + offset, containerPtr + offset, tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE);
            offset += tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE;
            // Enclave::Logging("DEBUG", "copy chunk content succ.\n");

            cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)tmpRecipeDecrypt, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)tmpRecipeEncrypt);
            // Enclave::Logging("DEBUG", "enc succ.\n");
            bool status;
            status = UpdateIndexStore(tmpHashStr, (char *)tmpRecipeEncrypt, sizeof(RecipeEntry_t));
            // Enclave::Logging("DEBUG", "update index succ.\n");
        }

        size_t curSize = secondContainerSize;
        // Enclave::Logging("DEBUG", "ready to merge\n");
        Ocall_MergeContent(upOutSGX->outClient, containerBuffer, curSize);
        _offline_Ocall++;
    }
    // free(tmpRecipeDecrypt);
    // free(tmpRecipeEncrypt);
    // Enclave::Logging("DEBUG", "ready to clean = 1\n");
    Ocall_CleanMerge(upOutSGX->outClient);
    _offline_Ocall++;
    return;
}

void OFFLineBackward::Init()
{
    Container_t *hot_container_ptr = &hot_container;
    Ocall_CreateUUID((uint8_t *)hot_container_ptr->containerID, CONTAINER_ID_LENGTH);
    string tmpContainerStr;
    tmpContainerStr.resize(CONTAINER_ID_LENGTH, 0);
    tmpContainerStr.assign((char *)hot_container_ptr->containerID, CONTAINER_ID_LENGTH);
    // Enclave::Logging("DEBUG", "Container id  is %s\n", tmpContainerStr.c_str());
    hot_container_ptr->currentSize = 0;
    // Enclave::Logging("DEBUG", "Init finished\n");

    Container_t *hot_base_container_ptr = &hot_base_container;
    Ocall_CreateUUID((uint8_t *)hot_base_container_ptr->containerID, CONTAINER_ID_LENGTH);
    string tmpBaseContainerStr;
    tmpBaseContainerStr.resize(CONTAINER_ID_LENGTH, 0);
    tmpBaseContainerStr.assign((char *)hot_base_container_ptr->containerID, CONTAINER_ID_LENGTH);
    // Enclave::Logging("DEBUG", "Base Container id  is %s\n", tmpBaseContainerStr.c_str());
    hot_base_container_ptr->currentSize = 0;
}

// RecipeEntry_t* GetRecipe(uint8_t* chunkhash) {

// }

uint8_t *OFFLineBackward::GetChunk_SF(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe)
{
    uint32_t offset = tmprecipe->offset;
    uint32_t length = tmprecipe->length;
    uint8_t *tmpchunkSF;
    string tmpContainerStr;
    tmpContainerStr.resize(CONTAINER_ID_LENGTH, 0);
    tmpContainerStr.assign((char *)tmprecipe->containerName, CONTAINER_ID_LENGTH);
    // tmpchunkSF = (uint8_t *)malloc(3 * CHUNK_HASH_SIZE);
    tmpchunkSF = offline_deltaSFBuffer_;
    memcpy(tmpchunkSF, tmpcontainer + offset + sizeof(RecipeEntry_t) + CHUNK_HASH_SIZE, 3 * CHUNK_HASH_SIZE);
    return tmpchunkSF;
}

uint8_t *OFFLineBackward::GetChunk_FP(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe)
{
    uint32_t offset = tmprecipe->offset;
    uint32_t length = tmprecipe->length;
    uint8_t *tmpchunkFP;
    string tmpContainerStr;
    tmpContainerStr.resize(CONTAINER_ID_LENGTH, 0);
    tmpContainerStr.assign((char *)tmprecipe->containerName, CONTAINER_ID_LENGTH);
    // tmpchunkFP = (uint8_t *)malloc(CHUNK_HASH_SIZE);
    tmpchunkFP = offline_deltaFPBuffer_;
    if (!tmpchunkFP)
    {
        Enclave::Logging("malloc", "tmpchunkFP\n");
    }
    memcpy(tmpchunkFP, tmpcontainer + offset + sizeof(RecipeEntry_t), CHUNK_HASH_SIZE);
    return tmpchunkFP;
}

uint8_t *OFFLineBackward::GetChunk_IV(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe, uint8_t *resBuffer)
{
    uint32_t offset = tmprecipe->offset;
    uint32_t length = tmprecipe->length;
    uint8_t *tmpchunkIV;
    string tmpContainerStr;
    tmpContainerStr.resize(CONTAINER_ID_LENGTH, 0);
    tmpContainerStr.assign((char *)tmprecipe->containerName, CONTAINER_ID_LENGTH);
    // tmpchunkIV = (uint8_t*)malloc(CRYPTO_BLOCK_SIZE);
    tmpchunkIV = resBuffer;
    if (!tmpchunkIV)
    {
        Enclave::Logging("malloc", "tmpchunkIV\n");
    }
    memcpy(tmpchunkIV, tmpcontainer + offset + sizeof(RecipeEntry_t) + 4 * CHUNK_HASH_SIZE + length, CRYPTO_BLOCK_SIZE);
    return tmpchunkIV;
}

uint8_t *OFFLineBackward::GetChunk_content(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe, bool cold_flag, pair<uint32_t, uint32_t> &tmppair)
{
    uint32_t offset = tmprecipe->offset;
    uint32_t length = tmprecipe->length;

    pair<uint32_t, uint32_t> _tmppair;
    _tmppair = {offset, length + 4 * CHUNK_HASH_SIZE + sizeof(RecipeEntry_t) + CRYPTO_BLOCK_SIZE};

    uint8_t *tmpchunkcontent;
    string tmpContainerStr;
    tmpContainerStr.resize(CONTAINER_ID_LENGTH, 0);
    tmpContainerStr.assign((char *)tmprecipe->containerName, CONTAINER_ID_LENGTH);
    if (cold_flag == true)
    {
        tmppair = _tmppair;
    }
    // ?
    // tmpchunkcontent = (uint8_t *)malloc(MAX_CHUNK_SIZE + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE);
    tmpchunkcontent = (uint8_t *)malloc(MAX_CHUNK_SIZE);
    memcpy(tmpchunkcontent, tmpcontainer + offset + sizeof(RecipeEntry_t) + 4 * CHUNK_HASH_SIZE, length);
    // tool::Logging(myName_.c_str(), "containerid: %s , offset: %d\n",tmpContainerStr.c_str(),offset);
    return tmpchunkcontent;
}

uint8_t *OFFLineBackward::GetChunk_content_buffer(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe, bool cold_flag, pair<uint32_t, uint32_t> &tmppair, uint8_t *res)
{
    uint32_t offset = tmprecipe->offset;
    uint32_t length = tmprecipe->length;
    // Enclave::Logging("DEBUG", "aa \n");
    pair<uint32_t, uint32_t> _tmppair;
    _tmppair = {offset, length + 4 * CHUNK_HASH_SIZE + sizeof(RecipeEntry_t) + CRYPTO_BLOCK_SIZE};

    uint8_t *tmpchunkcontent;
    string tmpContainerStr;
    tmpContainerStr.resize(CONTAINER_ID_LENGTH, 0);
    tmpContainerStr.assign((char *)tmprecipe->containerName, CONTAINER_ID_LENGTH);
    if (cold_flag == true)
    {
        tmppair = _tmppair;
    }
    // ?
    // tmpchunkcontent = (uint8_t *)malloc(MAX_CHUNK_SIZE + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE);
    // Enclave::Logging("DEBUG", "bb \n");
    tmpchunkcontent = res;
    memcpy(tmpchunkcontent, tmpcontainer + offset + sizeof(RecipeEntry_t) + 4 * CHUNK_HASH_SIZE, length);
    // Enclave::Logging("DEBUG", "cc \n");
    // tool::Logging(myName_.c_str(), "containerid: %s , offset: %d\n",tmpContainerStr.c_str(),offset);
    return tmpchunkcontent;
}

uint8_t *OFFLineBackward::GetNew_deltachunk(uint8_t *old_deltachunk, size_t old_deltasize, uint8_t *old_basechunk, size_t old_basesize, uint8_t *new_basechunk, size_t new_basesize, size_t *new_delta_size, bool &delta_flag, bool lz4_flag)
{
    // Enclave::Logging(myName_.c_str(), "old delta size: %d, old base size: %d, new base size: %d\n", old_deltasize, old_basesize, new_basesize);
    uint8_t *old_unique_chunk;
    size_t old_unique_chunk_size;
    if (!lz4_flag)
    {
        old_unique_chunk = ed3_decode_buffer(old_deltachunk, old_deltasize, old_basechunk, old_basesize, offline_tmpUniqueBuffer_, &old_unique_chunk_size);
    }
    else
    {
        old_unique_chunk_size = LZ4_decompress_safe((char *)old_deltachunk, (char *)offline_tmpUniqueBuffer_, old_deltasize, MAX_CHUNK_SIZE);
        if (old_unique_chunk_size < 0)
        {
            old_unique_chunk_size = old_deltasize;
            old_unique_chunk = old_deltachunk;
        }
        else
        {
            old_unique_chunk = offline_tmpUniqueBuffer_;
        }
    }

    // fprintf(stderr, "Unique chunk size:%d\n",old_unique_chunk_size);

    uint8_t *new_delta_chunk;
    size_t new_delta_chunk_size;
    new_delta_chunk = ed3_encode_buffer(old_unique_chunk, old_unique_chunk_size, new_basechunk, new_basesize, offline_plainNewDeltaChunkBuffer_, &new_delta_chunk_size);
    // uint8_t *recc_chunk;
    // size_t recc_size;
    // recc_chunk = ed3_decode(new_delta_chunk, new_delta_chunk_size, new_basechunk, new_basesize, &recc_size);
    // if (new_delta_chunk_size > old_deltasize)
    // {
    //     Enclave::Logging(myName_.c_str(), "bad delta\n");
    // }
    if (new_delta_chunk_size > old_unique_chunk_size)
    {
        Enclave::Logging("DEBUG", "encode bad, full size is %d and encode size is %d\n", old_unique_chunk_size, new_delta_chunk_size);
        delta_flag = false;
    }
    else
    {
        if (lz4_flag)
        {
            _baseChunkNum--;
            _baseDataSize -= old_deltasize;
            _lz4SaveSize -= (old_deltasize - old_unique_chunk_size);
        }
        _offlineCompress_size -= old_deltasize;
        _offlineCompress_size += new_delta_chunk_size;
        _offlineCurrBackup_size -= old_deltasize;
        _offlineCurrBackup_size += new_delta_chunk_size;
        _Offline_DeltaSaveSize += (old_deltasize - new_delta_chunk_size);
        _DeltaSaveSize += (old_deltasize - new_delta_chunk_size);
        _deltaDataSize -= old_deltasize;
        _deltaDataSize += new_delta_chunk_size;
        _offlineDeltanum++;
        _offlineDeDeltanum++;
    }
    // free(old_unique_chunk);
    // free(recc_chunk);
    *new_delta_size = new_delta_chunk_size;
    if (new_delta_chunk_size > old_deltasize)
        badDelta++;
    // Enclave::Logging(myName_.c_str(), "new delta size: %d\n", new_delta_chunk_size);
    return new_delta_chunk;
}

uint8_t *OFFLineBackward::xd3_decode(const uint8_t *in, size_t in_size, const uint8_t *ref, size_t ref_size, size_t *res_size)
{
    const auto max_buffer_size = (in_size + ref_size) * 2;
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(max_buffer_size);
    size_t sz;
    xd3_decode_memory(in, in_size, ref, ref_size, buffer, &sz, max_buffer_size, 0);
    uint8_t *res;
    res = (uint8_t *)malloc(sz);
    if (!res)
    {
        Enclave::Logging("malloc", "decode res\n");
    }
    *res_size = sz;
    memcpy(res, buffer, sz);
    free(buffer);
    return res;
}

uint8_t *OFFLineBackward::xd3_encode(const uint8_t *in, size_t in_size, const uint8_t *ref, size_t ref_size, size_t *res_size)
{
    size_t sz;
    const auto max_buffer_size = (in_size + ref_size) * 2;
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(max_buffer_size);
    xd3_encode_memory(in, in_size, ref, ref_size, buffer, &sz, max_buffer_size, 0);
    uint8_t *res;
    res = (uint8_t *)malloc(sz);
    if (!res)
    {
        Enclave::Logging("malloc", "encode res\n");
    }
    *res_size = sz;
    memcpy(res, buffer, sz);
    free(buffer);
    return res;
}

void OFFLineBackward::InsertHot_container(uint8_t *tmpchunkcontent, RecipeEntry_t *tmprecipe, uint8_t *tmpfp, uint8_t *tmpsf,
                                          uint8_t *tmpIV)
{
    Container_t *hot_container_ptr = &hot_container;
    uint32_t chunkSize = tmprecipe->length;
    uint32_t saveOffset = hot_container_ptr->currentSize; // TODO
    uint32_t writeOffset = saveOffset;
    if (tmprecipe->deltaFlag == NO_DELTA)
    {
        Enclave::Logging("ERROR", "Error: InsertHot_container get a base chunk recipe!\n");
        Enclave::Logging("ERROR", "Error: chunk hash is %02x%02x%02x%02x...\n", tmpfp[0], tmpfp[1], tmpfp[2], tmpfp[3]);
    } // change base to delta
    if (chunkSize + saveOffset + sizeof(RecipeEntry_t) + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE < MAX_CONTAINER_SIZE) // container size enough
    {
        // write recipe into container
        tmprecipe->offset = saveOffset;
        tmprecipe->deltaFlag = 1;
        // Enclave::Logging(myName_.c_str(), "Hot container id is %s\n", hot_container_ptr->containerID);
        memcpy(&tmprecipe->containerName[0], (uint8_t *)&hot_container_ptr->containerID[0], CONTAINER_ID_LENGTH);

        memcpy(hot_container_ptr->body + writeOffset, (uint8_t *)tmprecipe, sizeof(RecipeEntry_t));
        writeOffset += sizeof(RecipeEntry_t);
        // write chunk hash int container
        memcpy(hot_container_ptr->body + writeOffset, tmpfp, CHUNK_HASH_SIZE);
        writeOffset += CHUNK_HASH_SIZE;
        memcpy(hot_container_ptr->body + writeOffset, tmpsf, 3 * CHUNK_HASH_SIZE);
        writeOffset += 3 * CHUNK_HASH_SIZE;
        memcpy(hot_container_ptr->body + writeOffset, tmpchunkcontent, chunkSize);
        writeOffset += chunkSize;
        memcpy(hot_container_ptr->body + writeOffset, tmpIV, CRYPTO_BLOCK_SIZE);
    }
    else
    {
        // SaveHot_container(hot_container);
        // Enclave::Logging("DEBUG", "hot container id is %s\n", hot_container.containerID);
        Ocall_SavehotContainer(&hot_container.containerID[0], hot_container.body, hot_container.currentSize);
        Ocall_CreateUUID((uint8_t *)&hot_container_ptr->containerID[0], CONTAINER_ID_LENGTH);
        string NewContainerStr;
        hot_container_ptr->currentSize = 0;
        // reset this container during the ocall
        saveOffset = 0;
        writeOffset = saveOffset;
        tmprecipe->offset = saveOffset;
        tmprecipe->deltaFlag = 1;
        memcpy(&tmprecipe->containerName[0], (uint8_t *)&hot_container_ptr->containerID[0], CONTAINER_ID_LENGTH);
        memcpy(hot_container_ptr->body + writeOffset, (uint8_t *)tmprecipe, sizeof(RecipeEntry_t));
        writeOffset += sizeof(RecipeEntry_t);
        // write chunk hash int container
        memcpy(hot_container_ptr->body + writeOffset, tmpfp, CHUNK_HASH_SIZE);
        writeOffset += CHUNK_HASH_SIZE;
        memcpy(hot_container_ptr->body + writeOffset, tmpsf, 3 * CHUNK_HASH_SIZE);
        writeOffset += 3 * CHUNK_HASH_SIZE;
        memcpy(hot_container_ptr->body + writeOffset, tmpchunkcontent, chunkSize);
        writeOffset += chunkSize;
        memcpy(hot_container_ptr->body + writeOffset, tmpIV, CRYPTO_BLOCK_SIZE);
    }
    hot_container_ptr->currentSize = hot_container_ptr->currentSize + chunkSize + sizeof(RecipeEntry_t) + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE;
}

void OFFLineBackward::InsertHotBase_container(uint8_t *tmpchunkcontent, RecipeEntry_t *tmprecipe, uint8_t *tmpfp, uint8_t *tmpsf,
                                              uint8_t *tmpIV)
{
    Container_t *hot_container_ptr = &hot_base_container;
    uint32_t chunkSize = tmprecipe->length;
    uint32_t saveOffset = hot_container_ptr->currentSize; // TODO
    uint32_t writeOffset = saveOffset;
    if (tmprecipe->deltaFlag != NO_DELTA)
    {
        Enclave::Logging("ERROR", "Error: InsertHotBase_container get a delta chunk recipe!\n");
        Enclave::Logging("ERROR", "Error: chunk hash is %02x%02x%02x%02x...\n", tmpfp[0], tmpfp[1], tmpfp[2], tmpfp[3]);
    } // change delta to base
    if (chunkSize + saveOffset + sizeof(RecipeEntry_t) + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE < MAX_CONTAINER_SIZE) // container size enough
    {
        // write recipe into container
        tmprecipe->offset = saveOffset;
        tmprecipe->deltaFlag = NO_DELTA;
        // Enclave::Logging(myName_.c_str(), "Hot base container id is %s\n", hot_container_ptr->containerID);
        memcpy(&tmprecipe->containerName[0], (uint8_t *)&hot_container_ptr->containerID[0], CONTAINER_ID_LENGTH);

        memcpy(hot_container_ptr->body + writeOffset, (uint8_t *)tmprecipe, sizeof(RecipeEntry_t));
        writeOffset += sizeof(RecipeEntry_t);
        // write chunk hash int container
        memcpy(hot_container_ptr->body + writeOffset, tmpfp, CHUNK_HASH_SIZE);
        writeOffset += CHUNK_HASH_SIZE;
        memcpy(hot_container_ptr->body + writeOffset, tmpsf, 3 * CHUNK_HASH_SIZE);
        writeOffset += 3 * CHUNK_HASH_SIZE;
        memcpy(hot_container_ptr->body + writeOffset, tmpchunkcontent, chunkSize);
        writeOffset += chunkSize;
        memcpy(hot_container_ptr->body + writeOffset, tmpIV, CRYPTO_BLOCK_SIZE);
    }
    else
    {
        // SaveHot_container(hot_container);
        // Enclave::Logging("DEBUG", "hot base container id is %s\n", hot_base_container.containerID);
        Ocall_SavehotBaseContainer(&hot_base_container.containerID[0], hot_base_container.body, hot_base_container.currentSize);
        Ocall_CreateUUID((uint8_t *)&hot_container_ptr->containerID[0], CONTAINER_ID_LENGTH);
        string NewContainerStr;
        hot_container_ptr->currentSize = 0;
        // reset this container during the ocall
        saveOffset = 0;
        writeOffset = saveOffset;
        tmprecipe->offset = saveOffset;
        tmprecipe->deltaFlag = NO_DELTA;
        memcpy(&tmprecipe->containerName[0], (uint8_t *)&hot_container_ptr->containerID[0], CONTAINER_ID_LENGTH);
        memcpy(hot_container_ptr->body + writeOffset, (uint8_t *)tmprecipe, sizeof(RecipeEntry_t));
        writeOffset += sizeof(RecipeEntry_t);
        // write chunk hash int container
        memcpy(hot_container_ptr->body + writeOffset, tmpfp, CHUNK_HASH_SIZE);
        writeOffset += CHUNK_HASH_SIZE;
        memcpy(hot_container_ptr->body + writeOffset, tmpsf, 3 * CHUNK_HASH_SIZE);
        writeOffset += 3 * CHUNK_HASH_SIZE;
        memcpy(hot_container_ptr->body + writeOffset, tmpchunkcontent, chunkSize);
        writeOffset += chunkSize;
        memcpy(hot_container_ptr->body + writeOffset, tmpIV, CRYPTO_BLOCK_SIZE);
    }
    hot_container_ptr->currentSize = hot_container_ptr->currentSize + chunkSize + sizeof(RecipeEntry_t) + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE;
}

void OFFLineBackward::Insert_delta(string basechunkhash, string deltachunkhash)
{
    delta_map[basechunkhash].push_back(deltachunkhash);
    return;
}

bool OFFLineBackward::myCompare(pair<uint32_t, uint32_t> &v1, pair<uint32_t, uint32_t> &v2)
{
    return v1.first < v2.first;
}

void OFFLineBackward::Update_cold_container(UpOutSGX_t *upOutSGX, string container_id, vector<pair<uint32_t, uint32_t>> &cold_basechunk,
                                            EcallCrypto *cryptoObj_, EVP_CIPHER_CTX *cipherCtx)
{
    size_t Cold_container_size;
    bool delta_flag;
    // get container
    OutQueryEntry_t *outEntry = upOutSGX->outQuery->outQueryBase;

    memcpy(&outEntry->chunkAddr.containerName[0], (uint8_t *)&container_id[0], CONTAINER_ID_LENGTH);
    // Enclave::Logging("DBBUG", "container_id is %s\n", container_id.c_str());
    Ocall_OneColdContainer(upOutSGX->outClient, &delta_flag);
    Cold_container_size = outEntry->containersize;
    // memcpy(tmpColdContainer, outEntry->containerbuffer, Cold_container_size);
    uint8_t *Cold_container = outEntry->containerbuffer;

    // Enclave::Logging("CLOD", "container size  is %d\n", Cold_container_size);

    // sort
    sort(cold_basechunk.begin(), cold_basechunk.end(), myCompare);
    // for(int i=0;i<cold_basechunk.size();i++)
    //     Enclave::Logging("DBBUG", "offset is %d and len is %d\n", cold_basechunk[i].first, cold_basechunk[i].second);
    // Enclave::Logging("DBBUG", "sort finished\n");
    uint8_t *Cold_new_container = offline_mergeNewContainer_;
    // Cold_new_container = (uint8_t*)malloc(MAX_CONTAINER_SIZE);
    // if(Cold_new_container == NULL){
    //     Enclave::Logging("DBBUG", "MALLOC NULLLLLLLLLLLL\n");
    // }
    uint32_t saveset = 0;
    uint32_t newset = 0;
    uint32_t coldset = 0;
    RecipeEntry_t *tmpRecipeEncrypt = offline_mergeRecipeEnc_;
    // tmpRecipeEncrypt = (RecipeEntry_t*)malloc(sizeof(RecipeEntry_t));
    RecipeEntry_t *tmpRecipeDecrypt = offline_mergeRecipeDec_;
    // tmpRecipeDecrypt = (RecipeEntry_t*)malloc(sizeof(RecipeEntry_t));
    size_t Cold_new_size = 0;

    // uint8_t* tmpHashStr = (uint8_t*)malloc(CHUNK_HASH_SIZE);
    string tmpHashStr;
    tmpHashStr.resize(CHUNK_HASH_SIZE, 0);
    // string tmpRecipeStr;
    // uint8_t* tmpRecipeStr = (uint8_t*)malloc(sizeof(RecipeEntry_t));
    // tmpRecipeStr.resize(sizeof(RecipeEntry_t), 0);

    // Enclave::Logging("DBBUG", "sort2222 finished\n");

    for (int i = 0; i < cold_basechunk.size(); i++)
    {
        // Enclave::Logging("DBBUG", "cold base chunk size is  %d\n", cold_basechunk.size());
        while (saveset < cold_basechunk[i].first)
        {
            // Enclave::Logging("DBBUG", "write cold container\n");
            memcpy((uint8_t *)tmpRecipeDecrypt, Cold_container + saveset, sizeof(RecipeEntry_t));
            // Enclave::Logging("DBBUG", "tmpRecipe offset is %d\n", tmpRecipeDecrypt->offset);
            tmpHashStr.assign((char *)(Cold_container + saveset + sizeof(RecipeEntry_t)), CHUNK_HASH_SIZE);
            // memcpy((uint8_t*)&tmpHashStr[0], Cold_container + saveset + sizeof(RecipeEntry_t), CHUNK_HASH_SIZE);
            saveset += sizeof(RecipeEntry_t);
            tmpRecipeDecrypt->offset = tmpRecipeDecrypt->offset - coldset;
            // Enclave::Logging(myName_.c_str(), "offset: %d\n",tmpRecipe->offset);
            // memset(tmpRecipeEncrypt, 0, sizeof(RecipeEntry_t));
            // Enclave::Logging(myName_.c_str(), "length: %d\n",tmpRecipeDecrypt->length);
            // Enclave::Logging(myName_.c_str(), "offset: %d\n",tmpRecipeDecrypt->offset);
            memcpy(Cold_new_container + newset, tmpRecipeDecrypt, sizeof(RecipeEntry_t));
            // Enclave::Logging("DBBUG", "memcpy1\n");
            newset += sizeof(RecipeEntry_t);
            memcpy(Cold_new_container + newset, Cold_container + saveset, tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE);
            // Enclave::Logging("DBBUG", "memcpy\n");
            saveset += tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE;
            newset += tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE;
            // tool::Logging(myName_.c_str(), "length: %d\n",tmpRecipe->length);
            cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)tmpRecipeDecrypt, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)tmpRecipeEncrypt);
            // Enclave::Logging("DBBUG", "aes\n");
            // tmpRecipeStr.assign((char *)tmpRecipeEncrypt, sizeof(RecipeEntry_t));
            // memcpy(tmpRecipeStr, (uint8_t*)tmpRecipeEncrypt, sizeof(RecipeEntry_t));
            bool status;
            // Ocall_UpdateIndexStoreBuffer(&status, &tmpHashStr[0], CHUNK_HASH_SIZE, (uint8_t*)tmpRecipeEncrypt, sizeof(RecipeEntry_t));
            status = UpdateIndexStore(tmpHashStr, (char *)tmpRecipeEncrypt, sizeof(RecipeEntry_t));
            // Enclave::Logging("DBBUG", "update\n");
        }
        coldset += cold_basechunk[i].second;
        saveset += cold_basechunk[i].second;
    }
    // Enclave::Logging("DBBUG", "11111111111111111111\n");
    while (saveset < Cold_container_size)
    {
        // if(container_id == "000001k")
        // {
        //     Enclave::Logging(myName_.c_str(), "length: %u, offset: %u\n",
        //         tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE, newset);
        // }
        // memset(tmpRecipeDecrypt, 0, sizeof(RecipeEntry_t));
        memcpy((uint8_t *)tmpRecipeDecrypt, Cold_container + saveset, sizeof(RecipeEntry_t));
        // cryptoObj_->AESCBCDec(cipherCtx, (uint8_t*)tmpRecipeEncrypt, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t*)tmpRecipeDecrypt);
        tmpHashStr.assign((char *)(Cold_container + saveset + sizeof(RecipeEntry_t)), CHUNK_HASH_SIZE);
        // memcpy(tmpHashStr, Cold_container + saveset + sizeof(RecipeEntry_t), CHUNK_HASH_SIZE);
        saveset += sizeof(RecipeEntry_t);
        tmpRecipeDecrypt->offset = tmpRecipeDecrypt->offset - coldset;
        // Enclave::Logging(myName_.c_str(), "length: %d\n",tmpRecipeDecrypt->length);
        // Enclave::Logging(myName_.c_str(), "offset: %d\n",tmpRecipeDecrypt->offset);
        // memset(tmpRecipeEncrypt, 0, sizeof(RecipeEntry_t));

        memcpy(Cold_new_container + newset, tmpRecipeDecrypt, sizeof(RecipeEntry_t));
        newset += sizeof(RecipeEntry_t);
        memcpy(Cold_new_container + newset, Cold_container + saveset, tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE);
        saveset += tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE;
        newset += tmpRecipeDecrypt->length + 4 * CHUNK_HASH_SIZE + CRYPTO_BLOCK_SIZE;

        cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)tmpRecipeDecrypt, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)tmpRecipeEncrypt);
        // tmpRecipeStr.assign((char *)tmpRecipeEncrypt, sizeof(RecipeEntry_t));
        bool status;
        // Ocall_UpdateIndexStoreBuffer(&status, &tmpHashStr[0], CHUNK_HASH_SIZE, (uint8_t*)tmpRecipeEncrypt, sizeof(RecipeEntry_t));
        status = UpdateIndexStore(tmpHashStr, (char *)tmpRecipeEncrypt, sizeof(RecipeEntry_t));
    }

    Cold_new_size = Cold_container_size - coldset;

    // Enclave::Logging("debug", "Container Cold\n");
    Ocall_SaveColdContainer(&container_id[0], Cold_new_container, Cold_new_size, &delta_flag);
    _offline_Ocall++;
    // free(tmpRecipeEncrypt);
    // free(tmpRecipeDecrypt);
    // free(Cold_new_container);
    // Enclave::Logging(myName_.c_str(), "NEW_CONTAINER_down\n");
    return;
}

bool OFFLineBackward::UpdateIndexStore(const string &key, const char *buffer,
                                       size_t bufferSize)
{
    bool status;

    Ocall_UpdateIndexStoreBuffer(&status, key.c_str(), key.size(),
                                 (const uint8_t *)buffer, bufferSize);

    _offline_Ocall++;
    return status;
}

void OFFLineBackward::CleanLocal_Index()
{

    Ocall_CleanLocalIndex();
    _offline_Ocall++;
}

uint8_t *OFFLineBackward::ed3_encode(uint8_t *in, size_t in_size, uint8_t *ref,
                                     size_t ref_size, size_t *res_size) // 更改函数
{
    uint32_t res32;
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(MAX_CHUNK_SIZE);
    int resInt = this->EDeltaEncode(in, in_size, ref, ref_size, buffer, &res32);
    *res_size = res32;
    return buffer;
}

uint8_t *OFFLineBackward::ed3_decode(uint8_t *in, size_t in_size, uint8_t *ref, size_t ref_size, size_t *res_size) // 更改函数
{
    uint8_t *buffer;
    buffer = (uint8_t *)malloc(MAX_CHUNK_SIZE);
    uint32_t res32;
    int resInt = this->EDeltaDecode(in, in_size, ref, ref_size, buffer, &res32);
    *res_size = res32;
    return buffer;
}

uint8_t *OFFLineBackward::ed3_encode_buffer(uint8_t *in, size_t in_size, uint8_t *ref,
                                            size_t ref_size, uint8_t *res, size_t *res_size) // 更改函数
{
    uint32_t res32;
    int resInt = this->EDeltaEncode(in, in_size, ref, ref_size, res, &res32);
    *res_size = res32;
    return res;
}

uint8_t *OFFLineBackward::ed3_decode_buffer(uint8_t *in, size_t in_size, uint8_t *ref, size_t ref_size, uint8_t *res, size_t *res_size) // 更改函数
{
    uint32_t res32;
    int resInt = this->EDeltaDecode(in, in_size, ref, ref_size, res, &res32);
    *res_size = res32;
    return res;
}

/* flag=0 for 'D', 1 for 'S' */
void OFFLineBackward::set_flag(void *record, uint32_t flag)
{
    uint32_t *flag_length = (uint32_t *)record;
    if (flag == 0)
    {
        (*flag_length) &= ~(uint32_t)0 >> 1;
    }
    else
    {
        (*flag_length) |= (uint32_t)1 << 31;
    }
}

/* return 0 if flag=0, >0(not 1) if flag=1 */
u_int32_t OFFLineBackward::get_flag(void *record)
{
    u_int32_t *flag_length = (u_int32_t *)record;
    return (*flag_length) & (u_int32_t)1 << 31;
}

void OFFLineBackward::set_length(void *record, uint32_t length)
{
    uint32_t *flag_length = (uint32_t *)record;
    uint32_t musk = (*flag_length) & (uint32_t)1 << 31;
    *flag_length = length | musk;
}

uint32_t OFFLineBackward::get_length(void *record)
{
    uint32_t *flag_length = (uint32_t *)record;
    return (*flag_length) & ~(uint32_t)0 >> 1;
}

int OFFLineBackward::Chunking_v3(unsigned char *data, int len, int num_of_chunks,
                                 DeltaRecord *subChunkLink)
{
    int i = 0, *cut;
    /* cut is the chunking points in the stream */
    cut = cutEdelta_;
    int numBytes =
        rolling_gear_v3(data, len, num_of_chunks, cut); // 分割给定快的总字节数

    while (i < num_of_chunks)
    {
        int chunkLen = cut[i + 1] - cut[i];
        subChunkLink[i].nLength = chunkLen;
        subChunkLink[i].nOffset = cut[i]; /**/
        subChunkLink[i].DupFlag = 0;
        subChunkLink[i].nHash = weakHash(data + cut[i], chunkLen);
        //	SpookyHash::Hash64(data+ cut[i], chunkLen, 0x1af1);
        i++;
    }
    return numBytes;
}

// int OFFLineBackward::EDeltaEncode(uint8_t *newBuf, uint32_t newSize, uint8_t *baseBuf,
//                  uint32_t baseSize, uint8_t *deltaBuf, uint32_t *deltaSize) {
//   /* detect the head and tail of one chunk */
//   uint32_t beg = 0;
//   uint32_t end = 0;
//   uint32_t begSize = 0;
//   uint32_t endSize = 0;
//   float matchsum = 0.;
//   float match = 0.;
// //   Enclave::Logging(myName_.c_str(), "1\n");
//   while (begSize + 7 < baseSize && begSize + 7 < newSize) {
//     if (*(uint64_t *)(baseBuf + begSize) == *(uint64_t *)(newBuf + begSize)) {
//       begSize += 8;
//     } else
//       break;
//   }
//   while (begSize < baseSize && begSize < newSize) {
//     if (baseBuf[begSize] == newBuf[begSize]) {
//       begSize++;
//     } else
//       break;
//   }

//   if (begSize > 16)
//     beg = 1;
//   else
//     begSize = 0;

//   while (endSize + 7 < baseSize && endSize + 7 < newSize) {
//     if (*(uint64_t *)(baseBuf + baseSize - endSize - 8) ==
//         *(uint64_t *)(newBuf + newSize - endSize - 8)) {
//       endSize += 8;
//     } else
//       break;
//   }
//   while (endSize < baseSize && endSize < newSize) {
//     if (baseBuf[baseSize - endSize - 1] == newBuf[newSize - endSize - 1]) {
//       endSize++;
//     } else
//       break;
//   }

//   if (begSize + endSize > newSize)
//     endSize = newSize - begSize;

//   if (endSize > 16)
//     end = 1;
//   else
//     endSize = 0;
// //   /* end of detect */
// //   Enclave::Logging(myName_.c_str(), "2\n");

//   if (begSize + endSize >= baseSize) {
//     DeltaUnit1 record1;
//     DeltaUnit2 record2;
//     uint32_t deltaLen = 0;
//     if (beg) {
//       set_flag(&record1, 0);
//       record1.nOffset = 0;
//       set_length(&record1, begSize);
//       memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
//       deltaLen += sizeof(DeltaUnit1);
//     }
//     if (newSize - begSize - endSize > 0) {
//       set_flag(&record2, 1);
//       set_length(&record2, newSize - begSize - endSize);
//       memcpy(deltaBuf + deltaLen, &record2, sizeof(DeltaUnit2));
//       deltaLen += sizeof(DeltaUnit2);
//       memcpy(deltaBuf + deltaLen, newBuf + begSize, get_length(&record2));
//       deltaLen += get_length(&record2);
//     }
//     if (end) {
//       set_flag(&record1, 0);
//       record1.nOffset = baseSize - endSize;
//       set_length(&record1, endSize);
//       memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
//       deltaLen += sizeof(DeltaUnit1);
//     }

//     *deltaSize = deltaLen;
//     // Enclave::Logging(myName_.c_str(), "2.9\n");
//     return deltaLen;
//   }
// //   Enclave::Logging(myName_.c_str(), "3\n");

//   uint32_t deltaLen = 0;
//   uint32_t cursor_base = begSize;
//   uint32_t cursor_input = begSize;
//   uint32_t cursor_input1 = 0;
//   uint32_t cursor_input2 = 0;
//   uint32_t input_last_chunk_beg = begSize;
//   uint32_t inputPos = begSize;
//   uint32_t length;
//   uint64_t hash;
//   DeltaRecord *psDupSubCnk = NULL;
//   DeltaUnit1 record1{0, 0};
//   DeltaUnit2 record2{0};
//   set_flag(&record1, 0);
//   set_flag(&record2, 1);
//   int flag = 0; /* to represent the last record in the deltaBuf,
//        1 for DeltaUnit1, 2 for DeltaUnit2 */

//   auto res1  = psHTable_->find(0);
//   auto res2  = psHTable_->find(0);
//   auto res3  = psHTable_->find(0);

//   int numBase = 0;  /* the total number of chunks that the base has chunked */
//   int numBytes = 0; /* the number of bytes that the base chunks once */
//   DeltaRecord *BaseLink = BaseLink_;
// //   Enclave::Logging("edelta", "malloc size: %u\n", sizeof(DeltaRecord) * ((baseSize - begSize - endSize) / STRMIN + 50));
// //   *deltaSize = 1024;

//   int offset = (char *)&BaseLink[0].psNextSubCnk - (char *)&BaseLink[0];
// //   htable *psHTable = psHTable_;
// //   psHTable->init(offset, 8, baseSize/16);
// #if POST_DEDUP
//   psHTable->init(offset, 8, (baseSize - begSize - endSize) * 2 / (STRAVG + 1));
// #else
// //   psHTable->init(offset, 8, 8 * 1024);
// #endif

//   // int chunk_length;
//   int flag_chunk = 1; // to tell if basefile has been chunked to the end
//   int numBytes_old;
//   int numBytes_accu = 0; // accumulated numBytes in one turn of chunking the
//                          // base
//   int probe_match; // to tell which chunk for probing matches the some base
//   int flag_handle_probe; // to tell whether the probe chunks need to be handled

//   if (beg) {
//     record1.nOffset = 0;
//     set_length(&record1, begSize);
//     memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
//     deltaLen += sizeof(DeltaUnit1);
//     flag = 1;
//   }

// #define BASE_BEGIN 5
// #define BASE_EXPAND 3
// #define BASE_STEP 3
// #define INPUT_TRY 5

// /* if deltaLen > newSize * RECOMPRESS_THRESHOLD in the first round,we'll
//  * go back to greedy.
//  */
// #define GO_BACK_TO_GREEDY 0

// #define RECOMPRESS_THRESHOLD 0.2

//   DeltaRecord InputLink[INPUT_TRY];
//   // int test=0;

//   while (inputPos < newSize - endSize) {
//     if (flag_chunk) {
//       //		if( cursor_input - input_last_chunk_beg >= numBytes_accu
//       //* 0.8 ){
//       if ((cursor_input / (float)newSize) + 0.5 >=
//           (cursor_base / (float)baseSize)) {
//         numBytes_old = numBytes_accu;
//         numBytes_accu = 0;

//         /* chunk a few chunks in the input first */
//         // Chunking_v3(newBuf+cursor_input, newSize-endSize-cursor_input,
//         // INPUT_TRY, InputLink);
//         flag_handle_probe = 1;
//         probe_match = INPUT_TRY;
//         int chunk_number = BASE_BEGIN;
//         for (int i = 0; i < BASE_STEP; i++) {
//           numBytes = Chunking_v3(
//               baseBuf + cursor_base, baseSize - endSize - cursor_base,
//               chunk_number,
//               BaseLink + numBase); //一个分块base的循环找到 match的就可以跳出

//           for (int j = 0; j < chunk_number; j++) {
//             if (BaseLink[numBase + j].nLength == 0) {
//               flag_chunk = 0;
//               break;
//             }
//             BaseLink[numBase + j].nOffset += cursor_base;
//             psHTable_->emplace(BaseLink[numBase + j].nHash, (DeltaRecord *)&BaseLink[numBase + j]);
//             // psHTable->insert((unsigned char *)&BaseLink[numBase + j].nHash,
//             //                  &BaseLink[numBase + j]);
//           }

//           cursor_base += numBytes;
//           numBase += chunk_number;
//           numBytes_accu += numBytes;

//           chunk_number *= BASE_EXPAND;
//           if (i == 0) {
//             cursor_input1 = cursor_input;
//             for (int j = 0; j < INPUT_TRY; j++) {
//               cursor_input2 = cursor_input1;
//               cursor_input1 = chunk_gear(newBuf + cursor_input2,
//                                          newSize - cursor_input2 - endSize) +
//                               cursor_input2;
//               InputLink[j].nLength = cursor_input1 - cursor_input2;
//               InputLink[j].nHash =
//                   weakHash(newBuf + cursor_input2, InputLink[j].nLength);
//             //   InputLink[j].nHash = 9;
//                 //   weakHash(newBuf + cursor_input2, InputLink[j].nLength);
//             //   if ((psDupSubCnk = (DeltaRecord *)psHTable->lookup(
//             //            (unsigned char *)&(InputLink[j].nHash)))) {
//             //     probe_match = j;
//             //     goto lets_break;
//             //   }
//               res1 = psHTable_->find(InputLink[j].nHash);
//               if (res1 != psHTable_->end())
//               {
//                 psDupSubCnk = res1->second;
//                 probe_match = j;
//                 goto lets_break;
//               }
//             }
//           } else {
//             for (int j = 0; j < INPUT_TRY; j++) {
//               res2 = psHTable_->find(InputLink[j].nHash);
//               if (res2 != psHTable_->end())
//               {
//                 psDupSubCnk = res2->second;
//                 probe_match = j;
//                 goto lets_break;
//               }
//             }
//           }

//           if (flag_chunk == 0)
//           lets_break:
//             break;
//         }

//         input_last_chunk_beg =
//             (cursor_input > (input_last_chunk_beg + numBytes_old)
//                  ? cursor_input
//                  : (input_last_chunk_beg + numBytes_old));
//         // test++;
//       }
//     }

//     // to handle the chunks in input file for probing
//     if (flag_handle_probe) {
//       for (int i = 0; i < INPUT_TRY; i++) {
//         matchsum++;
//         length = InputLink[i].nLength;
//         cursor_input = length + inputPos;

//         if (i == probe_match)
//         {
//           flag_handle_probe = 0;
//           goto match;
//         }
//         else
//         {
//           if (flag == 2) { //把不match的块弄过去
//             /* continuous unique chunks only add unique bytes into the deltaBuf,
//              * but not change the last DeltaUnit2, so the DeltaUnit2 should be
//              * overwritten when flag=1 or at the end of the loop.
//              */
//             memcpy(deltaBuf + deltaLen, newBuf + inputPos, length);
//             deltaLen += length;
//             set_length(&record2, get_length(&record2) + length);
//           } else {
//             set_length(&record2, length);

//             memcpy(deltaBuf + deltaLen, &record2, sizeof(DeltaUnit2));
//             deltaLen += sizeof(DeltaUnit2);

//             memcpy(deltaBuf + deltaLen, newBuf + inputPos, length);
//             deltaLen += length;

//             flag = 2;
//           }

//           inputPos = cursor_input;
//         }
//       }

//       flag_handle_probe = 0;
//     }

//     cursor_input =
//         chunk_gear(newBuf + inputPos, newSize - inputPos - endSize) + inputPos;
//     matchsum++;
//     length = cursor_input - inputPos;
//     hash = weakHash(newBuf + inputPos, length);

//     /* lookup */
//     res3 = psHTable_->find(hash);
//     if (res3 != psHTable_->end())
//     {
//     psDupSubCnk = res3->second;
//     // printf("inputPos: %d length: %d\n", inputPos, length);
//     match:
//       if (length == psDupSubCnk->nLength &&
//           memcmp(newBuf + inputPos, baseBuf + psDupSubCnk->nOffset, length) ==
//               0) {
//         //	printf("match:%d\n",length);
//         match++;
//         if (flag == 2) {
//           /* continuous unique chunks only add unique bytes into the deltaBuf,
//            * but not change the last DeltaUnit2, so the DeltaUnit2 should be
//            * overwritten when flag=1 or at the end of the loop.
//            */
//           memcpy(deltaBuf + deltaLen - get_length(&record2) -
//                      sizeof(DeltaUnit2),
//                  &record2, sizeof(DeltaUnit2));
//         }

//         // greedily detect forward
//         int j = 0;

//         while (psDupSubCnk->nOffset + length + j + 7 < baseSize - endSize &&
//                cursor_input + j + 7 < newSize - endSize) {
//           if (*(uint64_t *)(baseBuf + psDupSubCnk->nOffset + length + j) ==
//               *(uint64_t *)(newBuf + cursor_input + j)) {
//             j += 8;
//           } else
//             break;
//         }
//         while (psDupSubCnk->nOffset + length + j < baseSize - endSize &&
//                cursor_input + j < newSize - endSize) {
//           if (baseBuf[psDupSubCnk->nOffset + length + j] ==
//               newBuf[cursor_input + j]) {
//             j++;
//           } else
//             break;
//         }

//         cursor_input += j;
//         if (psDupSubCnk->nOffset + length + j > cursor_base)
//           cursor_base = psDupSubCnk->nOffset + length + j;

//         set_length(&record1, cursor_input - inputPos);
//         record1.nOffset = psDupSubCnk->nOffset;

//         /* detect backward */
//         uint32_t k = 0;
//         if (flag == 2) {
//           while (k + 1 <= psDupSubCnk->nOffset &&
//                  k + 1 <= get_length(&record2)) {
//             if (baseBuf[psDupSubCnk->nOffset - (k + 1)] ==
//                 newBuf[inputPos - (k + 1)])
//               k++;
//             else
//               break;
//           }
//         }
//         if (k > 0) {
//           deltaLen -= get_length(&record2);
//           deltaLen -= sizeof(DeltaUnit2);

//           set_length(&record2, get_length(&record2) - k);

//           if (get_length(&record2) > 0) {
//             memcpy(deltaBuf + deltaLen, &record2, sizeof(DeltaUnit2));
//             deltaLen += sizeof(DeltaUnit2);
//             deltaLen += get_length(&record2);
//           }

//           set_length(&record1, get_length(&record1) + k);
//           record1.nOffset -= k;
//         }

//         memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
//         deltaLen += sizeof(DeltaUnit1);
//         flag = 1;
//       } else {
//         // printf("Spooky Hash Error!!!!!!!!!!!!!!!!!!\n");
//         goto handle_hash_error;
//       }
//     } else {
//     handle_hash_error:
//       //	printf("unmatch:%d\n",length);
//       if (flag == 2) {
//         /* continuous unique chunks only add unique bytes into the deltaBuf,
//          * but not change the last DeltaUnit2, so the DeltaUnit2 should be
//          * overwritten when flag=1 or at the end of the loop.
//          */
//         memcpy(deltaBuf + deltaLen, newBuf + inputPos, length);
//         deltaLen += length;
//         set_length(&record2, get_length(&record2) + length);
//       } else {
//         set_length(&record2, length);

//         memcpy(deltaBuf + deltaLen, &record2, sizeof(DeltaUnit2));
//         deltaLen += sizeof(DeltaUnit2);

//         memcpy(deltaBuf + deltaLen, newBuf + inputPos, length);
//         deltaLen += length;

//         flag = 2;
//       }
//     }

//     inputPos = cursor_input;
//     // printf("cursor_input:%d\n",inputPos);
//   }

//   if (flag == 2) {
//     /* continuous unique chunks only add unique bytes into the deltaBuf,
//      * but not change the last DeltaUnit2, so the DeltaUnit2 should be
//      * overwritten when flag=1 or at the end of the loop.
//      */
//     memcpy(deltaBuf + deltaLen - get_length(&record2) - sizeof(DeltaUnit2),
//            &record2, sizeof(DeltaUnit2));
//   }

//   if (end) {
//     record1.nOffset = baseSize - endSize;
//     set_length(&record1, endSize);
//     memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
//     deltaLen += sizeof(DeltaUnit1);
//   }

// //   if (psHTable) {
// //     free(psHTable->table);
// //     free(psHTable);
// //   }

//     // for(auto kv = psHTable_->begin(); kv != psHTable_->end(); )
//     // {
//     //     uint64_t key = kv->first;
//     //     DeltaRecord* value = kv->second;
//     //     free(value);
//     //     kv = psHTable_->erase(kv);
//     // }

//     psHTable_->clear();

// //   free(BaseLink);

// //   deltaLen = 1;
//   *deltaSize = deltaLen;
//   return deltaLen;
// // // *deltaSize = 1024;
// // //   return 1024;
// //   *deltaSize = 1024;
// //   return 1024;
// }

int OFFLineBackward::EDeltaEncode(uint8_t *newBuf, uint32_t newSize, uint8_t *baseBuf,
                                  uint32_t baseSize, uint8_t *deltaBuf, uint32_t *deltaSize)
{
    /* detect the head and tail of one chunk */
    uint32_t beg = 0, end = 0, begSize = 0, endSize = 0;
    float matchsum = 0;
    float match = 0;
    while (begSize + 7 < baseSize && begSize + 7 < newSize)
    {
        if (*(uint64_t *)(baseBuf + begSize) == *(uint64_t *)(newBuf + begSize))
        {
            begSize += 8;
        }
        else
            break;
    }
    while (begSize < baseSize && begSize < newSize)
    {
        if (baseBuf[begSize] == newBuf[begSize])
        {
            begSize++;
        }
        else
            break;
    }

    if (begSize > 16)
        beg = 1;
    else
        begSize = 0;

    while (endSize + 7 < baseSize && endSize + 7 < newSize)
    {
        if (*(uint64_t *)(baseBuf + baseSize - endSize - 8) ==
            *(uint64_t *)(newBuf + newSize - endSize - 8))
        {
            endSize += 8;
        }
        else
            break;
    }
    while (endSize < baseSize && endSize < newSize)
    {
        if (baseBuf[baseSize - endSize - 1] == newBuf[newSize - endSize - 1])
        {
            endSize++;
        }
        else
            break;
    }

    if (begSize + endSize > newSize)
        endSize = newSize - begSize;

    if (endSize > 16)
        end = 1;
    else
        endSize = 0;
    /* end of detect */

    if (begSize + endSize >= baseSize)
    {
        DeltaUnit1 record1;
        DeltaUnit2 record2;
        uint32_t deltaLen = 0;
        if (beg)
        {
            set_flag(&record1, 0);
            record1.nOffset = 0;
            set_length(&record1, begSize);
            memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
            deltaLen += sizeof(DeltaUnit1);
        }
        if (newSize - begSize - endSize > 0)
        {
            set_flag(&record2, 1);
            set_length(&record2, newSize - begSize - endSize);
            memcpy(deltaBuf + deltaLen, &record2, sizeof(DeltaUnit2));
            deltaLen += sizeof(DeltaUnit2);
            memcpy(deltaBuf + deltaLen, newBuf + begSize, get_length(&record2));
            deltaLen += get_length(&record2);
        }
        if (end)
        {
            set_flag(&record1, 0);
            record1.nOffset = baseSize - endSize;
            set_length(&record1, endSize);
            memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
            deltaLen += sizeof(DeltaUnit1);
        }

        *deltaSize = deltaLen;
        return deltaLen;
    }

    uint32_t deltaLen = 0;
    uint32_t cursor_base = begSize;
    uint32_t cursor_input = begSize;
    uint32_t cursor_input1 = 0;
    uint32_t cursor_input2 = 0;
    uint32_t input_last_chunk_beg = begSize;
    uint32_t inputPos = begSize;
    uint32_t length;
    uint64_t hash;
    DeltaRecord *psDupSubCnk = NULL;
    DeltaUnit1 record1{0, 0};
    DeltaUnit2 record2{0};
    set_flag(&record1, 0);
    set_flag(&record2, 1);
    int flag = 0; /* to represent the last record in the deltaBuf,
         1 for DeltaUnit1, 2 for DeltaUnit2 */

    int numBase = 0;  /* the total number of chunks that the base has chunked */
    int numBytes = 0; /* the number of bytes that the base chunks once */
                      //   DeltaRecord *BaseLink = (DeltaRecord *)malloc(
                      //       sizeof(DeltaRecord) * ((baseSize - begSize - endSize) / STRMIN + 50));
    DeltaRecord *BaseLink = BaseLink_;

    int offset = (char *)&BaseLink[0].psNextSubCnk - (char *)&BaseLink[0];
    htable *psHTable = psHTable2_;
    // psHTable->init(offset, 8, baseSize/16);
#if POST_DEDUP
    psHTable->init(offset, 8, (baseSize - begSize - endSize) * 2 / (STRAVG + 1));
#else
    psHTable2_->ResetTable();
    psHTable2_->SetOffset(offset);
//   init(offset, 8, 8 * 1024);
#endif

    // int chunk_length;
    int flag_chunk = 1; // to tell if basefile has been chunked to the end
    int numBytes_old;
    int numBytes_accu = 0; // accumulated numBytes in one turn of chunking the
                           // base
    int probe_match;       // to tell which chunk for probing matches the some base
    int flag_handle_probe; // to tell whether the probe chunks need to be handled

    if (beg)
    {
        record1.nOffset = 0;
        set_length(&record1, begSize);
        memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
        deltaLen += sizeof(DeltaUnit1);
        flag = 1;
    }

#define BASE_BEGIN 5
#define BASE_EXPAND 3
#define BASE_STEP 3
#define INPUT_TRY 5

/* if deltaLen > newSize * RECOMPRESS_THRESHOLD in the first round,we'll
 * go back to greedy.
 */
#define GO_BACK_TO_GREEDY 0

#define RECOMPRESS_THRESHOLD 0.2

    DeltaRecord InputLink[INPUT_TRY];
    // int test=0;

    while (inputPos < newSize - endSize)
    {
        if (flag_chunk)
        {
            //		if( cursor_input - input_last_chunk_beg >= numBytes_accu
            //* 0.8 ){
            if ((cursor_input / (float)newSize) + 0.5 >=
                (cursor_base / (float)baseSize))
            {
                numBytes_old = numBytes_accu;
                numBytes_accu = 0;

                /* chunk a few chunks in the input first */
                // Chunking_v3(newBuf+cursor_input, newSize-endSize-cursor_input,
                // INPUT_TRY, InputLink);
                flag_handle_probe = 1;
                probe_match = INPUT_TRY;
                int chunk_number = BASE_BEGIN;
                for (int i = 0; i < BASE_STEP; i++)
                {
                    numBytes = Chunking_v3(
                        baseBuf + cursor_base, baseSize - endSize - cursor_base,
                        chunk_number,
                        BaseLink + numBase); // 一个分块base的循环找到 match的就可以跳出

                    for (int j = 0; j < chunk_number; j++)
                    {
                        if (BaseLink[numBase + j].nLength == 0)
                        {
                            flag_chunk = 0;
                            break;
                        }
                        BaseLink[numBase + j].nOffset += cursor_base;
                        psHTable->insert((unsigned char *)&BaseLink[numBase + j].nHash,
                                         &BaseLink[numBase + j]);
                    }

                    cursor_base += numBytes;
                    numBase += chunk_number;
                    numBytes_accu += numBytes;

                    chunk_number *= BASE_EXPAND;
                    if (i == 0)
                    {
                        cursor_input1 = cursor_input;
                        for (int j = 0; j < INPUT_TRY; j++)
                        {
                            cursor_input2 = cursor_input1;
                            cursor_input1 = chunk_gear(newBuf + cursor_input2,
                                                       newSize - cursor_input2 - endSize) +
                                            cursor_input2;
                            InputLink[j].nLength = cursor_input1 - cursor_input2;
                            InputLink[j].nHash =
                                weakHash(newBuf + cursor_input2, InputLink[j].nLength);
                            if ((psDupSubCnk = (DeltaRecord *)psHTable->lookup(
                                     (unsigned char *)&(InputLink[j].nHash))))
                            {
                                probe_match = j;
                                goto lets_break;
                            }
                        }
                    }
                    else
                    {
                        for (int j = 0; j < INPUT_TRY; j++)
                        {
                            if ((psDupSubCnk = (DeltaRecord *)psHTable->lookup(
                                     (unsigned char *)&(InputLink[j].nHash))))
                            {
                                // printf("find INPUT_TRY: %d BASE_STEP: %d"
                                //	" cursor_input: %d round of chunk: %d\n",
                                //	j,i,cursor_input,test);
                                probe_match = j;
                                goto lets_break;
                            }
                        }
                    }

                    if (flag_chunk == 0)
                    lets_break:
                        break;
                }

                input_last_chunk_beg =
                    (cursor_input > (input_last_chunk_beg + numBytes_old)
                         ? cursor_input
                         : (input_last_chunk_beg + numBytes_old));
                // test++;
            }
        }

        // to handle the chunks in input file for probing
        if (flag_handle_probe)
        {
            for (int i = 0; i < INPUT_TRY; i++)
            {
                matchsum++;
                length = InputLink[i].nLength;
                cursor_input = length + inputPos;

                if (i == probe_match)
                {
                    flag_handle_probe = 0;
                    goto match;
                }
                else
                {
                    if (flag == 2)
                    { // 把不match的块弄过去
                        /* continuous unique chunks only add unique bytes into the deltaBuf,
                         * but not change the last DeltaUnit2, so the DeltaUnit2 should be
                         * overwritten when flag=1 or at the end of the loop.
                         */
                        memcpy(deltaBuf + deltaLen, newBuf + inputPos, length);
                        deltaLen += length;
                        set_length(&record2, get_length(&record2) + length);
                    }
                    else
                    {
                        set_length(&record2, length);

                        memcpy(deltaBuf + deltaLen, &record2, sizeof(DeltaUnit2));
                        deltaLen += sizeof(DeltaUnit2);

                        memcpy(deltaBuf + deltaLen, newBuf + inputPos, length);
                        deltaLen += length;

                        flag = 2;
                    }

                    inputPos = cursor_input;
                }
            }

            flag_handle_probe = 0;
        }

        cursor_input =
            chunk_gear(newBuf + inputPos, newSize - inputPos - endSize) + inputPos;
        matchsum++;
        length = cursor_input - inputPos;
        hash = weakHash(newBuf + inputPos, length);

        /* lookup */
        if ((psDupSubCnk =
                 (DeltaRecord *)psHTable->lookup((unsigned char *)&hash)))
        {
        // printf("inputPos: %d length: %d\n", inputPos, length);
        match:
            if (length == psDupSubCnk->nLength &&
                memcmp(newBuf + inputPos, baseBuf + psDupSubCnk->nOffset, length) ==
                    0)
            {
                //	printf("match:%d\n",length);
                match++;
                if (flag == 2)
                {
                    /* continuous unique chunks only add unique bytes into the deltaBuf,
                     * but not change the last DeltaUnit2, so the DeltaUnit2 should be
                     * overwritten when flag=1 or at the end of the loop.
                     */
                    memcpy(deltaBuf + deltaLen - get_length(&record2) -
                               sizeof(DeltaUnit2),
                           &record2, sizeof(DeltaUnit2));
                }

                // greedily detect forward
                int j = 0;

                while (psDupSubCnk->nOffset + length + j + 7 < baseSize - endSize &&
                       cursor_input + j + 7 < newSize - endSize)
                {
                    if (*(uint64_t *)(baseBuf + psDupSubCnk->nOffset + length + j) ==
                        *(uint64_t *)(newBuf + cursor_input + j))
                    {
                        j += 8;
                    }
                    else
                        break;
                }
                while (psDupSubCnk->nOffset + length + j < baseSize - endSize &&
                       cursor_input + j < newSize - endSize)
                {
                    if (baseBuf[psDupSubCnk->nOffset + length + j] ==
                        newBuf[cursor_input + j])
                    {
                        j++;
                    }
                    else
                        break;
                }

                cursor_input += j;
                if (psDupSubCnk->nOffset + length + j > cursor_base)
                    cursor_base = psDupSubCnk->nOffset + length + j;

                set_length(&record1, cursor_input - inputPos);
                record1.nOffset = psDupSubCnk->nOffset;

                /* detect backward */
                uint32_t k = 0;
                if (flag == 2)
                {
                    while (k + 1 <= psDupSubCnk->nOffset &&
                           k + 1 <= get_length(&record2))
                    {
                        if (baseBuf[psDupSubCnk->nOffset - (k + 1)] ==
                            newBuf[inputPos - (k + 1)])
                            k++;
                        else
                            break;
                    }
                }
                if (k > 0)
                {
                    deltaLen -= get_length(&record2);
                    deltaLen -= sizeof(DeltaUnit2);

                    set_length(&record2, get_length(&record2) - k);

                    if (get_length(&record2) > 0)
                    {
                        memcpy(deltaBuf + deltaLen, &record2, sizeof(DeltaUnit2));
                        deltaLen += sizeof(DeltaUnit2);
                        deltaLen += get_length(&record2);
                    }

                    set_length(&record1, get_length(&record1) + k);
                    record1.nOffset -= k;
                }

                memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
                deltaLen += sizeof(DeltaUnit1);
                flag = 1;
            }
            else
            {
                // printf("Spooky Hash Error!!!!!!!!!!!!!!!!!!\n");
                goto handle_hash_error;
            }
        }
        else
        {
        handle_hash_error:
            //	printf("unmatch:%d\n",length);
            if (flag == 2)
            {
                /* continuous unique chunks only add unique bytes into the deltaBuf,
                 * but not change the last DeltaUnit2, so the DeltaUnit2 should be
                 * overwritten when flag=1 or at the end of the loop.
                 */
                memcpy(deltaBuf + deltaLen, newBuf + inputPos, length);
                deltaLen += length;
                set_length(&record2, get_length(&record2) + length);
            }
            else
            {
                set_length(&record2, length);

                memcpy(deltaBuf + deltaLen, &record2, sizeof(DeltaUnit2));
                deltaLen += sizeof(DeltaUnit2);

                memcpy(deltaBuf + deltaLen, newBuf + inputPos, length);
                deltaLen += length;

                flag = 2;
            }
        }

        inputPos = cursor_input;
        // printf("cursor_input:%d\n",inputPos);
    }

    if (flag == 2)
    {
        /* continuous unique chunks only add unique bytes into the deltaBuf,
         * but not change the last DeltaUnit2, so the DeltaUnit2 should be
         * overwritten when flag=1 or at the end of the loop.
         */
        memcpy(deltaBuf + deltaLen - get_length(&record2) - sizeof(DeltaUnit2),
               &record2, sizeof(DeltaUnit2));
    }

    if (end)
    {
        record1.nOffset = baseSize - endSize;
        set_length(&record1, endSize);
        memcpy(deltaBuf + deltaLen, &record1, sizeof(DeltaUnit1));
        deltaLen += sizeof(DeltaUnit1);
    }

    //   if (psHTable) {
    //     free(psHTable->table);
    //     free(psHTable);
    //   }
    psHTable->ResetTable();

    //   free(BaseLink);

    *deltaSize = deltaLen;
    return deltaLen;
}

int OFFLineBackward::EDeltaDecode(uint8_t *deltaBuf, uint32_t deltaSize, uint8_t *baseBuf,
                                  uint32_t baseSize, uint8_t *outBuf, uint32_t *outSize)
{

    uint32_t dataLength = 0, readLength = 0;
    int matchnum = 0;
    // int matchlength = 0;
    // int unmatchlength = 0;
    int unmatchnum = 0;
    while (1)
    {
        u_int32_t flag = get_flag(deltaBuf + readLength);

        if (flag == 0)
        {
            matchnum++;
            DeltaUnit1 record;
            memcpy(&record, deltaBuf + readLength, sizeof(DeltaUnit1));
            readLength += sizeof(DeltaUnit1);
            // matchlength += get_length(&record);
            memcpy(outBuf + dataLength, baseBuf + record.nOffset,
                   get_length(&record));

            dataLength += get_length(&record);
        }
        else
        {
            unmatchnum++;
            DeltaUnit2 record;
            memcpy(&record, deltaBuf + readLength, sizeof(DeltaUnit2));
            readLength += sizeof(DeltaUnit2);
            // unmatchlength += get_length(&record);
            memcpy(outBuf + dataLength, deltaBuf + readLength, get_length(&record));
            readLength += get_length(&record);
            dataLength += get_length(&record);
        }

        if (readLength >= deltaSize)
        {
            break;
        }
    }
    *outSize = dataLength;
    return dataLength;
}

// ==================== Extension 离线优化功能实现 ====================
void OFFLineBackward::Extension_update(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_)
{
    Enclave::Logging(myName_.c_str(), "===== 开始Extension离线处理 =====\n");

    if (!upOutSGX)
    {
        Enclave::Logging(myName_.c_str(), "Extension_update: upOutSGX 为 NULL, 提前返回\n");
        return;
    }

    InitExtension(upOutSGX);

    EnclaveClient *sgxClient = (EnclaveClient *)upOutSGX->sgxClient;
    EVP_CIPHER_CTX *cipherCtx = sgxClient->_cipherCtx;
    OutQueryEntry_t *outEntry = upOutSGX->outQuery->outQueryBase;
    // Enclave::Logging(myName_.c_str(),
    //                  "Extension_update: upOutSGX=%p, sgxClient=%p, cipherCtx=%p, outEntry=%p\n",
    //                  (void *)upOutSGX, (void *)sgxClient, (void *)cipherCtx, (void *)outEntry);

    // 统计信息初始化
    _extensionProcessedGroups_ = 0;
    _extensionReselectedBase_ = 0;
    _extensionSavedSize_ = 0;
    // _offline_Ocall = 0;

    uint8_t *buffer = upOutSGX->test_buffer;
    uint32_t batchNum;
    int totalProcessedGroups = 0;
    uint64_t checkSum = 0;
    // 与 outClient->_test_buffer 分配保持一致，防御性检查
    const size_t TEST_BUFFER_BYTES = 200000 * CHUNK_HASH_SIZE;
    // Enclave::Logging(myName_.c_str(), "Extension_update: test_buffer=%p, TEST_BUFFER_BYTES=%zu\n", (void *)buffer, TEST_BUFFER_BYTES);
    do
    {
        Ocall_GetAllDeltaIndex(upOutSGX->outClient);
        _offline_Ocall++;
        // Enclave::Logging(myName_.c_str(), "Extension_update: Ocall_GetAllDeltaIndex 完成, _offline_Ocall=%llu\n", _offline_Ocall);
        // Enclave::Logging(myName_.c_str(), "ocall count is %d amd batch num is %d\n", _offline_Ocall, batchNum);
        memcpy(&batchNum, buffer, sizeof(uint32_t));
        size_t offset = sizeof(uint32_t);
        // Enclave::Logging(myName_.c_str(), "Extension_update: 解析批次 batchNum=%u, 初始offset=%zu\n", batchNum, offset);

        if (batchNum == 0)
        {
            Enclave::Logging(myName_.c_str(), "Extension_update: batchNum=0, 结束循环\n");
            break;
        }
        checkSum += batchNum;
        // 处理本批次的每个delta_index条目
        for (uint32_t i = 0; i < batchNum; i++)
        {
            // 读取基础块FP
            vector<string>().swap(candidateGroup); // 清空上次残留
            string baseChunkFP;
            baseChunkFP.assign((char *)(buffer + offset), CHUNK_HASH_SIZE);
            offset += CHUNK_HASH_SIZE;
            // 读取delta chunks数量
            uint32_t deltaCount;
            memcpy(&deltaCount, buffer + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);
            if (deltaCount == 0)
            {
                Enclave::Logging(myName_.c_str(), "Extension_update: delta count = 0");
                continue;
            }
            // Enclave::Logging(myName_.c_str(),
            //                  "Extension_update: 组 %u/%u, offset=%zu, deltaCount=%u\n",
            //                  i + 1, batchNum, offset, deltaCount);

            candidateGroup.push_back(baseChunkFP);
            // 读取所有delta chunk FPs
            // vector<string> deltaFPs;
            if (offset + (size_t)deltaCount * CHUNK_HASH_SIZE > TEST_BUFFER_BYTES)
            {
                // Enclave::Logging(myName_.c_str(), "Extension_update: buffer truncated in delta list, offset=%zu, deltaCount=%u\n", offset, deltaCount);
                batchNum = i; // 仅统计已安全解析的项
                break;
            }
            for (uint32_t j = 0; j < deltaCount; j++)
            {
                string deltaFP;
                deltaFP.assign((char *)(buffer + offset), CHUNK_HASH_SIZE);
                candidateGroup.push_back(deltaFP);
                offset += CHUNK_HASH_SIZE;
            }

            // Enclave::Logging(myName_.c_str(),
            //                  "Extension_update: 组 %u 构建完成, deltaFPs.size()=%zu, 下一offset=%zu\n",
            //                  i + 1, deltaFPs.size(), offset);

            // Enclave::Logging(myName_.c_str(), "Extension_update: 开始处理组 %u\n", i + 1);
            ProcessOneGroupChunk_Extension_Full(upOutSGX, cryptoObj_);
            // Enclave::Logging(myName_.c_str(), "Extension_update: 完成处理组 %u\n", i + 1);
            totalProcessedGroups++;
        }
    } while (batchNum > 0);

    // Enclave::Logging(myName_.c_str(), "checkSum is %d\n", checkSum);
    // 保存热容器（如果有新的增量数据生成）
    if (hot_container.currentSize != 0)
    {
        // Enclave::Logging(myName_.c_str(), "Extension_update: 保存热容器, currentSize=%u\n", hot_container.currentSize);
        Ocall_SavehotContainer(&hot_container.containerID[0], hot_container.body, hot_container.currentSize);
        _offline_Ocall++;
        // Enclave::Logging(myName_.c_str(), "Extension_update: Ocall_SavehotContainer 完成, _offline_Ocall=%llu\n", _offline_Ocall);
    }

    if (hot_base_container.currentSize != 0)
    {
        // Enclave::Logging(myName_.c_str(), "Extension_update: 保存热基础容器, currentSize=%u\n", hot_base_container.currentSize);
        Ocall_SavehotBaseContainer(&hot_base_container.containerID[0], hot_base_container.body, hot_base_container.currentSize);
        _offline_Ocall++;
        // Enclave::Logging(myName_.c_str(), "Extension_update: Ocall_SavehotContainer 完成, _offline_Ocall=%llu\n", _offline_Ocall);
    }
    CleanExtension();

    // 计算系统总压缩率
    double totalCompressionRatio = 0.0;
    if (_offlineCurrBackup_size > 0)
    {
        totalCompressionRatio = 100.0 * _offlineCompress_size / _offlineCurrBackup_size;
    }
    // clear extension map
    Ocall_CleanLocalIndex();
    _offline_Ocall++;
    Enclave::Logging(myName_.c_str(), "Extension_update: Ocall_CleanLocalIndex 完成, _offline_Ocall=%llu\n", _offline_Ocall);

    Enclave::Logging(myName_.c_str(), "===== Extension处理完成 =====\n");
    Enclave::Logging(myName_.c_str(), "处理组数: %llu, 重选基础块: %llu, Ocall次数: %llu\n",
                     _extensionProcessedGroups_, _extensionReselectedBase_, _offline_Ocall);
    Enclave::Logging(myName_.c_str(), "系统统计: 压缩大小: %llu bytes, 备份大小: %llu bytes\n",
                     _offlineCompress_size, _offlineCurrBackup_size);
    Enclave::Logging(myName_.c_str(), "基础块数: %lld, 增量块数: %llu\n", _baseChunkNum, _deltaChunkNum);
    Enclave::Logging(myName_.c_str(), "Extension节省空间: %llu bytes, 系统总压缩率: %.2f%%\n",
                     _extensionSavedSize_, totalCompressionRatio);
    Enclave::Logging(myName_.c_str(), "Extension_update: 汇总 checkSum=%llu, totalProcessedGroups=%d\n", checkSum, totalProcessedGroups);
}

/**
 * @brief 从数据块中提取特征
 * @details 使用GEAR哈希算法进行特征采样，模拟absMethod中的特征提取过程
 *          采样的特征用于计算不同数据块之间的相似性
 */
void OFFLineBackward::ExtractChunkFeatures(uint8_t *chunkPtr, size_t chunkSize, vector<uint64_t> &features)
{
    // Enclave::Logging(myName_.c_str(), "ExtractChunkFeatures: enter, ptr=%p, size=%zu\n", (void *)chunkPtr, chunkSize);
    features.clear();

    const uint64_t kSampleRatioMask = 0x0000400303410000ULL;
    uint64_t hash = 0;

    for (size_t i = 0; i < chunkSize; ++i)
    {
        hash = (hash << 1) + GEARmx[static_cast<uint8_t>(chunkPtr[i])];

        if (!(hash & kSampleRatioMask))
        {
            features.push_back(hash);
            extension_sampledFeatureCounts_[hash]++;
        }
    }
    // Enclave::Logging(myName_.c_str(), "ExtractChunkFeatures: exit, features=%zu\n", features.size());
}

/**
 * @brief 为一组数据块选择最优的基础块
 * @details 计算每个候选块的特征重用度得分，选择得分最高的作为新基础块
 *          得分基于该块包含的特征在整个数据集中的使用频率
 */
string OFFLineBackward::SelectOptimalBaseChunk(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_)
{
    string optimalBaseFP = candidateGroup[0];
    size_t maxScore = 0;
    extension_chunkFeatures_.clear();
    extension_chunkFeatures_.reserve(candidateGroup.size());

    EnclaveClient *sgxClient = (EnclaveClient *)upOutSGX->sgxClient;
    EVP_CIPHER_CTX *cipherCtx = sgxClient->_cipherCtx;
    OutQueryEntry_t *outEntry = upOutSGX->outQuery->outQueryBase;

    // load old base chunk recipe
    memcpy(&outEntry->chunkHash, (uint8_t *)&optimalBaseFP[0], CHUNK_HASH_SIZE);
    Ocall_OneRecipe(upOutSGX->outClient);
    _offline_Ocall++;
    cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)old_recipe_);
    // load old base chunk content
    memcpy(&outEntry->chunkAddr.containerName, old_recipe_->containerName, CONTAINER_ID_LENGTH);
    Ocall_OneContainer(upOutSGX->outClient);
    _offline_Ocall++;
    pair<uint32_t, uint32_t> tmpPair;
    uint8_t *encryptContent = GetChunk_content_buffer(outEntry->containerbuffer, old_recipe_, false, tmpPair, encOldChunkBuffer_);
    // decrypt
    uint8_t *oldBaseIV = GetChunk_IV(outEntry->containerbuffer, old_recipe_, offline_oldIVBuffer_);
    uint8_t *old_base_content_decrypt = offline_oldChunkDecrypt_;
    cryptoObj_->DecryptionWithKeyIV(cipherCtx, encryptContent, old_recipe_->length, Enclave::enclaveKey_, old_base_content_decrypt, oldBaseIV);
    // decompression
    uint8_t *old_base_content_decompression = offline_oldChunkDecompression_;
    int old_base_ref_size = LZ4_decompress_safe((char *)old_base_content_decrypt, (char *)old_base_content_decompression, old_recipe_->length, MAX_CHUNK_SIZE);
    uint8_t *old_chunk;
    if (old_base_ref_size < 0)
    {
        old_base_ref_size = old_recipe_->length;
        old_chunk = old_base_content_decrypt;
    }
    else
    {
        old_chunk = old_base_content_decompression;
    }
    // compute basechunk scores
    // vector<uint64_t> features;
    // features.clear();
    auto &vec = extension_chunkFeatures_[optimalBaseFP];
    vec.clear();
    ExtractChunkFeatures(old_chunk, old_base_ref_size, vec);
    Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: load old base chunk done\n");

    for (size_t i = 1; i < candidateGroup.size(); i++)
    {
        const string &chunkFP = candidateGroup[i];
        // get delta recipe
        memcpy(&outEntry->chunkHash, (uint8_t *)chunkFP.data(), CHUNK_HASH_SIZE);
        Ocall_OneRecipe(upOutSGX->outClient);
        _offline_Ocall++;
        cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)delta_recipe_);
        // get delta chunk content
        memcpy(&outEntry->chunkAddr.containerName, delta_recipe_->containerName, CONTAINER_ID_LENGTH);
        Ocall_OneDeltaContainer(upOutSGX->outClient);
        _offline_Ocall++;
        // decrypt
        uint8_t *deltaIV = GetChunk_IV(outEntry->containerbuffer, delta_recipe_, offline_deltaIVBuffer_);
        uint8_t *delta_content_crypt = GetChunk_content_buffer(outEntry->containerbuffer, delta_recipe_, false, tmpPair, offline_oldDeltaChunkEnc_);
        uint8_t *delta_content_decrypt = offline_oldDeltaChunkEnc_;
        size_t delta_size = delta_recipe_->length;
        cryptoObj_->DecryptionWithKeyIV(cipherCtx, delta_content_crypt, delta_size, Enclave::enclaveKey_, delta_content_decrypt, deltaIV);
        // delta decode
        uint8_t *old_unique_chunk;
        size_t old_unique_size;
        old_unique_chunk = ed3_decode_buffer(delta_content_decrypt, delta_size, old_chunk, old_base_ref_size, offline_tmpUniqueBuffer_, &old_unique_size);
        // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: LoadChunkData ret data=%p size=%zu for candidate[%zu]\n", (void *)chunkData, chunkSize, i);
        Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: load delta chunk done\n");
        LogExtensionChunkFeaturesStats("after loading candidate chunk");
        if (old_unique_chunk && old_unique_size > 0)
        {
            auto &vec = extension_chunkFeatures_[chunkFP];
            vec.clear();
            ExtractChunkFeatures(old_unique_chunk, old_unique_size, vec);
            // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: features extracted=%zu for candidate[%zu]\n", features.size(), i);
            // extension_chunkFeatures_[chunkFP] = features;
        }
        else
        {
            Enclave::Logging("ERROR", "Extension: 无法加载候选块 [%02x] 的数据\n", (uint8_t)chunkFP[0]);
        }
    }

    for (size_t i = 0; i < candidateGroup.size(); i++)
    {
        const string &chunkFP = candidateGroup[i];
        size_t currentScore = 0;
        // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: 计算候选块[%zu]得分, features=%zu\n",
        //                  i, extension_chunkFeatures_[chunkFP].size());
        // unordered_set<uint64_t> uniqueFeatures(extension_chunkFeatures_[chunkFP].begin(), extension_chunkFeatures_[chunkFP].end());
        auto it = extension_chunkFeatures_.find(chunkFP);
        if (it == extension_chunkFeatures_.end())
            continue;
        auto &vec = it->second;
        std::sort(vec.begin(), vec.end());
        vec.erase(std::unique(vec.begin(), vec.end()), vec.end());
        for (auto &feature : vec)
        {
            currentScore += extension_sampledFeatureCounts_[feature];
        }

        if (currentScore > maxScore)
        {
            maxScore = currentScore;
            optimalBaseFP = chunkFP;
            // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: 候选块[%zu]当前最高得分 %zu, 设为最优基础块\n",
            //                  i, maxScore);
        }
    }
    Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: 选择完成, optimalBaseFP=%02x, maxScore=%zu\n",
                     (uint8_t)optimalBaseFP[0], maxScore);
    return optimalBaseFP;
}

string OFFLineBackward::SelectOptimalBaseChunk(const vector<string> &chunkGroup, UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_, uint8_t *old_chunk, size_t old_chunk_ref_size, uint8_t *new_chunk, size_t new_chunk_ref_size)
{
    // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: enter, chunkGroup size=%zu\n", chunkGroup.size());
    string BaseFP1 = chunkGroup[0];
    size_t maxScore = 0;

    EnclaveClient *sgxClient = (EnclaveClient *)upOutSGX->sgxClient;
    EVP_CIPHER_CTX *cipherCtx = sgxClient->_cipherCtx;
    OutQueryEntry_t *outEntry = upOutSGX->outQuery->outQueryBase;

    pair<uint32_t, uint32_t> tmpPair;
    vector<uint64_t> features;
    ExtractChunkFeatures(old_chunk, old_chunk_ref_size, features);
    extension_chunkFeatures_[BaseFP1] = features;

    // basefp2cd
    string BaseFP2 = chunkGroup[1];
    features.clear();
    ExtractChunkFeatures(new_chunk, new_chunk_ref_size, features);
    extension_chunkFeatures_[BaseFP2] = features;

    for (size_t i = 2; i < chunkGroup.size(); i++)
    {
        const string &chunkFP = chunkGroup[i];
        // get delta recipe
        memcpy(&outEntry->chunkHash, (uint8_t *)chunkFP.data(), CHUNK_HASH_SIZE);
        Ocall_OneRecipe(upOutSGX->outClient);
        cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)delta_recipe_);
        // get delta chunk content
        memcpy(&outEntry->chunkAddr.containerName, delta_recipe_->containerName, CONTAINER_ID_LENGTH);
        if (delta_recipe_->deltaFlag == NO_DELTA)
        {
            Ocall_OneContainer(upOutSGX->outClient);
        }
        else
        {
            Ocall_OneDeltaContainer(upOutSGX->outClient);
        }
        // Ocall_OneDeltaContainer(upOutSGX->outClient);
        _offline_Ocall++;
        // decrypt
        memcpy(tmpDeltaContainer, outEntry->containerbuffer, MAX_CONTAINER_SIZE);
        uint8_t *deltaIV = GetChunk_IV(tmpDeltaContainer, delta_recipe_, offline_deltaIVBuffer_);
        uint8_t *delta_content_crypt = GetChunk_content_buffer(tmpDeltaContainer, delta_recipe_, false, tmpPair, offline_oldDeltaChunkEnc_);
        uint8_t *delta_content_decrypt = offline_oldDeltaChunkDec_;
        size_t delta_size = delta_recipe_->length;
        cryptoObj_->DecryptionWithKeyIV(cipherCtx, delta_content_crypt, delta_size, Enclave::enclaveKey_, delta_content_decrypt, deltaIV);
        uint8_t *old_unique_chunk;
        size_t old_unique_size;
        if (delta_recipe_->deltaFlag == NO_DELTA)
        {
            old_unique_size = LZ4_decompress_safe((char *)delta_content_decrypt, (char *)offline_tmpUniqueBuffer_, delta_size, MAX_CHUNK_SIZE);
            if (old_unique_size > 0)
            {
                old_unique_chunk = offline_tmpUniqueBuffer_;
            }
            else
            {
                old_unique_size = delta_size;
                old_unique_chunk = delta_content_decrypt;
            }
        }
        else
        {
            // delta decode
            old_unique_chunk = ed3_decode_buffer(delta_content_decrypt, delta_size, old_chunk, old_chunk_ref_size, offline_tmpUniqueBuffer_, &old_unique_size);
        }
        // delta decode
        // uint8_t *old_unique_chunk;
        // size_t old_unique_size;
        // old_unique_chunk = ed3_decode_buffer(delta_content_decrypt, delta_size, old_chunk, old_chunk_ref_size, offline_tmpUniqueBuffer_, &old_unique_size);
        // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: LoadChunkData ret data=%p size=%zu for candidate[%zu]\n", (void *)chunkData, chunkSize, i);
        if (old_unique_chunk && old_unique_size > 0)
        {
            // features.clear();
            ExtractChunkFeatures(old_unique_chunk, old_unique_size, features);
            // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: features extracted=%zu for candidate[%zu]\n", features.size(), i);
            extension_chunkFeatures_[chunkFP] = features;
        }
        else
        {
            Enclave::Logging("ERROR", "Extension: 无法加载候选块 [%02x] 的数据\n", (uint8_t)chunkFP[0]);
        }
    }

    string optimalBaseFP;
    for (size_t i = 0; i < chunkGroup.size(); i++)
    {
        const string &chunkFP = chunkGroup[i];
        size_t currentScore = 0;
        // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: 计算候选块[%zu]得分, features=%zu\n",
        //                  i, extension_chunkFeatures_[chunkFP].size());
        unordered_set<uint64_t> uniqueFeatures(extension_chunkFeatures_[chunkFP].begin(), extension_chunkFeatures_[chunkFP].end());
        for (auto &feature : uniqueFeatures)
        {
            currentScore += extension_sampledFeatureCounts_[feature];
        }
        // Enclave::Logging(myName_.c_str(), "currentScore for candidate[%zu](%02x) is %zu\n", i, (uint8_t)chunkFP[0], currentScore);
        // Enclave::Logging(myName_.c_str(), "maxScore is %zu\n", maxScore);
        if (currentScore > maxScore)
        {
            maxScore = currentScore;
            optimalBaseFP = chunkFP;
            // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: 候选块[%zu]当前最高得分 %zu, 设为最优基础块\n",
            //                  i, maxScore);
        }
    }
    // Enclave::Logging(myName_.c_str(), "SelectOptimalBaseChunk: 选择完成, optimalBaseFP=%02x, maxScore=%zu\n",
    //                  (uint8_t)optimalBaseFP[0], maxScore);
    return optimalBaseFP;
}
/**
 * @brief Extension算法全量处理版本：处理单个块组
 * @details 不依赖local_map，直接在当前基础块和所有增量块中选择最优基础块
 * @param baseChunkFP 当前基础块指纹
 * @param deltaFPs 增量块指纹列表
 * @param upOutSGX SGX通信结构体指针
 * @param cryptoObj_ 加密对象指针
 */
void OFFLineBackward::ProcessOneGroupChunk_Extension_Full(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_)
{
    _extensionProcessedGroups_++;
    extension_chunkFeatures_.clear();
    extension_sampledFeatureCounts_.clear();
    string optimalBaseFP = SelectOptimalBaseChunk(upOutSGX, cryptoObj_);

    // 如果最优基础块与当前基础块不同，进行重组织
    if (optimalBaseFP != candidateGroup[0])
    {
        // Enclave::Logging(myName_.c_str(), "Extension: 需重组织块组: base->optimal\n");
        ReorganizeChunkGroup_Extension(candidateGroup[0], optimalBaseFP, upOutSGX, cryptoObj_);
    }
    else
    {
        // Enclave::Logging(myName_.c_str(), "Extension: 保持原基础块(已最优)\n");
    }
    return;
}

/**
 * @brief Extension算法专用的块组重组织函数
 * @details 将候选组中的所有块重新以最优基础块为基准进行增量编码
 * @param oldBaseFP 原始基础块指纹
 * @param optimalBaseFP 选择的最优基础块指纹
 * @param candidateGroup 候选组：包含old_base、new_base、所有delta chunks
 * @param upOutSGX SGX输出结构
 * @param cryptoObj_ 加密对象
 */
void OFFLineBackward::ReorganizeChunkGroup_Extension(const string &oldBaseFP, const string &optimalBaseFP, UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_)
{
    EnclaveClient *sgxClient = (EnclaveClient *)upOutSGX->sgxClient;
    EVP_CIPHER_CTX *cipherCtx = sgxClient->_cipherCtx;
    OutQueryEntry_t *outEntry = upOutSGX->outQuery->outQueryBase;

    // Enclave::Logging(myName_.c_str(), "Extension: 开始重组织, 候选=%zu\n", candidateGroup.size());
    // get old base chunk data
    memcpy(&outEntry->chunkHash, (uint8_t *)oldBaseFP.data(), CHUNK_HASH_SIZE);
    Ocall_OneRecipe(upOutSGX->outClient);
    _offline_Ocall++;
    cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)old_recipe_);
    // load old base chunk content
    memcpy(&outEntry->chunkAddr.containerName, old_recipe_->containerName, CONTAINER_ID_LENGTH);
    Ocall_OneContainer(upOutSGX->outClient);
    _offline_Ocall++;
    pair<uint32_t, uint32_t> tmpPair;
    uint8_t *encryptContent = GetChunk_content_buffer(outEntry->containerbuffer, old_recipe_, false, tmpPair, encOldChunkBuffer_);
    // decrypt
    uint8_t *oldBaseIV = GetChunk_IV(outEntry->containerbuffer, old_recipe_, offline_oldIVBuffer_);
    uint8_t *oldBaseFp = GetChunk_FP(outEntry->containerbuffer, old_recipe_);
    uint8_t *oldBaseSF = GetChunk_SF(outEntry->containerbuffer, old_recipe_);
    uint8_t *old_base_content_decrypt = offline_oldChunkDecrypt_;
    cryptoObj_->DecryptionWithKeyIV(cipherCtx, encryptContent, old_recipe_->length, Enclave::enclaveKey_, old_base_content_decrypt, oldBaseIV);
    // decompression
    uint8_t *old_base_content_decompression = offline_oldChunkDecompression_;
    int old_base_ref_size = LZ4_decompress_safe((char *)old_base_content_decrypt, (char *)old_base_content_decompression, old_recipe_->length, MAX_CHUNK_SIZE);
    uint8_t *old_chunk;
    if (old_base_ref_size < 0)
    {
        old_base_ref_size = old_recipe_->length;
        old_chunk = old_base_content_decrypt;
    }
    else
    {
        old_chunk = old_base_content_decompression;
    }
    // Enclave::Logging(myName_.c_str(), "Extension: 旧基础块加载成功\n");
    // get optimal new base chunk data
    memcpy(&outEntry->chunkHash, (uint8_t *)optimalBaseFP.data(), CHUNK_HASH_SIZE);
    Ocall_OneRecipe(upOutSGX->outClient);
    _offline_Ocall++;
    cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)new_recipe_);
    memcpy(&outEntry->chunkAddr.containerName, new_recipe_->containerName, CONTAINER_ID_LENGTH);
    Ocall_OneDeltaContainer(upOutSGX->outClient);
    _offline_Ocall++;
    tmpPair;
    uint8_t *optimalBaseIV = GetChunk_IV(outEntry->containerbuffer, new_recipe_, offline_newIVBuffer_);
    // uint8_t *optimalBaseFP = GetChunk_FP(outEntry->containerbuffer, new_recipe_);
    uint8_t *optimalBaseSF = GetChunk_SF(outEntry->containerbuffer, new_recipe_);
    // decrypt optimal base chunk
    uint8_t *optimalEncryptContent = GetChunk_content_buffer(outEntry->containerbuffer, new_recipe_, false, tmpPair, encNewChunkBuffer_);

    uint8_t *optimalBaseDataDecrypt = offline_newChunkDecrypt_;
    cryptoObj_->DecryptionWithKeyIV(cipherCtx, optimalEncryptContent, new_recipe_->length, Enclave::enclaveKey_, optimalBaseDataDecrypt, optimalBaseIV);
    // delta encode
    uint8_t *optimal_chunk;
    size_t optimal_size;
    optimal_chunk = ed3_decode_buffer(optimalBaseDataDecrypt, new_recipe_->length, old_chunk, old_base_ref_size, offline_optimalChunkBuffer_, &optimal_size);
    Enclave::Logging(myName_.c_str(), "Extension: 新基础块加载成功\n");
    // 1. 获取最优基础块的数据内容
    // size_t optimalBaseSize;
    // size_t onlineBaseSize;
    // uint8_t *optimalBaseData = LoadChunkDataWithStatus(optimalBaseFP, upOutSGX, cryptoObj_, &optimalBaseSize, &optimalBaseFlag, &onlineBaseSize);
    // if (!optimalBaseData)
    // {
    //     Enclave::Logging(myName_.c_str(), "Extension: 无法加载最优基础块数据\n");
    //     return;
    // }
    // update superfeature index
    // memcpy(optimalBaseSFBuffer_, optimalBaseSF, 3 * CHUNK_HASH_SIZE);
    // memcpy((uint8_t *)&outEntry->superfeature, optimalBaseSFBuffer_, 3 * CHUNK_HASH_SIZE);
    // Ocall_OFFline_updateIndex(upOutSGX->outClient, 1);
    // memcpy(oldBaseChunkSFBuffer_, oldBaseSF, 3 * CHUNK_HASH_SIZE);
    // memcpy((uint8_t *)&outEntry->superfeature, oldBaseChunkSFBuffer_, 3 * CHUNK_HASH_SIZE);
    // Ocall_OFFline_updateIndex(upOutSGX->outClient, 0);
    // _offline_Ocall += 2;
    // Enclave::Logging(myName_.c_str(), "update sf index succeed\n");
    // Enclave::Logging(myName_.c_str(), "Extension: 最优基础块加载成功, size=%zu, flag=%u, onlineSize=%zu\n",
    //                  optimalBaseSize, (unsigned)optimalBaseFlag, onlineBaseSize);

    // 2. 从delta_map中移除旧的映射关系
    // delta_map.erase(oldBaseFP);

    // 3. 创建新的增量块列表
    // vector<string> newDeltaFPs;

    // 4. 分两步处理：先处理依赖于oldBaseFP的delta块，最后处理oldBaseFP本身
    // 4.1 首先处理所有delta块（除了oldBaseFP和optimalBaseFP）
    for (const string &chunkFP : candidateGroup)
    {
        if (chunkFP != optimalBaseFP && chunkFP != oldBaseFP)
        {
            memcpy(&outEntry->chunkHash, (uint8_t *)chunkFP.data(), CHUNK_HASH_SIZE);
            Ocall_OneRecipe(upOutSGX->outClient);
            _offline_Ocall++;
            cryptoObj_->AESCBCDec(cipherCtx, (uint8_t *)&outEntry->chunkAddr, sizeof(RecipeEntry_t), Enclave::indexQueryKey_, (uint8_t *)delta_recipe_);
            // get delta chunk content
            memcpy(&outEntry->chunkAddr.containerName, delta_recipe_->containerName, CONTAINER_ID_LENGTH);
            Ocall_OneDeltaContainer(upOutSGX->outClient);
            _offline_Ocall++;
            // decrypt
            uint8_t *deltaIV = GetChunk_IV(outEntry->containerbuffer, delta_recipe_, offline_deltaIVBuffer_);
            uint8_t *deltaFp = GetChunk_FP(outEntry->containerbuffer, delta_recipe_);
            uint8_t *deltaSF = GetChunk_SF(outEntry->containerbuffer, delta_recipe_);
            uint8_t *delta_content_crypt = GetChunk_content_buffer(outEntry->containerbuffer, delta_recipe_, false, tmpPair, offline_oldDeltaChunkEnc_);
            uint8_t *delta_content_decrypt = offline_oldDeltaChunkEnc_;
            size_t delta_size = delta_recipe_->length;
            cryptoObj_->DecryptionWithKeyIV(cipherCtx, delta_content_crypt, delta_size, Enclave::enclaveKey_, delta_content_decrypt, deltaIV);
            // delta decode
            uint8_t *old_unique_chunk;
            size_t old_unique_size;
            old_unique_chunk = ed3_decode_buffer(delta_content_decrypt, delta_size, old_chunk, old_base_ref_size, offline_tmpUniqueBuffer_, &old_unique_size);
            if (old_unique_chunk && old_unique_size > 0)
            {
                // Enclave::Logging(myName_.c_str(), "Extension: 处理delta块, originalSize=%zu, originalFlag=%u\n",
                //                  originalSize, (unsigned)originalDeltaFlag);
                // 基于最优基础块进行增量压缩，使用专用buffer避免冲突
                // Enclave::Logging(myName_.c_str(), "Extension: 处理delta块 [%02x] 原大小 %zu bytes, 原deltaFlag=%d\n",
                //                (uint8_t)chunkFP[0], originalSize, originalDeltaFlag);
                size_t newDeltaSize;
                uint8_t *newDeltaData = ed3_encode_buffer(old_unique_chunk, old_unique_size,
                                                          optimal_chunk, optimal_size,
                                                          offline_plainNewDeltaChunkBuffer_, &newDeltaSize);
                // Enclave::Logging(myName_.c_str(), "Extension: ed3_encode_buffer 返回, newDeltaData=%p, newDeltaSize=%zu\n",
                //                  (void *)newDeltaData, newDeltaSize);
                // Enclave::Logging(myName_.c_str(), "Extension: delta块 [%02x] 原大小 %zu bytes, 新增量大小 %zu bytes\n",
                //                (uint8_t)chunkFP[0], originalSize, newDeltaSize);
                // 检查压缩效果：只有当新增量更小时才更新
                if (newDeltaData)
                {
                    // Enclave::Logging(myName_.c_str(), "Extension: delta块 [%02x] 压缩效果良好，进行更新\n", (uint8_t)chunkFP[0]);
                    // 更新数据块为新的增量形式
                    uint32_t onlineSize = delta_recipe_->length;
                    delta_recipe_->length = newDeltaSize;
                    delta_recipe_->deltaFlag = DELTA;
                    memcpy(delta_recipe_->basechunkHash, (uint8_t *)optimalBaseFP.data(), CHUNK_HASH_SIZE);
                    uint8_t *encryptedDelta = offline_newDeltaChunkEnc_;
                    cryptoObj_->EncryptWithKeyIV(cipherCtx, newDeltaData, newDeltaSize, Enclave::enclaveKey_, encryptedDelta, deltaIV);
                    InsertHot_container(encryptedDelta, delta_recipe_, deltaFp, deltaSF, deltaIV);
                    // update recipe
                    uint8_t *outRecipe = offline_outRecipeBuffer_;
                    cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)delta_recipe_, sizeof(RecipeEntry_t),
                                          Enclave::indexQueryKey_, outRecipe);

                    bool status = UpdateIndexStore(chunkFP, (char *)outRecipe, sizeof(RecipeEntry_t));
                    // newDeltaFPs.push_back(chunkFP);
                    // UpdateChunkWithNewDelta(chunkFP, newDeltaData, newDeltaSize, optimalBaseFP, upOutSGX, cryptoObj_, 0);

                    // // 更新系统统计变量（参考Backward算法的统计方式）
                    // if(originalSize < newDeltaSize)
                    //     Enclave::Logging(myName_.c_str(), "Extension: 警告！delta块重压缩后大小反而变大了！原始=%zu, 新增量=%zu\n", originalSize, newDeltaSize);
                    _offlineCompress_size -= onlineSize;     // 减去原始压缩大小
                    _offlineCurrBackup_size -= onlineSize;   // 减去原始备份大小
                    _offlineCompress_size += newDeltaSize;   // 加上新的增量大小
                    _offlineCurrBackup_size += newDeltaSize; // 加上新的增量大小
                    // Enclave::Logging(myName_.c_str(), "Extension: delta块重压缩 [%02x] %zu -> %zu bytes (%.1f%%), 原deltaFlag=%d\n",
                    //    (uint8_t)chunkFP[0], originalSize, newDeltaSize,
                    //    100.0 * newDeltaSize / originalSize, originalDeltaFlag);
                }
                else
                {
                    failedNewDeltaCnt++;
                    Enclave::Logging(myName_.c_str(), "Extension: delta块 [%02x] 压缩效果不佳，保持原状\n", (uint8_t)chunkFP[0]);
                }

                // free(originalData);
            }
            else
            {
                Enclave::Logging(myName_.c_str(), "Extension: 加载delta块失败或大小为0\n");
            }
        }
    }
    // Enclave::Logging(myName_.c_str(), "Extension: 所有依赖旧基础块的delta块处理完成.\n");
    // 4.2 最后处理oldBaseFP（如果它不是最优基础块）
    if (oldBaseFP != optimalBaseFP)
    {
        size_t newDeltaSize;
        uint8_t *newDeltaData = ed3_encode_buffer(old_chunk, old_base_ref_size,
                                                  optimal_chunk, optimal_size,
                                                  offline_plainNewDeltaChunkBuffer_, &newDeltaSize);
        if (newDeltaData)
        {
            uint32_t onlineSize = old_recipe_->length;
            old_recipe_->length = newDeltaSize;
            old_recipe_->deltaFlag = DELTA;
            memcpy(old_recipe_->basechunkHash, (uint8_t *)optimalBaseFP.data(), CHUNK_HASH_SIZE);
            uint8_t *encryptedDelta = offline_newDeltaChunkEnc_;
            cryptoObj_->EncryptWithKeyIV(cipherCtx, newDeltaData, newDeltaSize, Enclave::enclaveKey_, encryptedDelta, oldBaseIV);
            InsertHot_container(encryptedDelta, old_recipe_, oldBaseFp, oldBaseSF, oldBaseIV);
            // update recipe
            uint8_t *outRecipe = offline_outRecipeBuffer_;
            cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)old_recipe_, sizeof(RecipeEntry_t),
                                  Enclave::indexQueryKey_, outRecipe);
            bool status = UpdateIndexStore(oldBaseFP, (char *)outRecipe, sizeof(RecipeEntry_t));
            // newDeltaFPs.push_back(oldBaseFP);

            _offlineCompress_size -= onlineSize;     // 减去原始压缩大小
            _offlineCurrBackup_size -= onlineSize;   // 减去原始备份
            _offlineCompress_size += newDeltaSize;   // 加上新的增量大小
            _offlineCurrBackup_size += newDeltaSize; // 加上新的增量大小
        }
    }
    // Enclave::Logging(myName_.c_str(), "Extension: 旧基础块处理完成\n");
    // lz4 compress optimal basechunk
    uint32_t onlinesize = new_recipe_->length;
    uint8_t *compressdata = offline_lz4CompressBuffer_;
    int compressSize = LZ4_compress_default((char *)optimal_chunk, (char *)compressdata, optimal_size, MAX_CHUNK_SIZE);

    uint8_t *finalData;
    size_t finalSize;
    if (compressSize > 0)
    {
        finalData = compressdata;
        finalSize = compressSize;
    }
    else
    {
        finalData = optimal_chunk;
        finalSize = optimal_size;
    }

    new_recipe_->length = finalSize;
    new_recipe_->deltaFlag = NO_DELTA;
    uint8_t *encryptedDelta = offline_newDeltaChunkEnc_;
    cryptoObj_->EncryptWithKeyIV(cipherCtx, finalData, finalSize, Enclave::enclaveKey_, encryptedDelta, optimalBaseIV);
    InsertHotBase_container(encryptedDelta, new_recipe_, (uint8_t *)optimalBaseFP.c_str(), optimalBaseSF, optimalBaseIV);
    // update recipe
    uint8_t *outRecipe = offline_outRecipeBuffer_;
    cryptoObj_->AESCBCEnc(cipherCtx, (uint8_t *)new_recipe_, sizeof(RecipeEntry_t),
                          Enclave::indexQueryKey_, outRecipe);
    bool status = UpdateIndexStore(optimalBaseFP, (char *)outRecipe, sizeof(RecipeEntry_t));

    _offlineCompress_size -= onlinesize;
    _offlineCurrBackup_size -= onlinesize;
    _offlineCompress_size += finalSize;
    _offlineCurrBackup_size += finalSize;

    // free(optimalBaseData);

    // // 6. 在delta_map中建立新的映射关系（在容器落盘后再更新索引）
    // if (!newDeltaFPs.empty())
    // {
    //     // delta_map[optimalBaseFP] = newDeltaFPs;

    //     // 更新外部增量索引（确保在容器落盘后进行）
    //     memset(upOutSGX->process_buffer, 0, 100000 * CHUNK_HASH_SIZE);
    //     memcpy(upOutSGX->process_buffer, &oldBaseFP[0], CHUNK_HASH_SIZE);
    //     for (size_t i = 0; i < newDeltaFPs.size(); i++)
    //     { // 限制批处理大小
    //         memcpy(upOutSGX->process_buffer + i * CHUNK_HASH_SIZE * 2,
    //                (uint8_t *)&optimalBaseFP[0], CHUNK_HASH_SIZE);
    //         memcpy(upOutSGX->process_buffer + i * CHUNK_HASH_SIZE * 2 + CHUNK_HASH_SIZE,
    //                (uint8_t *)&newDeltaFPs[i][0], CHUNK_HASH_SIZE);
    //     }
    //     Ocall_UpdateDeltaIndexOnly(upOutSGX->outClient, newDeltaFPs.size());
    //     _offline_Ocall++;
    //     // Enclave::Logging(myName_.c_str(), "Extension: 更新外部增量索引, pairCount=%zu, _offline_Ocall=%llu\n",
    //     //                  newDeltaFPs.size(), _offline_Ocall);

    //     // Enclave::Logging(myName_.c_str(), "Extension: 建立新映射关系，基础块 [%02x] -> %zu 个增量块\n",
    //     //                 (uint8_t)optimalBaseFP[0], newDeltaFPs.size());
    // }
    return;
}
/**
 * @brief 初始化Extension处理环境
 * @details 分配必要的缓冲区和初始化数据结构
 */
void OFFLineBackward::InitExtension(UpOutSGX_t *upOutSGX)
{
    Enclave::Logging(myName_.c_str(), "Init Start\n");
    // 清理数据结构
    extension_sampledFeatureCounts_.clear();
    extension_chunkFeatures_.clear();
    pendingIndexUpdates_.clear(); // 清空缓存的索引更新

    // 获取sgxClient指针，模仿Easy_update函数的做法
    EnclaveClient *sgxClient = (EnclaveClient *)upOutSGX->sgxClient;

    // 初始化 edelta 所需状态（与 Easy_update 保持一致）
    // 确保 EDeltaEncode/Decode 可用，避免空指针导致崩溃
    BaseLink_ = sgxClient->BaseLinkOffline_;
    psHTable2_ = sgxClient->psHTable2Offline_;
    cutEdelta_ = sgxClient->cutEdeltaOffline_;

    // 模仿Easy_update函数初始化各种缓冲区
    offline_tmpUniqueBuffer_ = sgxClient->offline_tmpUniqueBuffer_;
    offline_plainNewDeltaChunkBuffer_ = sgxClient->offline_plainNewDeltaChunkBuffer_;
    offline_plainOldUniqueBuffer_ = sgxClient->offline_plainOldUniqueBuffer_;
    offline_mergeNewContainer_ = sgxClient->offline_mergeNewContainer_;
    offline_mergeRecipeEnc_ = sgxClient->offline_mergeRecipeEnc_;
    offline_mergeRecipeDec_ = sgxClient->offline_mergeRecipeDec_;
    offline_oldChunkDecrypt_ = sgxClient->offline_oldChunkDecrypt_;
    offline_newChunkDecrypt_ = sgxClient->offline_newChunkDecrypt_;
    offline_oldChunkDecompression_ = sgxClient->offline_oldChunkDecompression_;
    offline_newChunkDecompression_ = sgxClient->offline_newChunkDecompression_;
    offline_deltaSFBuffer_ = sgxClient->offline_deltaSFBuffer_;
    offline_deltaIVBuffer_ = sgxClient->offline_deltaIVBuffer_;
    offline_deltaFPBuffer_ = sgxClient->offline_deltaFPBuffer_;
    offline_outRecipeBuffer_ = sgxClient->offline_outRecipeBuffer_;
    offline_oldIVBuffer_ = sgxClient->offline_oldIVBuffer_;
    offline_newIVBuffer_ = sgxClient->offline_newIVBuffer_;
    offline_newDeltaChunkEnc_ = sgxClient->offline_newDeltaChunkEnc_;
    offline_oldDeltaChunkDec_ = sgxClient->offline_oldDeltaChunkDec_;
    offline_oldDeltaChunkEnc_ = sgxClient->offline_oldDeltaChunkEnc_;
    encOldChunkBuffer_ = sgxClient->offline_encOldChunkBuffer_;
    encNewChunkBuffer_ = sgxClient->offline_encNewChunkBuffer_;
    offline_optimalChunkBuffer_ = sgxClient->offline_optimalChunkBuffer_;
    old_recipe_ = sgxClient->oldRecipe_;
    new_recipe_ = sgxClient->newRecipe_;
    delta_recipe_ = sgxClient->deltaRecipe_;
    optimalBaseSFBuffer_ = sgxClient->newBasechunkSf_;
    oldBaseChunkSFBuffer_ = sgxClient->oldBasechunkSf_;
    offline_lz4CompressBuffer_ = sgxClient->offline_lz4CompressBuffer_;
    Enclave::Logging(myName_.c_str(), "Init Done\n");
}

/**
 * @brief 清理Extension处理环境
 * @details 清理临时数据结构和释放缓冲区
 */
void OFFLineBackward::CleanExtension()
{
    // 清理数据结构
    extension_sampledFeatureCounts_.clear();
    extension_chunkFeatures_.clear();
    pendingIndexUpdates_.clear();

    Enclave::Logging(myName_.c_str(), "Extension环境清理完成，已释放专用缓冲区\n");
}

/**
 * @brief 统一的离线处理入口
 * @details 支持多种离线处理模式：Backward、Extension或混合模式
 *          这个函数提供了灵活的模式选择接口
 */
void OFFLineBackward::ProcessOfflineWithMode(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_, int mode)
{
    switch (mode)
    {
    case 0: // Backward模式
        Enclave::Logging("INFO", "执行Backward离线处理模式\n");
        Easy_update(upOutSGX, cryptoObj_);
        break;

    case 1: // Extension模式
        Enclave::Logging("INFO", "执行Extension离线处理模式\n");
        Extension_update(upOutSGX, cryptoObj_);
        break;

    case 2: // 混合模式：先Extension后Backward
        Enclave::Logging("INFO", "执行混合离线处理模式 (Extension + Backward)\n");
        Extension_update(upOutSGX, cryptoObj_);
        Easy_update(upOutSGX, cryptoObj_);
        break;

    default:
        Enclave::Logging("WARNING", "未知的离线处理模式: %d，使用默认Backward模式\n", mode);
        Easy_update(upOutSGX, cryptoObj_);
        break;
    }
}

void OFFLineBackward::PrintBinaryArray(const uint8_t *data, size_t len, bool upper /*= true*/)
{
    if (!data || len == 0)
    {
        Enclave::Logging("DEBUG", "(empty)\n");
        return;
    }
    const size_t cols = 16;

    // 单行最大长度估算: 偏移(8) + 两空格(2) + 十六进制(3*16=48) + 分组空格(1) + " |"(2) + ASCII(16) + "|\n"(2) ≈ 79
    // 远小于 BUFSIZ，每行一次 OCall。
    for (size_t i = 0; i < len; i += cols)
    {
        char line[128];
        size_t pos = 0;

        // 偏移
        pos += snprintf(line + pos, sizeof(line) - pos, "%08zx  ", i);

        // 十六进制区域
        for (size_t j = 0; j < cols; ++j)
        {
            if (i + j < len)
            {
                pos += snprintf(line + pos, sizeof(line) - pos,
                                upper ? "%02X " : "%02x ", data[i + j]);
            }
            else
            {
                pos += snprintf(line + pos, sizeof(line) - pos, "   ");
            }
            if (j == 7)
                pos += snprintf(line + pos, sizeof(line) - pos, " "); // 中间额外空格
        }

        // ASCII 区域
        pos += snprintf(line + pos, sizeof(line) - pos, " |");
        for (size_t j = 0; j < cols && i + j < len; ++j)
        {
            uint8_t c = data[i + j];
            line[pos++] = (c >= 32 && c <= 126) ? (char)c : '.';
        }
        pos += snprintf(line + pos, sizeof(line) - pos, "|\n");

        Enclave::Logging("DEBUG", "%s", line);
    }
}

void OFFLineBackward::LogExtensionChunkFeaturesStats(const char *tag)
{
    const size_t entries = extension_chunkFeatures_.size();
    const size_t buckets = extension_chunkFeatures_.bucket_count();

    size_t key_len_bytes = 0;
    size_t key_cap_bytes = 0;
    size_t vec_elems = 0;
    size_t vec_cap_elems = 0;

    for (const auto &kv : extension_chunkFeatures_)
    {
        key_len_bytes += kv.first.size();
        key_cap_bytes += kv.first.capacity();
        vec_elems += kv.second.size();
        vec_cap_elems += kv.second.capacity();
    }

    const size_t vec_cap_bytes = vec_cap_elems * sizeof(uint64_t);
    const size_t approx_total_bytes = key_cap_bytes + vec_cap_bytes; // 下界估算，不含节点/桶开销

    Enclave::Logging(
        myName_.c_str(),
        "ExtFeatures[%s]: entries=%zu, buckets=%zu, keys(len=%zuB, cap=%zuB), "
        "vectors(size=%zu elems, cap=%zu elems -> %zuB), approx_total>=%zuB\n",
        tag ? tag : "", entries, buckets,
        key_len_bytes, key_cap_bytes,
        vec_elems, vec_cap_elems, vec_cap_bytes,
        approx_total_bytes);
}