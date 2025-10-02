#ifndef ECALL_OFFLine_H
#define ECALL_OFFLine_H

#include "commonEnclave.h"
#include "functional"
#include <utility>

#include <iostream>
#include "ecallLz4.h"

#include "md5.h"
#include "util.h"
#include "xxhash.h"
using namespace std;

extern "C"
{
#include "config.h"
#include "xdelta3.h"
}
// #include "configure.h"

// Extension功能需要的外部声明
extern uint32_t GEAR[256]; // GEAR哈希表，用于特征提取

class OFFLineBackward
{
private:
    string myName_ = "offline_backward";
    unordered_map<string, vector<string>> delta_map; // the map (basechunkFP,vector(deltachunkFP));
                                                     // the map (old_basechunk, new_basechunk)

    // the map (containerid vector(offset,sum_size)) record the chunk gonna be deleted in each container
    unordered_map<string, vector<pair<uint32_t, uint32_t>>> cold_basemap;
    Container_t hot_container;
    Container_t hot_base_container;
    Container_t hot_delta_container;
    uint8_t *tmpOldContainer;
    uint8_t *tmpNewContainer;
    uint8_t *tmpDeltaContainer;
    uint8_t *tmpUseContainer;
    // uint8_t *tmpColdContainer;
    uint64_t GreeyOfflineSize = 0;
    // uint8_t *coldNewContainer_;

    uint8_t *offline_plainOldUniqueBuffer_;

    // for GetNew_deltachunk()
    uint8_t *offline_tmpUniqueBuffer_;
    uint8_t *offline_plainNewDeltaChunkBuffer_;
    uint8_t *offline_optimalChunkBuffer_;

    DeltaRecord *BaseLink_;
    unordered_map<uint64_t, DeltaRecord *> *psHTable_;
    htable *psHTable2_;
    int *cutEdelta_;

    // for merge container and update cold container
    uint8_t *offline_mergeNewContainer_;
    RecipeEntry_t *offline_mergeRecipeEnc_;
    RecipeEntry_t *offline_mergeRecipeDec_;

    // for offline process delta compression
    uint8_t *offline_oldChunkDecrypt_;
    uint8_t *offline_newChunkDecrypt_;
    uint8_t *offline_oldChunkDecompression_;
    uint8_t *offline_newChunkDecompression_;
    uint8_t *offline_newDeltaChunkEnc_;
    uint8_t *offline_oldDeltaChunkDec_;
    uint8_t *offline_oldDeltaChunkEnc_;
    uint8_t *encOldChunkBuffer_;
    uint8_t *encNewChunkBuffer_;
    RecipeEntry_t *old_recipe_;
    RecipeEntry_t *new_recipe_;
    RecipeEntry_t *delta_recipe_;
    RecipeEntry_t *tmp_recipe_;
    uint8_t *offline_lz4CompressBuffer_;

    // for offline delta chunk
    uint8_t *offline_deltaSFBuffer_;
    uint8_t *offline_deltaIVBuffer_;
    uint8_t *offline_oldIVBuffer_;
    uint8_t *offline_newIVBuffer_;
    uint8_t *offline_deltaFPBuffer_;
    uint8_t *offline_outRecipeBuffer_;

    // for extension
    vector<string> candidateGroup;
    uint64_t failedNewDeltaCnt = 0;

public:
    unordered_map<string, string> local_basemap;
    uint64_t _offlineCompress_size = 0;
    uint64_t _offlineCurrBackup_size = 0;
    uint64_t _offlineDeltanum = 0;
    uint64_t _offlineDeDeltanum = 0;
    uint64_t _offlineDeletenum = 0;
    long long _Offline_DeltaSaveSize = 0;
    long long _baseChunkNum = 0;
    uint64_t _baseDataSize = 0;
    uint64_t _deltaChunkNum = 0;
    uint64_t _deltaDataSize = 0;
    long long _lz4SaveSize = 0;
    uint64_t _DeltaSaveSize = 0;
    uint64_t _offlinedeltaChunkNum = 0;
    uint64_t _offline_Ocall = 0;
    bool Offline_Flag;
    uint64_t badDelta = 0;

    string curHotBaseContainerID;
    string tmpBaseContainerID;
    string curHotDeltaContainerID;
    string tmpDeltaContainerID;
    uint64_t selectOptimalBaseTime = 0;
    uint64_t selectOptimalBaseCount = 0;
    uint64_t _startTimeOffline = 0;
    uint64_t _endTimeOffline = 0;
    uint64_t _testOcallTimeOffline = 0;
    uint64_t _testOcallCountOffline = 0;
    /**
     * @brief Construct a new Ecall Offline processer object
     *
     */
    OFFLineBackward();

    /**
     * @brief Destory a new Ecall Offline processer object
     *
     */
    ~OFFLineBackward();

    /**
     * @brief Print basic information
     *
     */
    void Print();

    /**
     * @brief Init basic information
     *
     */
    void Init();

    void Update();

    /**
     * @brief Update hot container
     * @param old_basechunkhash
     * @param delta_chunkhash
     * @param new_basechunkhash
     */
    void Update_hot_container(string old_basechunkhash, string delta_chunkhash, string new_basechunkhash);

    /**
     * @brief Update cold container
     * @param upOutSGX
     * @param container_id
     * @param cold_basechunk
     * @param cryptoObj_
     * @param cipherCtx
     */
    void Update_cold_container(UpOutSGX_t *upOutSGX, string container_id, vector<pair<uint32_t, uint32_t>> &cold_basechunk,
                               EcallCrypto *cryptoObj_, EVP_CIPHER_CTX *cipherCtx);

    static bool myCompare(pair<uint32_t, uint32_t> &v1, pair<uint32_t, uint32_t> &v2);

    /**
     * @brief Insert pair to Delta Index
     * @param basechunkhash
     * @param deltachunkhash
     */
    void Insert_delta(string basechunkhash, string deltachunkhash);

    /**
     * @brief Insert pair to Delta Index
     * @param oldchunkhash
     * @param newchunkhash
     */
    void Insert_local(string oldchunkhash, string newchunkhash);

    /**
     * @brief Get the chunk recipe
     * @param chunkhash
     */
    RecipeEntry_t *GetRecipe(uint8_t *chunkhash);

    /**
     * @brief Get the content of old container
     * @param container_id
     * @param Cold_container
     * @param tmpContainerSize
     */
    bool GetOldContainer(string container_id, uint8_t **Cold_container, size_t *tmpContainerSize);

    /**
     * @brief Get the content of new container
     * @param container_id
     * @param Cold_container
     * @param tmpContainerSize
     */
    bool GetNewContainer(string container_id, uint8_t **Cold_container, size_t *tmpContainerSize);

    /**
     * @brief Get the content of delta container
     * @param container_id
     * @param Cold_container
     * @param tmpContainerSize
     */
    bool GetDeltaContainer(string container_id, uint8_t **Cold_container, size_t *tmpContainerSize);

    /**
     * @brief Get the content of cold container
     * @param container_id
     * @param Cold_container
     * @param tmpContainerSize
     * @param delta_flag
     */
    bool GetColdContainer(string container_id, uint8_t **Cold_container, size_t *tmpContainerSize, uint8_t &delta_flag);

    /**
     * @brief Get the content of target chunk
     * @param tmpcontainer
     * @param tmprecipe
     * @param cold_flag
     * @param tmppair
     */
    uint8_t *GetChunk_content(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe, bool cold_flag, pair<uint32_t, uint32_t> &tmppair);

    uint8_t *GetChunk_content_buffer(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe, bool cold_flag, pair<uint32_t, uint32_t> &tmppair, uint8_t *res);

    /**
     * @brief Get the content of new deltachunk
     * @param old_deltachunk
     * @param old_deltasize
     * @param old_basechunk
     * @param old_basesize
     * @param new_basechunk
     * @param new_basesize
     * @param new_delta_size
     * @param delta_flag
     */
    uint8_t *GetNew_deltachunk(uint8_t *old_deltachunk, size_t old_deltasize, uint8_t *old_basechunk, size_t old_basesize, uint8_t *new_basechunk, size_t new_basesize, size_t *new_delta_size, bool &delta_flag, bool lz4_flag);

    /**
     * @brief Get the content of new deltachunk
     * @param old_deltachunk
     * @param new_basechunk
     */
    uint8_t *GetBase_deltachunk(uint8_t *old_deltachunk, uint8_t *new_basechunk);

    /**
     * @brief Save new delta chunks
     * @param tmpchunkcontent pointer to deltachunk content
     * @param tmprecipe pointer to deltachunk recipe
     * @param tmpfp pointer to deltachunk hash
     * @param tmpsf pointer to deltachunk superfeature
     * @param tmpIV pointer to deltachunk iv
     */
    void InsertHot_container(uint8_t *tmpchunkcontent, RecipeEntry_t *tmprecipe, uint8_t *tmpfp, uint8_t *tmpsf,
                             uint8_t *tmpIV);

    void InsertHotBase_container(uint8_t *tmpchunkcontent, RecipeEntry_t *tmprecipe, uint8_t *tmpfp, uint8_t *tmpsf,
                                 uint8_t *tmpIV);

    /**
     * @brief Save new container to disk
     * @param newContainer
     */
    void SaveHot_container(Container_t &newContainer);

    /**
     * @brief offline phase
     * @param upOutSGX
     * @param cryptoObj_
     */
    void Easy_update(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    /**
     * @brief the the content of superfeature
     * @param tmpcontainer
     * @param tmprecipe
     */
    uint8_t *GetChunk_SF(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe);

    /**
     * @brief the the content of iv key
     * @param tmpcontainer
     * @param tmprecipe
     */
    uint8_t *GetChunk_IV(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe, uint8_t *resBuffer);

    /**
     * @brief do delta compression
     *
     * @param in target chunk buffer
     * @param in_size target chunk size
     * @param ref base chunk buffer
     * @param ref_size base chunk size
     * @param res_size delta chunk size
     * @return delta chunk buffer
     */
    uint8_t *xd3_encode(const uint8_t *in, size_t in_size, const uint8_t *ref, size_t ref_size, size_t *res_size);

    /**
     * @brief do delta decompression
     *
     * @param in delta chunk buffer
     * @param in_size delta chunk size
     * @param ref base chunk buffer
     * @param ref_size base chunk size
     * @param res_size target chunk size
     * @return target chunk buffer
     */
    uint8_t *xd3_decode(const uint8_t *in, size_t in_size, const uint8_t *ref, size_t ref_size, size_t *res_size);

    /**
     * @brief the the content of hash
     * @param tmpcontainer
     * @param tmprecipe
     */
    uint8_t *GetChunk_FP(uint8_t *tmpcontainer, RecipeEntry_t *tmprecipe);

    /**
     * @brief update the index
     * @param key chunkhash
     * @param buffer chunkhash buffer
     * @param bufferSize chunkhash size
     */
    bool UpdateIndexStore(const string &key, const char *buffer,
                          size_t bufferSize);

    void CleanLocal_Index();

    void MergeContainer(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_, EVP_CIPHER_CTX *cipherCtx);

    /* flag=0 for 'D', 1 for 'S' */
    void set_flag(void *record, uint32_t flag);

    /* return 0 if flag=0, >0(not 1) if flag=1 */
    u_int32_t get_flag(void *record);

    void set_length(void *record, uint32_t length);

    uint32_t get_length(void *record);

    int Chunking_v3(unsigned char *data, int len, int num_of_chunks, DeltaRecord *subChunkLink);

    int EDeltaEncode(uint8_t *newBuf, uint32_t newSize, uint8_t *baseBuf,
                     uint32_t baseSize, uint8_t *deltaBuf, uint32_t *deltaSize);

    int EDeltaDecode(uint8_t *deltaBuf, uint32_t deltaSize, uint8_t *baseBuf,
                     uint32_t baseSize, uint8_t *outBuf, uint32_t *outSize);

    uint8_t *ed3_encode(uint8_t *in, size_t in_size, uint8_t *ref, size_t ref_size, size_t *res_size);

    uint8_t *ed3_decode(uint8_t *in, size_t in_size, uint8_t *ref, size_t ref_size, size_t *res_size);

    uint8_t *ed3_encode_buffer(uint8_t *in, size_t in_size, uint8_t *ref,
                               size_t ref_size, uint8_t *res, size_t *res_size);

    uint8_t *ed3_decode_buffer(uint8_t *in, size_t in_size, uint8_t *ref,
                               size_t ref_size, uint8_t *res, size_t *res_size);

    // ==================== Extension 离线优化功能 ====================

    /**
     * @brief Extension 离线处理主函数
     * @details 基于特征分析重新选择最优基础块，提高增量压缩效率
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     */
    void Extension_update(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    /**
     * @brief 从数据块中提取特征
     * @details 使用GEAR哈希算法进行特征采样，用于后续的相似性分析
     * @param chunkPtr 数据块指针
     * @param chunkSize 数据块大小
     * @param features 输出的特征向量
     */
    void ExtractChunkFeatures(uint8_t *chunkPtr, size_t chunkSize, vector<uint64_t> &features);

    /**
     * @brief 为一组数据块选择最优的基础块
     * @details 计算每个候选块的特征重用度得分，选择得分最高的作为新基础块
     * @param chunkGroup 候选数据块指纹列表
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     * @return 最优基础块的指纹
     */
    string SelectOptimalBaseChunk(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    string SelectOptimalBaseChunk(const vector<string> &chunkGroup, UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_, uint8_t *old_chunk, size_t old_chunk_ref_size, uint8_t *new_chunk, size_t new_chunk_ref_size);

    /**
     * @brief 基于新基础块重新组织数据块组
     * @details 将旧的基础块和增量块重新组织，以新选择的基础块为中心重新建立增量关系
     * @param oldBaseFP 原基础块指纹
     * @param newBaseFP 新基础块指纹
     * @param deltaFPs 增量块指纹列表
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     */
    void ReorganizeChunkGroup(const string &oldBaseFP, const string &newBaseFP,
                              vector<string> &deltaFPs, UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    /**
     * @brief 处理单个数据块组的Extension优化
     * @details 对一个基础块及其相关增量块执行Extension算法优化
     * @param old_baseFP 原始基础块指纹
     * @param new_baseFP inline阶段选择的新基础块指纹
     * @param deltaFPs 增量块指纹列表
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     */
    void ProcessOneGroupChunk_Extension(const string &old_baseFP, const string &new_baseFP, vector<string> &deltaFPs,
                                        UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    /**
     * @brief Extension算法全量处理版本：处理单个块组
     * @details 不依赖local_map，直接在当前基础块和所有增量块中选择最优基础块
     * @param baseChunkFP 当前基础块指纹
     * @param deltaFPs 增量块指纹列表
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     */
    void ProcessOneGroupChunk_Extension_Full(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    /**
     * @brief Extension算法专用的块组重组织函数
     * @details 将候选组中的所有块重新以最优基础块为基准进行增量编码
     * @param oldBaseFP 原始基础块指纹
     * @param optimalBaseFP 选择的最优基础块指纹
     * @param candidateGroup 候选组：包含old_base、new_base、所有delta chunks
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     */
    void ReorganizeChunkGroup_Extension(const string &oldBaseFP, const string &optimalBaseFP,
                                        UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    /**
     * @brief 获取数据块的完整数据内容
     * @details 从容器中加载、解密、解压缩数据块，返回原始数据
     * @param chunkFP 数据块指纹
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     * @param chunkSize 输出数据块大小
     * @return 数据块内容指针，需要调用者释放内存
     */
    uint8_t *LoadChunkData(const string &chunkFP, UpOutSGX_t *upOutSGX,
                           EcallCrypto *cryptoObj_, size_t *chunkSize);

    /**
     * @brief Extension 加载块数据并返回状态信息
     * @details 获取数据块内容和deltaFlag状态，用于统计更新
     * @param chunkFP 数据块指纹
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     * @param chunkSize 返回数据块大小的指针
     * @param deltaFlag 返回数据块的deltaFlag状态
     * @return 数据块内容指针，需要调用者释放内存
     */
    uint8_t *LoadChunkDataWithStatus(const string &chunkFP, UpOutSGX_t *upOutSGX,
                                     EcallCrypto *cryptoObj_, size_t *chunkSize,
                                     uint8_t *deltaFlag, size_t *onlineSize);

    /**
     * @brief 重构原始数据块内容
     * @details 如果是增量块，先解压得到原始数据；如果是基础块，直接返回内容
     * @param chunkFP 数据块指纹
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     * @param originalSize 输出原始数据大小
     * @return 原始数据指针，需要调用者释放内存
     */
    uint8_t *ReconstructOriginalChunk(const string &chunkFP, UpOutSGX_t *upOutSGX,
                                      EcallCrypto *cryptoObj_, size_t *originalSize);

    /**
     * @brief 用新的增量数据更新数据块
     * @details 更新数据块的内容、配方和索引，将其转换为基于新基础块的增量块
     * @param chunkFP 要更新的数据块指纹
     * @param newDeltaData 新的增量数据
     * @param newDeltaSize 新增量数据大小
     * @param newBaseFP 新基础块指纹
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     */
    void UpdateChunkWithNewDelta(const string &chunkFP, uint8_t *newDeltaData, RecipeEntry_t delta_recipe, UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    /**
     * @brief 将数据块更新为基础块状态
     * @details 将增量块提升为基础块，更新其recipe信息
     * @param chunkFP 数据块指纹
     * @param baseData 基础块原始数据
     * @param baseSize 基础块数据大小
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     */
    void UpdateChunkAsBaseChunk(const string &chunkFP, uint8_t *baseData, size_t baseSize,
                                UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_);

    /**
     * @brief 初始化Extension处理环境
     * @details 分配必要的缓冲区和初始化数据结构
     */
    void InitExtension(UpOutSGX_t *upOutSGX);

    /**
     * @brief 清理Extension处理环境
     * @details 清理临时数据结构和释放缓冲区
     */
    void CleanExtension();

    /**
     * @brief 统一的离线处理入口
     * @details 支持多种离线处理模式：Backward、Extension或混合模式
     * @param upOutSGX SGX通信结构体指针
     * @param cryptoObj_ 加密对象指针
     * @param mode 处理模式 (0=Backward, 1=Extension, 2=混合)
     */
    void ProcessOfflineWithMode(UpOutSGX_t *upOutSGX, EcallCrypto *cryptoObj_, int mode);

    void PrintBinaryArray(const uint8_t *data, size_t len, bool upper = true);

    void LogExtensionChunkFeaturesStats(const char *tag = nullptr);

    // Extension 相关的私有数据成员
    unordered_map<uint64_t, size_t> extension_sampledFeatureCounts_;  // 特征使用计数
    unordered_map<string, vector<uint64_t>> extension_chunkFeatures_; // 数据块特征映射
    unordered_map<string, string> pendingIndexUpdates_;               // 缓存的索引更新（延迟到容器落盘后）

    // Extension 统计信息
    uint64_t _extensionProcessedGroups_ = 0; // 已处理的数据块组数量
    uint64_t _extensionReselectedBase_ = 0;  // 重新选择基础块的次数
    uint64_t _extensionSavedSize_ = 0;       // Extension优化节省的存储空间
    uint64_t _extension_Ocall = 0;           // Extension过程中的Ocall调用次数

    uint8_t *optimalBaseSFBuffer_;
    uint8_t *oldBaseChunkSFBuffer_;
    // vector<uint64_t> features;
};
#endif
