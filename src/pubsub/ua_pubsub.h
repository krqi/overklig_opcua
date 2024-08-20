
#ifndef UA_PUBSUB_H_
#define UA_PUBSUB_H_

#define UA_INTERNAL
#include <opcua/server.h>
#include <opcua/server_pubsub.h>

#include "opcua_queue.h"
#include "ziptree.h"
#include "mp_printf.h"
#include "ua_pubsub_networkmessage.h"

#ifdef UA_ENABLE_PUBSUB_SKS
#include "ua_pubsub_keystorage.h"
#endif


_UA_BEGIN_DECLS

#ifdef UA_ENABLE_PUBSUB

#define UA_PUBSUB_MAXCHANNELS 8

struct UA_WriterGroup;
typedef struct UA_WriterGroup UA_WriterGroup;

struct UA_ReaderGroup;
typedef struct UA_ReaderGroup UA_ReaderGroup;

struct UA_SecurityGroup;
typedef struct UA_SecurityGroup UA_SecurityGroup;

struct UA_DataSetReader;
typedef struct UA_DataSetReader UA_DataSetReader;

const char *
UA_PubSubState_name(UA_PubSubState state);



typedef struct {
    UA_NodeId identifier;
    UA_PubSubComponentEnumType componentType;
    UA_PubSubState state;
    UA_String logIdString; 
} UA_PubSubComponentHead;

#define UA_LOG_PUBSUB_INTERNAL(LOGGER, LEVEL, COMPONENT, MSG, ...)      \
    if(UA_LOGLEVEL <= UA_LOGLEVEL_##LEVEL) {                            \
        UA_LOG_##LEVEL(LOGGER, UA_LOGCATEGORY_PUBSUB, "%S" MSG "%.0s",  \
                       (COMPONENT)->head.logIdString, __VA_ARGS__);     \
    }

#define UA_LOG_TRACE_PUBSUB(LOGGER, COMPONENT, ...)                          \
    UA_MACRO_EXPAND(UA_LOG_PUBSUB_INTERNAL(LOGGER, TRACE, COMPONENT, __VA_ARGS__, ""))
#define UA_LOG_DEBUG_PUBSUB(LOGGER, COMPONENT, ...)                          \
    UA_MACRO_EXPAND(UA_LOG_PUBSUB_INTERNAL(LOGGER, DEBUG, COMPONENT, __VA_ARGS__, ""))
#define UA_LOG_INFO_PUBSUB(LOGGER, COMPONENT, ...)                           \
    UA_MACRO_EXPAND(UA_LOG_PUBSUB_INTERNAL(LOGGER, INFO, COMPONENT, __VA_ARGS__, ""))
#define UA_LOG_WARNING_PUBSUB(LOGGER, COMPONENT, ...)                        \
    UA_MACRO_EXPAND(UA_LOG_PUBSUB_INTERNAL(LOGGER, WARNING, COMPONENT, __VA_ARGS__, ""))
#define UA_LOG_ERROR_PUBSUB(LOGGER, COMPONENT, ...)                          \
    UA_MACRO_EXPAND(UA_LOG_PUBSUB_INTERNAL(LOGGER, ERROR, COMPONENT, __VA_ARGS__, ""))
#define UA_LOG_FATAL_PUBSUB(LOGGER, COMPONENT, ...)                          \
    UA_MACRO_EXPAND(UA_LOG_PUBSUB_INTERNAL(LOGGER, FATAL, COMPONENT, __VA_ARGS__, ""))

void
UA_PubSubComponentHead_clear(UA_PubSubComponentHead *psch);





typedef struct UA_PublishedDataSet {
    UA_PubSubComponentHead head;
    TAILQ_ENTRY(UA_PublishedDataSet) listEntry;
    TAILQ_HEAD(, UA_DataSetField) fields;
    UA_PublishedDataSetConfig config;
    UA_DataSetMetaDataType dataSetMetaData;
    UA_UInt16 fieldSize;
    UA_UInt16 promotedFieldsCount;
    UA_UInt16 configurationFreezeCounter;
} UA_PublishedDataSet;

UA_StatusCode
UA_PublishedDataSetConfig_copy(const UA_PublishedDataSetConfig *src,
                               UA_PublishedDataSetConfig *dst);

UA_PublishedDataSet *
UA_PublishedDataSet_findPDSbyId(UA_Server *server, UA_NodeId identifier);

UA_PublishedDataSet *
UA_PublishedDataSet_findPDSbyName(UA_Server *server, UA_String name);

UA_AddPublishedDataSetResult
UA_PublishedDataSet_create(UA_Server *server,
                           const UA_PublishedDataSetConfig *publishedDataSetConfig,
                           UA_NodeId *pdsIdentifier);

void
UA_PublishedDataSet_clear(UA_Server *server,
                          UA_PublishedDataSet *publishedDataSet);

UA_StatusCode
UA_PublishedDataSet_remove(UA_Server *server, UA_PublishedDataSet *publishedDataSet);

UA_StatusCode
getPublishedDataSetConfig(UA_Server *server, const UA_NodeId pds,
                          UA_PublishedDataSetConfig *config);





typedef struct UA_StandaloneSubscribedDataSet {
    UA_PubSubComponentHead head;
    UA_StandaloneSubscribedDataSetConfig config;
    TAILQ_ENTRY(UA_StandaloneSubscribedDataSet) listEntry;
    UA_DataSetReader *connectedReader;
} UA_StandaloneSubscribedDataSet;

UA_StatusCode
UA_StandaloneSubscribedDataSetConfig_copy(const UA_StandaloneSubscribedDataSetConfig *src,
                                          UA_StandaloneSubscribedDataSetConfig *dst);

UA_StandaloneSubscribedDataSet *
UA_StandaloneSubscribedDataSet_findSDSbyId(UA_Server *server, UA_NodeId identifier);

UA_StandaloneSubscribedDataSet *
UA_StandaloneSubscribedDataSet_findSDSbyName(UA_Server *server, UA_String identifier);

void
UA_StandaloneSubscribedDataSet_clear(UA_Server *server,
                                     UA_StandaloneSubscribedDataSet *subscribedDataSet);

void
UA_StandaloneSubscribedDataSet_remove(UA_Server *server, UA_StandaloneSubscribedDataSet *sds);





typedef struct UA_PubSubConnection {
    UA_PubSubComponentHead head;
    TAILQ_ENTRY(UA_PubSubConnection) listEntry;

    
    UA_PubSubConnectionConfig config;
    UA_Boolean json; 

    UA_ConnectionManager *cm;
    uintptr_t recvChannels[UA_PUBSUB_MAXCHANNELS];
    size_t recvChannelsSize;
    uintptr_t sendChannel;

    size_t writerGroupsSize;
    LIST_HEAD(, UA_WriterGroup) writerGroups;

    size_t readerGroupsSize;
    LIST_HEAD(, UA_ReaderGroup) readerGroups;

    UA_UInt16 configurationFreezeCounter;

    UA_Boolean deleteFlag; 
    UA_DelayedCallback dc; 
} UA_PubSubConnection;

UA_StatusCode
UA_PubSubConnectionConfig_copy(const UA_PubSubConnectionConfig *src,
                               UA_PubSubConnectionConfig *dst);

UA_PubSubConnection *
UA_PubSubConnection_findConnectionbyId(UA_Server *server,
                                       UA_NodeId connectionIdentifier);

UA_StatusCode
UA_PubSubConnection_create(UA_Server *server,
                           const UA_PubSubConnectionConfig *connectionConfig,
                           UA_NodeId *connectionIdentifier);

void
UA_PubSubConnectionConfig_clear(UA_PubSubConnectionConfig *connectionConfig);

void
UA_PubSubConnection_delete(UA_Server *server, UA_PubSubConnection *c);

UA_StatusCode
UA_PubSubConnection_connect(UA_Server *server, UA_PubSubConnection *c,
                            UA_Boolean validate);

void
UA_PubSubConnection_process(UA_Server *server, UA_PubSubConnection *c,
                            UA_ByteString msg);

void
UA_PubSubConnection_disconnect(UA_PubSubConnection *c);

UA_EventLoop *
UA_PubSubConnection_getEL(UA_Server *server, UA_PubSubConnection *c);

UA_StatusCode
UA_PubSubConnection_setPubSubState(UA_Server *server, UA_PubSubConnection *c,
                                   UA_PubSubState targetState);





typedef struct UA_DataSetWriterSample {
    UA_Boolean valueChanged;
    UA_DataValue value;
} UA_DataSetWriterSample;

typedef struct UA_DataSetWriter {
    UA_PubSubComponentHead head;
    LIST_ENTRY(UA_DataSetWriter) listEntry;

    UA_DataSetWriterConfig config;
    UA_WriterGroup *linkedWriterGroup;
    UA_PublishedDataSet *connectedDataSet;
    UA_ConfigurationVersionDataType connectedDataSetVersion;

    
    UA_UInt16 deltaFrameCounter; 
    size_t lastSamplesCount;
    UA_DataSetWriterSample *lastSamples;

    UA_UInt16 actualDataSetMessageSequenceCount;
    UA_Boolean configurationFrozen;
    UA_UInt64 pubSubStateTimerId;
} UA_DataSetWriter;

UA_StatusCode
UA_DataSetWriterConfig_copy(const UA_DataSetWriterConfig *src,
                            UA_DataSetWriterConfig *dst);

UA_DataSetWriter *
UA_DataSetWriter_findDSWbyId(UA_Server *server, UA_NodeId identifier);

UA_StatusCode
UA_DataSetWriter_setPubSubState(UA_Server *server, UA_DataSetWriter *dsw,
                                UA_PubSubState targetState);

UA_StatusCode
UA_DataSetWriter_generateDataSetMessage(UA_Server *server,
                                        UA_DataSetMessage *dsm,
                                        UA_DataSetWriter *dsw);

UA_StatusCode
UA_DataSetWriter_prepareDataSet(UA_Server *server, UA_DataSetWriter *dsw,
                                UA_DataSetMessage *dsm);

void
UA_DataSetWriter_freezeConfiguration(UA_Server *server, UA_DataSetWriter *dsw);

void
UA_DataSetWriter_unfreezeConfiguration(UA_Server *server, UA_DataSetWriter *dsw);

UA_StatusCode
UA_DataSetWriter_create(UA_Server *server,
                        const UA_NodeId writerGroup, const UA_NodeId dataSet,
                        const UA_DataSetWriterConfig *dataSetWriterConfig,
                        UA_NodeId *writerIdentifier);


UA_StatusCode
UA_DataSetWriter_remove(UA_Server *server, UA_DataSetWriter *dsw);





struct UA_WriterGroup {
    UA_PubSubComponentHead head;
    LIST_ENTRY(UA_WriterGroup) listEntry;

    UA_WriterGroupConfig config;

    LIST_HEAD(, UA_DataSetWriter) writers;
    UA_UInt32 writersCount;

    UA_UInt64 publishCallbackId; 
    UA_NetworkMessageOffsetBuffer bufferedMessage;
    UA_UInt16 sequenceNumber; 
    UA_Boolean configurationFrozen;
    UA_DateTime lastPublishTimeStamp;

    UA_PubSubConnection *linkedConnection;
    uintptr_t sendChannel;
    UA_Boolean deleteFlag;

    UA_UInt32 securityTokenId;
    UA_UInt32 nonceSequenceNumber; 
    void *securityPolicyContext;
#ifdef UA_ENABLE_PUBSUB_SKS
    UA_PubSubKeyStorage *keyStorage; 
#endif
};

UA_StatusCode
UA_WriterGroup_create(UA_Server *server, const UA_NodeId connection,
                      const UA_WriterGroupConfig *writerGroupConfig,
                      UA_NodeId *writerGroupIdentifier);

UA_StatusCode
UA_WriterGroup_remove(UA_Server *server, UA_WriterGroup *wg);

void
UA_WriterGroup_disconnect(UA_WriterGroup *wg);

UA_StatusCode
UA_WriterGroup_connect(UA_Server *server, UA_WriterGroup *wg,
                       UA_Boolean validate);

UA_Boolean
UA_WriterGroup_canConnect(UA_WriterGroup *wg);

UA_StatusCode
setWriterGroupEncryptionKeys(UA_Server *server, const UA_NodeId writerGroup,
                             UA_UInt32 securityTokenId,
                             const UA_ByteString signingKey,
                             const UA_ByteString encryptingKey,
                             const UA_ByteString keyNonce);

UA_StatusCode
UA_WriterGroupConfig_copy(const UA_WriterGroupConfig *src,
                          UA_WriterGroupConfig *dst);

UA_WriterGroup *
UA_WriterGroup_findWGbyId(UA_Server *server, UA_NodeId identifier);

UA_StatusCode
UA_WriterGroup_freezeConfiguration(UA_Server *server, UA_WriterGroup *wg);

UA_StatusCode
UA_WriterGroup_unfreezeConfiguration(UA_Server *server, UA_WriterGroup *wg);

UA_StatusCode
UA_WriterGroup_setPubSubState(UA_Server *server, UA_WriterGroup *wg,
                              UA_PubSubState targetState);
UA_StatusCode
UA_WriterGroup_addPublishCallback(UA_Server *server, UA_WriterGroup *wg);

void
UA_WriterGroup_publishCallback(UA_Server *server,
                               UA_WriterGroup *wg);

UA_StatusCode
UA_WriterGroup_updateConfig(UA_Server *server, UA_WriterGroup *wg,
                            const UA_WriterGroupConfig *config);

UA_StatusCode
UA_WriterGroup_enableWriterGroup(UA_Server *server,
                                 const UA_NodeId writerGroup);





typedef struct UA_DataSetField {
    UA_DataSetFieldConfig config;
    TAILQ_ENTRY(UA_DataSetField) listEntry;
    UA_NodeId identifier;
    UA_NodeId publishedDataSet;     
    UA_FieldMetaData fieldMetaData; 
    UA_UInt64 sampleCallbackId;
    UA_Boolean sampleCallbackIsRegistered;
    UA_Boolean configurationFrozen;
} UA_DataSetField;

UA_StatusCode
UA_DataSetFieldConfig_copy(const UA_DataSetFieldConfig *src,
                           UA_DataSetFieldConfig *dst);

UA_DataSetField *
UA_DataSetField_findDSFbyId(UA_Server *server, UA_NodeId identifier);

UA_DataSetFieldResult
UA_DataSetField_remove(UA_Server *server, UA_DataSetField *currentField);

UA_DataSetFieldResult
UA_DataSetField_create(UA_Server *server, const UA_NodeId publishedDataSet,
                       const UA_DataSetFieldConfig *fieldConfig,
                       UA_NodeId *fieldIdentifier);

void
UA_PubSubDataSetField_sampleValue(UA_Server *server, UA_DataSetField *field,
                                  UA_DataValue *value);






struct UA_DataSetReader {
    UA_PubSubComponentHead head;
    LIST_ENTRY(UA_DataSetReader) listEntry;

    UA_DataSetReaderConfig config;
    UA_ReaderGroup *linkedReaderGroup;

    UA_Boolean configurationFrozen;
    UA_NetworkMessageOffsetBuffer bufferedMessage;

#ifdef UA_ENABLE_PUBSUB_MONITORING
    
    UA_ServerCallback msgRcvTimeoutTimerCallback;
    UA_UInt64 msgRcvTimeoutTimerId;
#endif
    UA_DateTime lastHeartbeatReceived;
};


void
UA_DataSetReader_process(UA_Server *server,
                         UA_DataSetReader *dataSetReader,
                         UA_DataSetMessage *dataSetMsg);

UA_StatusCode
UA_DataSetReader_checkIdentifier(UA_Server *server, UA_NetworkMessage *msg,
                                 UA_DataSetReader *reader,
                                 UA_ReaderGroupConfig readerGroupConfig);

UA_StatusCode
UA_DataSetReader_create(UA_Server *server, UA_NodeId readerGroupIdentifier,
                        const UA_DataSetReaderConfig *dataSetReaderConfig,
                        UA_NodeId *readerIdentifier);

UA_StatusCode
UA_DataSetReader_prepareOffsetBuffer(Ctx *ctx, UA_DataSetReader *reader,
                                     UA_ByteString *buf);

void
UA_DataSetReader_decodeAndProcessRT(UA_Server *server, UA_DataSetReader *dsr,
                                    UA_ByteString buf);

UA_StatusCode
UA_DataSetReader_remove(UA_Server *server, UA_DataSetReader *dsr);


UA_StatusCode UA_TargetVariables_copy(const UA_TargetVariables *src,
                                      UA_TargetVariables *dst);


void UA_TargetVariables_clear(UA_TargetVariables *subscribedDataSetTarget);


UA_StatusCode UA_FieldTargetVariable_copy(const UA_FieldTargetVariable *src,
                                          UA_FieldTargetVariable *dst);

UA_StatusCode
DataSetReader_createTargetVariables(UA_Server *server, UA_DataSetReader *dsr,
                                    size_t targetVariablesSize,
                                    const UA_FieldTargetVariable *targetVariables);


UA_StatusCode
UA_DataSetReader_setPubSubState(UA_Server *server, UA_DataSetReader *dsr,
                                UA_PubSubState targetState);





struct UA_ReaderGroup {
    UA_PubSubComponentHead head;
    LIST_ENTRY(UA_ReaderGroup) listEntry;

    UA_ReaderGroupConfig config;

    LIST_HEAD(, UA_DataSetReader) readers;
    UA_UInt32 readersCount;

    UA_Boolean configurationFrozen;
    UA_Boolean hasReceived; 

    UA_PubSubConnection *linkedConnection;
    uintptr_t recvChannels[UA_PUBSUB_MAXCHANNELS];
    size_t recvChannelsSize;
    UA_Boolean deleteFlag;

    UA_UInt32 securityTokenId;
    UA_UInt32 nonceSequenceNumber; 
    void *securityPolicyContext;
#ifdef UA_ENABLE_PUBSUB_SKS
    UA_PubSubKeyStorage *keyStorage;
#endif
};

UA_StatusCode
UA_ReaderGroup_create(UA_Server *server, UA_NodeId connectionId,
                      const UA_ReaderGroupConfig *rgc,
                      UA_NodeId *readerGroupId);

UA_StatusCode
UA_ReaderGroup_remove(UA_Server *server, UA_ReaderGroup *rg);

UA_StatusCode
UA_ReaderGroup_connect(UA_Server *server, UA_ReaderGroup *rg, UA_Boolean validate);

void
UA_ReaderGroup_disconnect(UA_ReaderGroup *rg);

UA_StatusCode
setReaderGroupEncryptionKeys(UA_Server *server, const UA_NodeId readerGroup,
                             UA_UInt32 securityTokenId,
                             const UA_ByteString signingKey,
                             const UA_ByteString encryptingKey,
                             const UA_ByteString keyNonce);

UA_StatusCode
UA_ReaderGroupConfig_copy(const UA_ReaderGroupConfig *src,
                          UA_ReaderGroupConfig *dst);

UA_ReaderGroup *
UA_ReaderGroup_findRGbyId(UA_Server *server, UA_NodeId identifier);

UA_DataSetReader *
UA_ReaderGroup_findDSRbyId(UA_Server *server, UA_NodeId identifier);

UA_StatusCode
UA_ReaderGroup_freezeConfiguration(UA_Server *server, UA_ReaderGroup *rg);

UA_StatusCode
UA_ReaderGroup_unfreezeConfiguration(UA_Server *server, UA_ReaderGroup *rg);

UA_StatusCode
UA_ReaderGroup_setPubSubState(UA_Server *server, UA_ReaderGroup *rg,
                              UA_PubSubState targetState);

UA_Boolean
UA_ReaderGroup_decodeAndProcessRT(UA_Server *server, UA_ReaderGroup *rg,
                                  UA_ByteString buf);

UA_Boolean
UA_ReaderGroup_process(UA_Server *server, UA_ReaderGroup *rg,
                       UA_NetworkMessage *nm);





UA_StatusCode
verifyAndDecryptNetworkMessage(const UA_Logger *logger, UA_ByteString buffer,
                               Ctx *ctx, UA_NetworkMessage *nm,
                               UA_ReaderGroup *rg);

UA_StatusCode
UA_PubSubConnection_decodeNetworkMessage(UA_PubSubConnection *connection,
                                         UA_Server *server, UA_ByteString buffer,
                                         UA_NetworkMessage *nm);

#ifdef UA_ENABLE_PUBSUB_SKS





struct UA_SecurityGroup {
    UA_String securityGroupId;
    UA_SecurityGroupConfig config;
    UA_PubSubKeyStorage *keyStorage;
    UA_NodeId securityGroupNodeId;
    UA_UInt64 callbackId;
    UA_DateTime baseTime;
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    UA_NodeId securityGroupFolderId;
#endif
    TAILQ_ENTRY(UA_SecurityGroup) listEntry;
};

UA_StatusCode
UA_SecurityGroupConfig_copy(const UA_SecurityGroupConfig *src,
                            UA_SecurityGroupConfig *dst);


UA_SecurityGroup *
UA_SecurityGroup_findSGbyName(UA_Server *server, UA_String securityGroupName);


UA_SecurityGroup *
UA_SecurityGroup_findSGbyId(UA_Server *server, UA_NodeId identifier);

void
UA_SecurityGroup_delete(UA_SecurityGroup *sg);

void
removeSecurityGroup(UA_Server *server, UA_SecurityGroup *sg);

#endif 





typedef struct UA_TopicAssign {
    UA_ReaderGroup *rgIdentifier;
    UA_String topic;
    TAILQ_ENTRY(UA_TopicAssign) listEntry;
} UA_TopicAssign;

typedef enum {
    UA_WRITER_GROUP = 0,
    UA_DATA_SET_WRITER = 1,
} UA_ReserveIdType;

typedef struct UA_ReserveId {
    UA_UInt16 id;
    UA_ReserveIdType reserveIdType;
    UA_String transportProfileUri;
    UA_NodeId sessionId;
    ZIP_ENTRY(UA_ReserveId) treeEntry;
} UA_ReserveId;

typedef ZIP_HEAD(UA_ReserveIdTree, UA_ReserveId) UA_ReserveIdTree;

typedef struct UA_PubSubManager {
    UA_UInt64 defaultPublisherId;
    size_t connectionsSize;
    TAILQ_HEAD(, UA_PubSubConnection) connections;

    size_t publishedDataSetsSize;
    TAILQ_HEAD(, UA_PublishedDataSet) publishedDataSets;

    size_t subscribedDataSetsSize;
    TAILQ_HEAD(, UA_StandaloneSubscribedDataSet) subscribedDataSets;

    size_t topicAssignSize;
    TAILQ_HEAD(, UA_TopicAssign) topicAssign;

    size_t reserveIdsSize;
    UA_ReserveIdTree reserveIds;

#ifdef UA_ENABLE_PUBSUB_SKS
    LIST_HEAD(, UA_PubSubKeyStorage) pubSubKeyList;

    size_t securityGroupsSize;
    TAILQ_HEAD(, UA_SecurityGroup) securityGroups;
#endif

#ifndef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    UA_UInt32 uniqueIdCount;
#endif
} UA_PubSubManager;

UA_StatusCode
UA_PubSubManager_addPubSubTopicAssign(UA_Server *server, UA_ReaderGroup *rg,
                                      UA_String topic);

UA_StatusCode
UA_PubSubManager_reserveIds(UA_Server *server, UA_NodeId sessionId,
                            UA_UInt16 numRegWriterGroupIds,
                            UA_UInt16 numRegDataSetWriterIds,
                            UA_String transportProfileUri, UA_UInt16 **writerGroupIds,
                            UA_UInt16 **dataSetWriterIds);

void
UA_PubSubManager_freeIds(UA_Server *server);

void
UA_PubSubManager_init(UA_Server *server, UA_PubSubManager *psm);

void
UA_PubSubManager_shutdown(UA_Server *server, UA_PubSubManager *psm);

void
UA_PubSubManager_delete(UA_Server *server, UA_PubSubManager *psm);

#ifndef UA_ENABLE_PUBSUB_INFORMATIONMODEL
void
UA_PubSubManager_generateUniqueNodeId(UA_PubSubManager *psm, UA_NodeId *nodeId);
#endif

#ifdef UA_ENABLE_PUBSUB_FILE_CONFIG
UA_StatusCode
UA_PubSubManager_loadPubSubConfigFromByteString(UA_Server *server,
                                                const UA_ByteString buffer);


UA_StatusCode
UA_PubSubManager_getEncodedPubSubConfiguration(UA_Server *server,
                                               UA_ByteString *buffer);
#endif

UA_Guid
UA_PubSubManager_generateUniqueGuid(UA_Server *server);

UA_UInt32
UA_PubSubConfigurationVersionTimeDifference(UA_DateTime now);





#ifdef UA_ENABLE_PUBSUB_MONITORING

UA_StatusCode
UA_PubSubManager_setDefaultMonitoringCallbacks(UA_PubSubMonitoringInterface *mif);

#endif 

#endif 

_UA_END_DECLS

#endif 
