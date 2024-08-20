
#ifndef UA_SERVER_PUBSUB_H
#define UA_SERVER_PUBSUB_H

#include <opcua/common.h>
#include <opcua/util.h>
#include <opcua/client.h>
#include <opcua/plugin/securitypolicy.h>
#include <opcua/plugin/eventloop.h>

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_PUBSUB


typedef enum  {
    UA_PUBSUB_COMPONENT_CONNECTION,
    UA_PUBSUB_COMPONENT_WRITERGROUP,
    UA_PUBSUB_COMPONENT_DATASETWRITER,
    UA_PUBSUB_COMPONENT_READERGROUP,
    UA_PUBSUB_COMPONENT_DATASETREADER,
    UA_PUBSUB_COMPONENT_PUBLISHEDDATASET,
    UA_PUBSUB_COMPONENT_SUBSCRIBEDDDATASET
} UA_PubSubComponentEnumType;



typedef enum {
    UA_PUBLISHERIDTYPE_BYTE   = 0,
    UA_PUBLISHERIDTYPE_UINT16 = 1,
    UA_PUBLISHERIDTYPE_UINT32 = 2,
    UA_PUBLISHERIDTYPE_UINT64 = 3,
    UA_PUBLISHERIDTYPE_STRING = 4
} UA_PublisherIdType;

typedef struct {
    UA_PublisherIdType idType;
    union {
        UA_Byte byte;
        UA_UInt16 uint16;
        UA_UInt32 uint32;
        UA_UInt64 uint64;
        UA_String string;
    } id;
} UA_PublisherId;

UA_EXPORT UA_StatusCode
UA_PublisherId_copy(const UA_PublisherId *src, UA_PublisherId *dst);

UA_EXPORT void
UA_PublisherId_clear(UA_PublisherId *p);


UA_EXPORT UA_StatusCode
UA_PublisherId_fromVariant(UA_PublisherId *p, const UA_Variant *src);


UA_EXPORT void
UA_PublisherId_toVariant(const UA_PublisherId *p, UA_Variant *dst);

typedef struct {
    UA_String name;
    UA_Boolean enabled;
    UA_PublisherId publisherId;
    UA_String transportProfileUri;
    UA_Variant address;
    UA_KeyValueMap connectionProperties;
    UA_Variant connectionTransportSettings;

} UA_PubSubConnectionConfig;

#ifdef UA_ENABLE_PUBSUB_MONITORING

typedef enum {
    UA_PUBSUB_MONITORING_MESSAGE_RECEIVE_TIMEOUT
    // extend as needed
} UA_PubSubMonitoringType;


typedef struct {
    UA_StatusCode (*createMonitoring)(UA_Server *server, UA_NodeId Id,
                                      UA_PubSubComponentEnumType eComponentType,
                                      UA_PubSubMonitoringType eMonitoringType,
                                      void *data, UA_ServerCallback callback);
    UA_StatusCode (*startMonitoring)(UA_Server *server, UA_NodeId Id,
                                     UA_PubSubComponentEnumType eComponentType,
                                     UA_PubSubMonitoringType eMonitoringType, void *data);
    UA_StatusCode (*stopMonitoring)(UA_Server *server, UA_NodeId Id,
                                    UA_PubSubComponentEnumType eComponentType,
                                    UA_PubSubMonitoringType eMonitoringType, void *data);
    UA_StatusCode (*updateMonitoringInterval)(UA_Server *server, UA_NodeId Id,
                                              UA_PubSubComponentEnumType eComponentType,
                                              UA_PubSubMonitoringType eMonitoringType,
                                              void *data);
    UA_StatusCode (*deleteMonitoring)(UA_Server *server, UA_NodeId Id,
                                      UA_PubSubComponentEnumType eComponentType,
                                      UA_PubSubMonitoringType eMonitoringType, void *data);
} UA_PubSubMonitoringInterface;

#endif 


struct UA_PubSubConfiguration {
    void (*stateChangeCallback)(UA_Server *server, UA_NodeId *id,
                                UA_PubSubState state, UA_StatusCode status);

    UA_Boolean enableDeltaFrames;

#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    UA_Boolean enableInformationModelMethods;
#endif

    
    size_t securityPoliciesSize;
    UA_PubSubSecurityPolicy *securityPolicies;

#ifdef UA_ENABLE_PUBSUB_MONITORING
    UA_PubSubMonitoringInterface monitoringInterface;
#endif
};

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Server_addPubSubConnection(UA_Server *server,
                              const UA_PubSubConnectionConfig *connectionConfig,
                              UA_NodeId *connectionId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_enablePubSubConnection(UA_Server *server,
                                 const UA_NodeId connectionId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_disablePubSubConnection(UA_Server *server,
                                  const UA_NodeId connectionId);


UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Server_getPubSubConnectionConfig(UA_Server *server,
                                    const UA_NodeId connectionId,
                                    UA_PubSubConnectionConfig *config);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Server_removePubSubConnection(UA_Server *server, const UA_NodeId connectionId);



typedef enum {
    UA_PUBSUB_DATASET_PUBLISHEDITEMS,
    UA_PUBSUB_DATASET_PUBLISHEDEVENTS,
    UA_PUBSUB_DATASET_PUBLISHEDITEMS_TEMPLATE,
    UA_PUBSUB_DATASET_PUBLISHEDEVENTS_TEMPLATE,
} UA_PublishedDataSetType;

typedef struct {
    UA_DataSetMetaDataType metaData;
    size_t variablesToAddSize;
    UA_PublishedVariableDataType *variablesToAdd;
} UA_PublishedDataItemsTemplateConfig;

typedef struct {
    UA_NodeId eventNotfier;
    UA_ContentFilter filter;
} UA_PublishedEventConfig;

typedef struct {
    UA_DataSetMetaDataType metaData;
    UA_NodeId eventNotfier;
    size_t selectedFieldsSize;
    UA_SimpleAttributeOperand *selectedFields;
    UA_ContentFilter filter;
} UA_PublishedEventTemplateConfig;


typedef struct {
    UA_String name;
    UA_PublishedDataSetType publishedDataSetType;
    union {
        UA_PublishedDataItemsTemplateConfig itemsTemplate;
        UA_PublishedEventConfig event;
        UA_PublishedEventTemplateConfig eventTemplate;
    } config;
} UA_PublishedDataSetConfig;

void UA_EXPORT
UA_PublishedDataSetConfig_clear(UA_PublishedDataSetConfig *pdsConfig);

typedef struct {
    UA_StatusCode addResult;
    size_t fieldAddResultsSize;
    UA_StatusCode *fieldAddResults;
    UA_ConfigurationVersionDataType configurationVersion;
} UA_AddPublishedDataSetResult;

UA_EXPORT UA_AddPublishedDataSetResult UA_THREADSAFE
UA_Server_addPublishedDataSet(UA_Server *server,
                              const UA_PublishedDataSetConfig *publishedDataSetConfig,
                              UA_NodeId *pdsId);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_getPublishedDataSetConfig(UA_Server *server, const UA_NodeId pdsId,
                                    UA_PublishedDataSetConfig *config);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_getPublishedDataSetMetaData(UA_Server *server, const UA_NodeId pdsId,
                                      UA_DataSetMetaDataType *metaData);

UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Server_removePublishedDataSet(UA_Server *server, const UA_NodeId pdsId);


typedef struct{
    UA_ConfigurationVersionDataType configurationVersion;
    UA_String fieldNameAlias;
    UA_Boolean promotedField;
    UA_PublishedVariableDataType publishParameters;

    
    struct {
        UA_Boolean rtFieldSourceEnabled;
        UA_Boolean rtInformationModelNode;
        //TODO -> decide if suppress C++ warnings and use 'UA_DataValue * * const staticValueSource;'
        UA_DataValue ** staticValueSource;
    } rtValueSource;
    UA_UInt32 maxStringLength;

} UA_DataSetVariableConfig;

typedef enum {
    UA_PUBSUB_DATASETFIELD_VARIABLE,
    UA_PUBSUB_DATASETFIELD_EVENT
} UA_DataSetFieldType;

typedef struct {
    UA_DataSetFieldType dataSetFieldType;
    union {
        
        UA_DataSetVariableConfig variable;
    } field;
} UA_DataSetFieldConfig;

void UA_EXPORT
UA_DataSetFieldConfig_clear(UA_DataSetFieldConfig *dataSetFieldConfig);

typedef struct {
    UA_StatusCode result;
    UA_ConfigurationVersionDataType configurationVersion;
} UA_DataSetFieldResult;

UA_EXPORT UA_DataSetFieldResult UA_THREADSAFE
UA_Server_addDataSetField(UA_Server *server,
                          const UA_NodeId publishedDataSet,
                          const UA_DataSetFieldConfig *fieldConfig,
                          UA_NodeId *fieldId);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_getDataSetFieldConfig(UA_Server *server, const UA_NodeId dsfId,
                                UA_DataSetFieldConfig *config);

UA_EXPORT UA_DataSetFieldResult UA_THREADSAFE
UA_Server_removeDataSetField(UA_Server *server, const UA_NodeId dsfId);


typedef struct {
    UA_StatusCode (*addCustomCallback)(UA_Server *server, UA_NodeId identifier,
                                       UA_ServerCallback callback,
                                       void *data, UA_Double interval_ms,
                                       UA_DateTime *baseTime, UA_TimerPolicy timerPolicy,
                                       UA_UInt64 *callbackId);

    UA_StatusCode (*changeCustomCallback)(UA_Server *server, UA_NodeId identifier,
                                          UA_UInt64 callbackId, UA_Double interval_ms,
                                          UA_DateTime *baseTime, UA_TimerPolicy timerPolicy);

    void (*removeCustomCallback)(UA_Server *server, UA_NodeId identifier, UA_UInt64 callbackId);

} UA_PubSub_CallbackLifecycle;


typedef enum {
    UA_PUBSUB_ENCODING_UADP = 0,
    UA_PUBSUB_ENCODING_JSON = 1,
    UA_PUBSUB_ENCODING_BINARY = 2
} UA_PubSubEncodingType;


typedef enum {
    UA_PUBSUB_RT_NONE = 0,
    UA_PUBSUB_RT_DIRECT_VALUE_ACCESS = 1,
    UA_PUBSUB_RT_FIXED_SIZE = 2,
    UA_PUBSUB_RT_DETERMINISTIC = 3,
} UA_PubSubRTLevel;

typedef struct {
    UA_String name;
    UA_Boolean enabled;
    UA_UInt16 writerGroupId;
    UA_Duration publishingInterval;
    UA_Double keepAliveTime;
    UA_Byte priority;
    UA_ExtensionObject transportSettings;
    UA_ExtensionObject messageSettings;
    UA_KeyValueMap groupProperties;
    UA_PubSubEncodingType encodingMimeType;
    
    UA_PubSub_CallbackLifecycle pubsubManagerCallback;
    UA_UInt16 maxEncapsulatedDataSetMessageCount;
    
    UA_PubSubRTLevel rtLevel;

    UA_MessageSecurityMode securityMode; 
    UA_PubSubSecurityPolicy *securityPolicy;
    UA_String securityGroupId;
} UA_WriterGroupConfig;

void UA_EXPORT
UA_WriterGroupConfig_clear(UA_WriterGroupConfig *writerGroupConfig);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_addWriterGroup(UA_Server *server, const UA_NodeId connection,
                         const UA_WriterGroupConfig *writerGroupConfig,
                         UA_NodeId *wgId);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_getWriterGroupConfig(UA_Server *server, const UA_NodeId wgId,
                               UA_WriterGroupConfig *config);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_updateWriterGroupConfig(UA_Server *server, const UA_NodeId wgId,
                                  const UA_WriterGroupConfig *config);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_WriterGroup_getState(UA_Server *server, const UA_NodeId wgId,
                               UA_PubSubState *state);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_WriterGroup_publish(UA_Server *server, const UA_NodeId wgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_WriterGroup_lastPublishTimestamp(UA_Server *server, const UA_NodeId wgId,
                                    UA_DateTime *timestamp);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_removeWriterGroup(UA_Server *server, const UA_NodeId wgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_freezeWriterGroupConfiguration(UA_Server *server,
                                         const UA_NodeId wgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_unfreezeWriterGroupConfiguration(UA_Server *server,
                                           const UA_NodeId wgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_enableWriterGroup(UA_Server *server, const UA_NodeId wgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_disableWriterGroup(UA_Server *server, const UA_NodeId wgId);

#define UA_Server_setWriterGroupOperational(server, wgId)   \
    UA_Server_enableWriterGroup(server, wgId)

#define UA_Server_setWriterGroupDisabled(server, wgId)          \
    UA_Server_disableWriterGroup(server, wgId)


UA_StatusCode UA_EXPORT UA_THREADSAFE
UA_Server_setWriterGroupEncryptionKeys(UA_Server *server, const UA_NodeId wgId,
                                       UA_UInt32 securityTokenId,
                                       const UA_ByteString signingKey,
                                       const UA_ByteString encryptingKey,
                                       const UA_ByteString keyNonce);


typedef struct {
    UA_String name;
    UA_UInt16 dataSetWriterId;
    UA_DataSetFieldContentMask dataSetFieldContentMask;
    UA_UInt32 keyFrameCount;
    UA_ExtensionObject messageSettings;
    UA_ExtensionObject transportSettings;
    UA_String dataSetName;
    UA_KeyValueMap dataSetWriterProperties;
} UA_DataSetWriterConfig;

void UA_EXPORT
UA_DataSetWriterConfig_clear(UA_DataSetWriterConfig *pdsConfig);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_addDataSetWriter(UA_Server *server,
                           const UA_NodeId writerGroup, const UA_NodeId dataSet,
                           const UA_DataSetWriterConfig *dataSetWriterConfig,
                           UA_NodeId *dswId);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_getDataSetWriterConfig(UA_Server *server, const UA_NodeId dswId,
                                 UA_DataSetWriterConfig *config);

UA_EXPORT UA_StatusCode  UA_THREADSAFE
UA_Server_enableDataSetWriter(UA_Server *server, const UA_NodeId dswId);

UA_EXPORT UA_StatusCode  UA_THREADSAFE
UA_Server_disableDataSetWriter(UA_Server *server, const UA_NodeId dswId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_DataSetWriter_getState(UA_Server *server, const UA_NodeId dswId,
                                 UA_PubSubState *state);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_removeDataSetWriter(UA_Server *server, const UA_NodeId dswId);



typedef enum {
    UA_PUBSUB_SDS_TARGET,
    UA_PUBSUB_SDS_MIRROR
} UA_SubscribedDataSetEnumType;

typedef struct {
    
    UA_FieldTargetDataType targetVariable;

    UA_DataValue **externalDataValue;
    void *targetVariableContext; 
    void (*beforeWrite)(UA_Server *server,
                        const UA_NodeId *readerIdentifier,
                        const UA_NodeId *readerGroupIdentifier,
                        const UA_NodeId *targetVariableIdentifier,
                        void *targetVariableContext,
                        UA_DataValue **externalDataValue);
    void (*afterWrite)(UA_Server *server,
                       const UA_NodeId *readerIdentifier,
                       const UA_NodeId *readerGroupIdentifier,
                       const UA_NodeId *targetVariableIdentifier,
                       void *targetVariableContext,
                       UA_DataValue **externalDataValue);
} UA_FieldTargetVariable;

typedef struct {
    size_t targetVariablesSize;
    UA_FieldTargetVariable *targetVariables;
} UA_TargetVariables;


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_DataSetReader_createTargetVariables(UA_Server *server, const UA_NodeId dsrId,
                                              size_t targetVariablesSize,
                                              const UA_FieldTargetVariable *targetVariables);



typedef enum {
    UA_PUBSUB_RT_UNKNOWN = 0,
    UA_PUBSUB_RT_VARIANT = 1,
    UA_PUBSUB_RT_DATA_VALUE = 2,
    UA_PUBSUB_RT_RAW = 4,
} UA_PubSubRtEncoding;


typedef struct {
    UA_String name;
    UA_PublisherId publisherId;
    UA_UInt16 writerGroupId;
    UA_UInt16 dataSetWriterId;
    UA_DataSetMetaDataType dataSetMetaData;
    UA_DataSetFieldContentMask dataSetFieldContentMask;
    UA_Double messageReceiveTimeout;
    UA_ExtensionObject messageSettings;
    UA_ExtensionObject transportSettings;
    UA_SubscribedDataSetEnumType subscribedDataSetType;
    
    union {
        UA_TargetVariables subscribedDataSetTarget;
        // UA_SubscribedDataSetMirrorDataType subscribedDataSetMirror;
    } subscribedDataSet;
    
    UA_String linkedStandaloneSubscribedDataSetName;
    UA_PubSubRtEncoding expectedEncoding;
} UA_DataSetReaderConfig;

UA_EXPORT UA_StatusCode
UA_DataSetReaderConfig_copy(const UA_DataSetReaderConfig *src,
                            UA_DataSetReaderConfig *dst);

UA_EXPORT void
UA_DataSetReaderConfig_clear(UA_DataSetReaderConfig *cfg);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_DataSetReader_updateConfig(UA_Server *server, const UA_NodeId dsrId,
                                     UA_NodeId readerGroupIdentifier,
                                     const UA_DataSetReaderConfig *config);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_DataSetReader_getConfig(UA_Server *server, const UA_NodeId dsrId,
                                  UA_DataSetReaderConfig *config);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_DataSetReader_getState(UA_Server *server, UA_NodeId dsrId,
                                 UA_PubSubState *state);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_enableDataSetReader(UA_Server *server, const UA_NodeId dsrId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_disableDataSetReader(UA_Server *server, const UA_NodeId dsrId);

typedef struct {
    UA_String name;
    UA_SubscribedDataSetEnumType subscribedDataSetType;
    union {
        
        UA_TargetVariablesDataType target;
    } subscribedDataSet;
    UA_DataSetMetaDataType dataSetMetaData;
    UA_Boolean isConnected;
} UA_StandaloneSubscribedDataSetConfig;

void
UA_StandaloneSubscribedDataSetConfig_clear(UA_StandaloneSubscribedDataSetConfig *sdsConfig);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_addStandaloneSubscribedDataSet(UA_Server *server,
                                         const UA_StandaloneSubscribedDataSetConfig *sdsConfig,
                                         UA_NodeId *sdsId);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_removeStandaloneSubscribedDataSet(UA_Server *server,
                                            const UA_NodeId sdsId);



typedef struct {
    UA_String name;

    
    UA_PubSubRTLevel rtLevel;
    UA_KeyValueMap groupProperties;
    UA_PubSubEncodingType encodingMimeType;
    UA_ExtensionObject transportSettings;

    UA_MessageSecurityMode securityMode;
    UA_PubSubSecurityPolicy *securityPolicy;
    UA_String securityGroupId;
} UA_ReaderGroupConfig;

void UA_EXPORT
UA_ReaderGroupConfig_clear(UA_ReaderGroupConfig *readerGroupConfig);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_addDataSetReader(UA_Server *server, UA_NodeId readerGroupIdentifier,
                           const UA_DataSetReaderConfig *dataSetReaderConfig,
                           UA_NodeId *readerIdentifier);


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_removeDataSetReader(UA_Server *server, UA_NodeId readerIdentifier);



UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_ReaderGroup_getConfig(UA_Server *server, const UA_NodeId rgId,
                                UA_ReaderGroupConfig *config);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_ReaderGroup_getState(UA_Server *server, const UA_NodeId rgId,
                               UA_PubSubState *state);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_addReaderGroup(UA_Server *server, const UA_NodeId connectionId,
                         const UA_ReaderGroupConfig *readerGroupConfig,
                         UA_NodeId *readerGroupIdentifier);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_removeReaderGroup(UA_Server *server, const UA_NodeId rgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_freezeReaderGroupConfiguration(UA_Server *server, const UA_NodeId rgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_unfreezeReaderGroupConfiguration(UA_Server *server, const UA_NodeId rgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_enableReaderGroup(UA_Server *server, const UA_NodeId rgId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_disableReaderGroup(UA_Server *server, const UA_NodeId rgId);

#define UA_Server_setReaderGroupOperational(server, rgId) \
    UA_Server_enableReaderGroup(server, rgId)

#define UA_Server_setReaderGroupDisabled(server, rgId) \
    UA_Server_disableReaderGroup(server, rgId)


UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_setReaderGroupEncryptionKeys(UA_Server *server, UA_NodeId readerGroup,
                                       UA_UInt32 securityTokenId,
                                       UA_ByteString signingKey,
                                       UA_ByteString encryptingKey,
                                       UA_ByteString keyNonce);

#ifdef UA_ENABLE_PUBSUB_SKS


typedef struct {
    UA_String securityGroupName;
    UA_Duration keyLifeTime;
    UA_String securityPolicyUri;
    UA_UInt32 maxFutureKeyCount;
    UA_UInt32 maxPastKeyCount;
} UA_SecurityGroupConfig;

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_addSecurityGroup(UA_Server *server, UA_NodeId securityGroupFolderNodeId,
                           const UA_SecurityGroupConfig *securityGroupConfig,
                           UA_NodeId *securityGroupNodeId);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_removeSecurityGroup(UA_Server *server, const UA_NodeId securityGroup);

typedef void
(*UA_Server_sksPullRequestCallback)(UA_Server *server, UA_StatusCode sksPullRequestStatus, void* context);

UA_StatusCode UA_EXPORT
UA_Server_setSksClient(UA_Server *server, UA_String securityGroupId,
                       UA_ClientConfig *clientConfig, const char *endpointUrl,
                       UA_Server_sksPullRequestCallback callback, void *context);

UA_EXPORT UA_StatusCode UA_THREADSAFE
UA_Server_setReaderGroupActivateKey(UA_Server *server, const UA_NodeId readerGroupId);

UA_EXPORT UA_StatusCode  UA_THREADSAFE
UA_Server_setWriterGroupActivateKey(UA_Server *server, const UA_NodeId writerGroup);

#endif 

#endif 

_UA_END_DECLS

#endif 
