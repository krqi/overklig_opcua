
#include <opcua/types.h>
#include "ua_pubsub.h"
#include "ua_pubsub_ns0.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_PUBSUB 

#ifdef UA_ENABLE_PUBSUB_SKS
#include "ua_pubsub_keystorage.h"
#endif

#define UA_DATETIMESTAMP_2000 125911584000000000
#define UA_RESERVEID_FIRST_ID 0x8000

static const char *pubSubStateNames[6] = {
    "Disabled", "Paused", "Operational", "Error", "PreOperational", "Invalid"
};

const char *
UA_PubSubState_name(UA_PubSubState state) {
    if(state < UA_PUBSUBSTATE_DISABLED || state > UA_PUBSUBSTATE_PREOPERATIONAL)
        return pubSubStateNames[5];
    return pubSubStateNames[state];
}

void
UA_PubSubComponentHead_clear(UA_PubSubComponentHead *psch) {
    UA_NodeId_clear(&psch->identifier);
    UA_String_clear(&psch->logIdString);
    memset(psch, 0, sizeof(UA_PubSubComponentHead));
}

UA_StatusCode
UA_PublisherId_copy(const UA_PublisherId *src,
                    UA_PublisherId *dst) {
    memcpy(dst, src, sizeof(UA_PublisherId));
    if(src->idType == UA_PUBLISHERIDTYPE_STRING)
        return UA_String_copy(&src->id.string, &dst->id.string);
    return UA_STATUSCODE_GOOD;
}

void
UA_PublisherId_clear(UA_PublisherId *p) {
    if(p->idType == UA_PUBLISHERIDTYPE_STRING)
        UA_String_clear(&p->id.string);
    memset(p, 0, sizeof(UA_PublisherId));
}

UA_StatusCode
UA_PublisherId_fromVariant(UA_PublisherId *p, const UA_Variant *src) {
    if(!UA_Variant_isScalar(src))
        return UA_STATUSCODE_BADINTERNALERROR;

    memset(p, 0, sizeof(UA_PublisherId));

    const void *data = (const void*)src->data;
    if(src->type == &UA_TYPES[UA_TYPES_BYTE]) {
        p->idType = UA_PUBLISHERIDTYPE_BYTE;
        p->id.byte = *(const UA_Byte*)data;
    } else if(src->type == &UA_TYPES[UA_TYPES_UINT16]) {
        p->idType  = UA_PUBLISHERIDTYPE_UINT16;
        p->id.uint16 = *(const UA_UInt16*)data;
    } else if(src->type == &UA_TYPES[UA_TYPES_UINT32]) {
        p->idType  = UA_PUBLISHERIDTYPE_UINT32;
        p->id.uint32 = *(const UA_UInt32*)data;
    } else if(src->type == &UA_TYPES[UA_TYPES_UINT64]) {
        p->idType  = UA_PUBLISHERIDTYPE_UINT64;
        p->id.uint64 = *(const UA_UInt64*)data;
    } else if(src->type == &UA_TYPES[UA_TYPES_STRING]) {
        p->idType  = UA_PUBLISHERIDTYPE_STRING;
        return UA_String_copy((const UA_String *)data, &p->id.string);
    } else {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return UA_STATUSCODE_GOOD;
}

void
UA_PublisherId_toVariant(const UA_PublisherId *p, UA_Variant *dst) {
    UA_PublisherId *p2 = (UA_PublisherId*)(uintptr_t)p;
    switch(p->idType) {
    case UA_PUBLISHERIDTYPE_BYTE:
        UA_Variant_setScalar(dst, &p2->id.byte, &UA_TYPES[UA_TYPES_BYTE]); break;
    case UA_PUBLISHERIDTYPE_UINT16:
        UA_Variant_setScalar(dst, &p2->id.uint16, &UA_TYPES[UA_TYPES_UINT16]); break;
    case UA_PUBLISHERIDTYPE_UINT32:
        UA_Variant_setScalar(dst, &p2->id.uint32, &UA_TYPES[UA_TYPES_UINT32]); break;
    case UA_PUBLISHERIDTYPE_UINT64:
        UA_Variant_setScalar(dst, &p2->id.uint64, &UA_TYPES[UA_TYPES_UINT64]); break;
    case UA_PUBLISHERIDTYPE_STRING:
        UA_Variant_setScalar(dst, &p2->id.string, &UA_TYPES[UA_TYPES_STRING]); break;
    default: break; 
    }
}

static void
UA_PubSubManager_addTopic(UA_PubSubManager *psm, UA_TopicAssign *topicAssign) {
    TAILQ_INSERT_TAIL(&psm->topicAssign, topicAssign, listEntry);
    psm->topicAssignSize++;
}

static UA_TopicAssign *
UA_TopicAssign_new(UA_ReaderGroup *readerGroup,
                   UA_String topic, const UA_Logger *logger) {
    UA_TopicAssign *topicAssign = (UA_TopicAssign *)
        UA_calloc(1, sizeof(UA_TopicAssign));
    if(!topicAssign) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SERVER,
                     "PubSub TopicAssign creation failed. Out of Memory.");
        return NULL;
    }
    topicAssign->rgIdentifier = readerGroup;
    topicAssign->topic = topic;
    return topicAssign;
}

UA_StatusCode
UA_PubSubManager_addPubSubTopicAssign(UA_Server *server, UA_ReaderGroup *rg,
                                      UA_String topic) {
    UA_PubSubManager *psm = &server->pubSubManager;
    UA_TopicAssign *topicAssign = UA_TopicAssign_new(rg, topic, server->config.logging);
    UA_PubSubManager_addTopic(psm, topicAssign);
    return UA_STATUSCODE_GOOD;
}

static enum ZIP_CMP
cmpReserveId(const void *a, const void *b) {
    const UA_ReserveId *aa = (const UA_ReserveId*)a;
    const UA_ReserveId *bb = (const UA_ReserveId*)b;
    if(aa->id != bb->id)
        return (aa->id < bb->id) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
    if(aa->reserveIdType != bb->reserveIdType)
        return (aa->reserveIdType < bb->reserveIdType) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
    return (enum ZIP_CMP)UA_order(&aa->transportProfileUri,
                                  &bb->transportProfileUri, &UA_TYPES[UA_TYPES_STRING]);
}

ZIP_FUNCTIONS(UA_ReserveIdTree, UA_ReserveId, treeEntry, UA_ReserveId, id, cmpReserveId)

static UA_ReserveId *
UA_ReserveId_new(UA_Server *server, UA_UInt16 id, UA_String transportProfileUri,
                 UA_ReserveIdType reserveIdType, UA_NodeId sessionId) {
    UA_ReserveId *reserveId = (UA_ReserveId *)
        UA_calloc(1, sizeof(UA_ReserveId));
    if(!reserveId) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "PubSub ReserveId creation failed. Out of Memory.");
        return NULL;
    }
    reserveId->id = id;
    reserveId->reserveIdType = reserveIdType;
    UA_String_copy(&transportProfileUri, &reserveId->transportProfileUri);
    reserveId->sessionId = sessionId;

    return reserveId;
}

static UA_Boolean
UA_ReserveId_isFree(UA_Server *server, UA_UInt16 id, UA_String transportProfileUri,
                    UA_ReserveIdType reserveIdType) {
    UA_PubSubManager *psm = &server->pubSubManager;

    
    UA_ReserveId compare;
    compare.id = id;
    compare.reserveIdType = reserveIdType;
    compare.transportProfileUri = transportProfileUri;
    if(ZIP_FIND(UA_ReserveIdTree, &psm->reserveIds, &compare))
        return false;

    UA_PubSubConnection *tmpConnection;
    TAILQ_FOREACH(tmpConnection, &psm->connections, listEntry) {
        UA_WriterGroup *writerGroup;
        LIST_FOREACH(writerGroup, &tmpConnection->writerGroups, listEntry) {
            if(reserveIdType == UA_WRITER_GROUP) {
                if(UA_String_equal(&tmpConnection->config.transportProfileUri,
                                   &transportProfileUri) &&
                   writerGroup->config.writerGroupId == id)
                    return false;
            
            } else {
                UA_DataSetWriter *currentWriter;
                LIST_FOREACH(currentWriter, &writerGroup->writers, listEntry) {
                    if(UA_String_equal(&tmpConnection->config.transportProfileUri,
                                       &transportProfileUri) &&
                       currentWriter->config.dataSetWriterId == id)
                        return false;
                }
            }
        }
    }
    return true;
}

static UA_UInt16
UA_ReserveId_createId(UA_Server *server,  UA_NodeId sessionId,
                      UA_String transportProfileUri, UA_ReserveIdType reserveIdType) {
    
    UA_UInt16 numberOfIds = 0x8000;
    
    static UA_UInt16 next_id_writerGroup = UA_RESERVEID_FIRST_ID;
    static UA_UInt16 next_id_writer = UA_RESERVEID_FIRST_ID;
    UA_UInt16 next_id;
    UA_Boolean is_free = false;

    if(reserveIdType == UA_WRITER_GROUP)
        next_id = next_id_writerGroup;
    else
        next_id = next_id_writer;

    for(;numberOfIds > 0;numberOfIds--) {
        if(next_id < UA_RESERVEID_FIRST_ID)
            next_id = UA_RESERVEID_FIRST_ID;
        is_free = UA_ReserveId_isFree(server, next_id, transportProfileUri, reserveIdType);
        if(is_free)
            break;
        next_id++;
    }
    if(!is_free) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "PubSub ReserveId creation failed. No free ID could be found.");
        return 0;
    }

    if(reserveIdType == UA_WRITER_GROUP)
        next_id_writerGroup = (UA_UInt16)(next_id + 1);
    else
        next_id_writer = (UA_UInt16)(next_id + 1);

    UA_ReserveId *reserveId =
        UA_ReserveId_new(server, next_id, transportProfileUri, reserveIdType, sessionId);
    if(!reserveId)
        return 0;

    UA_PubSubManager *psm = &server->pubSubManager;
    ZIP_INSERT(UA_ReserveIdTree, &psm->reserveIds, reserveId);
    psm->reserveIdsSize++;
    return next_id;
}

static void *
removeReserveId(void *context, UA_ReserveId *elem) {
    UA_String_clear(&elem->transportProfileUri);
    UA_free(elem);
    return NULL;
}

struct RemoveInactiveReserveIdContext {
    UA_Server *server;
    UA_ReserveIdTree newTree;
};


static void *
removeInactiveReserveId(void *context, UA_ReserveId *elem) {
    struct RemoveInactiveReserveIdContext *ctx =
        (struct RemoveInactiveReserveIdContext*)context;

    if(UA_NodeId_equal(&ctx->server->adminSession.sessionId, &elem->sessionId))
        goto still_active;

    session_list_entry *session;
    LIST_FOREACH(session, &ctx->server->sessions, pointers) {
        if(UA_NodeId_equal(&session->session.sessionId, &elem->sessionId))
            goto still_active;
    }

    ctx->server->pubSubManager.reserveIdsSize--;
    UA_String_clear(&elem->transportProfileUri);
    UA_free(elem);
    return NULL;

 still_active:
    ZIP_INSERT(UA_ReserveIdTree, &ctx->newTree, elem);
    return NULL;
}

void
UA_PubSubManager_freeIds(UA_Server *server) {
    struct RemoveInactiveReserveIdContext removeCtx;
    removeCtx.server = server;
    removeCtx.newTree.root = NULL;
    ZIP_ITER(UA_ReserveIdTree, &server->pubSubManager.reserveIds,
             removeInactiveReserveId, &removeCtx);
    server->pubSubManager.reserveIds = removeCtx.newTree;
}

UA_StatusCode
UA_PubSubManager_reserveIds(UA_Server *server, UA_NodeId sessionId, UA_UInt16 numRegWriterGroupIds,
                            UA_UInt16 numRegDataSetWriterIds, UA_String transportProfileUri,
                            UA_UInt16 **writerGroupIds, UA_UInt16 **dataSetWriterIds) {
    UA_PubSubManager_freeIds(server);

    
    UA_String profile_1 = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-uadp");
    UA_String profile_2 = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json");
    UA_String profile_3 = UA_STRING("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp");
    if(!UA_String_equal(&transportProfileUri, &profile_1) &&
       !UA_String_equal(&transportProfileUri, &profile_2) &&
       !UA_String_equal(&transportProfileUri, &profile_3)) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "PubSub ReserveId creation failed. No valid transport profile uri.");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    *writerGroupIds = (UA_UInt16*)UA_Array_new(numRegWriterGroupIds, &UA_TYPES[UA_TYPES_UINT16]);
    *dataSetWriterIds = (UA_UInt16*)UA_Array_new(numRegDataSetWriterIds, &UA_TYPES[UA_TYPES_UINT16]);

    for(int i = 0; i < numRegWriterGroupIds; i++) {
        (*writerGroupIds)[i] =
            UA_ReserveId_createId(server, sessionId, transportProfileUri, UA_WRITER_GROUP);
    }
    for(int i = 0; i < numRegDataSetWriterIds; i++) {
        (*dataSetWriterIds)[i] =
            UA_ReserveId_createId(server, sessionId, transportProfileUri, UA_DATA_SET_WRITER);
    }
    return UA_STATUSCODE_GOOD;
}

UA_UInt32
UA_PubSubConfigurationVersionTimeDifference(UA_DateTime now) {
    UA_UInt32 timeDiffSince2000 = (UA_UInt32)(now - UA_DATETIMESTAMP_2000);
    return timeDiffSince2000;
}

#ifndef UA_ENABLE_PUBSUB_INFORMATIONMODEL
void
UA_PubSubManager_generateUniqueNodeId(UA_PubSubManager *psm, UA_NodeId *nodeId) {
    *nodeId = UA_NODEID_NUMERIC(1, ++psm->uniqueIdCount);
}
#endif

UA_Guid
UA_PubSubManager_generateUniqueGuid(UA_Server *server) {
    while(true) {
        UA_NodeId testId = UA_NODEID_GUID(1, UA_Guid_random());
        const UA_Node *testNode = UA_NODESTORE_GET(server, &testId);
        if(!testNode)
            return testId.identifier.guid;
        UA_NODESTORE_RELEASE(server, testNode);
    }
}

static UA_UInt64
generateRandomUInt64(UA_Server *server) {
    UA_UInt64 id = 0;
    UA_Guid ident = UA_Guid_random();

    id = id + ident.data1;
    id = (id << 32) + ident.data2;
    id = (id << 16) + ident.data3;
    return id;
}


void
UA_PubSubManager_init(UA_Server *server, UA_PubSubManager *psm) {
    //TODO: Using the Mac address to generate the defaultPublisherId.
    // In the future, this can be retrieved from the eventloop.
    psm->defaultPublisherId = generateRandomUInt64(server);

    TAILQ_INIT(&psm->connections);
    TAILQ_INIT(&psm->publishedDataSets);
    TAILQ_INIT(&psm->subscribedDataSets);
    TAILQ_INIT(&psm->topicAssign);

#ifdef UA_ENABLE_PUBSUB_SKS
    TAILQ_INIT(&psm->securityGroups);
#endif
}

void
UA_PubSubManager_shutdown(UA_Server *server, UA_PubSubManager *psm) {
    UA_PubSubConnection *tmpConnection;
    TAILQ_FOREACH(tmpConnection, &psm->connections, listEntry) {
        UA_PubSubConnection_setPubSubState(server, tmpConnection, UA_PUBSUBSTATE_DISABLED);
    }
}

void
UA_PubSubManager_delete(UA_Server *server, UA_PubSubManager *psm) {
    UA_LOG_INFO(server->config.logging, UA_LOGCATEGORY_SERVER,
                "PubSub cleanup was called.");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_PubSubConnection *tmpConnection1, *tmpConnection2;
    TAILQ_FOREACH_SAFE(tmpConnection1, &psm->connections, listEntry, tmpConnection2) {
        UA_PubSubConnection_delete(server, tmpConnection1);
    }

    
    UA_PublishedDataSet *tmpPDS1, *tmpPDS2;
    TAILQ_FOREACH_SAFE(tmpPDS1, &psm->publishedDataSets, listEntry, tmpPDS2){
        UA_PublishedDataSet_remove(server, tmpPDS1);
    }

    
    UA_TopicAssign *tmpTopicAssign1, *tmpTopicAssign2;
    TAILQ_FOREACH_SAFE(tmpTopicAssign1, &psm->topicAssign, listEntry, tmpTopicAssign2){
        psm->topicAssignSize--;
        TAILQ_REMOVE(&psm->topicAssign, tmpTopicAssign1, listEntry);
        UA_free(tmpTopicAssign1);
    }

    
    ZIP_ITER(UA_ReserveIdTree, &psm->reserveIds, removeReserveId, NULL);
    psm->reserveIdsSize = 0;

    
    UA_StandaloneSubscribedDataSet *tmpSDS1, *tmpSDS2;
    TAILQ_FOREACH_SAFE(tmpSDS1, &psm->subscribedDataSets, listEntry, tmpSDS2) {
        UA_StandaloneSubscribedDataSet_remove(server, tmpSDS1);
    }

#ifdef UA_ENABLE_PUBSUB_SKS
    
    UA_SecurityGroup *tmpSG1, *tmpSG2;
    TAILQ_FOREACH_SAFE(tmpSG1, &psm->securityGroups, listEntry, tmpSG2) {
        removeSecurityGroup(server, tmpSG1);
    }

    
    UA_PubSubKeyStorage *ks, *ksTmp;
    LIST_FOREACH_SAFE(ks, &psm->pubSubKeyList, keyStorageList, ksTmp) {
        UA_PubSubKeyStorage_delete(server, ks);
    }
#endif
}

#ifdef UA_ENABLE_PUBSUB_MONITORING

static UA_StatusCode
UA_PubSubComponent_createMonitoring(UA_Server *server, UA_NodeId Id,
                                    UA_PubSubComponentEnumType eComponentType,
                                    UA_PubSubMonitoringType eMonitoringType,
                                    void *data, UA_ServerCallback callback) {
    if(!server || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_DataSetReader *reader = (UA_DataSetReader*) data;

    if(eComponentType != UA_PUBSUB_COMPONENT_DATASETREADER) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "Error UA_PubSubComponent_createMonitoring(): "
                            "PubSub component type '%i' is not supported",
                            eComponentType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    if(eMonitoringType != UA_PUBSUB_MONITORING_MESSAGE_RECEIVE_TIMEOUT) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "UA_PubSubComponent_createMonitoring(): "
                            "DataSetReader does not support timeout type '%i'",
                            eMonitoringType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    reader->msgRcvTimeoutTimerCallback = callback;

    UA_LOG_DEBUG_PUBSUB(server->config.logging, reader,
                        "UA_PubSubComponent_createMonitoring(): "
                        "Set MessageReceiveTimeout callback");

    return UA_STATUSCODE_GOOD;
}

static void
monitoringReceiveTimeoutOnce(UA_Server *server, void *data) {
    UA_LOCK(&server->serviceMutex);
    UA_DataSetReader *reader = (UA_DataSetReader*)data;
    reader->msgRcvTimeoutTimerCallback(server, reader);
    UA_EventLoop *el = server->config.eventLoop;
    el->removeCyclicCallback(el, reader->msgRcvTimeoutTimerId);
    reader->msgRcvTimeoutTimerId = 0;
    UA_UNLOCK(&server->serviceMutex);
}

static UA_StatusCode
UA_PubSubComponent_startMonitoring(UA_Server *server, UA_NodeId Id,
                                   UA_PubSubComponentEnumType eComponentType,
                                   UA_PubSubMonitoringType eMonitoringType, void *data) {
    if(!server || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_DataSetReader *reader = (UA_DataSetReader*)data;

    if(eComponentType != UA_PUBSUB_COMPONENT_DATASETREADER) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "Error UA_PubSubComponent_startMonitoring(): PubSub component "
                            "type '%i' is not supported", eComponentType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    if(eMonitoringType != UA_PUBSUB_MONITORING_MESSAGE_RECEIVE_TIMEOUT) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "UA_PubSubComponent_startMonitoring(): "
                            "DataSetReader does not support timeout type '%i'",
                            eMonitoringType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    
    if(reader->config.messageReceiveTimeout <= 0.0) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, reader,
                              "Cannot monitor timeout for messageReceiveTimeout == 0");
        return UA_STATUSCODE_GOOD;
    }

    UA_EventLoop *el = server->config.eventLoop;
    UA_StatusCode ret =
        el->addCyclicCallback(el, (UA_Callback)monitoringReceiveTimeoutOnce, server,
                              reader, reader->config.messageReceiveTimeout,
                              NULL, UA_TIMER_HANDLE_CYCLEMISS_WITH_CURRENTTIME,
                              &reader->msgRcvTimeoutTimerId);
    if(ret != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "Error UA_PubSubComponent_startMonitoring(): "
                            "MessageReceiveTimeout: Start timer failed");
        return ret;
    }

    UA_LOG_DEBUG_PUBSUB(server->config.logging, reader,
                        "UA_PubSubComponent_startMonitoring(): "
                        "MessageReceiveTimeout = '%f' Timer Id = '%u'",
                        reader->config.messageReceiveTimeout,
                        (UA_UInt32)reader->msgRcvTimeoutTimerId);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_PubSubComponent_stopMonitoring(UA_Server *server, UA_NodeId Id,
                                  UA_PubSubComponentEnumType eComponentType,
                                  UA_PubSubMonitoringType eMonitoringType, void *data) {
    if(!server || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_DataSetReader *reader = (UA_DataSetReader*) data;

    if(eComponentType != UA_PUBSUB_COMPONENT_DATASETREADER) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "Error UA_PubSubComponent_stopMonitoring(): "
                            "PubSub component type '%i' is not supported",
                            eComponentType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    if(eMonitoringType != UA_PUBSUB_MONITORING_MESSAGE_RECEIVE_TIMEOUT) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "UA_PubSubComponent_stopMonitoring(): "
                            "DataSetReader does not support timeout type '%i'",
                            eMonitoringType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    UA_LOG_DEBUG_PUBSUB(server->config.logging, reader,
                        "UA_PubSubComponent_stopMonitoring(): "
                        "MessageReceiveTimeout: MessageReceiveTimeout = '%f' "
                        "Timer Id = '%u'", reader->config.messageReceiveTimeout,
                        (UA_UInt32)reader->msgRcvTimeoutTimerId);

    UA_EventLoop *el = server->config.eventLoop;
    el->removeCyclicCallback(el, reader->msgRcvTimeoutTimerId);
    reader->msgRcvTimeoutTimerId = 0;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_PubSubComponent_updateMonitoringInterval(UA_Server *server, UA_NodeId Id,
                                            UA_PubSubComponentEnumType eComponentType,
                                            UA_PubSubMonitoringType eMonitoringType,
                                            void *data) {
    if(!server || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_DataSetReader *reader = (UA_DataSetReader*) data;

    if(eComponentType != UA_PUBSUB_COMPONENT_DATASETREADER) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "Error UA_PubSubComponent_updateMonitoringInterval(): "
                            "PubSub component type '%i' is not supported",
                            eComponentType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    if(eMonitoringType != UA_PUBSUB_MONITORING_MESSAGE_RECEIVE_TIMEOUT) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "UA_PubSubComponent_createMonitoring(): "
                            "DataSetReader does not support timeout type '%i'",
                            eMonitoringType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    UA_EventLoop *el = server->config.eventLoop;
    UA_StatusCode ret =
        el->modifyCyclicCallback(el, reader->msgRcvTimeoutTimerId,
                                 reader->config.messageReceiveTimeout, NULL,
                                 UA_TIMER_HANDLE_CYCLEMISS_WITH_CURRENTTIME);
    if(ret != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "Error UA_PubSubComponent_updateMonitoringInterval(): "
                            "Update timer interval failed");
        return ret;
    }

    UA_LOG_DEBUG_PUBSUB(server->config.logging, reader,
                        "UA_PubSubComponent_updateMonitoringInterval(): "
                        "MessageReceiveTimeout: new MessageReceiveTimeout "
                        "= '%f' Timer Id = '%u'",
                        reader->config.messageReceiveTimeout,
                        (UA_UInt32) reader->msgRcvTimeoutTimerId);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_PubSubComponent_deleteMonitoring(UA_Server *server, UA_NodeId Id,
                                    UA_PubSubComponentEnumType eComponentType,
                                    UA_PubSubMonitoringType eMonitoringType, void *data) {
    if(!server || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_DataSetReader *reader = (UA_DataSetReader*) data;

    if(eComponentType != UA_PUBSUB_COMPONENT_DATASETREADER) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "Error UA_PubSubComponent_deleteMonitoring(): PubSub component type "
                            "'%i' is not supported", eComponentType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    if(eMonitoringType != UA_PUBSUB_MONITORING_MESSAGE_RECEIVE_TIMEOUT) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, reader,
                            "UA_PubSubComponent_deleteMonitoring(): "
                            "DataSetReader does not support timeout type '%i'",
                            eMonitoringType);
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    if(reader->msgRcvTimeoutTimerId != 0) {
        UA_PubSubComponent_stopMonitoring(server, Id, eComponentType,
                                          eMonitoringType, data);
    }

    UA_LOG_DEBUG_PUBSUB(server->config.logging, reader,
                        "UA_PubSubComponent_deleteMonitoring(): DataSetReader "
                        "MessageReceiveTimeout: Timer Id = '%u'",
                        (UA_UInt32)reader->msgRcvTimeoutTimerId);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_PubSubManager_setDefaultMonitoringCallbacks(UA_PubSubMonitoringInterface *mif) {
    if(!mif)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    mif->createMonitoring = UA_PubSubComponent_createMonitoring;
    mif->startMonitoring = UA_PubSubComponent_startMonitoring;
    mif->stopMonitoring = UA_PubSubComponent_stopMonitoring;
    mif->updateMonitoringInterval = UA_PubSubComponent_updateMonitoringInterval;
    mif->deleteMonitoring = UA_PubSubComponent_deleteMonitoring;
    return UA_STATUSCODE_GOOD;
}

#endif 

#endif 
