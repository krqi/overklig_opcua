
#include <opcua/server_pubsub.h>
#include "ua_pubsub.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_PUBSUB 

#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
#include "ua_pubsub_networkmessage.h"
#include "ua_pubsub_ns0.h"
#endif

#define MALLOCMEMBUFSIZE 256

typedef struct {
    size_t pos;
    char buf[MALLOCMEMBUFSIZE];
} MembufCalloc;

static void *
membufCalloc(void *context,
             size_t nelem, size_t elsize) {
    if(nelem > MALLOCMEMBUFSIZE || elsize > MALLOCMEMBUFSIZE)
        return NULL;
    size_t total = nelem * elsize;

    MembufCalloc *mc = (MembufCalloc*)context;
    if(mc->pos + total > MALLOCMEMBUFSIZE)
        return NULL;
    void *mem = mc->buf + mc->pos;
    mc->pos += total;
    memset(mem, 0, total);
    return mem;
}

UA_ReaderGroup *
UA_ReaderGroup_findRGbyId(UA_Server *server, UA_NodeId identifier) {
    UA_ReaderGroup *rg;
    UA_PubSubConnection *psc;
    TAILQ_FOREACH(psc, &server->pubSubManager.connections, listEntry) {
        LIST_FOREACH(rg, &psc->readerGroups, listEntry) {
            if(UA_NodeId_equal(&identifier, &rg->head.identifier))
                return rg;
        }
    }
    return NULL;
}

UA_DataSetReader *
UA_ReaderGroup_findDSRbyId(UA_Server *server, UA_NodeId identifier) {
    UA_ReaderGroup *rg;
    UA_PubSubConnection *psc;
    UA_DataSetReader *tmpReader;
    TAILQ_FOREACH(psc, &server->pubSubManager.connections, listEntry) {
        LIST_FOREACH(rg, &psc->readerGroups, listEntry) {
            LIST_FOREACH(tmpReader, &rg->readers, listEntry) {
                if(UA_NodeId_equal(&tmpReader->head.identifier, &identifier))
                    return tmpReader;
            }
        }
    }
    return NULL;
}



UA_StatusCode
UA_ReaderGroupConfig_copy(const UA_ReaderGroupConfig *src,
                          UA_ReaderGroupConfig *dst) {
    memcpy(dst, src, sizeof(UA_ReaderGroupConfig));
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    res |= UA_String_copy(&src->name, &dst->name);
    res |= UA_KeyValueMap_copy(&src->groupProperties, &dst->groupProperties);
    res |= UA_String_copy(&src->securityGroupId, &dst->securityGroupId);
    if(res != UA_STATUSCODE_GOOD)
        UA_ReaderGroupConfig_clear(dst);
    return res;
}

void
UA_ReaderGroupConfig_clear(UA_ReaderGroupConfig *readerGroupConfig) {
    UA_String_clear(&readerGroupConfig->name);
    UA_KeyValueMap_clear(&readerGroupConfig->groupProperties);
    UA_String_clear(&readerGroupConfig->securityGroupId);
}



UA_StatusCode
UA_ReaderGroup_create(UA_Server *server, UA_NodeId connectionId,
                      const UA_ReaderGroupConfig *rgc,
                      UA_NodeId *readerGroupId) {
    
    if(!rgc)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    
    UA_PubSubConnection *connection =
        UA_PubSubConnection_findConnectionbyId(server, connectionId);
    if(!connection)
        return UA_STATUSCODE_BADNOTFOUND;

    if(connection->configurationFreezeCounter > 0) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, connection,
                              "Adding ReaderGroup failed. "
                              "Connection configuration is frozen.");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    
    UA_ReaderGroup *newGroup = (UA_ReaderGroup *)UA_calloc(1, sizeof(UA_ReaderGroup));
    if(!newGroup)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    newGroup->head.componentType = UA_PUBSUB_COMPONENT_READERGROUP;
    newGroup->linkedConnection = connection;

    
    UA_StatusCode retval = UA_ReaderGroupConfig_copy(rgc, &newGroup->config);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(newGroup);
        return retval;
    }

    
    LIST_INSERT_HEAD(&connection->readerGroups, newGroup, listEntry);
    connection->readerGroupsSize++;

#ifdef UA_ENABLE_PUBSUB_SKS
    if(rgc->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       rgc->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        if(!UA_String_isEmpty(&rgc->securityGroupId) && rgc->securityPolicy) {
            
            newGroup->keyStorage =
                UA_PubSubKeyStorage_findKeyStorage(server, rgc->securityGroupId);

            if(!newGroup->keyStorage) {
                
                newGroup->keyStorage = (UA_PubSubKeyStorage *)
                    UA_calloc(1, sizeof(UA_PubSubKeyStorage));
                if(!newGroup->keyStorage) {
                    UA_ReaderGroup_remove(server, newGroup);
                    return UA_STATUSCODE_BADOUTOFMEMORY;
                }
                retval = UA_PubSubKeyStorage_init(server, newGroup->keyStorage,
                                                  &rgc->securityGroupId,
                                                  rgc->securityPolicy, 0, 0);
                if(retval != UA_STATUSCODE_GOOD) {
                    UA_ReaderGroup_remove(server, newGroup);
                    return retval;
                }
            }

            
            newGroup->keyStorage->referenceCount++;
        }
    }
#endif

#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    retval |= addReaderGroupRepresentation(server, newGroup);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ReaderGroup_remove(server, newGroup);
        return retval;
    }
#else
    UA_PubSubManager_generateUniqueNodeId(&server->pubSubManager,
                                          &newGroup->head.identifier);
#endif

    
    char tmpLogIdStr[128];
    mp_snprintf(tmpLogIdStr, 128, "%SReaderGroup %N\t| ",
                connection->head.logIdString, newGroup->head.identifier);
    newGroup->head.logIdString = UA_STRING_ALLOC(tmpLogIdStr);

    UA_LOG_INFO_PUBSUB(server->config.logging, newGroup, "ReaderGroup created");

    
    retval = UA_ReaderGroup_connect(server, newGroup, true);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, newGroup,
                            "Could not validate the connection parameters");
        UA_ReaderGroup_remove(server, newGroup);
        return retval;
    }

    
    UA_PubSubConnection_setPubSubState(server, connection, connection->head.state);

    
    if(readerGroupId)
        UA_NodeId_copy(&newGroup->head.identifier, readerGroupId);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_addReaderGroup(UA_Server *server, const UA_NodeId connectionIdentifier,
                         const UA_ReaderGroupConfig *readerGroupConfig,
                         UA_NodeId *readerGroupIdentifier) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res =
        UA_ReaderGroup_create(server, connectionIdentifier,
                              readerGroupConfig, readerGroupIdentifier);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_ReaderGroup_remove(UA_Server *server, UA_ReaderGroup *rg) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(rg->configurationFrozen) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, rg,
                              "Remove ReaderGroup failed. "
                              "Subscriber configuration is frozen.");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    UA_PubSubConnection *connection = rg->linkedConnection;
    UA_assert(connection);
    if(connection->configurationFreezeCounter > 0) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, rg,
                              "Deleting the ReaderGroup failed. "
                              "PubSubConnection is frozen.");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    rg->deleteFlag = true;
    UA_ReaderGroup_setPubSubState(server, rg, UA_PUBSUBSTATE_DISABLED);

    UA_DataSetReader *dsr, *tmp_dsr;
    LIST_FOREACH_SAFE(dsr, &rg->readers, listEntry, tmp_dsr) {
        UA_DataSetReader_remove(server, dsr);
    }

    if(rg->config.securityPolicy && rg->securityPolicyContext) {
        rg->config.securityPolicy->deleteContext(rg->securityPolicyContext);
        rg->securityPolicyContext = NULL;
    }

#ifdef UA_ENABLE_PUBSUB_SKS
    if(rg->keyStorage) {
        UA_PubSubKeyStorage_detachKeyStorage(server, rg->keyStorage);
        rg->keyStorage = NULL;
    }
#endif

    if(rg->recvChannelsSize == 0) {
        
        LIST_REMOVE(rg, listEntry);
        connection->readerGroupsSize--;
        rg->linkedConnection = NULL;

        
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
        deleteNode(server, rg->head.identifier, true);
#endif

        UA_LOG_INFO_PUBSUB(server->config.logging, rg, "ReaderGroup deleted");

        UA_ReaderGroupConfig_clear(&rg->config);
        UA_PubSubComponentHead_clear(&rg->head);
        UA_free(rg);
    }

    
    UA_PubSubConnection_setPubSubState(server, connection, connection->head.state);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_removeReaderGroup(UA_Server *server, const UA_NodeId groupIdentifier) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    UA_ReaderGroup *rg = UA_ReaderGroup_findRGbyId(server, groupIdentifier);
    if(rg)
        res = UA_ReaderGroup_remove(server, rg);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_Server_ReaderGroup_getConfig(UA_Server *server, const UA_NodeId readerGroupIdentifier,
                                UA_ReaderGroupConfig *config) {
    if(!config)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_LOCK(&server->serviceMutex);

    
    UA_ReaderGroup *currentReaderGroup =
        UA_ReaderGroup_findRGbyId(server, readerGroupIdentifier);
    if(!currentReaderGroup) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_StatusCode ret =
        UA_ReaderGroupConfig_copy(&currentReaderGroup->config, config);

    UA_UNLOCK(&server->serviceMutex);
    return ret;
}

UA_StatusCode
UA_Server_ReaderGroup_getState(UA_Server *server, const UA_NodeId readerGroupIdentifier,
                               UA_PubSubState *state) {
    if((server == NULL) || (state == NULL))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode ret = UA_STATUSCODE_BADNOTFOUND;
    UA_ReaderGroup *rg = UA_ReaderGroup_findRGbyId(server, readerGroupIdentifier);
    if(rg) {
        *state = rg->head.state;
        ret = UA_STATUSCODE_GOOD;
    }
    UA_UNLOCK(&server->serviceMutex);
    return ret;
}

UA_StatusCode
UA_ReaderGroup_setPubSubState(UA_Server *server, UA_ReaderGroup *rg,
                              UA_PubSubState targetState) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(rg->deleteFlag && targetState != UA_PUBSUBSTATE_DISABLED) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, rg,
                              "The ReaderGroup is being deleted. Can only be disabled.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode ret = UA_STATUSCODE_GOOD;
    UA_PubSubConnection *connection = rg->linkedConnection;
    UA_PubSubState oldState = rg->head.state;
    rg->head.state = targetState;

    switch(rg->head.state) {
        
    default:
        rg->head.state = UA_PUBSUBSTATE_ERROR;
        ret = UA_STATUSCODE_BADINTERNALERROR;
        
    case UA_PUBSUBSTATE_DISABLED:
    case UA_PUBSUBSTATE_ERROR:
        UA_ReaderGroup_disconnect(rg);
        rg->hasReceived = false;
        break;

        
    case UA_PUBSUBSTATE_PAUSED:
    case UA_PUBSUBSTATE_PREOPERATIONAL:
    case UA_PUBSUBSTATE_OPERATIONAL:
        if(connection->head.state == UA_PUBSUBSTATE_DISABLED ||
           connection->head.state == UA_PUBSUBSTATE_ERROR) {
            
            rg->head.state = UA_PUBSUBSTATE_PAUSED;
        } else {
            
            rg->head.state = connection->head.state;
            if(rg->head.state == UA_PUBSUBSTATE_OPERATIONAL && !rg->hasReceived)
                rg->head.state = UA_PUBSUBSTATE_PREOPERATIONAL;

            
            ret = UA_ReaderGroup_connect(server, rg, false);
            if(ret != UA_STATUSCODE_GOOD)
                rg->head.state = UA_PUBSUBSTATE_ERROR;
        }
        break;
    }

    
    if(rg->head.state != oldState) {
        UA_ServerConfig *pConfig = &server->config;
        UA_LOG_INFO_PUBSUB(pConfig->logging, rg, "State change: %s -> %s",
                           UA_PubSubState_name(oldState),
                           UA_PubSubState_name(rg->head.state));
        if(pConfig->pubSubConfig.stateChangeCallback != 0) {
            UA_UNLOCK(&server->serviceMutex);
            pConfig->pubSubConfig.
                stateChangeCallback(server, &rg->head.identifier, rg->head.state, ret);
            UA_LOCK(&server->serviceMutex);
        }
    }

    
    UA_DataSetReader *dsr;
    LIST_FOREACH(dsr, &rg->readers, listEntry) {
        UA_DataSetReader_setPubSubState(server, dsr, dsr->head.state);
    }

    return ret;
}

#ifdef UA_ENABLE_PUBSUB_SKS
UA_StatusCode
UA_Server_setReaderGroupActivateKey(UA_Server *server,
                                    const UA_NodeId readerGroupId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode ret = UA_STATUSCODE_BADNOTFOUND;
    UA_ReaderGroup *rg = UA_ReaderGroup_findRGbyId(server, readerGroupId);
    if(rg) {
        if(rg->keyStorage && rg->keyStorage->currentItem) {
            UA_StatusCode retval = UA_PubSubKeyStorage_activateKeyToChannelContext(
                server, rg->head.identifier, rg->config.securityGroupId);
            if(retval != UA_STATUSCODE_GOOD) {
                UA_UNLOCK(&server->serviceMutex);
                return retval;
            }
        }
    }
    UA_UNLOCK(&server->serviceMutex);
    return ret;
}
#endif

UA_StatusCode
UA_Server_enableReaderGroup(UA_Server *server, const UA_NodeId readerGroupId){
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode ret = UA_STATUSCODE_BADNOTFOUND;
    UA_ReaderGroup *rg = UA_ReaderGroup_findRGbyId(server, readerGroupId);
    if(rg)
        ret = UA_ReaderGroup_setPubSubState(server, rg, UA_PUBSUBSTATE_OPERATIONAL);
    UA_UNLOCK(&server->serviceMutex);
    return ret;
}

UA_StatusCode
UA_Server_disableReaderGroup(UA_Server *server, const UA_NodeId readerGroupId){
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode ret = UA_STATUSCODE_BADNOTFOUND;
    UA_ReaderGroup *rg = UA_ReaderGroup_findRGbyId(server, readerGroupId);
    if(rg)
        ret = UA_ReaderGroup_setPubSubState(server, rg, UA_PUBSUBSTATE_DISABLED);
    UA_UNLOCK(&server->serviceMutex);
    return ret;
}

UA_StatusCode
setReaderGroupEncryptionKeys(UA_Server *server, const UA_NodeId readerGroup,
                             UA_UInt32 securityTokenId,
                             const UA_ByteString signingKey,
                             const UA_ByteString encryptingKey,
                             const UA_ByteString keyNonce) {
    UA_ReaderGroup *rg = UA_ReaderGroup_findRGbyId(server, readerGroup);
    UA_CHECK_MEM(rg, return UA_STATUSCODE_BADNOTFOUND);
    if(rg->config.encodingMimeType == UA_PUBSUB_ENCODING_JSON) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, rg,
                              "JSON encoding is enabled. The message security is "
                              "only defined for the UADP message mapping.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    if(!rg->config.securityPolicy) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, rg,
                              "No SecurityPolicy configured for the ReaderGroup");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(securityTokenId != rg->securityTokenId) {
        rg->securityTokenId = securityTokenId;
        rg->nonceSequenceNumber = 1;
    }

    
    if(!rg->securityPolicyContext) {
        return rg->config.securityPolicy->
            newContext(rg->config.securityPolicy->policyContext,
                       &signingKey, &encryptingKey, &keyNonce,
                       &rg->securityPolicyContext);
    }

    
    return rg->config.securityPolicy->
        setSecurityKeys(rg->securityPolicyContext, &signingKey,
                        &encryptingKey, &keyNonce);
}

UA_StatusCode
UA_Server_setReaderGroupEncryptionKeys(UA_Server *server,
                                       const UA_NodeId readerGroup,
                                       UA_UInt32 securityTokenId,
                                       const UA_ByteString signingKey,
                                       const UA_ByteString encryptingKey,
                                       const UA_ByteString keyNonce) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = setReaderGroupEncryptionKeys(server, readerGroup,
                                                     securityTokenId, signingKey,
                                                     encryptingKey, keyNonce);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}



UA_StatusCode
UA_ReaderGroup_freezeConfiguration(UA_Server *server, UA_ReaderGroup *rg) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    if(rg->configurationFrozen)
        return UA_STATUSCODE_GOOD;

    
    UA_PubSubConnection *pubSubConnection = rg->linkedConnection;
    pubSubConnection->configurationFreezeCounter++;

    
    rg->configurationFrozen = true;

    
    UA_DataSetReader *dsr;
    UA_UInt16 dsrCount = 0;
    LIST_FOREACH(dsr, &rg->readers, listEntry){
        dsr->configurationFrozen = true;
        dsrCount++;
    }

    
    if((rg->config.rtLevel & UA_PUBSUB_RT_FIXED_SIZE) == 0)
        return UA_STATUSCODE_GOOD;

    if(dsrCount > 1) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, rg,
                              "Multiple DSR in a readerGroup not supported in RT "
                              "fixed size configuration");
        return UA_STATUSCODE_BADNOTIMPLEMENTED;
    }

    dsr = LIST_FIRST(&rg->readers);

    
    if(dsr->config.messageSettings.content.decoded.type !=
       &UA_TYPES[UA_TYPES_UADPDATASETREADERMESSAGEDATATYPE]) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, dsr,
                              "PubSub-RT configuration fail: Non-RT capable encoding.");
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    
    if(dsr->config.publisherId.idType == UA_PUBLISHERIDTYPE_STRING) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, dsr,
                              "PubSub-RT configuration fail: String PublisherId");
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    size_t fieldsSize = dsr->config.dataSetMetaData.fieldsSize;
    for(size_t i = 0; i < fieldsSize; i++) {
        
        
        
        
        
        
        
        
        
        
        
        
        

        
        

        

        UA_FieldMetaData *field = &dsr->config.dataSetMetaData.fields[i];
        if((UA_NodeId_equal(&field->dataType, &UA_TYPES[UA_TYPES_STRING].typeId) ||
            UA_NodeId_equal(&field->dataType, &UA_TYPES[UA_TYPES_BYTESTRING].typeId)) &&
           field->maxStringLength == 0) {
            UA_LOG_WARNING_PUBSUB(server->config.logging, dsr,
                                  "PubSub-RT configuration fail: "
                                  "PDS contains String/ByteString with dynamic length.");
            return UA_STATUSCODE_BADNOTSUPPORTED;
        } else if(!UA_DataType_isNumeric(UA_findDataType(&field->dataType)) &&
                  !UA_NodeId_equal(&field->dataType, &UA_TYPES[UA_TYPES_BOOLEAN].typeId)) {
            UA_LOG_WARNING_PUBSUB(server->config.logging, dsr,
                                  "PubSub-RT configuration fail: "
                                  "PDS contains variable with dynamic size.");
            return UA_STATUSCODE_BADNOTSUPPORTED;
        }
    }

    UA_NetworkMessageOffsetBuffer_clear(&dsr->bufferedMessage);

    return UA_ReaderGroup_setPubSubState(server, rg, rg->head.state);
}

UA_StatusCode
UA_Server_freezeReaderGroupConfiguration(UA_Server *server,
                                         const UA_NodeId readerGroupId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    UA_ReaderGroup *rg = UA_ReaderGroup_findRGbyId(server, readerGroupId);
    if(rg)
        res = UA_ReaderGroup_freezeConfiguration(server, rg);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_ReaderGroup_unfreezeConfiguration(UA_Server *server, UA_ReaderGroup *rg) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(!rg->configurationFrozen)
        return UA_STATUSCODE_GOOD;

    
    UA_PubSubConnection *pubSubConnection = rg->linkedConnection;
    pubSubConnection->configurationFreezeCounter--;

    
    rg->configurationFrozen = false;

    
    UA_DataSetReader *dataSetReader;
    LIST_FOREACH(dataSetReader, &rg->readers, listEntry) {
        dataSetReader->configurationFrozen = false;
        UA_NetworkMessageOffsetBuffer_clear(&dataSetReader->bufferedMessage);
    }

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_unfreezeReaderGroupConfiguration(UA_Server *server,
                                           const UA_NodeId readerGroupId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    UA_ReaderGroup *rg = UA_ReaderGroup_findRGbyId(server, readerGroupId);
    if(rg)
        res = UA_ReaderGroup_unfreezeConfiguration(server, rg);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_Boolean
UA_ReaderGroup_process(UA_Server *server, UA_ReaderGroup *rg,
                       UA_NetworkMessage *nm) {
    
    if(rg->head.state != UA_PUBSUBSTATE_OPERATIONAL &&
       rg->head.state != UA_PUBSUBSTATE_PREOPERATIONAL)
        return false;

    
    rg->hasReceived = true;
    UA_ReaderGroup_setPubSubState(server, rg, rg->head.state);

    UA_Boolean processed = false;
    UA_DataSetReader *reader, *reader_tmp;
    LIST_FOREACH_SAFE(reader, &rg->readers, listEntry, reader_tmp) {
        UA_StatusCode res = UA_DataSetReader_checkIdentifier(server, nm, reader,
                                                             rg->config);
        if(res != UA_STATUSCODE_GOOD)
            continue;

        
        if(reader->head.state != UA_PUBSUBSTATE_OPERATIONAL &&
           reader->head.state != UA_PUBSUBSTATE_PREOPERATIONAL)
            continue;

        
        if(!rg->hasReceived) {
            rg->hasReceived = true;
            UA_ReaderGroup_setPubSubState(server, rg, rg->head.state);
        }

        
        processed = true;

        if(!nm->payloadHeaderEnabled) {
            UA_DataSetReader_process(server, reader,
                                     nm->payload.dataSetPayload.dataSetMessages);
            continue;
        }

        
        UA_DataSetPayloadHeader *ph = &nm->payloadHeader.dataSetPayloadHeader;
        for(UA_Byte i = 0; i < ph->count; i++) {
            if(reader->config.dataSetWriterId == ph->dataSetWriterIds[i]) {
                UA_DataSetReader_process(server, reader,
                                         &nm->payload.dataSetPayload.dataSetMessages[i]);
            }
        }
    }

    return processed;
}

UA_Boolean
UA_ReaderGroup_decodeAndProcessRT(UA_Server *server, UA_ReaderGroup *rg,
                                  UA_ByteString buf) {
    rg->hasReceived = true;
    if(rg->head.state == UA_PUBSUBSTATE_PREOPERATIONAL)
        UA_ReaderGroup_setPubSubState(server, rg, UA_PUBSUBSTATE_OPERATIONAL);

    
    Ctx ctx;
    ctx.pos = buf.data;
    ctx.end = buf.data + buf.length;
    ctx.depth = 0;
    memset(&ctx.opts, 0, sizeof(UA_DecodeBinaryOptions));
    ctx.opts.customTypes = server->config.customDataTypes;

    UA_Boolean processed = false;
    UA_NetworkMessage currentNetworkMessage;
    memset(&currentNetworkMessage, 0, sizeof(UA_NetworkMessage));

    MembufCalloc mc;
    mc.pos = 0;
    ctx.opts.callocContext = &mc;
    ctx.opts.calloc = membufCalloc;

    UA_StatusCode rv = UA_NetworkMessage_decodeHeaders(&ctx, &currentNetworkMessage);
    if(rv != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, rg,
                              "PubSub receive. decoding headers failed");
        return false;
    }

    
    rv = verifyAndDecryptNetworkMessage(server->config.logging, buf, &ctx,
                                        &currentNetworkMessage, rg);
    if(rv != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, rg, "Subscribe failed. "
                              "Verify and decrypt network message failed.");
        return false;
    }

    
    UA_DataSetReader *dsr;
    LIST_FOREACH(dsr, &rg->readers, listEntry) {
        
        if(dsr->head.state != UA_PUBSUBSTATE_OPERATIONAL &&
           dsr->head.state != UA_PUBSUBSTATE_PREOPERATIONAL)
            continue;

        
        rv = UA_DataSetReader_checkIdentifier(server, &currentNetworkMessage,
                                              dsr, rg->config);
        if(rv != UA_STATUSCODE_GOOD) {
            UA_LOG_DEBUG_PUBSUB(server->config.logging, dsr,
                                "PubSub receive. Message intended for a different reader.");
            continue;
        }

        
        UA_DataSetReader_decodeAndProcessRT(server, dsr, buf);
        processed = true;
    }

    return processed;
}





static UA_StatusCode
needsDecryption(const UA_Logger *logger,
                const UA_NetworkMessage *networkMessage,
                const UA_MessageSecurityMode securityMode,
                UA_Boolean *doDecrypt) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Boolean requiresEncryption = securityMode > UA_MESSAGESECURITYMODE_SIGN;
    UA_Boolean isEncrypted = networkMessage->securityHeader.networkMessageEncrypted;

    if(isEncrypted && requiresEncryption) {
        *doDecrypt = true;
    } else if(!isEncrypted && !requiresEncryption) {
        *doDecrypt = false;
    } else {
        if(isEncrypted) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "PubSub receive. "
                         "Message is encrypted but ReaderGroup does not expect encryption");
            retval = UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
        } else {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "PubSub receive. "
                         "Message is not encrypted but ReaderGroup requires encryption");
            retval = UA_STATUSCODE_BADSECURITYMODEREJECTED;
        }
    }
    return retval;
}

static UA_StatusCode
needsValidation(const UA_Logger *logger,
                const UA_NetworkMessage *networkMessage,
                const UA_MessageSecurityMode securityMode,
                UA_Boolean *doValidate) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Boolean isSigned = networkMessage->securityHeader.networkMessageSigned;
    UA_Boolean requiresSignature = securityMode > UA_MESSAGESECURITYMODE_NONE;

    if(isSigned &&
       requiresSignature) {
        *doValidate = true;
    } else if(!isSigned && !requiresSignature) {
        *doValidate = false;
    } else {
        if(isSigned) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "PubSub receive. "
                         "Message is signed but ReaderGroup does not expect signatures");
            retval = UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT;
        } else {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "PubSub receive. "
                         "Message is not signed but ReaderGroup requires signature");
            retval = UA_STATUSCODE_BADSECURITYMODEREJECTED;
        }
    }
    return retval;
}

UA_StatusCode
verifyAndDecryptNetworkMessage(const UA_Logger *logger, UA_ByteString buffer,
                               Ctx *ctx, UA_NetworkMessage *nm,
                               UA_ReaderGroup *rg) {
    UA_MessageSecurityMode securityMode = rg->config.securityMode;
    UA_Boolean doValidate = false;
    UA_Boolean doDecrypt = false;

    UA_StatusCode rv = needsValidation(logger, nm, securityMode, &doValidate);
    UA_CHECK_STATUS_WARN(rv, return rv, logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "PubSub receive. Validation security mode error");

    rv = needsDecryption(logger, nm, securityMode, &doDecrypt);
    UA_CHECK_STATUS_WARN(rv, return rv, logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "PubSub receive. Decryption security mode error");

    if(!doValidate && !doDecrypt)
        return UA_STATUSCODE_GOOD;

    void *channelContext = rg->securityPolicyContext;
    UA_PubSubSecurityPolicy *securityPolicy = rg->config.securityPolicy;
    UA_CHECK_MEM_ERROR(channelContext, return UA_STATUSCODE_BADINVALIDARGUMENT,
                       logger, UA_LOGCATEGORY_SERVER,
                       "PubSub receive. securityPolicyContext must be initialized "
                       "when security mode is enabled to sign and/or encrypt");
    UA_CHECK_MEM_ERROR(securityPolicy, return UA_STATUSCODE_BADINVALIDARGUMENT,
                       logger, UA_LOGCATEGORY_SERVER,
                       "PubSub receive. securityPolicy must be set when security mode"
                       "is enabled to sign and/or encrypt");

    
    if(doValidate) {
        size_t sigSize = securityPolicy->symmetricModule.cryptoModule.
            signatureAlgorithm.getLocalSignatureSize(channelContext);
        UA_ByteString toBeVerified = {buffer.length - sigSize, buffer.data};
        UA_ByteString signature = {sigSize, buffer.data + buffer.length - sigSize};

        rv = securityPolicy->symmetricModule.cryptoModule.signatureAlgorithm.
            verify(channelContext, &toBeVerified, &signature);
        UA_CHECK_STATUS_WARN(rv, return rv, logger, UA_LOGCATEGORY_SECURITYPOLICY,
                             "PubSub receive. Signature nvalid");

        
        ctx->end -= sigSize;
    }

    
    if(doDecrypt) {
        const UA_ByteString nonce = {
            (size_t)nm->securityHeader.messageNonceSize,
            (UA_Byte*)(uintptr_t)nm->securityHeader.messageNonce
        };
        rv = securityPolicy->setMessageNonce(channelContext, &nonce);
        UA_CHECK_STATUS_WARN(rv, return rv, logger, UA_LOGCATEGORY_SECURITYPOLICY,
                             "PubSub receive. Faulty Nonce set");

        UA_ByteString toBeDecrypted = {(uintptr_t)(ctx->end - ctx->pos), ctx->pos};
        rv = securityPolicy->symmetricModule.cryptoModule
            .encryptionAlgorithm.decrypt(channelContext, &toBeDecrypted);
        UA_CHECK_STATUS_WARN(rv, return rv, logger, UA_LOGCATEGORY_SECURITYPOLICY,
                             "PubSub receive. Faulty Decryption");
    }

    return UA_STATUSCODE_GOOD;
}

#endif 
