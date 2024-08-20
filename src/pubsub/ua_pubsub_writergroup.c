
#include "ua_pubsub.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_PUBSUB 

#include "ua_pubsub_networkmessage.h"

#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
#include "ua_pubsub_ns0.h"
#endif

#define UA_MAX_STACKBUF 128 

static UA_StatusCode
encryptAndSign(UA_WriterGroup *wg, const UA_NetworkMessage *nm,
               UA_Byte *signStart, UA_Byte *encryptStart,
               UA_Byte *msgEnd);

static UA_StatusCode
generateNetworkMessage(UA_PubSubConnection *connection, UA_WriterGroup *wg,
                       UA_DataSetMessage *dsm, UA_UInt16 *writerIds, UA_Byte dsmCount,
                       UA_ExtensionObject *messageSettings,
                       UA_ExtensionObject *transportSettings,
                       UA_NetworkMessage *networkMessage);

UA_Boolean
UA_WriterGroup_canConnect(UA_WriterGroup *wg) {
    
    if(wg->sendChannel != 0)
        return false;

    if(wg->config.transportSettings.encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY)
        return false;

    return true;
}

UA_StatusCode
UA_WriterGroup_addPublishCallback(UA_Server *server, UA_WriterGroup *wg) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(wg->publishCallbackId != 0)
        return UA_STATUSCODE_GOOD;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(wg->config.pubsubManagerCallback.addCustomCallback) {
        
        retval = wg->config.pubsubManagerCallback.
            addCustomCallback(server, wg->head.identifier,
                              (UA_ServerCallback)UA_WriterGroup_publishCallback,
                              wg, wg->config.publishingInterval,
                              NULL, UA_TIMER_HANDLE_CYCLEMISS_WITH_CURRENTTIME,
                              &wg->publishCallbackId);
    } else {
        
        UA_EventLoop *el = UA_PubSubConnection_getEL(server, wg->linkedConnection);
        retval = el->addCyclicCallback(el, (UA_Callback)UA_WriterGroup_publishCallback,
                                       server, wg, wg->config.publishingInterval,
                                       NULL ,
                                       UA_TIMER_HANDLE_CYCLEMISS_WITH_CURRENTTIME,
                                       &wg->publishCallbackId);
    }

    return retval;
}

static void
UA_WriterGroup_removePublishCallback(UA_Server *server, UA_WriterGroup *wg) {
    if(wg->publishCallbackId == 0)
        return;
    if(wg->config.pubsubManagerCallback.removeCustomCallback) {
        wg->config.pubsubManagerCallback.
            removeCustomCallback(server, wg->head.identifier, wg->publishCallbackId);
    } else {
        UA_EventLoop *el = UA_PubSubConnection_getEL(server, wg->linkedConnection);
        el->removeCyclicCallback(el, wg->publishCallbackId);
    }
    wg->publishCallbackId = 0;
}

UA_StatusCode
UA_WriterGroup_create(UA_Server *server, const UA_NodeId connection,
                      const UA_WriterGroupConfig *writerGroupConfig,
                      UA_NodeId *writerGroupIdentifier) {
    
    UA_PubSubManager_freeIds(server);
    if(!writerGroupConfig)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    
    UA_PubSubConnection *currentConnectionContext =
        UA_PubSubConnection_findConnectionbyId(server, connection);
    if(!currentConnectionContext)
        return UA_STATUSCODE_BADNOTFOUND;

    if(currentConnectionContext->configurationFreezeCounter > 0) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_SERVER,
                       "Adding WriterGroup failed. PubSubConnection is frozen.");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    
    const UA_ExtensionObject *ms = &writerGroupConfig->messageSettings;
    if(ms->content.decoded.type) {
        if(writerGroupConfig->encodingMimeType == UA_PUBSUB_ENCODING_JSON &&
           (ms->encoding != UA_EXTENSIONOBJECT_DECODED ||
            ms->content.decoded.type != &UA_TYPES[UA_TYPES_JSONWRITERGROUPMESSAGEDATATYPE])) {
            return UA_STATUSCODE_BADTYPEMISMATCH;
        }

        if(writerGroupConfig->encodingMimeType == UA_PUBSUB_ENCODING_UADP &&
           (ms->encoding != UA_EXTENSIONOBJECT_DECODED ||
            ms->content.decoded.type != &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE])) {
            return UA_STATUSCODE_BADTYPEMISMATCH;
        }
    }

    
    UA_WriterGroup *newWriterGroup = (UA_WriterGroup*)UA_calloc(1, sizeof(UA_WriterGroup));
    if(!newWriterGroup)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    newWriterGroup->head.componentType = UA_PUBSUB_COMPONENT_WRITERGROUP;
    newWriterGroup->linkedConnection = currentConnectionContext;

    
    UA_WriterGroupConfig *newConfig = &newWriterGroup->config;
    UA_StatusCode res = UA_WriterGroupConfig_copy(writerGroupConfig, newConfig);
    if(res != UA_STATUSCODE_GOOD) {
        UA_free(newWriterGroup);
        return res;
    }

    
    if(!newConfig->messageSettings.content.decoded.type) {
        UA_UadpWriterGroupMessageDataType *wgm = UA_UadpWriterGroupMessageDataType_new();
        newConfig->messageSettings.content.decoded.data = wgm;
        newConfig->messageSettings.content.decoded.type =
            &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE];
        newConfig->messageSettings.encoding = UA_EXTENSIONOBJECT_DECODED;
    }

    
    LIST_INSERT_HEAD(&currentConnectionContext->writerGroups, newWriterGroup, listEntry);
    currentConnectionContext->writerGroupsSize++;

    
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    res = addWriterGroupRepresentation(server, newWriterGroup);
    if(res != UA_STATUSCODE_GOOD) {
        UA_WriterGroup_remove(server, newWriterGroup);
        return res;
    }
#else
    UA_PubSubManager_generateUniqueNodeId(&server->pubSubManager,
                                          &newWriterGroup->head.identifier);
#endif

    
    char tmpLogIdStr[128];
    mp_snprintf(tmpLogIdStr, 128, "%SWriterGroup %N\t| ",
                currentConnectionContext->head.logIdString,
                newWriterGroup->head.identifier);
    newWriterGroup->head.logIdString = UA_STRING_ALLOC(tmpLogIdStr);

    UA_LOG_INFO_PUBSUB(server->config.logging, newWriterGroup, "WriterGroup created");

    
    res = UA_WriterGroup_connect(server, newWriterGroup, true);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, newWriterGroup,
                            "Could not validate the connection parameters");
        UA_WriterGroup_remove(server, newWriterGroup);
        return res;
    }

#ifdef UA_ENABLE_PUBSUB_SKS
    if(writerGroupConfig->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       writerGroupConfig->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        if(!UA_String_isEmpty(&writerGroupConfig->securityGroupId) &&
           writerGroupConfig->securityPolicy) {
            
            newWriterGroup->keyStorage =
                UA_PubSubKeyStorage_findKeyStorage(server, writerGroupConfig->securityGroupId);

            if(!newWriterGroup->keyStorage) {
                
                newWriterGroup->keyStorage = (UA_PubSubKeyStorage *)
                    UA_calloc(1, sizeof(UA_PubSubKeyStorage));
                if(!newWriterGroup->keyStorage) {
                    UA_WriterGroup_remove(server, newWriterGroup);
                    return UA_STATUSCODE_BADOUTOFMEMORY;
                }
                res = UA_PubSubKeyStorage_init(server, newWriterGroup->keyStorage,
                                               &writerGroupConfig->securityGroupId,
                                               writerGroupConfig->securityPolicy, 0, 0);
                if(res != UA_STATUSCODE_GOOD) {
                    UA_WriterGroup_remove(server, newWriterGroup);
                    return res;
                }
            }

            
            newWriterGroup->keyStorage->referenceCount++;
        }
    }

#endif

    
    UA_PubSubConnection_setPubSubState(server, currentConnectionContext,
                                       currentConnectionContext->head.state);

    
    if(writerGroupIdentifier)
        UA_NodeId_copy(&newWriterGroup->head.identifier, writerGroupIdentifier);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_addWriterGroup(UA_Server *server, const UA_NodeId connection,
                         const UA_WriterGroupConfig *writerGroupConfig,
                         UA_NodeId *writerGroupIdentifier) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = UA_WriterGroup_create(server, connection, writerGroupConfig,
                                              writerGroupIdentifier);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_WriterGroup_remove(UA_Server *server, UA_WriterGroup *wg) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(wg->configurationFrozen) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "Deleting the WriterGroup failed. "
                              "WriterGroup is frozen.");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    UA_PubSubConnection *connection = wg->linkedConnection;
    UA_assert(connection);
    if(connection->configurationFreezeCounter > 0) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "Deleting the WriterGroup failed. "
                              "PubSubConnection is frozen.");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    wg->deleteFlag = true;
    UA_WriterGroup_setPubSubState(server, wg, UA_PUBSUBSTATE_DISABLED);

    UA_DataSetWriter *dsw, *dsw_tmp;
    LIST_FOREACH_SAFE(dsw, &wg->writers, listEntry, dsw_tmp) {
        UA_DataSetWriter_remove(server, dsw);
    }

    if(wg->config.securityPolicy && wg->securityPolicyContext) {
        wg->config.securityPolicy->deleteContext(wg->securityPolicyContext);
        wg->securityPolicyContext = NULL;
    }

#ifdef UA_ENABLE_PUBSUB_SKS
    if(wg->keyStorage) {
        UA_PubSubKeyStorage_detachKeyStorage(server, wg->keyStorage);
        wg->keyStorage = NULL;
    }
#endif

    if(wg->sendChannel == 0) {
        
        LIST_REMOVE(wg, listEntry);
        connection->writerGroupsSize--;
        wg->linkedConnection = NULL;

        
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
        deleteNode(server, wg->head.identifier, true);
#endif

        UA_LOG_INFO_PUBSUB(server->config.logging, wg, "WriterGroup deleted");

        UA_WriterGroupConfig_clear(&wg->config);
        UA_NetworkMessageOffsetBuffer_clear(&wg->bufferedMessage);
        UA_PubSubComponentHead_clear(&wg->head);
        UA_free(wg);
    }

    
    UA_PubSubConnection_setPubSubState(server, connection, connection->head.state);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_removeWriterGroup(UA_Server *server, const UA_NodeId writerGroup) {
    UA_LOCK(&server->serviceMutex);
    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroup);
    if(!wg) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    UA_StatusCode res = UA_WriterGroup_remove(server, wg);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_WriterGroup_freezeConfiguration(UA_Server *server, UA_WriterGroup *wg) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(wg->configurationFrozen)
        return UA_STATUSCODE_GOOD;

    
    UA_PubSubConnection *pubSubConnection =  wg->linkedConnection;
    pubSubConnection->configurationFreezeCounter++;

    
    wg->configurationFrozen = true;

    
    UA_DataSetWriter *dsw;
    LIST_FOREACH(dsw, &wg->writers, listEntry) {
        UA_DataSetWriter_freezeConfiguration(server, dsw);
    }

    
    if((wg->config.rtLevel & UA_PUBSUB_RT_FIXED_SIZE) == 0)
        return UA_STATUSCODE_GOOD;

    
    if(wg->config.encodingMimeType != UA_PUBSUB_ENCODING_UADP) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "PubSub-RT configuration fail: Non-RT capable encoding.");
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    //TODO Clarify: should we only allow = maxEncapsulatedDataSetMessageCount == 1 with RT?
    //TODO Clarify: Behaviour if the finale size is more than MTU

    
    size_t msgSize;
    UA_ByteString buf;
    const UA_Byte *bufEnd;
    UA_Byte *bufPos;
    UA_NetworkMessage networkMessage;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_STACKARRAY(UA_UInt16, dsWriterIds, wg->writersCount);
    UA_STACKARRAY(UA_DataSetMessage, dsmStore, wg->writersCount);

    
    size_t dsmCount = 0;
    LIST_FOREACH(dsw, &wg->writers, listEntry) {
        dsWriterIds[dsmCount] = dsw->config.dataSetWriterId;
        res = UA_DataSetWriter_prepareDataSet(server, dsw, &dsmStore[dsmCount]);
        if(res != UA_STATUSCODE_GOOD)
            goto cleanup_dsm;
        dsmCount++;
    }

    
    memset(&networkMessage, 0, sizeof(networkMessage));
    res = generateNetworkMessage(pubSubConnection, wg, dsmStore, dsWriterIds,
                                 (UA_Byte) dsmCount, &wg->config.messageSettings,
                                 &wg->config.transportSettings, &networkMessage);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup_dsm;

    memset(&wg->bufferedMessage, 0, sizeof(UA_NetworkMessageOffsetBuffer));
    msgSize = UA_NetworkMessage_calcSizeBinaryWithOffsetBuffer(&networkMessage,
                                                               &wg->bufferedMessage);

    if(wg->config.securityMode > UA_MESSAGESECURITYMODE_NONE) {
        UA_PubSubSecurityPolicy *sp = wg->config.securityPolicy;
        msgSize += sp->symmetricModule.cryptoModule.
                   signatureAlgorithm.getLocalSignatureSize(sp->policyContext);
    }

    
    res = UA_ByteString_allocBuffer(&buf, msgSize);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;
    wg->bufferedMessage.buffer = buf;

    
    bufEnd = &wg->bufferedMessage.buffer.data[wg->bufferedMessage.buffer.length];
    bufPos = wg->bufferedMessage.buffer.data;

    
    if(wg->config.securityMode > UA_MESSAGESECURITYMODE_NONE) {
        UA_Byte *payloadPosition;
        UA_NetworkMessage_encodeBinaryWithEncryptStart(&networkMessage, &bufPos, bufEnd,
                                                       &payloadPosition);
        wg->bufferedMessage.payloadPosition = payloadPosition;
        wg->bufferedMessage.nm = (UA_NetworkMessage *)UA_calloc(1,sizeof(UA_NetworkMessage));
        wg->bufferedMessage.nm->securityHeader = networkMessage.securityHeader;
        UA_ByteString_allocBuffer(&wg->bufferedMessage.encryptBuffer, msgSize);
    }

    if(wg->config.securityMode <= UA_MESSAGESECURITYMODE_NONE)
        UA_NetworkMessage_encodeBinaryWithEncryptStart(&networkMessage, &bufPos, bufEnd, NULL);

    if(wg->config.rtLevel & UA_PUBSUB_RT_DIRECT_VALUE_ACCESS) {
        size_t fieldPos = 0;
        LIST_FOREACH(dsw, &wg->writers, listEntry) {
            UA_PublishedDataSet *pds = dsw->connectedDataSet;
            if(!pds)
                continue;

            
            UA_DataSetField *dsf;
            TAILQ_FOREACH(dsf, &pds->fields, listEntry) {
                UA_NetworkMessageOffsetType contentType;
                
                do {
                    fieldPos++;
                    contentType = wg->bufferedMessage.offsets[fieldPos].contentType;
                } while(contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_DATAVALUE &&
                        contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_VARIANT &&
                        contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_RAW);
                UA_assert(fieldPos < wg->bufferedMessage.offsetsSize);

                if(!dsf->config.field.variable.rtValueSource.rtFieldSourceEnabled)
                    continue;

                
                UA_DataValue_clear(&wg->bufferedMessage.offsets[fieldPos].content.value);
                wg->bufferedMessage.offsets[fieldPos].content.externalValue =
                    dsf->config.field.variable.rtValueSource.staticValueSource;

                
                wg->bufferedMessage.offsets[fieldPos].contentType =
                    (UA_NetworkMessageOffsetType)(contentType + 1);
            }
        }
    }

 cleanup:
    UA_free(networkMessage.payload.dataSetPayload.sizes);

 cleanup_dsm:
    
    for(size_t i = 0; i < dsmCount; i++) {
        UA_DataSetMessage_clear(&dsmStore[i]);
    }
    return res;
}

UA_StatusCode
UA_Server_freezeWriterGroupConfiguration(UA_Server *server,
                                         const UA_NodeId writerGroup) {
    UA_LOCK(&server->serviceMutex);
    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroup);
    if(!wg) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    UA_StatusCode res = UA_WriterGroup_freezeConfiguration(server, wg);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_WriterGroup_unfreezeConfiguration(UA_Server *server, UA_WriterGroup *wg) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(!wg->configurationFrozen)
        return UA_STATUSCODE_GOOD;

    UA_PubSubConnection *pubSubConnection =  wg->linkedConnection;
    pubSubConnection->configurationFreezeCounter--;

    
    UA_DataSetWriter *dsw;
    LIST_FOREACH(dsw, &wg->writers, listEntry) {
        UA_DataSetWriter_unfreezeConfiguration(server, dsw);
    }

    UA_NetworkMessageOffsetBuffer_clear(&wg->bufferedMessage);
    wg->configurationFrozen = false;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_enableWriterGroup(UA_Server *server,
                            const UA_NodeId writerGroup)  {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = UA_WriterGroup_enableWriterGroup(server, writerGroup);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_WriterGroup_enableWriterGroup(UA_Server *server,
                                 const UA_NodeId writerGroup) {
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroup);
    if(wg)
        res = UA_WriterGroup_setPubSubState(server, wg, UA_PUBSUBSTATE_OPERATIONAL);
    return res;
}

UA_StatusCode
UA_Server_unfreezeWriterGroupConfiguration(UA_Server *server,
                                           const UA_NodeId writerGroup) {
    UA_LOCK(&server->serviceMutex);
    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroup);
    if(!wg) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    UA_StatusCode res = UA_WriterGroup_unfreezeConfiguration(server, wg);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

#ifdef UA_ENABLE_PUBSUB_SKS
UA_StatusCode
UA_Server_setWriterGroupActivateKey(UA_Server *server,
                                    const UA_NodeId writerGroup) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroup);
    if(wg) {

        if(wg->keyStorage && wg->keyStorage->currentItem) {
            res = UA_PubSubKeyStorage_activateKeyToChannelContext(
                server, wg->head.identifier, wg->config.securityGroupId);
            if(res != UA_STATUSCODE_GOOD) {
                UA_UNLOCK(&server->serviceMutex);
                return res;
            }
        }
    }
    UA_UNLOCK(&server->serviceMutex);
    return res;
}
#endif

UA_StatusCode
UA_Server_setWriterGroupDisabled(UA_Server *server,
                                 const UA_NodeId writerGroup) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroup);
    if(wg)
        res = UA_WriterGroup_setPubSubState(server, wg, UA_PUBSUBSTATE_DISABLED);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_WriterGroupConfig_copy(const UA_WriterGroupConfig *src,
                          UA_WriterGroupConfig *dst) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    memcpy(dst, src, sizeof(UA_WriterGroupConfig));
    res |= UA_String_copy(&src->name, &dst->name);
    res |= UA_ExtensionObject_copy(&src->transportSettings, &dst->transportSettings);
    res |= UA_ExtensionObject_copy(&src->messageSettings, &dst->messageSettings);
    res |= UA_KeyValueMap_copy(&src->groupProperties, &dst->groupProperties);
    res |= UA_String_copy(&src->securityGroupId, &dst->securityGroupId);
    if(res != UA_STATUSCODE_GOOD)
        UA_WriterGroupConfig_clear(dst);
    return res;
}

UA_StatusCode
UA_Server_getWriterGroupConfig(UA_Server *server, const UA_NodeId writerGroup,
                               UA_WriterGroupConfig *config) {
    if(!config)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_LOCK(&server->serviceMutex);
    UA_WriterGroup *currentWG = UA_WriterGroup_findWGbyId(server, writerGroup);
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    if(currentWG)
        res = UA_WriterGroupConfig_copy(&currentWG->config, config);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_WriterGroup_updateConfig(UA_Server *server, UA_WriterGroup *wg,
                            const UA_WriterGroupConfig *config) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(!config)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(wg->configurationFrozen) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "Modify WriterGroup failed. WriterGroup is frozen.");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    //The update functionality will be extended during the next PubSub batches.
    //Currently is only a change of the publishing interval possible.
    if(wg->config.maxEncapsulatedDataSetMessageCount != config->maxEncapsulatedDataSetMessageCount) {
        wg->config.maxEncapsulatedDataSetMessageCount = config->maxEncapsulatedDataSetMessageCount;
        if(wg->config.messageSettings.encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY) {
            UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                                  "MaxEncapsulatedDataSetMessag need enabled "
                                  "'PayloadHeader' within the message settings.");
        }
    }

    if(wg->config.publishingInterval != config->publishingInterval) {
        wg->config.publishingInterval = config->publishingInterval;
        if(wg->config.rtLevel == UA_PUBSUB_RT_NONE &&
           wg->head.state == UA_PUBSUBSTATE_OPERATIONAL) {
            UA_WriterGroup_removePublishCallback(server, wg);
            res = UA_WriterGroup_addPublishCallback(server, wg);
            if(res != UA_STATUSCODE_GOOD) {
                UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                                      "Modify WriterGroup failed. Adding publish callback failed"
                                      "with status code %s", UA_StatusCode_name(res));
                return res;
            }
        }
    }

    if(wg->config.priority != config->priority) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "Priority parameter is not yet "
                              "supported for WriterGroup updates");
    }

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_updateWriterGroupConfig(UA_Server *server, const UA_NodeId writerGroupIdentifier,
                                  const UA_WriterGroupConfig *config) {
    UA_LOCK(&server->serviceMutex);
    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroupIdentifier);
    if(!wg) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_StatusCode res = UA_WriterGroup_updateConfig(server, wg, config);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_Server_WriterGroup_getState(UA_Server *server, const UA_NodeId writerGroupIdentifier,
                               UA_PubSubState *state) {
    if((server == NULL) || (state == NULL))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_LOCK(&server->serviceMutex);
    UA_WriterGroup *currentWriterGroup =
        UA_WriterGroup_findWGbyId(server, writerGroupIdentifier);
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(currentWriterGroup) {
        *state = currentWriterGroup->head.state;
    } else {
        res = UA_STATUSCODE_BADNOTFOUND;
    }
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_Server_WriterGroup_publish(UA_Server *server, const UA_NodeId writerGroupIdentifier) {
    UA_LOCK(&server->serviceMutex);

    //search WriterGroup ToDo create lookup table for more efficiency
    UA_WriterGroup *wg;
    wg = UA_WriterGroup_findWGbyId(server, writerGroupIdentifier);
    if(!wg) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    UA_UNLOCK(&server->serviceMutex);
    UA_WriterGroup_publishCallback(server, wg);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_WriterGroup_lastPublishTimestamp(UA_Server *server, const UA_NodeId writerGroupId,
                                    UA_DateTime *timestamp) {
    UA_LOCK(&server->serviceMutex);
    //search WriterGroup ToDo create lookup table for more efficiency
    UA_WriterGroup *wg;
    wg = UA_WriterGroup_findWGbyId(server, writerGroupId);
    if(!wg) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    *timestamp = wg->lastPublishTimeStamp;
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_BADNOTFOUND;
}

UA_WriterGroup *
UA_WriterGroup_findWGbyId(UA_Server *server, UA_NodeId identifier) {
    UA_PubSubConnection *tmpConnection;
    TAILQ_FOREACH(tmpConnection, &server->pubSubManager.connections, listEntry) {
        UA_WriterGroup *tmpWriterGroup;
        LIST_FOREACH(tmpWriterGroup, &tmpConnection->writerGroups, listEntry) {
            if(UA_NodeId_equal(&identifier, &tmpWriterGroup->head.identifier))
                return tmpWriterGroup;
        }
    }
    return NULL;
}

UA_StatusCode
setWriterGroupEncryptionKeys(UA_Server *server, const UA_NodeId writerGroup,
                             UA_UInt32 securityTokenId,
                             const UA_ByteString signingKey,
                             const UA_ByteString encryptingKey,
                             const UA_ByteString keyNonce) {
    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroup);
    UA_StatusCode res = UA_STATUSCODE_BAD;

    if(!wg)
        return UA_STATUSCODE_BADNOTFOUND;
    if(wg->config.encodingMimeType == UA_PUBSUB_ENCODING_JSON) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "JSON encoding is enabled. The message security is only defined for the UADP message mapping.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    if(!wg->config.securityPolicy) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "No SecurityPolicy configured for the WriterGroup");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(securityTokenId != wg->securityTokenId) {
        wg->securityTokenId = securityTokenId;
        wg->nonceSequenceNumber = 1;
    }

    if(!wg->securityPolicyContext) {
        
        res = wg->config.securityPolicy->
            newContext(wg->config.securityPolicy->policyContext,
                       &signingKey, &encryptingKey, &keyNonce,
                       &wg->securityPolicyContext);
    } else {
        
         res = wg->config.securityPolicy->
            setSecurityKeys(wg->securityPolicyContext, &signingKey, &encryptingKey, &keyNonce);
    }

    if(res != UA_STATUSCODE_GOOD)
        return res;
    return UA_WriterGroup_setPubSubState(server, wg, wg->head.state);
}

UA_StatusCode
UA_Server_setWriterGroupEncryptionKeys(UA_Server *server, const UA_NodeId writerGroup,
                                       UA_UInt32 securityTokenId,
                                       const UA_ByteString signingKey,
                                       const UA_ByteString encryptingKey,
                                       const UA_ByteString keyNonce) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = setWriterGroupEncryptionKeys(server, writerGroup, securityTokenId,
                                                     signingKey, encryptingKey, keyNonce);

    UA_UNLOCK(&server->serviceMutex);
    return res;
}

void
UA_WriterGroupConfig_clear(UA_WriterGroupConfig *writerGroupConfig) {
    UA_String_clear(&writerGroupConfig->name);
    UA_ExtensionObject_clear(&writerGroupConfig->transportSettings);
    UA_ExtensionObject_clear(&writerGroupConfig->messageSettings);
    UA_KeyValueMap_clear(&writerGroupConfig->groupProperties);
    UA_String_clear(&writerGroupConfig->securityGroupId);
    memset(writerGroupConfig, 0, sizeof(UA_WriterGroupConfig));
}

UA_StatusCode
UA_WriterGroup_setPubSubState(UA_Server *server, UA_WriterGroup *wg,
                              UA_PubSubState targetState) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(wg->deleteFlag && targetState != UA_PUBSUBSTATE_DISABLED) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "The WriterGroup is being deleted. Can only be disabled.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode ret = UA_STATUSCODE_GOOD;
    UA_PubSubConnection *connection = wg->linkedConnection;
    UA_PubSubState oldState = wg->head.state;
    wg->head.state = targetState;

    switch(wg->head.state) {
        
    default:
        wg->head.state = UA_PUBSUBSTATE_ERROR;
        ret = UA_STATUSCODE_BADINTERNALERROR;
        
    case UA_PUBSUBSTATE_DISABLED:
    case UA_PUBSUBSTATE_ERROR:
        UA_WriterGroup_disconnect(wg);
        UA_WriterGroup_removePublishCallback(server, wg);
        break;

        
    case UA_PUBSUBSTATE_PAUSED:
    case UA_PUBSUBSTATE_PREOPERATIONAL:
    case UA_PUBSUBSTATE_OPERATIONAL:
        if(connection->head.state != UA_PUBSUBSTATE_OPERATIONAL) {
            wg->head.state = UA_PUBSUBSTATE_PAUSED;
            UA_WriterGroup_disconnect(wg);
            UA_WriterGroup_removePublishCallback(server, wg);
            break;
        }

        ret = UA_WriterGroup_connect(server, wg, false);
        if(ret != UA_STATUSCODE_GOOD)
            break;

        wg->head.state = UA_PUBSUBSTATE_OPERATIONAL;

        
        if(UA_WriterGroup_canConnect(wg))
            wg->head.state = UA_PUBSUBSTATE_PREOPERATIONAL;

        
        if(wg->config.securityMode > UA_MESSAGESECURITYMODE_NONE &&
           wg->securityTokenId == 0)
            wg->head.state = UA_PUBSUBSTATE_PREOPERATIONAL;

        
        if(wg->head.state == UA_PUBSUBSTATE_OPERATIONAL)
            ret = UA_WriterGroup_addPublishCallback(server, wg);
        break;
    }

    
    if(ret != UA_STATUSCODE_GOOD) {
        wg->head.state = UA_PUBSUBSTATE_ERROR;
        UA_WriterGroup_disconnect(wg);
        UA_WriterGroup_removePublishCallback(server, wg);
    }

    if(wg->head.state != oldState) {
        
        UA_ServerConfig *pConfig = &server->config;
        UA_LOG_INFO_PUBSUB(pConfig->logging, wg, "State change: %s -> %s",
                           UA_PubSubState_name(oldState),
                           UA_PubSubState_name(wg->head.state));
        if(pConfig->pubSubConfig.stateChangeCallback != 0) {
            UA_UNLOCK(&server->serviceMutex);
            pConfig->pubSubConfig.
                stateChangeCallback(server, &wg->head.identifier, wg->head.state, ret);
            UA_LOCK(&server->serviceMutex);
        }
    }

    UA_DataSetWriter *writer;
    LIST_FOREACH(writer, &wg->writers, listEntry) {
        UA_DataSetWriter_setPubSubState(server, writer, writer->head.state);
    }

    return ret;
}

static UA_StatusCode
encryptAndSign(UA_WriterGroup *wg, const UA_NetworkMessage *nm,
               UA_Byte *signStart, UA_Byte *encryptStart,
               UA_Byte *msgEnd) {
    UA_StatusCode rv;
    void *channelContext = wg->securityPolicyContext;

    if(nm->securityHeader.networkMessageEncrypted) {
        
        const UA_ByteString nonce = {
            (size_t)nm->securityHeader.messageNonceSize,
            (UA_Byte*)(uintptr_t)nm->securityHeader.messageNonce
        };
        rv = wg->config.securityPolicy->setMessageNonce(channelContext, &nonce);
        UA_CHECK_STATUS(rv, return rv);

        
        UA_ByteString toBeEncrypted =
            {(uintptr_t)msgEnd - (uintptr_t)encryptStart, encryptStart};
        rv = wg->config.securityPolicy->symmetricModule.cryptoModule.encryptionAlgorithm.
            encrypt(channelContext, &toBeEncrypted);
        UA_CHECK_STATUS(rv, return rv);
    }

    if(nm->securityHeader.networkMessageSigned) {
        UA_ByteString toBeSigned = {(uintptr_t)msgEnd - (uintptr_t)signStart,
                                    signStart};

        size_t sigSize = wg->config.securityPolicy->symmetricModule.cryptoModule.
                     signatureAlgorithm.getLocalSignatureSize(channelContext);
        UA_ByteString signature = {sigSize, msgEnd};

        rv = wg->config.securityPolicy->symmetricModule.cryptoModule.
            signatureAlgorithm.sign(channelContext, &toBeSigned, &signature);
        UA_CHECK_STATUS(rv, return rv);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
encodeNetworkMessage(UA_WriterGroup *wg, UA_NetworkMessage *nm,
                     UA_ByteString *buf) {
    UA_Byte *bufPos = buf->data;
    UA_Byte *bufEnd = &buf->data[buf->length];

    UA_Byte *networkMessageStart = bufPos;
    UA_StatusCode rv = UA_NetworkMessage_encodeHeaders(nm, &bufPos, bufEnd);
    UA_CHECK_STATUS(rv, return rv);

    UA_Byte *payloadStart = bufPos;
    rv = UA_NetworkMessage_encodePayload(nm, &bufPos, bufEnd);
    UA_CHECK_STATUS(rv, return rv);

    rv = UA_NetworkMessage_encodeFooters(nm, &bufPos, bufEnd);
    UA_CHECK_STATUS(rv, return rv);

    
    UA_Byte *footerEnd = bufPos;
    return encryptAndSign(wg, nm, networkMessageStart, payloadStart, footerEnd);
}

static void
sendNetworkMessageBuffer(UA_Server *server, UA_WriterGroup *wg, 
                         UA_PubSubConnection *connection, uintptr_t connectionId,
                         UA_ByteString *buffer) {
    UA_StatusCode res = connection->cm->
        sendWithConnection(connection->cm, connectionId,
                           &UA_KEYVALUEMAP_NULL, buffer);

    
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, wg,
                            "Sending NetworkMessage failed");
        UA_WriterGroup_setPubSubState(server, wg, UA_PUBSUBSTATE_ERROR);
        UA_PubSubConnection_setPubSubState(server, connection, UA_PUBSUBSTATE_ERROR);
        return;
    }

    
    wg->sequenceNumber++;
}

#ifdef UA_ENABLE_JSON_ENCODING
static UA_StatusCode
sendNetworkMessageJson(UA_Server *server, UA_PubSubConnection *connection, UA_WriterGroup *wg,
                       UA_DataSetMessage *dsm, UA_UInt16 *writerIds, UA_Byte dsmCount) {
    
    UA_NetworkMessage nm;
    memset(&nm, 0, sizeof(UA_NetworkMessage));
    nm.version = 1;
    nm.networkMessageType = UA_NETWORKMESSAGE_DATASET;
    nm.payloadHeaderEnabled = true;
    nm.payloadHeader.dataSetPayloadHeader.count = dsmCount;
    nm.payloadHeader.dataSetPayloadHeader.dataSetWriterIds = writerIds;
    nm.payload.dataSetPayload.dataSetMessages = dsm;
    nm.publisherIdEnabled = true;
    nm.publisherId = connection->config.publisherId;

    
    size_t msgSize = UA_NetworkMessage_calcSizeJsonInternal(&nm, NULL, 0, NULL, 0, true);

    UA_ConnectionManager *cm = connection->cm;
    if(!cm)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    uintptr_t sendChannel = connection->sendChannel;
    if(wg->sendChannel != 0)
        sendChannel = wg->sendChannel;
    if(sendChannel == 0) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, wg,
                            "Cannot send, no open connection");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    UA_ByteString buf;
    UA_StatusCode res = cm->allocNetworkBuffer(cm, sendChannel, &buf, msgSize);
    UA_CHECK_STATUS(res, return res);

    
    UA_Byte *bufPos = buf.data;
    const UA_Byte *bufEnd = &buf.data[msgSize];
    res = UA_NetworkMessage_encodeJsonInternal(&nm, &bufPos, &bufEnd, NULL, 0, NULL, 0, true);
    if(res != UA_STATUSCODE_GOOD) {
        cm->freeNetworkBuffer(cm, sendChannel, &buf);
        return res;
    }
    UA_assert(bufPos == bufEnd);

    
    sendNetworkMessageBuffer(server, wg, connection, sendChannel, &buf);
    return UA_STATUSCODE_GOOD;
}
#endif

static UA_StatusCode
generateNetworkMessage(UA_PubSubConnection *connection, UA_WriterGroup *wg,
                       UA_DataSetMessage *dsm, UA_UInt16 *writerIds, UA_Byte dsmCount,
                       UA_ExtensionObject *messageSettings,
                       UA_ExtensionObject *transportSettings,
                       UA_NetworkMessage *networkMessage) {
    if(messageSettings->content.decoded.type !=
       &UA_TYPES[UA_TYPES_UADPWRITERGROUPMESSAGEDATATYPE])
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_UadpWriterGroupMessageDataType *wgm = (UA_UadpWriterGroupMessageDataType*)
            messageSettings->content.decoded.data;

    networkMessage->publisherIdEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_PUBLISHERID) != 0;
    networkMessage->groupHeaderEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_GROUPHEADER) != 0;
    networkMessage->groupHeader.writerGroupIdEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_WRITERGROUPID) != 0;
    networkMessage->groupHeader.groupVersionEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_GROUPVERSION) != 0;
    networkMessage->groupHeader.networkMessageNumberEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_NETWORKMESSAGENUMBER) != 0;
    networkMessage->groupHeader.sequenceNumberEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_SEQUENCENUMBER) != 0;
    networkMessage->payloadHeaderEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_PAYLOADHEADER) != 0;
    networkMessage->timestampEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_TIMESTAMP) != 0;
    networkMessage->picosecondsEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_PICOSECONDS) != 0;
    networkMessage->dataSetClassIdEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_DATASETCLASSID) != 0;
    networkMessage->promotedFieldsEnabled =
        ((u64)wgm->networkMessageContentMask &
         (u64)UA_UADPNETWORKMESSAGECONTENTMASK_PROMOTEDFIELDS) != 0;

    
    if(wg->config.securityMode > UA_MESSAGESECURITYMODE_NONE) {
        networkMessage->securityEnabled = true;
        networkMessage->securityHeader.networkMessageSigned = true;
        if(wg->config.securityMode >= UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
            networkMessage->securityHeader.networkMessageEncrypted = true;
        networkMessage->securityHeader.securityTokenId = wg->securityTokenId;

        UA_ByteString nonce = {4, networkMessage->securityHeader.messageNonce};
        UA_StatusCode rv = wg->config.securityPolicy->symmetricModule.
            generateNonce(wg->config.securityPolicy->policyContext, &nonce);
        if(rv != UA_STATUSCODE_GOOD)
            return rv;
        UA_Byte *pos = &networkMessage->securityHeader.messageNonce[4];
        const UA_Byte *end = &networkMessage->securityHeader.messageNonce[8];
        UA_UInt32_encodeBinary(&wg->nonceSequenceNumber, &pos, end);
        networkMessage->securityHeader.messageNonceSize = 8;
    }

    networkMessage->version = 1;
    networkMessage->networkMessageType = UA_NETWORKMESSAGE_DATASET;
    networkMessage->publisherId = connection->config.publisherId;

    if(networkMessage->groupHeader.sequenceNumberEnabled)
        networkMessage->groupHeader.sequenceNumber = wg->sequenceNumber;

    if(networkMessage->groupHeader.groupVersionEnabled)
        networkMessage->groupHeader.groupVersion = wgm->groupVersion;

    
    UA_UInt16 *dsmLengths = (UA_UInt16 *) UA_calloc(dsmCount, sizeof(UA_UInt16));
    if(!dsmLengths)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    for(UA_Byte i = 0; i < dsmCount; i++)
        dsmLengths[i] = (UA_UInt16) UA_DataSetMessage_calcSizeBinary(&dsm[i], NULL, 0);

    networkMessage->payloadHeader.dataSetPayloadHeader.count = dsmCount;
    networkMessage->payloadHeader.dataSetPayloadHeader.dataSetWriterIds = writerIds;
    networkMessage->groupHeader.writerGroupId = wg->config.writerGroupId;
    
    networkMessage->groupHeader.networkMessageNumber = 1;
    networkMessage->payload.dataSetPayload.sizes = dsmLengths;
    networkMessage->payload.dataSetPayload.dataSetMessages = dsm;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sendNetworkMessageBinary(UA_Server *server, UA_PubSubConnection *connection, UA_WriterGroup *wg,
                         UA_DataSetMessage *dsm, UA_UInt16 *writerIds, UA_Byte dsmCount) {
    UA_NetworkMessage nm;
    memset(&nm, 0, sizeof(UA_NetworkMessage));

    
    UA_StatusCode rv =
        generateNetworkMessage(connection, wg, dsm, writerIds, dsmCount,
                               &wg->config.messageSettings,
                               &wg->config.transportSettings, &nm);
    UA_CHECK_STATUS(rv, return rv);

    size_t msgSize = UA_NetworkMessage_calcSizeBinary(&nm);
    if(wg->config.securityMode > UA_MESSAGESECURITYMODE_NONE) {
        UA_PubSubSecurityPolicy *sp = wg->config.securityPolicy;
        msgSize += sp->symmetricModule.cryptoModule.
            signatureAlgorithm.getLocalSignatureSize(sp->policyContext);
    }

    UA_ConnectionManager *cm = connection->cm;
    if(!cm)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    uintptr_t sendChannel = connection->sendChannel;
    if(wg->sendChannel != 0)
        sendChannel = wg->sendChannel;
    if(sendChannel == 0) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, wg,
                            "Cannot send, no open connection");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    UA_ByteString buf = UA_BYTESTRING_NULL;
    rv = cm->allocNetworkBuffer(cm, sendChannel, &buf, msgSize);
    UA_CHECK_STATUS(rv, return rv);

    
    rv = encodeNetworkMessage(wg, &nm, &buf);
    if(rv != UA_STATUSCODE_GOOD) {
        cm->freeNetworkBuffer(cm, sendChannel, &buf);
        UA_free(nm.payload.dataSetPayload.sizes);
        return rv;
    }

    
    sendNetworkMessageBuffer(server, wg, connection, sendChannel, &buf);

    UA_free(nm.payload.dataSetPayload.sizes);
    return UA_STATUSCODE_GOOD;
}

static void
sampleOffsetPublishingValues(UA_Server *server, UA_WriterGroup *wg) {
    UA_LOCK(&server->serviceMutex);

    size_t fieldPos = 0;
    UA_DataSetWriter *dsw;
    LIST_FOREACH(dsw, &wg->writers, listEntry) {
        UA_PublishedDataSet *pds = dsw->connectedDataSet;
        if(!pds)
            continue;

        
        UA_DataSetField *dsf;
        TAILQ_FOREACH(dsf, &pds->fields, listEntry) {
            
            UA_NetworkMessageOffsetType contentType;
            do {
                fieldPos++;
                contentType = wg->bufferedMessage.offsets[fieldPos].contentType;
            } while(contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_DATAVALUE &&
                    contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_DATAVALUE_EXTERNAL &&
                    contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_VARIANT &&
                    contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_VARIANT_EXTERNAL &&
                    contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_RAW &&
                    contentType != UA_PUBSUB_OFFSETTYPE_PAYLOAD_RAW_EXTERNAL);

            if(contentType == UA_PUBSUB_OFFSETTYPE_PAYLOAD_DATAVALUE_EXTERNAL ||
               contentType == UA_PUBSUB_OFFSETTYPE_PAYLOAD_VARIANT_EXTERNAL ||
               contentType == UA_PUBSUB_OFFSETTYPE_PAYLOAD_RAW_EXTERNAL)
                continue;

            
            UA_DataValue *dfv = &wg->bufferedMessage.offsets[fieldPos].content.value;
            UA_DataValue_clear(dfv);
            UA_PubSubDataSetField_sampleValue(server, dsf, dfv);
        }
    }

    UA_UNLOCK(&server->serviceMutex);
}

static void
publishWithOffsets(UA_Server *server, UA_WriterGroup *wg,
                   UA_PubSubConnection *connection) {
    UA_assert(wg->configurationFrozen);

    if((wg->config.rtLevel & UA_PUBSUB_RT_DIRECT_VALUE_ACCESS) == 0)
        sampleOffsetPublishingValues(server, wg);

    UA_StatusCode res =
        UA_NetworkMessage_updateBufferedMessage(&wg->bufferedMessage);

    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_DEBUG_PUBSUB(server->config.logging, wg,
                            "PubSub sending. Unknown field type.");
        return;
    }

    UA_ByteString *buf = &wg->bufferedMessage.buffer;

    
    if(wg->config.securityMode > UA_MESSAGESECURITYMODE_NONE) {
        size_t sigSize = wg->config.securityPolicy->symmetricModule.cryptoModule.
            signatureAlgorithm.getLocalSignatureSize(wg->securityPolicyContext);

        UA_Byte payloadOffset = (UA_Byte)(wg->bufferedMessage.payloadPosition -
                                          wg->bufferedMessage.buffer.data);
        memcpy(wg->bufferedMessage.encryptBuffer.data,
               wg->bufferedMessage.buffer.data,
               wg->bufferedMessage.buffer.length);
        res = encryptAndSign(wg, wg->bufferedMessage.nm,
                             wg->bufferedMessage.encryptBuffer.data,
                             wg->bufferedMessage.encryptBuffer.data + payloadOffset,
                             wg->bufferedMessage.encryptBuffer.data +
                                 wg->bufferedMessage.encryptBuffer.length - sigSize);

        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR_PUBSUB(server->config.logging, wg,
                                "PubSub Encryption failed");
            return;
        }

        buf = &wg->bufferedMessage.encryptBuffer;
    }

    UA_ConnectionManager *cm = connection->cm;
    if(!cm)
        return;

    
    uintptr_t sendChannel = connection->sendChannel;
    if(wg->sendChannel != 0)
        sendChannel = wg->sendChannel;
    if(sendChannel == 0) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, wg,
                            "Cannot send, no open connection");
        return;
    }

    
    UA_ByteString outBuf;
    res = cm->allocNetworkBuffer(cm, sendChannel, &outBuf, buf->length);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, wg,
                            "PubSub message memory allocation failed");
        return;
    }
    memcpy(outBuf.data, buf->data, buf->length);
    sendNetworkMessageBuffer(server, wg, connection, sendChannel, &outBuf);
}

static void
sendNetworkMessage(UA_Server *server, UA_WriterGroup *wg, UA_PubSubConnection *connection,
                   UA_DataSetMessage *dsm, UA_UInt16 *writerIds, UA_Byte dsmCount) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    switch(wg->config.encodingMimeType) {
    case UA_PUBSUB_ENCODING_UADP:
        res = sendNetworkMessageBinary(server, connection, wg, dsm, writerIds, dsmCount);
        break;
#ifdef UA_ENABLE_JSON_ENCODING
    case UA_PUBSUB_ENCODING_JSON:
        res = sendNetworkMessageJson(server, connection, wg, dsm, writerIds, dsmCount);
        break;
#endif
    default:
        res = UA_STATUSCODE_BADNOTSUPPORTED;
        break;
    }

    
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, wg,
                            "PubSub Publish: Could not send a NetworkMessage "
                            "with status code %s", UA_StatusCode_name(res));
        UA_WriterGroup_setPubSubState(server, wg, UA_PUBSUBSTATE_ERROR);
    }
}

void
UA_WriterGroup_publishCallback(UA_Server *server, UA_WriterGroup *wg) {
    UA_assert(wg != NULL);
    UA_assert(server != NULL);

    UA_LOG_DEBUG_PUBSUB(server->config.logging, wg, "Publish Callback");

    
    UA_PubSubConnection *connection = wg->linkedConnection;
    if(!connection) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, wg,
                            "Publish failed. PubSubConnection invalid");
        UA_LOCK(&server->serviceMutex);
        UA_WriterGroup_setPubSubState(server, wg, UA_PUBSUBSTATE_ERROR);
        UA_UNLOCK(&server->serviceMutex);
        return;
    }

    
    if(wg->config.rtLevel & UA_PUBSUB_RT_FIXED_SIZE) {
        publishWithOffsets(server, wg, connection);
        return;
    }

    UA_LOCK(&server->serviceMutex);

    
    if(wg->writersCount == 0) {
        UA_UNLOCK(&server->serviceMutex);
        return;
    }

    
    UA_Byte maxDSM = (UA_Byte)wg->config.maxEncapsulatedDataSetMessageCount;
    if(wg->config.maxEncapsulatedDataSetMessageCount > UA_BYTE_MAX)
        maxDSM = UA_BYTE_MAX;
    if(maxDSM == 0)
        maxDSM = 1; 

    size_t dsmCount = 0;
    UA_STACKARRAY(UA_UInt16, dsWriterIds, wg->writersCount);
    UA_STACKARRAY(UA_DataSetMessage, dsmStore, wg->writersCount);

    UA_DataSetWriter *dsw;
    UA_EventLoop *el = UA_PubSubConnection_getEL(server, wg->linkedConnection);
    LIST_FOREACH(dsw, &wg->writers, listEntry) {
        if(dsw->head.state != UA_PUBSUBSTATE_OPERATIONAL)
            continue;

        
        UA_PublishedDataSet *pds = dsw->connectedDataSet;

        
        dsWriterIds[dsmCount] = dsw->config.dataSetWriterId;
        UA_StatusCode res =
            UA_DataSetWriter_generateDataSetMessage(server, &dsmStore[dsmCount], dsw);
        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR_PUBSUB(server->config.logging, dsw,
                                "PubSub Publish: DataSetMessage creation failed");
            UA_DataSetWriter_setPubSubState(server, dsw, UA_PUBSUBSTATE_ERROR);
            continue;
        }

        
        if(pds && pds->promotedFieldsCount > 0) {
            wg->lastPublishTimeStamp = el->dateTime_nowMonotonic(el);
            sendNetworkMessage(server, wg, connection, &dsmStore[dsmCount],
                               &dsWriterIds[dsmCount], 1);

            
            if(wg->config.rtLevel & UA_PUBSUB_RT_DIRECT_VALUE_ACCESS &&
               dsmStore[dsmCount].header.dataSetMessageType == UA_DATASETMESSAGE_DATAKEYFRAME) {
                for(size_t i = 0; i < dsmStore[dsmCount].data.keyFrameData.fieldCount; ++i) {
                    dsmStore[dsmCount].data.keyFrameData.dataSetFields[i].value.data = NULL;
                }
            }
            UA_DataSetMessage_clear(&dsmStore[dsmCount]);

            continue; 
        }

        dsmCount++;
    }

    
    UA_Byte nmDsmCount = 0;
    for(size_t i = 0; i < dsmCount; i += nmDsmCount) {
        
        nmDsmCount = (i + maxDSM > dsmCount) ? (UA_Byte)(dsmCount - i) : maxDSM;
        wg->lastPublishTimeStamp = el->dateTime_nowMonotonic(el);
        
        sendNetworkMessage(server, wg, connection, &dsmStore[i],
                           &dsWriterIds[i], nmDsmCount);
    }

    
    for(size_t i = 0; i < dsmCount; i++) {
        if(wg->config.rtLevel & UA_PUBSUB_RT_DIRECT_VALUE_ACCESS &&
           dsmStore[i].header.dataSetMessageType == UA_DATASETMESSAGE_DATAKEYFRAME) {
            for(size_t j = 0; j < dsmStore[i].data.keyFrameData.fieldCount; ++j) {
                dsmStore[i].data.keyFrameData.dataSetFields[j].value.data = NULL;
            }
        }
        UA_DataSetMessage_clear(&dsmStore[i]);
    }

    UA_UNLOCK(&server->serviceMutex);
}

#endif 
