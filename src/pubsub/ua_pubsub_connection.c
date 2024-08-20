
#include "ua_pubsub.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
#include "ua_pubsub_ns0.h"
#endif

#ifdef UA_ENABLE_PUBSUB 

UA_StatusCode
UA_PubSubConnection_decodeNetworkMessage(UA_PubSubConnection *connection,
                                         UA_Server *server, UA_ByteString buffer,
                                         UA_NetworkMessage *nm) {
#ifdef UA_DEBUG_DUMP_PKGS
    UA_dump_hex_pkg(buffer->data, buffer->length);
#endif

    
    Ctx ctx;
    ctx.pos = buffer.data;
    ctx.end = buffer.data + buffer.length;
    ctx.depth = 0;
    memset(&ctx.opts, 0, sizeof(UA_DecodeBinaryOptions));
    ctx.opts.customTypes = server->config.customDataTypes;

    
    UA_StatusCode rv = UA_NetworkMessage_decodeHeaders(&ctx, nm);
    if(rv != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, connection,
                              "PubSub receive. decoding headers failed");
        UA_NetworkMessage_clear(nm);
        return rv;
    }

    UA_Boolean processed = false;
    UA_ReaderGroup *readerGroup;
    UA_DataSetReader *reader;

    LIST_FOREACH(readerGroup, &connection->readerGroups, listEntry) {
        LIST_FOREACH(reader, &readerGroup->readers, listEntry) {
            UA_StatusCode retval =
                UA_DataSetReader_checkIdentifier(server, nm, reader, readerGroup->config);
            if(retval != UA_STATUSCODE_GOOD)
                continue;
            processed = true;
            rv = verifyAndDecryptNetworkMessage(server->config.logging, buffer, &ctx, nm, readerGroup);
            if(rv != UA_STATUSCODE_GOOD) {
                UA_LOG_WARNING_PUBSUB(server->config.logging, connection,
                                      "Subscribe failed, verify and decrypt "
                                      "network message failed.");
                UA_NetworkMessage_clear(nm);
                return rv;
            }

            
            goto loops_exit;
        }
    }

loops_exit:
    if(!processed) {
        UA_LOG_INFO_PUBSUB(server->config.logging, connection,
                           "Dataset reader not found. Check PublisherId, "
                           "WriterGroupId and DatasetWriterId");
    }

    rv = UA_NetworkMessage_decodePayload(&ctx, nm);
    if(rv != UA_STATUSCODE_GOOD) {
        UA_NetworkMessage_clear(nm);
        return rv;
    }

    rv = UA_NetworkMessage_decodeFooters(&ctx, nm);
    if(rv != UA_STATUSCODE_GOOD) {
        UA_NetworkMessage_clear(nm);
        return rv;
    }

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_PubSubConnectionConfig_copy(const UA_PubSubConnectionConfig *src,
                               UA_PubSubConnectionConfig *dst) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    memcpy(dst, src, sizeof(UA_PubSubConnectionConfig));
    res |= UA_PublisherId_copy(&src->publisherId, &dst->publisherId);
    res |= UA_String_copy(&src->name, &dst->name);
    res |= UA_Variant_copy(&src->address, &dst->address);
    res |= UA_String_copy(&src->transportProfileUri, &dst->transportProfileUri);
    res |= UA_Variant_copy(&src->connectionTransportSettings,
                           &dst->connectionTransportSettings);
    res |= UA_KeyValueMap_copy(&src->connectionProperties,
                               &dst->connectionProperties);
    if(res != UA_STATUSCODE_GOOD)
        UA_PubSubConnectionConfig_clear(dst);
    return res;
}

UA_StatusCode
UA_Server_getPubSubConnectionConfig(UA_Server *server, const UA_NodeId connection,
                                    UA_PubSubConnectionConfig *config) {
    if(!config)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_LOCK(&server->serviceMutex);
    UA_PubSubConnection *currentPubSubConnection =
        UA_PubSubConnection_findConnectionbyId(server, connection);
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    if(currentPubSubConnection)
        res = UA_PubSubConnectionConfig_copy(&currentPubSubConnection->config, config);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_PubSubConnection *
UA_PubSubConnection_findConnectionbyId(UA_Server *server, UA_NodeId connectionIdentifier) {
    UA_PubSubConnection *pubSubConnection;
    TAILQ_FOREACH(pubSubConnection, &server->pubSubManager.connections, listEntry){
        if(UA_NodeId_equal(&connectionIdentifier, &pubSubConnection->head.identifier))
            break;
    }
    return pubSubConnection;
}

void
UA_PubSubConnectionConfig_clear(UA_PubSubConnectionConfig *connectionConfig) {
    UA_PublisherId_clear(&connectionConfig->publisherId);
    UA_String_clear(&connectionConfig->name);
    UA_String_clear(&connectionConfig->transportProfileUri);
    UA_Variant_clear(&connectionConfig->connectionTransportSettings);
    UA_Variant_clear(&connectionConfig->address);
    UA_KeyValueMap_clear(&connectionConfig->connectionProperties);
}

UA_StatusCode
UA_PubSubConnection_create(UA_Server *server, const UA_PubSubConnectionConfig *cc,
                           UA_NodeId *cId) {
    if(!server || !cc)
        return UA_STATUSCODE_BADINTERNALERROR;

    
    UA_PubSubConnection *c = (UA_PubSubConnection*)
        UA_calloc(1, sizeof(UA_PubSubConnection));
    if(!c)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    c->head.componentType = UA_PUBSUB_COMPONENT_CONNECTION;

    
    UA_StatusCode ret = UA_PubSubConnectionConfig_copy(cc, &c->config);
    UA_CHECK_STATUS(ret, UA_free(c); return ret);

    
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    
    addPubSubConnectionRepresentation(server, c);
#else
    
    UA_PubSubManager_generateUniqueNodeId(&server->pubSubManager,
                                          &c->head.identifier);
#endif

    
    UA_PubSubManager *pubSubManager = &server->pubSubManager;
    TAILQ_INSERT_HEAD(&pubSubManager->connections, c, listEntry);
    pubSubManager->connectionsSize++;

    
    char tmpLogIdStr[128];
    mp_snprintf(tmpLogIdStr, 128, "PubSubConnection %N\t| ", c->head.identifier);
    c->head.logIdString = UA_STRING_ALLOC(tmpLogIdStr);

    UA_LOG_INFO_PUBSUB(server->config.logging, c, "Connection created");

    
    ret = UA_PubSubConnection_connect(server, c, true);
    if(ret != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_PUBSUB(server->config.logging, c,
                            "Could not validate connection parameters");
        UA_PubSubConnection_delete(server, c);
        return ret;
    }

    
    ret = UA_PubSubConnection_setPubSubState(server, c, UA_PUBSUBSTATE_OPERATIONAL);
    if(ret != UA_STATUSCODE_GOOD)
        goto cleanup;

    if(cId)
        UA_NodeId_copy(&c->head.identifier, cId);

 cleanup:
    if(ret != UA_STATUSCODE_GOOD)
        UA_PubSubConnection_delete(server, c);
    return ret;
}

UA_StatusCode
UA_Server_addPubSubConnection(UA_Server *server, const UA_PubSubConnectionConfig *cc,
                              UA_NodeId *cId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = UA_PubSubConnection_create(server, cc, cId);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static void
delayedPubSubConnection_delete(void *application, void *context) {
    UA_Server *server = (UA_Server*)application;
    UA_PubSubConnection *c = (UA_PubSubConnection*)context;
    UA_LOCK(&server->serviceMutex);
    UA_PubSubConnection_delete(server, c);
    UA_UNLOCK(&server->serviceMutex);
}

void
UA_PubSubConnection_delete(UA_Server *server, UA_PubSubConnection *c) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    c->deleteFlag = true;
    UA_PubSubConnection_setPubSubState(server, c, UA_PUBSUBSTATE_DISABLED);

    UA_ReaderGroup *readerGroup, *tmpReaderGroup;
    LIST_FOREACH(readerGroup, &c->readerGroups, listEntry) {
        UA_ReaderGroup_setPubSubState(server, readerGroup, UA_PUBSUBSTATE_DISABLED);
        UA_ReaderGroup_unfreezeConfiguration(server, readerGroup);
    }

    UA_WriterGroup *writerGroup, *tmpWriterGroup;
    LIST_FOREACH(writerGroup, &c->writerGroups, listEntry) {
        UA_WriterGroup_setPubSubState(server, writerGroup, UA_PUBSUBSTATE_DISABLED);
        UA_WriterGroup_unfreezeConfiguration(server, writerGroup);
    }

    
    LIST_FOREACH_SAFE(readerGroup, &c->readerGroups, listEntry, tmpReaderGroup) {
        UA_ReaderGroup_remove(server, readerGroup);
    }

    LIST_FOREACH_SAFE(writerGroup, &c->writerGroups, listEntry, tmpWriterGroup) {
        UA_WriterGroup_remove(server, writerGroup);
    }

    
    if(c->sendChannel != 0 || c->recvChannelsSize > 0)
        return;

    if(!LIST_EMPTY(&c->writerGroups) || !LIST_EMPTY(&c->readerGroups)) {
        UA_EventLoop *el = UA_PubSubConnection_getEL(server, c);
        c->dc.callback = delayedPubSubConnection_delete;
        c->dc.application = server;
        c->dc.context = c;
        el->addDelayedCallback(el, &c->dc);
        return;
    }

    
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    deleteNode(server, c->head.identifier, true);
#endif

    
    TAILQ_REMOVE(&server->pubSubManager.connections, c, listEntry);
    server->pubSubManager.connectionsSize--;

    UA_LOG_INFO_PUBSUB(server->config.logging, c, "Connection deleted");

    UA_PubSubConnectionConfig_clear(&c->config);
    UA_PubSubComponentHead_clear(&c->head);
    UA_free(c);
}

UA_StatusCode
UA_Server_removePubSubConnection(UA_Server *server, const UA_NodeId connection) {
    UA_LOCK(&server->serviceMutex);
    UA_PubSubConnection *psc =
        UA_PubSubConnection_findConnectionbyId(server, connection);
    if(!psc) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    UA_PubSubConnection_setPubSubState(server, psc, UA_PUBSUBSTATE_DISABLED);
    UA_PubSubConnection_delete(server, psc);
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}

void
UA_PubSubConnection_process(UA_Server *server, UA_PubSubConnection *c,
                            UA_ByteString msg) {
    
    UA_ReaderGroup *rg;
    UA_Boolean processed = false;
    UA_ReaderGroup *nonRtRg = NULL;
    LIST_FOREACH(rg, &c->readerGroups, listEntry) {
        if(rg->head.state != UA_PUBSUBSTATE_OPERATIONAL &&
           rg->head.state != UA_PUBSUBSTATE_PREOPERATIONAL)
            continue;
        if(rg->config.rtLevel != UA_PUBSUB_RT_FIXED_SIZE) {
            nonRtRg = rg;
            continue;
        } 
        processed |= UA_ReaderGroup_decodeAndProcessRT(server, rg, msg);
    }

    
    if(!nonRtRg)
        goto finish;

    
    UA_StatusCode res;
    UA_NetworkMessage nm;
    memset(&nm, 0, sizeof(UA_NetworkMessage));
    if(nonRtRg->config.encodingMimeType == UA_PUBSUB_ENCODING_UADP) {
        res = UA_PubSubConnection_decodeNetworkMessage(c, server, msg, &nm);
    } else { 
#ifdef UA_ENABLE_JSON_ENCODING
        res = UA_NetworkMessage_decodeJson(&msg, &nm, NULL);
#else
        res = UA_STATUSCODE_BADNOTSUPPORTED;
#endif
    }
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, c,
                              "Verify, decrypt and decode network message failed");
        return;
    }

    
    LIST_FOREACH(rg, &c->readerGroups, listEntry) {
        if(rg->head.state != UA_PUBSUBSTATE_OPERATIONAL &&
           rg->head.state != UA_PUBSUBSTATE_PREOPERATIONAL)
            continue;
        if(rg->config.rtLevel == UA_PUBSUB_RT_FIXED_SIZE)
            continue;
        processed |= UA_ReaderGroup_process(server, rg, &nm);
    }
    UA_NetworkMessage_clear(&nm);

 finish:
    if(!processed) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, c,
                              "Message received that could not be processed. "
                              "Check PublisherID, WriterGroupID and DatasetWriterID.");
    }
}

UA_StatusCode
UA_PubSubConnection_setPubSubState(UA_Server *server, UA_PubSubConnection *c,
                                   UA_PubSubState targetState) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(c->deleteFlag && targetState != UA_PUBSUBSTATE_DISABLED) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, c,
                              "The connection is being deleted. Can only be disabled.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode ret = UA_STATUSCODE_GOOD;
    UA_PubSubState oldState = c->head.state;

 set_state:

    switch(targetState) {
        case UA_PUBSUBSTATE_ERROR:
        case UA_PUBSUBSTATE_PAUSED:
        case UA_PUBSUBSTATE_DISABLED:
            
            UA_PubSubConnection_disconnect(c);
            c->head.state = targetState;
            break;

        case UA_PUBSUBSTATE_PREOPERATIONAL:
        case UA_PUBSUBSTATE_OPERATIONAL:
            if(oldState == UA_PUBSUBSTATE_PREOPERATIONAL || oldState == UA_PUBSUBSTATE_OPERATIONAL)
                c->head.state = UA_PUBSUBSTATE_OPERATIONAL;
            else
                c->head.state = UA_PUBSUBSTATE_PREOPERATIONAL;

            ret = UA_PubSubConnection_connect(server, c, false);
            if(ret != UA_STATUSCODE_GOOD) {
                targetState = UA_PUBSUBSTATE_ERROR;
                goto set_state;
            }
            break;
        default:
            UA_LOG_WARNING_PUBSUB(server->config.logging, c,
                                  "Received unknown PubSub state!");
            return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    if(c->head.state != oldState) {
        UA_ServerConfig *config = &server->config;
        UA_LOG_INFO_PUBSUB(config->logging, c, "State change: %s -> %s",
                           UA_PubSubState_name(oldState),
                           UA_PubSubState_name(c->head.state));
        UA_UNLOCK(&server->serviceMutex);
        if(config->pubSubConfig.stateChangeCallback)
            config->pubSubConfig.stateChangeCallback(server, &c->head.identifier, targetState, ret);
        UA_LOCK(&server->serviceMutex);
    }

    UA_ReaderGroup *readerGroup;
    LIST_FOREACH(readerGroup, &c->readerGroups, listEntry) {
        UA_ReaderGroup_setPubSubState(server, readerGroup, readerGroup->head.state);
    }
    UA_WriterGroup *writerGroup;
    LIST_FOREACH(writerGroup, &c->writerGroups, listEntry) {
        UA_WriterGroup_setPubSubState(server, writerGroup, writerGroup->head.state);
    }
    return ret;
}

static UA_StatusCode
enablePubSubConnection(UA_Server *server, const UA_NodeId connectionId) {
    UA_PubSubConnection *psc = UA_PubSubConnection_findConnectionbyId(server, connectionId);
    return (psc) ? UA_PubSubConnection_setPubSubState(server, psc, UA_PUBSUBSTATE_OPERATIONAL)
        : UA_STATUSCODE_BADNOTFOUND;
}

static UA_StatusCode
disablePubSubConnection(UA_Server *server, const UA_NodeId connectionId) {
    UA_PubSubConnection *psc = UA_PubSubConnection_findConnectionbyId(server, connectionId);
    return (psc) ? UA_PubSubConnection_setPubSubState(server, psc, UA_PUBSUBSTATE_DISABLED)
        : UA_STATUSCODE_BADNOTFOUND;
}

UA_StatusCode
UA_Server_enablePubSubConnection(UA_Server *server,
                                 const UA_NodeId connectionId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = enablePubSubConnection(server, connectionId);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_Server_disablePubSubConnection(UA_Server *server,
                                  const UA_NodeId connectionId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = disablePubSubConnection(server, connectionId);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_EventLoop *
UA_PubSubConnection_getEL(UA_Server *server, UA_PubSubConnection *c) {
    if(c->config.eventLoop)
        return c->config.eventLoop;
    return server->config.eventLoop;
}

#endif 
