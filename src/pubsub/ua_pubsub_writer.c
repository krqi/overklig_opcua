
#include "ua_pubsub.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_PUBSUB 

#include "ua_pubsub_networkmessage.h"

#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
#include "ua_pubsub_ns0.h"
#endif

#include "ua_types_encoding_binary.h"

UA_StatusCode
UA_DataSetWriterConfig_copy(const UA_DataSetWriterConfig *src,
                            UA_DataSetWriterConfig *dst){
    UA_StatusCode retVal = UA_STATUSCODE_GOOD;
    memcpy(dst, src, sizeof(UA_DataSetWriterConfig));
    retVal |= UA_String_copy(&src->name, &dst->name);
    retVal |= UA_String_copy(&src->dataSetName, &dst->dataSetName);
    retVal |= UA_ExtensionObject_copy(&src->messageSettings, &dst->messageSettings);
    retVal |= UA_KeyValueMap_copy(&src->dataSetWriterProperties, &dst->dataSetWriterProperties);
    if(retVal != UA_STATUSCODE_GOOD)
        UA_DataSetWriterConfig_clear(dst);
    return retVal;
}

UA_StatusCode
UA_Server_getDataSetWriterConfig(UA_Server *server, const UA_NodeId dswId,
                                 UA_DataSetWriterConfig *config) {
    if(!config)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_LOCK(&server->serviceMutex);
    UA_DataSetWriter *dsw = UA_DataSetWriter_findDSWbyId(server, dswId);
    UA_StatusCode res = UA_STATUSCODE_BADNOTFOUND;
    if(dsw)
        res = UA_DataSetWriterConfig_copy(&dsw->config, config);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_Server_DataSetWriter_getState(UA_Server *server, const UA_NodeId dataSetWriterIdentifier,
                               UA_PubSubState *state) {
    if((server == NULL) || (state == NULL))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_LOCK(&server->serviceMutex);
    UA_DataSetWriter *dsw = UA_DataSetWriter_findDSWbyId(server, dataSetWriterIdentifier);
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(dsw) {
        *state = dsw->head.state;
    } else {
        res = UA_STATUSCODE_BADNOTFOUND;
    }
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_DataSetWriter *
UA_DataSetWriter_findDSWbyId(UA_Server *server, UA_NodeId identifier) {
    UA_PubSubConnection *pubSubConnection;
    TAILQ_FOREACH(pubSubConnection, &server->pubSubManager.connections, listEntry) {
        UA_WriterGroup *tmpWriterGroup;
        LIST_FOREACH(tmpWriterGroup, &pubSubConnection->writerGroups, listEntry) {
            UA_DataSetWriter *tmpWriter;
            LIST_FOREACH(tmpWriter, &tmpWriterGroup->writers, listEntry) {
                if(UA_NodeId_equal(&tmpWriter->head.identifier, &identifier))
                    return tmpWriter;
            }
        }
    }
    return NULL;
}

void
UA_DataSetWriterConfig_clear(UA_DataSetWriterConfig *pdsConfig) {
    UA_String_clear(&pdsConfig->name);
    UA_String_clear(&pdsConfig->dataSetName);
    UA_KeyValueMap_clear(&pdsConfig->dataSetWriterProperties);
    UA_ExtensionObject_clear(&pdsConfig->messageSettings);
    memset(pdsConfig, 0, sizeof(UA_DataSetWriterConfig));
}

UA_StatusCode
UA_Server_enableDataSetWriter(UA_Server *server, const UA_NodeId dswId) {
    UA_LOCK(&server->serviceMutex);
    UA_DataSetWriter *dsw = UA_DataSetWriter_findDSWbyId(server, dswId);
    if(!dsw) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_StatusCode ret =
        UA_DataSetWriter_setPubSubState(server, dsw, UA_PUBSUBSTATE_OPERATIONAL);
    UA_UNLOCK(&server->serviceMutex);
    return ret;
}

UA_StatusCode
UA_Server_disableDataSetWriter(UA_Server *server, const UA_NodeId dswId) {
    UA_LOCK(&server->serviceMutex);
    UA_DataSetWriter *dsw = UA_DataSetWriter_findDSWbyId(server, dswId);
    if(!dsw) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_StatusCode ret =
        UA_DataSetWriter_setPubSubState(server, dsw, UA_PUBSUBSTATE_DISABLED);
    UA_UNLOCK(&server->serviceMutex);
    return ret;
}

UA_StatusCode
UA_DataSetWriter_setPubSubState(UA_Server *server, UA_DataSetWriter *dsw,
                                UA_PubSubState targetState) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_WriterGroup *wg = dsw->linkedWriterGroup;
    UA_assert(wg);

    UA_PubSubState oldState = dsw->head.state;
    dsw->head.state = targetState;

    switch(dsw->head.state) {
        
    case UA_PUBSUBSTATE_DISABLED:
    case UA_PUBSUBSTATE_ERROR:
        break;

        
    case UA_PUBSUBSTATE_PAUSED:
    case UA_PUBSUBSTATE_PREOPERATIONAL:
    case UA_PUBSUBSTATE_OPERATIONAL:
        if(wg->head.state == UA_PUBSUBSTATE_DISABLED ||
           wg->head.state == UA_PUBSUBSTATE_ERROR) {
            dsw->head.state = UA_PUBSUBSTATE_PAUSED; 
        } else {
            dsw->head.state = wg->head.state; 
        }
        break;

    default:
        dsw->head.state = UA_PUBSUBSTATE_ERROR;
        res = UA_STATUSCODE_BADINTERNALERROR;
        break;
    }

    
    if(dsw->head.state != oldState) {
        UA_ServerConfig *config = &server->config;
        UA_LOG_INFO_PUBSUB(config->logging, dsw, "State change: %s -> %s",
                           UA_PubSubState_name(oldState),
                           UA_PubSubState_name(dsw->head.state));
        if(config->pubSubConfig.stateChangeCallback != 0) {
            UA_UNLOCK(&server->serviceMutex);
            config->pubSubConfig.
                stateChangeCallback(server, &dsw->head.identifier, dsw->head.state, res);
            UA_LOCK(&server->serviceMutex);
        }
    }

    return res;
}

UA_StatusCode
UA_DataSetWriter_create(UA_Server *server,
                        const UA_NodeId writerGroup, const UA_NodeId dataSet,
                        const UA_DataSetWriterConfig *dataSetWriterConfig,
                        UA_NodeId *writerIdentifier) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    if(!dataSetWriterConfig)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_WriterGroup *wg = UA_WriterGroup_findWGbyId(server, writerGroup);
    if(!wg)
        return UA_STATUSCODE_BADNOTFOUND;

    
    if(UA_NodeId_isNull(&dataSet) && dataSetWriterConfig->keyFrameCount != 1) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "Adding DataSetWriter failed: DataSet can be null only for "
                              "a heartbeat in which case KeyFrameCount shall be 1");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    if(wg->configurationFrozen) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, wg,
                              "Adding DataSetWriter failed: WriterGroup is frozen");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    UA_PublishedDataSet *pds = NULL;

    if(!UA_NodeId_isNull(&dataSet)) {
        pds = UA_PublishedDataSet_findPDSbyId(server, dataSet);
        if(!pds)
            return UA_STATUSCODE_BADNOTFOUND;

        if(pds->configurationFreezeCounter > 0) {
            UA_LOG_WARNING_PUBSUB(server->config.logging, pds,
                                  "Adding DataSetWriter failed: PublishedDataSet is frozen");
            return UA_STATUSCODE_BADCONFIGURATIONERROR;
        }

        if(wg->config.rtLevel != UA_PUBSUB_RT_NONE) {
            UA_DataSetField *tmpDSF;
            TAILQ_FOREACH(tmpDSF, &pds->fields, listEntry) {
                if(!tmpDSF->config.field.variable.rtValueSource.rtFieldSourceEnabled &&
                   !tmpDSF->config.field.variable.rtValueSource.rtInformationModelNode) {
                    UA_LOG_WARNING_PUBSUB(server->config.logging, pds,
                                          "Adding DataSetWriter failed: "
                                          "Fields in PDS are not RT capable");
                    return UA_STATUSCODE_BADCONFIGURATIONERROR;
                }
            }
        }
    }

    UA_DataSetWriter *newDataSetWriter = (UA_DataSetWriter *)
        UA_calloc(1, sizeof(UA_DataSetWriter));
    if(!newDataSetWriter)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    newDataSetWriter->head.componentType = UA_PUBSUB_COMPONENT_DATASETWRITER;
    newDataSetWriter->linkedWriterGroup = wg;

    
    UA_StatusCode res =
        UA_DataSetWriterConfig_copy(dataSetWriterConfig, &newDataSetWriter->config);
    UA_CHECK_STATUS(res, UA_free(newDataSetWriter); return res);

    if(pds) {
        
        newDataSetWriter->connectedDataSetVersion =
            pds->dataSetMetaData.configurationVersion;

        if(server->config.pubSubConfig.enableDeltaFrames) {
            
            if(pds->fieldSize > 0) {
                newDataSetWriter->lastSamples = (UA_DataSetWriterSample*)
                    UA_calloc(pds->fieldSize, sizeof(UA_DataSetWriterSample));
                if(!newDataSetWriter->lastSamples) {
                    UA_DataSetWriterConfig_clear(&newDataSetWriter->config);
                    UA_free(newDataSetWriter);
                    return UA_STATUSCODE_BADOUTOFMEMORY;
                }
                newDataSetWriter->lastSamplesCount = pds->fieldSize;
                for(size_t i = 0; i < newDataSetWriter->lastSamplesCount; i++) {
                    UA_DataValue_init(&newDataSetWriter->lastSamples[i].value);
                    newDataSetWriter->lastSamples[i].valueChanged = false;
                }
            }
        }
        
        newDataSetWriter->connectedDataSet = pds;
    } else {
        
        newDataSetWriter->connectedDataSetVersion.majorVersion = 0;
        newDataSetWriter->connectedDataSetVersion.minorVersion = 0;
        newDataSetWriter->connectedDataSet = NULL;
    }

    
    LIST_INSERT_HEAD(&wg->writers, newDataSetWriter, listEntry);
    wg->writersCount++;

    
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    res |= addDataSetWriterRepresentation(server, newDataSetWriter);
#else
    UA_PubSubManager_generateUniqueNodeId(&server->pubSubManager,
                                          &newDataSetWriter->head.identifier);
#endif

    
    char tmpLogIdStr[128];
    mp_snprintf(tmpLogIdStr, 128, "%SDataSetWriter %N\t| ",
                newDataSetWriter->linkedWriterGroup->head.logIdString,
                newDataSetWriter->head.identifier);
    newDataSetWriter->head.logIdString = UA_STRING_ALLOC(tmpLogIdStr);

    UA_LOG_INFO_PUBSUB(server->config.logging, newDataSetWriter, "Writer created");

    
    UA_DataSetWriter_setPubSubState(server, newDataSetWriter,
                                    UA_PUBSUBSTATE_OPERATIONAL);

    if(writerIdentifier)
        UA_NodeId_copy(&newDataSetWriter->head.identifier, writerIdentifier);
    return res;
}

UA_StatusCode
UA_Server_addDataSetWriter(UA_Server *server,
                           const UA_NodeId writerGroup, const UA_NodeId dataSet,
                           const UA_DataSetWriterConfig *dataSetWriterConfig,
                           UA_NodeId *writerIdentifier) {
    UA_LOCK(&server->serviceMutex);
    
    UA_PubSubManager_freeIds(server);
    UA_StatusCode res = UA_DataSetWriter_create(server, writerGroup, dataSet,
                                                dataSetWriterConfig, writerIdentifier);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

void
UA_DataSetWriter_freezeConfiguration(UA_Server *server,
                                     UA_DataSetWriter *dsw) {
    UA_PublishedDataSet *pds = dsw->connectedDataSet;
    if(pds) { 
        pds->configurationFreezeCounter++;
        UA_DataSetField *dsf;
        TAILQ_FOREACH(dsf, &pds->fields, listEntry) {
            dsf->configurationFrozen = true;
        }
    }
    dsw->configurationFrozen = true;
}

void
UA_DataSetWriter_unfreezeConfiguration(UA_Server *server,
                                       UA_DataSetWriter *dsw) {
    UA_PublishedDataSet *pds = dsw->connectedDataSet;
    if(pds) { 
        pds->configurationFreezeCounter--;
        if(pds->configurationFreezeCounter == 0) {
            UA_DataSetField *dsf;
            TAILQ_FOREACH(dsf, &pds->fields, listEntry){
                dsf->configurationFrozen = false;
            }
        }
        dsw->configurationFrozen = false;
    }
}

UA_StatusCode
UA_DataSetWriter_prepareDataSet(UA_Server *server, UA_DataSetWriter *dsw,
                                UA_DataSetMessage *dsm) {
    
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_PublishedDataSet *pds = dsw->connectedDataSet;
    if(!pds) {
        res = UA_DataSetWriter_generateDataSetMessage(server, dsm, dsw);
        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING_PUBSUB(server->config.logging, dsw,
                                  "PubSub-RT configuration fail: "
                                  "Heartbeat DataSetMessage creation failed");
        }
        return res;
    }

    UA_WriterGroup *wg = dsw->linkedWriterGroup;
    UA_assert(wg);

    
    if(wg->config.rtLevel > UA_PUBSUB_RT_NONE &&
       pds->promotedFieldsCount > 0) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, dsw,
                              "PubSub-RT configuration fail: "
                              "PDS contains promoted fields");
        return UA_STATUSCODE_BADNOTSUPPORTED;
    }

    
    UA_DataSetField *dsf;
    TAILQ_FOREACH(dsf, &pds->fields, listEntry) {
        UA_NodeId *publishedVariable =
            &dsf->config.field.variable.publishParameters.publishedVariable;

        
        const UA_VariableNode *rtNode = (const UA_VariableNode*)
            UA_NODESTORE_GET(server, publishedVariable);
        if(rtNode && rtNode->head.nodeClass != UA_NODECLASS_VARIABLE) {
            UA_LOG_ERROR_PUBSUB(server->config.logging, dsw,
                                "PubSub-RT configuration fail: "
                                "PDS points to a node that is not a variable");
            UA_NODESTORE_RELEASE(server, (const UA_Node *)rtNode);
            return UA_STATUSCODE_BADNOTSUPPORTED;
        }
        UA_NODESTORE_RELEASE(server, (const UA_Node *)rtNode);

        

        
        if(wg->config.rtLevel & UA_PUBSUB_RT_DIRECT_VALUE_ACCESS &&
           !dsf->config.field.variable.rtValueSource.rtFieldSourceEnabled) {
            UA_LOG_ERROR_PUBSUB(server->config.logging, dsw,
                                "PubSub-RT configuration fail: PDS published-variable "
                                "does not have an external data source");
            return UA_STATUSCODE_BADNOTSUPPORTED;
        }

        
        if(wg->config.rtLevel & UA_PUBSUB_RT_FIXED_SIZE) {
            if((UA_NodeId_equal(&dsf->fieldMetaData.dataType,
                                &UA_TYPES[UA_TYPES_STRING].typeId) ||
                UA_NodeId_equal(&dsf->fieldMetaData.dataType,
                                &UA_TYPES[UA_TYPES_BYTESTRING].typeId)) &&
               dsf->fieldMetaData.maxStringLength == 0) {
                UA_LOG_WARNING_PUBSUB(server->config.logging, dsw,
                                      "PubSub-RT configuration fail: "
                                      "PDS contains String/ByteString with dynamic length");
                return UA_STATUSCODE_BADNOTSUPPORTED;
            } else if(!UA_DataType_isNumeric(
                          UA_findDataType(&dsf->fieldMetaData.dataType)) &&
                      !UA_NodeId_equal(&dsf->fieldMetaData.dataType,
                                       &UA_TYPES[UA_TYPES_BOOLEAN].typeId)) {
                UA_LOG_WARNING_PUBSUB(server->config.logging, dsw,
                                      "PubSub-RT configuration fail: "
                                      "PDS contains variable with dynamic size");
                return UA_STATUSCODE_BADNOTSUPPORTED;
            }
        }
    }

    
    res = UA_DataSetWriter_generateDataSetMessage(server, dsm, dsw);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, dsw,
                              "PubSub-RT configuration fail: "
                              "DataSetMessage buffering failed");
    }

    return res;
}

UA_StatusCode
UA_DataSetWriter_remove(UA_Server *server, UA_DataSetWriter *dsw) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(dsw->configurationFrozen) {
        UA_LOG_WARNING_PUBSUB(server->config.logging, dsw,
                              "Remove DataSetWriter failed: WriterGroup is frozen");
        return UA_STATUSCODE_BADCONFIGURATIONERROR;
    }

    
#ifdef UA_ENABLE_PUBSUB_INFORMATIONMODEL
    deleteNode(server, dsw->head.identifier, true);
#endif

    
    UA_WriterGroup *linkedWriterGroup = dsw->linkedWriterGroup;
    LIST_REMOVE(dsw, listEntry);
    linkedWriterGroup->writersCount--;

    UA_LOG_INFO_PUBSUB(server->config.logging, dsw, "Writer deleted");

    UA_DataSetWriterConfig_clear(&dsw->config);

    if(server->config.pubSubConfig.enableDeltaFrames) {
        
        for(size_t i = 0; i < dsw->lastSamplesCount; i++) {
            UA_DataValue_clear(&dsw->lastSamples[i].value);
        }
        UA_free(dsw->lastSamples);
        dsw->lastSamples = NULL;
        dsw->lastSamplesCount = 0;
    }

    UA_PubSubComponentHead_clear(&dsw->head);
    UA_free(dsw);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_removeDataSetWriter(UA_Server *server, const UA_NodeId dswId) {
    UA_LOCK(&server->serviceMutex);
    UA_DataSetWriter *dsw = UA_DataSetWriter_findDSWbyId(server, dswId);
    if(!dsw) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    UA_StatusCode res = UA_DataSetWriter_remove(server, dsw);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}






static UA_Boolean
valueChangedVariant(UA_Variant *oldValue, UA_Variant *newValue) {
    if(!oldValue || !newValue)
        return false;

    size_t oldValueEncodingSize = UA_calcSizeBinary(oldValue, &UA_TYPES[UA_TYPES_VARIANT]);
    size_t newValueEncodingSize = UA_calcSizeBinary(newValue, &UA_TYPES[UA_TYPES_VARIANT]);
    if(oldValueEncodingSize == 0 || newValueEncodingSize == 0)
        return false;

    if(oldValueEncodingSize != newValueEncodingSize)
        return true;

    UA_ByteString oldValueEncoding = UA_BYTESTRING_NULL;
    UA_StatusCode res = UA_ByteString_allocBuffer(&oldValueEncoding, oldValueEncodingSize);
    if(res != UA_STATUSCODE_GOOD)
        return false;

    UA_ByteString newValueEncoding = UA_BYTESTRING_NULL;
    res = UA_ByteString_allocBuffer(&newValueEncoding, newValueEncodingSize);
    if(res != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&oldValueEncoding);
        return false;
    }

    UA_Byte *bufPosOldValue = oldValueEncoding.data;
    const UA_Byte *bufEndOldValue = &oldValueEncoding.data[oldValueEncoding.length];
    UA_Byte *bufPosNewValue = newValueEncoding.data;
    const UA_Byte *bufEndNewValue = &newValueEncoding.data[newValueEncoding.length];

    UA_Boolean compareResult = false; 

    res = UA_encodeBinaryInternal(oldValue, &UA_TYPES[UA_TYPES_VARIANT],
                                  &bufPosOldValue, &bufEndOldValue, NULL, NULL);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    res = UA_encodeBinaryInternal(newValue, &UA_TYPES[UA_TYPES_VARIANT],
                                  &bufPosNewValue, &bufEndNewValue, NULL, NULL);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    oldValueEncoding.length = (uintptr_t)bufPosOldValue - (uintptr_t)oldValueEncoding.data;
    newValueEncoding.length = (uintptr_t)bufPosNewValue - (uintptr_t)newValueEncoding.data;
    compareResult = !UA_ByteString_equal(&oldValueEncoding, &newValueEncoding);

 cleanup:
    UA_ByteString_clear(&oldValueEncoding);
    UA_ByteString_clear(&newValueEncoding);
    return compareResult;
}

static UA_StatusCode
UA_PubSubDataSetWriter_generateKeyFrameMessage(UA_Server *server,
                                               UA_DataSetMessage *dataSetMessage,
                                               UA_DataSetWriter *dsw) {
    UA_PublishedDataSet *pds = dsw->connectedDataSet;
    if(!pds)
        return UA_STATUSCODE_BADNOTFOUND;

    
    dataSetMessage->header.dataSetMessageValid = true;
    dataSetMessage->header.dataSetMessageType = UA_DATASETMESSAGE_DATAKEYFRAME;
    dataSetMessage->data.keyFrameData.fieldCount = pds->fieldSize;
    dataSetMessage->data.keyFrameData.dataSetFields = (UA_DataValue *)
            UA_Array_new(pds->fieldSize, &UA_TYPES[UA_TYPES_DATAVALUE]);
    dataSetMessage->data.keyFrameData.dataSetMetaDataType = &pds->dataSetMetaData;
    if(!dataSetMessage->data.keyFrameData.dataSetFields)
        return UA_STATUSCODE_BADOUTOFMEMORY;

#ifdef UA_ENABLE_JSON_ENCODING
    dataSetMessage->data.keyFrameData.fieldNames = (UA_String *)
        UA_Array_new(pds->fieldSize, &UA_TYPES[UA_TYPES_STRING]);
    if(!dataSetMessage->data.keyFrameData.fieldNames) {
        UA_DataSetMessage_clear(dataSetMessage);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
#endif

    
    size_t counter = 0;
    UA_DataSetField *dsf;
    TAILQ_FOREACH(dsf, &pds->fields, listEntry) {
#ifdef UA_ENABLE_JSON_ENCODING
        
        UA_String_copy(&dsf->config.field.variable.fieldNameAlias,
                       &dataSetMessage->data.keyFrameData.fieldNames[counter]);
#endif

        
        UA_DataValue *dfv = &dataSetMessage->data.keyFrameData.dataSetFields[counter];
        UA_PubSubDataSetField_sampleValue(server, dsf, dfv);

        
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_STATUSCODE) == 0)
            dfv->hasStatus = false;

        
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_SOURCETIMESTAMP) == 0)
            dfv->hasSourceTimestamp = false;
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_SOURCEPICOSECONDS) == 0)
            dfv->hasSourcePicoseconds = false;
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_SERVERTIMESTAMP) == 0)
            dfv->hasServerTimestamp = false;
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_SERVERPICOSECONDS) == 0)
            dfv->hasServerPicoseconds = false;

        if(server->config.pubSubConfig.enableDeltaFrames) {
            
            UA_DataValue_clear(&dsw->lastSamples[counter].value);
            UA_DataValue_copy(dfv, &dsw->lastSamples[counter].value);
        }
        counter++;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_PubSubDataSetWriter_generateDeltaFrameMessage(UA_Server *server,
                                                 UA_DataSetMessage *dsm,
                                                 UA_DataSetWriter *dsw) {
    UA_PublishedDataSet *pds = dsw->connectedDataSet;
    if(!pds)
        return UA_STATUSCODE_BADNOTFOUND;

    
    dsm->header.dataSetMessageValid = true;
    dsm->header.dataSetMessageType = UA_DATASETMESSAGE_DATADELTAFRAME;
    if(pds->fieldSize == 0)
        return UA_STATUSCODE_GOOD;

    UA_DataSetField *dsf;
    UA_UInt16 counter = 0;
    TAILQ_FOREACH(dsf, &pds->fields, listEntry) {
        
        UA_DataValue value;
        UA_DataValue_init(&value);
        UA_PubSubDataSetField_sampleValue(server, dsf, &value);

        
        UA_DataSetWriterSample *ls = &dsw->lastSamples[counter];
        if(valueChangedVariant(&ls->value.value, &value.value)) {
            
            dsm->data.deltaFrameData.fieldCount++;
            ls->valueChanged = true;

            
            UA_DataValue_clear(&ls->value);
            ls->value = value;
        } else {
            UA_DataValue_clear(&value);
            ls->valueChanged = false;
        }

        counter++;
    }

    
    UA_DataSetMessage_DeltaFrameField *deltaFields = (UA_DataSetMessage_DeltaFrameField *)
        UA_calloc(counter, sizeof(UA_DataSetMessage_DeltaFrameField));
    if(!deltaFields)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    dsm->data.deltaFrameData.deltaFrameFields = deltaFields;
    dsm->data.deltaFrameData.fieldCount = counter;

    size_t currentDeltaField = 0;
    for(size_t i = 0; i < pds->fieldSize; i++) {
        if(!dsw->lastSamples[i].valueChanged)
            continue;

        UA_DataSetMessage_DeltaFrameField *dff = &deltaFields[currentDeltaField];

        dff->fieldIndex = (UA_UInt16) i;
        UA_DataValue_copy(&dsw->lastSamples[i].value, &dff->fieldValue);

        
        dsw->lastSamples[i].valueChanged = false;

        
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_STATUSCODE) == 0)
            dff->fieldValue.hasStatus = false;

        
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_SOURCETIMESTAMP) == 0)
            dff->fieldValue.hasSourceTimestamp = false;
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_SOURCEPICOSECONDS) == 0)
            dff->fieldValue.hasServerPicoseconds = false;
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_SERVERTIMESTAMP) == 0)
            dff->fieldValue.hasServerTimestamp = false;
        if(((u64)dsw->config.dataSetFieldContentMask &
            (u64)UA_DATASETFIELDCONTENTMASK_SERVERPICOSECONDS) == 0)
            dff->fieldValue.hasServerPicoseconds = false;

        currentDeltaField++;
    }
    return UA_STATUSCODE_GOOD;
}


UA_StatusCode
UA_DataSetWriter_generateDataSetMessage(UA_Server *server,
                                        UA_DataSetMessage *dataSetMessage,
                                        UA_DataSetWriter *dsw) {
    
    UA_PublishedDataSet *pds = dsw->connectedDataSet;

    UA_WriterGroup *wg = dsw->linkedWriterGroup;
    UA_EventLoop *el = UA_PubSubConnection_getEL(server, wg->linkedConnection);

    
    memset(dataSetMessage, 0, sizeof(UA_DataSetMessage));

    UA_UadpDataSetWriterMessageDataType defaultUadpConfiguration;
    UA_UadpDataSetWriterMessageDataType *dsm = NULL;
    UA_JsonDataSetWriterMessageDataType *jsonDsm = NULL;
    const UA_ExtensionObject *ms = &dsw->config.messageSettings;
    if(ms->content.decoded.type == &UA_TYPES[UA_TYPES_UADPDATASETWRITERMESSAGEDATATYPE]) {
        dsm = (UA_UadpDataSetWriterMessageDataType*)ms->content.decoded.data; 
    } else if(ms->content.decoded.type == &UA_TYPES[UA_TYPES_JSONDATASETWRITERMESSAGEDATATYPE]) {
        jsonDsm = (UA_JsonDataSetWriterMessageDataType*)ms->content.decoded.data; 
    } else {
        memset(&defaultUadpConfiguration, 0, sizeof(UA_UadpDataSetWriterMessageDataType));
        defaultUadpConfiguration.dataSetMessageContentMask = (UA_UadpDataSetMessageContentMask)
            ((u64)UA_UADPDATASETMESSAGECONTENTMASK_TIMESTAMP |
             (u64)UA_UADPDATASETMESSAGECONTENTMASK_MAJORVERSION |
             (u64)UA_UADPDATASETMESSAGECONTENTMASK_MINORVERSION);
        dsm = &defaultUadpConfiguration; 
    }

    
    if(dsw->config.dataSetFieldContentMask &
       (u64)UA_DATASETFIELDCONTENTMASK_RAWDATA) {
        dataSetMessage->header.fieldEncoding = UA_FIELDENCODING_RAWDATA;
    } else if((u64)dsw->config.dataSetFieldContentMask &
              ((u64)UA_DATASETFIELDCONTENTMASK_SOURCETIMESTAMP |
               (u64)UA_DATASETFIELDCONTENTMASK_SERVERPICOSECONDS |
               (u64)UA_DATASETFIELDCONTENTMASK_SOURCEPICOSECONDS |
               (u64)UA_DATASETFIELDCONTENTMASK_STATUSCODE)) {
        dataSetMessage->header.fieldEncoding = UA_FIELDENCODING_DATAVALUE;
    } else {
        dataSetMessage->header.fieldEncoding = UA_FIELDENCODING_VARIANT;
    }

    if(dsm) {
        
        if(dsm->networkMessageNumber != 0 || dsm->dataSetOffset != 0 ||
           dsm->configuredSize != 0) {
            UA_LOG_WARNING_PUBSUB(server->config.logging, dsw,
                                  "Static DSM configuration not supported, using defaults");
            dsm->networkMessageNumber = 0;
            dsm->dataSetOffset = 0;
            // dsm->configuredSize = 0;
        }

        
        dataSetMessage->configuredSize = dsm->configuredSize;

        if((u64)dsm->dataSetMessageContentMask &
           (u64)UA_UADPDATASETMESSAGECONTENTMASK_MAJORVERSION) {
            dataSetMessage->header.configVersionMajorVersionEnabled = true;
            if(!pds) {
                
                dataSetMessage->header.configVersionMajorVersion = 0;
            } else {
                dataSetMessage->header.configVersionMajorVersion =
                    pds->dataSetMetaData.configurationVersion.majorVersion;
            }
        }
        if((u64)dsm->dataSetMessageContentMask &
           (u64)UA_UADPDATASETMESSAGECONTENTMASK_MINORVERSION) {
            dataSetMessage->header.configVersionMinorVersionEnabled = true;
            if(!pds) {
                
                dataSetMessage->header.configVersionMinorVersion = 0;
            } else {
                dataSetMessage->header.configVersionMinorVersion =
                    pds->dataSetMetaData.configurationVersion.minorVersion;
            }
        }

        if((u64)dsm->dataSetMessageContentMask &
           (u64)UA_UADPDATASETMESSAGECONTENTMASK_SEQUENCENUMBER) {
            dataSetMessage->header.dataSetMessageSequenceNrEnabled = true;
            dataSetMessage->header.dataSetMessageSequenceNr =
                dsw->actualDataSetMessageSequenceCount;
        }

        if((u64)dsm->dataSetMessageContentMask &
           (u64)UA_UADPDATASETMESSAGECONTENTMASK_TIMESTAMP) {
            dataSetMessage->header.timestampEnabled = true;
            dataSetMessage->header.timestamp = el->dateTime_now(el);
        }

        
        if((u64)dsm->dataSetMessageContentMask &
           (u64)UA_UADPDATASETMESSAGECONTENTMASK_PICOSECONDS) {
            dataSetMessage->header.picoSecondsIncluded = false;
        }

        
        if((u64)dsm->dataSetMessageContentMask &
           (u64)UA_UADPDATASETMESSAGECONTENTMASK_STATUS) {
            dataSetMessage->header.statusEnabled = true;
        }
    } else if(jsonDsm) {
        if((u64)jsonDsm->dataSetMessageContentMask &
           (u64)UA_JSONDATASETMESSAGECONTENTMASK_METADATAVERSION) {
            dataSetMessage->header.configVersionMajorVersionEnabled = true;
            if(!pds) {
                
                dataSetMessage->header.configVersionMajorVersion = 0;
            } else {
                dataSetMessage->header.configVersionMajorVersion =
                pds->dataSetMetaData.configurationVersion.majorVersion;
            }
       }
        if((u64)jsonDsm->dataSetMessageContentMask &
           (u64)UA_JSONDATASETMESSAGECONTENTMASK_METADATAVERSION) {
            dataSetMessage->header.configVersionMinorVersionEnabled = true;
            if(!pds) {
                
                dataSetMessage->header.configVersionMinorVersion = 0;
            } else {
                dataSetMessage->header.configVersionMinorVersion =
                pds->dataSetMetaData.configurationVersion.minorVersion;
            }
       }

        if((u64)jsonDsm->dataSetMessageContentMask &
           (u64)UA_JSONDATASETMESSAGECONTENTMASK_SEQUENCENUMBER) {
            dataSetMessage->header.dataSetMessageSequenceNrEnabled = true;
            dataSetMessage->header.dataSetMessageSequenceNr =
                dsw->actualDataSetMessageSequenceCount;
        }

        if((u64)jsonDsm->dataSetMessageContentMask &
           (u64)UA_JSONDATASETMESSAGECONTENTMASK_TIMESTAMP) {
            dataSetMessage->header.timestampEnabled = true;
            dataSetMessage->header.timestamp = el->dateTime_now(el);
        }

        
        if((u64)jsonDsm->dataSetMessageContentMask &
           (u64)UA_JSONDATASETMESSAGECONTENTMASK_STATUS) {
            dataSetMessage->header.statusEnabled = true;
        }
    }

    
    dsw->actualDataSetMessageSequenceCount++;

    if(!pds) {
        
        dataSetMessage->header.dataSetMessageValid = true;
        dataSetMessage->header.dataSetMessageType = UA_DATASETMESSAGE_DATAKEYFRAME;
        dataSetMessage->data.keyFrameData.fieldCount = 0;
        return UA_STATUSCODE_GOOD;
    }

    if(dsm && server->config.pubSubConfig.enableDeltaFrames) {
        if(dsw->connectedDataSetVersion.majorVersion !=
           pds->dataSetMetaData.configurationVersion.majorVersion ||
           dsw->connectedDataSetVersion.minorVersion !=
           pds->dataSetMetaData.configurationVersion.minorVersion) {
            
            for(size_t i = 0; i < dsw->lastSamplesCount; i++)
                UA_DataValue_clear(&dsw->lastSamples[i].value);

            
            dsw->lastSamplesCount = pds->fieldSize;
            UA_DataSetWriterSample *newSamplesArray = (UA_DataSetWriterSample * )
                UA_realloc(dsw->lastSamples,
                           sizeof(UA_DataSetWriterSample) * dsw->lastSamplesCount);
            if(!newSamplesArray)
                return UA_STATUSCODE_BADOUTOFMEMORY;
            dsw->lastSamples = newSamplesArray;
            memset(dsw->lastSamples, 0,
                   sizeof(UA_DataSetWriterSample) * dsw->lastSamplesCount);

            dsw->connectedDataSetVersion =
                pds->dataSetMetaData.configurationVersion;
            UA_PubSubDataSetWriter_generateKeyFrameMessage(server, dataSetMessage,
                                                           dsw);
            dsw->deltaFrameCounter = 0;
            return UA_STATUSCODE_GOOD;
        }

        if(pds->fieldSize > 1 && dsw->deltaFrameCounter > 0 &&
           dsw->deltaFrameCounter <= dsw->config.keyFrameCount) {
            UA_PubSubDataSetWriter_generateDeltaFrameMessage(server, dataSetMessage,
                                                             dsw);
            dsw->deltaFrameCounter++;
            return UA_STATUSCODE_GOOD;
        }

        dsw->deltaFrameCounter = 1;
    }

    return UA_PubSubDataSetWriter_generateKeyFrameMessage(server, dataSetMessage,
                                                          dsw);
}

#endif 
