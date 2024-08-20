
#include "ua_server_internal.h"
#include "ua_services.h"
#include "ua_subscription.h"

#ifdef UA_ENABLE_SUBSCRIPTIONS 

#ifdef UA_ENABLE_DA

static UA_StatusCode
setAbsoluteFromPercentageDeadband(UA_Server *server, UA_Session *session,
                                  const UA_MonitoredItem *mon, UA_DataChangeFilter *filter) {
    
    if(filter->deadbandValue < 0.0 || filter->deadbandValue > 100.0)
        return UA_STATUSCODE_BADMONITOREDITEMFILTERUNSUPPORTED;

    
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, "EURange");
    UA_BrowsePathResult bpr =
        browseSimplifiedBrowsePath(server, mon->itemToMonitor.nodeId, 1, &qn);
    if(bpr.statusCode != UA_STATUSCODE_GOOD || bpr.targetsSize < 1) {
        UA_BrowsePathResult_clear(&bpr);
        return UA_STATUSCODE_BADMONITOREDITEMFILTERUNSUPPORTED;
    }

    
    UA_ReadValueId rvi;
    UA_ReadValueId_init(&rvi);
    rvi.nodeId = bpr.targets->targetId.nodeId;
    rvi.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_DataValue rangeVal = readWithSession(server, session, &rvi,
                                            UA_TIMESTAMPSTORETURN_NEITHER);
    UA_BrowsePathResult_clear(&bpr);
    if(!UA_Variant_isScalar(&rangeVal.value) ||
       rangeVal.value.type != &UA_TYPES[UA_TYPES_RANGE]) {
        UA_DataValue_clear(&rangeVal);
        return UA_STATUSCODE_BADMONITOREDITEMFILTERUNSUPPORTED;
    }

    
    UA_Range *euRange = (UA_Range*)rangeVal.value.data;
    UA_Double absDeadband = (filter->deadbandValue/100.0) * (euRange->high - euRange->low);

    UA_DataValue_clear(&rangeVal);

    
    if(absDeadband < 0.0 || absDeadband != absDeadband) {
        UA_DataValue_clear(&rangeVal);
        return UA_STATUSCODE_BADMONITOREDITEMFILTERUNSUPPORTED;
    }

    
    filter->deadbandType = UA_DEADBANDTYPE_ABSOLUTE;
    filter->deadbandValue = absDeadband;
    return UA_STATUSCODE_GOOD;
}

#endif 

void
Service_SetTriggering(UA_Server *server, UA_Session *session,
                      const UA_SetTriggeringRequest *request,
                      UA_SetTriggeringResponse *response) {
    
    if(request->linksToRemoveSize == 0 &&
       request->linksToAddSize == 0) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADNOTHINGTODO;
        return;
    }

    
    UA_Subscription *sub = UA_Session_getSubscriptionById(session, request->subscriptionId);
    if(!sub) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
    Subscription_resetLifetime(sub);

    
    UA_MonitoredItem *mon = UA_Subscription_getMonitoredItem(sub, request->triggeringItemId);
    if(!mon) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADMONITOREDITEMIDINVALID;
        return;
    }

    
    if(request->linksToRemoveSize > 0) {
        response->removeResults = (UA_StatusCode*)
            UA_Array_new(request->linksToRemoveSize, &UA_TYPES[UA_TYPES_STATUSCODE]);
        if(!response->removeResults) {
            response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
            return;
        }
        response->removeResultsSize = request->linksToRemoveSize;
    }

    if(request->linksToAddSize> 0) {
        response->addResults = (UA_StatusCode*)
            UA_Array_new(request->linksToAddSize, &UA_TYPES[UA_TYPES_STATUSCODE]);
        if(!response->addResults) {
            UA_Array_delete(response->removeResults,
                            request->linksToAddSize, &UA_TYPES[UA_TYPES_STATUSCODE]);
            response->removeResults = NULL;
            response->removeResultsSize = 0;
            response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
            return;
        }
        response->addResultsSize = request->linksToAddSize;
    }

    
    for(size_t i = 0; i < request->linksToRemoveSize; i++)
        response->removeResults[i] =
            UA_MonitoredItem_removeLink(sub, mon, request->linksToRemove[i]);

    for(size_t i = 0; i < request->linksToAddSize; i++)
        response->addResults[i] =
            UA_MonitoredItem_addLink(sub, mon, request->linksToAdd[i]);
}

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
static UA_StatusCode
checkEventFilterParam(UA_Server *server, UA_Session *session,
                      const UA_MonitoredItem *mon,
                      UA_MonitoringParameters *params,
                      UA_ExtensionObject *filterResult) {
    UA_assert(mon->itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER);

    
    if(params->filter.encoding != UA_EXTENSIONOBJECT_DECODED &&
       params->filter.encoding != UA_EXTENSIONOBJECT_DECODED_NODELETE)
        return UA_STATUSCODE_BADEVENTFILTERINVALID;
    if(params->filter.content.decoded.type != &UA_TYPES[UA_TYPES_EVENTFILTER])
        return UA_STATUSCODE_BADEVENTFILTERINVALID;

    UA_EventFilter *eventFilter = (UA_EventFilter *)params->filter.content.decoded.data;

    
    if(eventFilter->selectClausesSize == 0 ||
       eventFilter->selectClausesSize > UA_EVENTFILTER_MAXSELECT)
        return UA_STATUSCODE_BADEVENTFILTERINVALID;

    
    if(eventFilter->whereClause.elementsSize > UA_EVENTFILTER_MAXELEMENTS)
        return UA_STATUSCODE_BADEVENTFILTERINVALID;

    
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    const UA_ContentFilter *cf = &eventFilter->whereClause;
    UA_ContentFilterElementResult whereRes[UA_EVENTFILTER_MAXELEMENTS];
    for(size_t i = 0; i < cf->elementsSize; ++i) {
        UA_ContentFilterElement *ef = &cf->elements[i];
        whereRes[i] = UA_ContentFilterElementValidation(server, i, cf->elementsSize, ef);
        if(whereRes[i].statusCode != UA_STATUSCODE_GOOD && res == UA_STATUSCODE_GOOD)
            res = whereRes[i].statusCode;
    }

    
    UA_StatusCode selectRes[UA_EVENTFILTER_MAXSELECT];
    for(size_t i = 0; i < eventFilter->selectClausesSize; i++) {
        const UA_SimpleAttributeOperand *sao = &eventFilter->selectClauses[i];
        selectRes[i] = UA_SimpleAttributeOperandValidation(server, sao);
        if(selectRes[i] != UA_STATUSCODE_GOOD && res == UA_STATUSCODE_GOOD)
            res = selectRes[i];
    }

    
    if(res != UA_STATUSCODE_GOOD) {
        UA_EventFilterResult *efr = UA_EventFilterResult_new();
        if(!efr) {
            res = UA_STATUSCODE_BADOUTOFMEMORY;
        } else {
            UA_EventFilterResult tmp_efr;
            UA_EventFilterResult_init(&tmp_efr);
            tmp_efr.selectClauseResultsSize = eventFilter->selectClausesSize;
            tmp_efr.selectClauseResults = selectRes;
            tmp_efr.whereClauseResult.elementResultsSize = cf->elementsSize;
            tmp_efr.whereClauseResult.elementResults = whereRes;
            UA_EventFilterResult_copy(&tmp_efr, efr);
            UA_ExtensionObject_setValue(filterResult, efr,
                                        &UA_TYPES[UA_TYPES_EVENTFILTERRESULT]);
        }
    }

    for(size_t i = 0; i < cf->elementsSize; ++i)
        UA_ContentFilterElementResult_clear(&whereRes[i]);
    return res;
}
#endif


static UA_StatusCode
checkAdjustMonitoredItemParams(UA_Server *server, UA_Session *session,
                               const UA_MonitoredItem *mon,
                               const UA_DataType* valueType,
                               UA_MonitoringParameters *params,
                               UA_ExtensionObject *filterResult) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(mon->itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER) {
        
#ifndef UA_ENABLE_SUBSCRIPTIONS_EVENTS
        return UA_STATUSCODE_BADNOTSUPPORTED;
#else
        UA_StatusCode res = checkEventFilterParam(server, session, mon,
                                                  params, filterResult);
        if(res != UA_STATUSCODE_GOOD)
            return res;
#endif
    } else {
        if(params->filter.encoding != UA_EXTENSIONOBJECT_DECODED &&
           params->filter.encoding != UA_EXTENSIONOBJECT_DECODED_NODELETE &&
           params->filter.encoding != UA_EXTENSIONOBJECT_ENCODED_NOBODY)
            return UA_STATUSCODE_BADMONITOREDITEMFILTERUNSUPPORTED;

        if(params->filter.encoding != UA_EXTENSIONOBJECT_ENCODED_NOBODY &&
           params->filter.content.decoded.type != &UA_TYPES[UA_TYPES_DATACHANGEFILTER])
            return UA_STATUSCODE_BADFILTERNOTALLOWED;

        
        if(params->filter.content.decoded.type == &UA_TYPES[UA_TYPES_DATACHANGEFILTER]) {
            UA_DataChangeFilter *filter = (UA_DataChangeFilter *)
                params->filter.content.decoded.data;
            switch(filter->deadbandType) {
            case UA_DEADBANDTYPE_NONE:
                break;
            case UA_DEADBANDTYPE_ABSOLUTE:
                if(mon->itemToMonitor.attributeId != UA_ATTRIBUTEID_VALUE ||
                   !valueType || !UA_DataType_isNumeric(valueType))
                    return UA_STATUSCODE_BADFILTERNOTALLOWED;
                break;
#ifdef UA_ENABLE_DA
            case UA_DEADBANDTYPE_PERCENT: {
                if(mon->itemToMonitor.attributeId != UA_ATTRIBUTEID_VALUE ||
                   !valueType || !UA_DataType_isNumeric(valueType))
                    return UA_STATUSCODE_BADFILTERNOTALLOWED;
                UA_StatusCode res =
                    setAbsoluteFromPercentageDeadband(server, session, mon, filter);
                if(res != UA_STATUSCODE_GOOD)
                    return res;
                break;
            }
#endif
            default:
                return UA_STATUSCODE_BADMONITOREDITEMFILTERUNSUPPORTED;
            }
        }
    }

    if(mon->itemToMonitor.attributeId == UA_ATTRIBUTEID_VALUE) {
        const UA_Node *node = UA_NODESTORE_GET(server, &mon->itemToMonitor.nodeId);
        if(node) {
            const UA_VariableNode *vn = &node->variableNode;
            if(node->head.nodeClass == UA_NODECLASS_VARIABLE) {
                
                UA_Double samplingInterval = params->samplingInterval;
                if(samplingInterval < 0 && mon->subscription)
                    samplingInterval = mon->subscription->publishingInterval;
                
                if(samplingInterval < vn->minimumSamplingInterval)
                    params->samplingInterval = vn->minimumSamplingInterval;
            }
            UA_NODESTORE_RELEASE(server, node);
        }
    }
        

    if(mon->subscription && params->samplingInterval < 0.0)
        params->samplingInterval = mon->subscription->publishingInterval;

    
    if(params->samplingInterval != 0.0) {
        UA_BOUNDEDVALUE_SETWBOUNDS(server->config.samplingIntervalLimits,
                                   params->samplingInterval, params->samplingInterval);
        
        if(mon->parameters.samplingInterval != mon->parameters.samplingInterval)
            params->samplingInterval = server->config.samplingIntervalLimits.min;
    }

    
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    if(mon->itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER) {
        
        if(params->queueSize == 0) {
            params->queueSize = server->config.queueSizeLimits.max;
        } else {
            UA_BOUNDEDVALUE_SETWBOUNDS(server->config.queueSizeLimits,
                                       params->queueSize, params->queueSize);
        }
    } else
#endif
    {
        
        if(params->queueSize == 0)
            params->queueSize = 1;
        if(params->queueSize != 1)
            UA_BOUNDEDVALUE_SETWBOUNDS(server->config.queueSizeLimits,
                                       params->queueSize, params->queueSize);
    }

    return UA_STATUSCODE_GOOD;
}

static const UA_String
binaryEncoding = {sizeof("Default Binary") - 1, (UA_Byte *)"Default Binary"};


struct createMonContext {
    UA_Subscription *sub;
    UA_TimestampsToReturn timestampsToReturn;
    UA_LocalMonitoredItem *localMon; 
};

static void
Operation_CreateMonitoredItem(UA_Server *server, UA_Session *session,
                              struct createMonContext *cmc,
                              const UA_MonitoredItemCreateRequest *request,
                              UA_MonitoredItemCreateResult *result) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(!cmc->localMon &&
       (((server->config.maxMonitoredItems != 0) &&
         (server->monitoredItemsSize >= server->config.maxMonitoredItems)) ||
        ((server->config.maxMonitoredItemsPerSubscription != 0) &&
         (cmc->sub->monitoredItemsSize >= server->config.maxMonitoredItemsPerSubscription)))) {
        result->statusCode = UA_STATUSCODE_BADTOOMANYMONITOREDITEMS;
        return;
    }

    
    if(request->itemToMonitor.dataEncoding.name.length > 0 &&
       (!UA_String_equal(&binaryEncoding, &request->itemToMonitor.dataEncoding.name) ||
        request->itemToMonitor.dataEncoding.namespaceIndex != 0)) {
        result->statusCode = UA_STATUSCODE_BADDATAENCODINGUNSUPPORTED;
        return;
    }

    
    if(request->itemToMonitor.attributeId != UA_ATTRIBUTEID_VALUE &&
       request->itemToMonitor.dataEncoding.name.length > 0) {
        result->statusCode = UA_STATUSCODE_BADDATAENCODINGINVALID;
        return;
    }

    UA_DataValue v = readWithSession(server, session, &request->itemToMonitor,
                                     cmc->timestampsToReturn);
    if(v.hasStatus &&
       (v.status == UA_STATUSCODE_BADNODEIDUNKNOWN ||
        v.status == UA_STATUSCODE_BADATTRIBUTEIDINVALID ||
        v.status == UA_STATUSCODE_BADDATAENCODINGUNSUPPORTED ||
        v.status == UA_STATUSCODE_BADDATAENCODINGINVALID ||
        v.status == UA_STATUSCODE_BADINDEXRANGEINVALID
        )) {
        result->statusCode = v.status;
        UA_DataValue_clear(&v);
        return;
    }

    
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    if(request->itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER) {
        if(!v.hasValue || !v.value.data) {
            result->statusCode = UA_STATUSCODE_BADINTERNALERROR;
            UA_DataValue_clear(&v);
            return;
        }
        UA_Byte eventNotifierValue = *((UA_Byte *)v.value.data);
        if((eventNotifierValue & 0x01) != 1) {
            result->statusCode = UA_STATUSCODE_BADNOTSUPPORTED;
            UA_LOG_INFO_SUBSCRIPTION(server->config.logging, cmc->sub,
                                     "Could not create a MonitoredItem as the "
                                     "'SubscribeToEvents' bit of the EventNotifier "
                                     "attribute is not set");
            UA_DataValue_clear(&v);
            return;
        }
    }
#endif

    const UA_DataType *valueType = v.value.type;
    UA_DataValue_clear(&v);

    
    UA_MonitoredItem *newMon = NULL;
    if(cmc->localMon) {
        newMon = &cmc->localMon->monitoredItem;
        cmc->localMon = NULL; 
    } else {
        newMon = (UA_MonitoredItem*)UA_malloc(sizeof(UA_MonitoredItem));
        if(!newMon) {
            result->statusCode = UA_STATUSCODE_BADOUTOFMEMORY;
            return;
        }
    }

    
    UA_MonitoredItem_init(newMon);
    newMon->subscription = cmc->sub;
    newMon->timestampsToReturn = cmc->timestampsToReturn;
    result->statusCode |= UA_ReadValueId_copy(&request->itemToMonitor,
                                              &newMon->itemToMonitor);
    result->statusCode |= UA_MonitoringParameters_copy(&request->requestedParameters,
                                                       &newMon->parameters);
    result->statusCode |= checkAdjustMonitoredItemParams(server, session, newMon,
                                                         valueType, &newMon->parameters,
                                                         &result->filterResult);
    if(result->statusCode != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO_SUBSCRIPTION(server->config.logging, cmc->sub,
                                 "Could not create a MonitoredItem "
                                 "with StatusCode %s",
                                 UA_StatusCode_name(result->statusCode));
        UA_MonitoredItem_delete(server, newMon);
        return;
    }

    
    newMon->lastValue.hasStatus = true;
    newMon->lastValue.status = ~(UA_StatusCode)0;

    
    UA_Server_registerMonitoredItem(server, newMon);

    
    result->statusCode = UA_MonitoredItem_setMonitoringMode(server, newMon,
                                                            request->monitoringMode);
    if(result->statusCode != UA_STATUSCODE_GOOD) {
        UA_MonitoredItem_delete(server, newMon);
        return;
    }

    
    result->revisedSamplingInterval = newMon->parameters.samplingInterval;
    result->revisedQueueSize = newMon->parameters.queueSize;
    result->monitoredItemId = newMon->monitoredItemId;

    UA_LOG_INFO_SUBSCRIPTION(server->config.logging, cmc->sub,
                             "MonitoredItem %" PRIi32 " | "
                             "Created the MonitoredItem "
                             "(Sampling Interval: %.2fms, Queue Size: %lu)",
                             newMon->monitoredItemId,
                             newMon->parameters.samplingInterval,
                             (unsigned long)newMon->parameters.queueSize);
}

void
Service_CreateMonitoredItems(UA_Server *server, UA_Session *session,
                             const UA_CreateMonitoredItemsRequest *request,
                             UA_CreateMonitoredItemsResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing CreateMonitoredItemsRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(server->config.maxMonitoredItemsPerCall != 0 &&
       request->itemsToCreateSize > server->config.maxMonitoredItemsPerCall) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    
    if(request->timestampsToReturn < UA_TIMESTAMPSTORETURN_SOURCE ||
       request->timestampsToReturn > UA_TIMESTAMPSTORETURN_NEITHER) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTIMESTAMPSTORETURNINVALID;
        return;
    }

    
    UA_Subscription *sub = UA_Session_getSubscriptionById(session, request->subscriptionId);
    if(!sub) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
    Subscription_resetLifetime(sub);

    
    struct createMonContext cmc;
    cmc.timestampsToReturn = request->timestampsToReturn;
    cmc.sub = sub;
    cmc.localMon = NULL;

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_CreateMonitoredItem,
                                           &cmc, &request->itemsToCreateSize,
                                           &UA_TYPES[UA_TYPES_MONITOREDITEMCREATEREQUEST],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_MONITOREDITEMCREATERESULT]);
}

UA_MonitoredItemCreateResult
UA_Server_createDataChangeMonitoredItem(UA_Server *server,
                                        UA_TimestampsToReturn timestampsToReturn,
                                        const UA_MonitoredItemCreateRequest item,
                                        void *monitoredItemContext,
                                        UA_Server_DataChangeNotificationCallback callback) {
    UA_MonitoredItemCreateResult result;
    UA_MonitoredItemCreateResult_init(&result);

    
    if(item.itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "DataChange-MonitoredItem cannot be created for the "
                     "EventNotifier attribute");
        result.statusCode = UA_STATUSCODE_BADINTERNALERROR;
        return result;
    }

    
    UA_LocalMonitoredItem *localMon = (UA_LocalMonitoredItem*)
        UA_calloc(1, sizeof(UA_LocalMonitoredItem));
    if(!localMon) {
        result.statusCode = UA_STATUSCODE_BADOUTOFMEMORY;
        return result;
    }
    localMon->context = monitoredItemContext;
    localMon->callback.dataChangeCallback = callback;

    
    struct createMonContext cmc;
    cmc.sub = server->adminSubscription;
    cmc.localMon = localMon;
    cmc.timestampsToReturn = timestampsToReturn;

    UA_LOCK(&server->serviceMutex);
    Operation_CreateMonitoredItem(server, &server->adminSession, &cmc, &item, &result);
    UA_UNLOCK(&server->serviceMutex);

    
    if(result.statusCode != UA_STATUSCODE_GOOD && cmc.localMon)
        UA_free(localMon);

    return result;
}

UA_MonitoredItemCreateResult
UA_Server_createEventMonitoredItemEx(UA_Server *server,
                                     const UA_MonitoredItemCreateRequest item,
                                     void *monitoredItemContext,
                                     UA_Server_EventNotificationCallback callback) {
    UA_MonitoredItemCreateResult result;
    UA_MonitoredItemCreateResult_init(&result);

    
    if(item.itemToMonitor.attributeId != UA_ATTRIBUTEID_EVENTNOTIFIER) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "Event-MonitoredItem must monitor the EventNotifier attribute");
        result.statusCode = UA_STATUSCODE_BADINTERNALERROR;
        return result;
    }

    const UA_ExtensionObject *filter = &item.requestedParameters.filter;
    if((filter->encoding != UA_EXTENSIONOBJECT_DECODED &&
        filter->encoding != UA_EXTENSIONOBJECT_DECODED_NODELETE) ||
       filter->content.decoded.type != &UA_TYPES[UA_TYPES_EVENTFILTER]) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "Filter is not of EventFilter data type");
        result.statusCode = UA_STATUSCODE_BADINTERNALERROR;
        return result;
    }

    UA_EventFilter *ef = (UA_EventFilter*)filter->content.decoded.data;
    if(ef->selectClausesSize == 0) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "Event filter must define at least one select clause");
        result.statusCode = UA_STATUSCODE_BADINTERNALERROR;
        return result;
    }

    
    UA_LocalMonitoredItem *localMon = (UA_LocalMonitoredItem*)
        UA_calloc(1, sizeof(UA_LocalMonitoredItem));
    if(!localMon) {
        result.statusCode = UA_STATUSCODE_BADOUTOFMEMORY;
        return result;
    }
    localMon->context = monitoredItemContext;
    localMon->callback.eventCallback = callback;

    
    localMon->eventFields.map = (UA_KeyValuePair*)
        UA_calloc(ef->selectClausesSize, sizeof(UA_KeyValuePair));
    if(!localMon->eventFields.map) {
        UA_free(localMon);
        result.statusCode = UA_STATUSCODE_BADOUTOFMEMORY;
        return result;
    }
    localMon->eventFields.mapSize = ef->selectClausesSize;

#ifdef UA_ENABLE_PARSING
    for(size_t i = 0; i < ef->selectClausesSize; i++) {
        result.statusCode |=
            UA_SimpleAttributeOperand_print(&ef->selectClauses[i],
                                            &localMon->eventFields.map[i].key.name);
    }
    if(result.statusCode != UA_STATUSCODE_GOOD) {
        UA_KeyValueMap_clear(&localMon->eventFields);
        UA_free(localMon);
        return result;
    }
#endif

    
    struct createMonContext cmc;
    cmc.sub = server->adminSubscription;
    cmc.localMon = localMon;
    cmc.timestampsToReturn = UA_TIMESTAMPSTORETURN_NEITHER;

    UA_LOCK(&server->serviceMutex);
    Operation_CreateMonitoredItem(server, &server->adminSession, &cmc, &item, &result);
    UA_UNLOCK(&server->serviceMutex);

    
    if(result.statusCode != UA_STATUSCODE_GOOD && cmc.localMon) {
        UA_KeyValueMap_clear(&localMon->eventFields);
        UA_free(localMon);
    }
    return result;
}

UA_MonitoredItemCreateResult
UA_Server_createEventMonitoredItem(UA_Server *server, const UA_NodeId nodeId,
                                   const UA_EventFilter filter, void *monitoredItemContext,
                                   UA_Server_EventNotificationCallback callback) {
    UA_MonitoredItemCreateRequest item;
    UA_MonitoredItemCreateRequest_init(&item);
    item.itemToMonitor.nodeId = nodeId;
    item.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    item.monitoringMode = UA_MONITORINGMODE_REPORTING;
    UA_ExtensionObject_setValue(&item.requestedParameters.filter,
                                (void*)(uintptr_t)&filter,
                                &UA_TYPES[UA_TYPES_EVENTFILTER]);
    return UA_Server_createEventMonitoredItemEx(server, item, monitoredItemContext, callback);
}

static void
Operation_ModifyMonitoredItem(UA_Server *server, UA_Session *session, UA_Subscription *sub,
                              const UA_MonitoredItemModifyRequest *request,
                              UA_MonitoredItemModifyResult *result) {
    
    UA_MonitoredItem *mon = UA_Subscription_getMonitoredItem(sub, request->monitoredItemId);
    if(!mon) {
        result->statusCode = UA_STATUSCODE_BADMONITOREDITEMIDINVALID;
        return;
    }

    
    UA_MonitoringParameters params;
    result->statusCode =
        UA_MonitoringParameters_copy(&request->requestedParameters, &params);
    if(result->statusCode != UA_STATUSCODE_GOOD)
        return;

    UA_DataValue v = readWithSession(server, session, &mon->itemToMonitor,
                                     mon->timestampsToReturn);

    result->statusCode =
        checkAdjustMonitoredItemParams(server, session, mon, v.value.type,
                                       &params, &result->filterResult);
    UA_DataValue_clear(&v);
    if(result->statusCode != UA_STATUSCODE_GOOD) {
        UA_MonitoringParameters_clear(&params);
        return;
    }

    
    UA_Double oldSamplingInterval = mon->parameters.samplingInterval;

    
    UA_MonitoringParameters_clear(&mon->parameters);
    mon->parameters = params;

    
    if(oldSamplingInterval != mon->parameters.samplingInterval) {
        UA_MonitoredItem_unregisterSampling(server, mon);
        result->statusCode =
            UA_MonitoredItem_setMonitoringMode(server, mon, mon->monitoringMode);
    }

    result->revisedSamplingInterval = mon->parameters.samplingInterval;
    result->revisedQueueSize = mon->parameters.queueSize;

    if(result->revisedSamplingInterval < 0.0 && mon->subscription)
        result->revisedSamplingInterval = mon->subscription->publishingInterval;

    
    UA_MonitoredItem_ensureQueueSpace(server, mon);

    
    UA_MonitoredItem_removeOverflowInfoBits(mon);

    if(result->revisedSamplingInterval < 0.0 && mon->subscription)
        result->revisedSamplingInterval = mon->subscription->publishingInterval;

    UA_LOG_INFO_SUBSCRIPTION(server->config.logging, sub,
                             "MonitoredItem %" PRIi32 " | "
                             "Modified the MonitoredItem "
                             "(Sampling Interval: %fms, Queue Size: %lu)",
                             mon->monitoredItemId,
                             mon->parameters.samplingInterval,
                             (unsigned long)mon->queueSize);
}

void
Service_ModifyMonitoredItems(UA_Server *server, UA_Session *session,
                             const UA_ModifyMonitoredItemsRequest *request,
                             UA_ModifyMonitoredItemsResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing ModifyMonitoredItemsRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(server->config.maxMonitoredItemsPerCall != 0 &&
       request->itemsToModifySize > server->config.maxMonitoredItemsPerCall) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    
    if(request->timestampsToReturn > UA_TIMESTAMPSTORETURN_NEITHER) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTIMESTAMPSTORETURNINVALID;
        return;
    }

    
    UA_Subscription *sub = UA_Session_getSubscriptionById(session, request->subscriptionId);
    if(!sub) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
    Subscription_resetLifetime(sub);

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_ModifyMonitoredItem,
                                           sub, &request->itemsToModifySize,
                                           &UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYREQUEST],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYRESULT]);
}

struct setMonitoringContext {
    UA_Subscription *sub;
    UA_MonitoringMode monitoringMode;
};

static void
Operation_SetMonitoringMode(UA_Server *server, UA_Session *session,
                            struct setMonitoringContext *smc,
                            const UA_UInt32 *monitoredItemId, UA_StatusCode *result) {
    UA_MonitoredItem *mon = UA_Subscription_getMonitoredItem(smc->sub, *monitoredItemId);
    if(!mon) {
        *result = UA_STATUSCODE_BADMONITOREDITEMIDINVALID;
        return;
    }
    *result = UA_MonitoredItem_setMonitoringMode(server, mon, smc->monitoringMode);
}

void
Service_SetMonitoringMode(UA_Server *server, UA_Session *session,
                          const UA_SetMonitoringModeRequest *request,
                          UA_SetMonitoringModeResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session, "Processing SetMonitoringMode");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(server->config.maxMonitoredItemsPerCall != 0 &&
       request->monitoredItemIdsSize > server->config.maxMonitoredItemsPerCall) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    
    UA_Subscription *sub = UA_Session_getSubscriptionById(session, request->subscriptionId);
    if(!sub) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
    Subscription_resetLifetime(sub);

    
    struct setMonitoringContext smc;
    smc.sub = sub;
    smc.monitoringMode = request->monitoringMode;

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_SetMonitoringMode,
                                           &smc, &request->monitoredItemIdsSize,
                                           &UA_TYPES[UA_TYPES_UINT32],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_STATUSCODE]);
}

static void
Operation_DeleteMonitoredItem(UA_Server *server, UA_Session *session, UA_Subscription *sub,
                              const UA_UInt32 *monitoredItemId, UA_StatusCode *result) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_MonitoredItem *mon = UA_Subscription_getMonitoredItem(sub, *monitoredItemId);
    if(!mon) {
        *result = UA_STATUSCODE_BADMONITOREDITEMIDINVALID;
        return;
    }
    UA_MonitoredItem_delete(server, mon);
}

void
Service_DeleteMonitoredItems(UA_Server *server, UA_Session *session,
                             const UA_DeleteMonitoredItemsRequest *request,
                             UA_DeleteMonitoredItemsResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing DeleteMonitoredItemsRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(server->config.maxMonitoredItemsPerCall != 0 &&
       request->monitoredItemIdsSize > server->config.maxMonitoredItemsPerCall) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    
    UA_Subscription *sub = UA_Session_getSubscriptionById(session, request->subscriptionId);
    if(!sub) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
    Subscription_resetLifetime(sub);

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_DeleteMonitoredItem,
                                           sub, &request->monitoredItemIdsSize,
                                           &UA_TYPES[UA_TYPES_UINT32],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_STATUSCODE]);
}

UA_StatusCode
UA_Server_deleteMonitoredItem(UA_Server *server, UA_UInt32 monitoredItemId) {
    UA_LOCK(&server->serviceMutex);

    UA_Subscription *sub = server->adminSubscription;
    UA_MonitoredItem *mon;
    LIST_FOREACH(mon, &sub->monitoredItems, listEntry) {
        if(mon->monitoredItemId == monitoredItemId)
            break;
    }

    UA_StatusCode res = UA_STATUSCODE_BADMONITOREDITEMIDINVALID;
    if(mon) {
        UA_MonitoredItem_delete(server, mon);
        res = UA_STATUSCODE_GOOD;
    }

    UA_UNLOCK(&server->serviceMutex);
    return res;
}

#endif 
