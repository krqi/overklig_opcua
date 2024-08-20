
#include "ua_server_internal.h"
#include "ua_services.h"
#include "ua_subscription.h"

#ifdef UA_ENABLE_SUBSCRIPTIONS 

static void
setSubscriptionSettings(UA_Server *server, UA_Subscription *subscription,
                        UA_Double requestedPublishingInterval,
                        UA_UInt32 requestedLifetimeCount,
                        UA_UInt32 requestedMaxKeepAliveCount,
                        UA_UInt32 maxNotificationsPerPublish,
                        UA_Byte priority) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_BOUNDEDVALUE_SETWBOUNDS(server->config.publishingIntervalLimits,
                               requestedPublishingInterval,
                               subscription->publishingInterval);
    
    if(requestedPublishingInterval != requestedPublishingInterval)
        subscription->publishingInterval = server->config.publishingIntervalLimits.min;
    UA_BOUNDEDVALUE_SETWBOUNDS(server->config.keepAliveCountLimits,
                               requestedMaxKeepAliveCount, subscription->maxKeepAliveCount);
    UA_BOUNDEDVALUE_SETWBOUNDS(server->config.lifeTimeCountLimits,
                               requestedLifetimeCount, subscription->lifeTimeCount);
    if(subscription->lifeTimeCount < 3 * subscription->maxKeepAliveCount)
        subscription->lifeTimeCount = 3 * subscription->maxKeepAliveCount;
    subscription->notificationsPerPublish = maxNotificationsPerPublish;
    if(maxNotificationsPerPublish == 0 ||
       maxNotificationsPerPublish > server->config.maxNotificationsPerPublish)
        subscription->notificationsPerPublish = server->config.maxNotificationsPerPublish;
    subscription->priority = priority;
}

void
Service_CreateSubscription(UA_Server *server, UA_Session *session,
                           const UA_CreateSubscriptionRequest *request,
                           UA_CreateSubscriptionResponse *response) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(((server->config.maxSubscriptions != 0) &&
        (server->subscriptionsSize >= server->config.maxSubscriptions)) ||
       ((server->config.maxSubscriptionsPerSession != 0) &&
        (session->subscriptionsSize >= server->config.maxSubscriptionsPerSession))) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYSUBSCRIPTIONS;
        return;
    }

    
    UA_Subscription *sub = UA_Subscription_new();
    if(!sub) {
        UA_LOG_DEBUG_SESSION(server->config.logging, session,
                             "Processing CreateSubscriptionRequest failed");
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }

    
    setSubscriptionSettings(server, sub, request->requestedPublishingInterval,
                            request->requestedLifetimeCount,
                            request->requestedMaxKeepAliveCount,
                            request->maxNotificationsPerPublish, request->priority);
    sub->subscriptionId = ++server->lastSubscriptionId;  

    
    LIST_INSERT_HEAD(&server->subscriptions, sub, serverListEntry);
    server->subscriptionsSize++;

    
    server->serverDiagnosticsSummary.currentSubscriptionCount++;
    server->serverDiagnosticsSummary.cumulatedSubscriptionCount++;

    
    UA_Session_attachSubscription(session, sub);

    
#ifdef UA_ENABLE_DIAGNOSTICS
    createSubscriptionObject(server, session, sub);
#endif

    UA_SubscriptionState sState = (request->publishingEnabled) ?
        UA_SUBSCRIPTIONSTATE_ENABLED : UA_SUBSCRIPTIONSTATE_ENABLED_NOPUBLISH;
    UA_StatusCode res = Subscription_setState(server, sub, sState);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_DEBUG_SESSION(server->config.logging, sub->session,
                             "Subscription %" PRIu32 " | Could not register "
                             "publish callback with error code %s",
                             sub->subscriptionId, UA_StatusCode_name(res));
        response->responseHeader.serviceResult = res;
        UA_Subscription_delete(server, sub);
        return;
    }

    UA_LOG_INFO_SUBSCRIPTION(server->config.logging, sub,
                             "Subscription created (Publishing interval %.2fms, "
                             "max %lu notifications per publish)",
                             sub->publishingInterval,
                             (long unsigned)sub->notificationsPerPublish);

    
    response->subscriptionId = sub->subscriptionId;
    response->revisedPublishingInterval = sub->publishingInterval;
    response->revisedLifetimeCount = sub->lifeTimeCount;
    response->revisedMaxKeepAliveCount = sub->maxKeepAliveCount;
}

void
Service_ModifySubscription(UA_Server *server, UA_Session *session,
                           const UA_ModifySubscriptionRequest *request,
                           UA_ModifySubscriptionResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing ModifySubscriptionRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_Subscription *sub = UA_Session_getSubscriptionById(session, request->subscriptionId);
    if(!sub) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
    UA_Double oldPublishingInterval = sub->publishingInterval;
    UA_Byte oldPriority = sub->priority;

    
    setSubscriptionSettings(server, sub, request->requestedPublishingInterval,
                            request->requestedLifetimeCount,
                            request->requestedMaxKeepAliveCount,
                            request->maxNotificationsPerPublish, request->priority);

    
    Subscription_resetLifetime(sub);

    
    if(sub->publishingInterval != oldPublishingInterval) {
        if(sub->publishCallbackId > 0)
            changeRepeatedCallbackInterval(server, sub->publishCallbackId,
                                           sub->publishingInterval);

        UA_MonitoredItem *mon;
        LIST_FOREACH(mon, &sub->monitoredItems, listEntry) {
            if(mon->parameters.samplingInterval == sub->publishingInterval ||
               mon->parameters.samplingInterval == oldPublishingInterval) {
                UA_MonitoredItem_unregisterSampling(server, mon);
                UA_MonitoredItem_registerSampling(server, mon);
            }
        }
    }

    if(oldPriority != sub->priority) {
        UA_Session_detachSubscription(server, session, sub, false);
        UA_Session_attachSubscription(session, sub);
    }

    
    response->revisedPublishingInterval = sub->publishingInterval;
    response->revisedLifetimeCount = sub->lifeTimeCount;
    response->revisedMaxKeepAliveCount = sub->maxKeepAliveCount;

    
#ifdef UA_ENABLE_DIAGNOSTICS
    sub->modifyCount++;
#endif
}

static void
Operation_SetPublishingMode(UA_Server *server, UA_Session *session,
                            const UA_Boolean *publishingEnabled,
                            const UA_UInt32 *subscriptionId,
                            UA_StatusCode *result) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_Subscription *sub = UA_Session_getSubscriptionById(session, *subscriptionId);
    if(!sub) {
        *result = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
    UA_SubscriptionState sState = (*publishingEnabled) ?
        UA_SUBSCRIPTIONSTATE_ENABLED : UA_SUBSCRIPTIONSTATE_ENABLED_NOPUBLISH;
    *result = Subscription_setState(server, sub, sState);

    
    Subscription_resetLifetime(sub);
}

void
Service_SetPublishingMode(UA_Server *server, UA_Session *session,
                          const UA_SetPublishingModeRequest *request,
                          UA_SetPublishingModeResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing SetPublishingModeRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_Boolean publishingEnabled = request->publishingEnabled; 
    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_SetPublishingMode,
                                           &publishingEnabled,
                                           &request->subscriptionIdsSize,
                                           &UA_TYPES[UA_TYPES_UINT32],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_STATUSCODE]);
}

UA_StatusCode
Service_Publish(UA_Server *server, UA_Session *session,
                const UA_PublishRequest *request, UA_UInt32 requestId) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing PublishRequest with RequestId %u", requestId);
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(TAILQ_EMPTY(&session->subscriptions))
        return UA_STATUSCODE_BADNOSUBSCRIPTION;

    UA_Session_ensurePublishQueueSpace(server, session);

    
    UA_PublishResponseEntry *entry = (UA_PublishResponseEntry *)
        UA_malloc(sizeof(UA_PublishResponseEntry));
    if(!entry)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    
    entry->requestId = requestId;
    UA_PublishResponse *response = &entry->response;
    UA_PublishResponse_init(response);
    response->responseHeader.requestHandle = request->requestHeader.requestHandle;

    
    if(request->subscriptionAcknowledgementsSize > 0) {
        response->results = (UA_StatusCode *)
            UA_Array_new(request->subscriptionAcknowledgementsSize,
                         &UA_TYPES[UA_TYPES_STATUSCODE]);
        if(!response->results) {
            UA_free(entry);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        response->resultsSize = request->subscriptionAcknowledgementsSize;
    }

    

    
    for(size_t i = 0; i < request->subscriptionAcknowledgementsSize; ++i) {
        UA_SubscriptionAcknowledgement *ack = &request->subscriptionAcknowledgements[i];
        UA_Subscription *sub = UA_Session_getSubscriptionById(session, ack->subscriptionId);
        if(!sub) {
            response->results[i] = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
            UA_LOG_DEBUG_SESSION(server->config.logging, session,
                                 "Cannot process acknowledgements subscription %u" PRIu32,
                                 ack->subscriptionId);
            continue;
        }
        
        response->results[i] =
            UA_Subscription_removeRetransmissionMessage(sub, ack->sequenceNumber);
    }

    
    entry->maxTime = UA_INT64_MAX;
    if(request->requestHeader.timeoutHint > 0) {
        UA_EventLoop *el = server->config.eventLoop;
        entry->maxTime = el->dateTime_nowMonotonic(el) +
            (request->requestHeader.timeoutHint * UA_DATETIME_MSEC);
    }

    UA_Session_queuePublishReq(session, entry, false);
    UA_LOG_DEBUG_SESSION(server->config.logging, session, "Queued a publication message");

    UA_Subscription *late, *late_tmp;
    TAILQ_FOREACH_SAFE(late, &session->subscriptions, sessionListEntry, late_tmp) {
        
        if(!late->late)
            continue;

        
        UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, late,
                                  "Send PublishResponse on a late subscription");
        UA_Subscription_publish(server, late);

        if(late->state >= UA_SUBSCRIPTIONSTATE_ENABLED_NOPUBLISH) {
            UA_Subscription *after = TAILQ_NEXT(late, sessionListEntry);
            while(after && after->priority >= late->priority)
                after = TAILQ_NEXT(after, sessionListEntry);
            TAILQ_REMOVE(&session->subscriptions, late, sessionListEntry);
            if(after)
                TAILQ_INSERT_BEFORE(after, late, sessionListEntry);
            else
                TAILQ_INSERT_TAIL(&session->subscriptions, late, sessionListEntry);
        }

        
        if(session->responseQueueSize == 0)
            break;
    }

    return UA_STATUSCODE_GOOD;
}

static void
Operation_DeleteSubscription(UA_Server *server, UA_Session *session, void *_,
                             const UA_UInt32 *subscriptionId, UA_StatusCode *result) {
    UA_Subscription *sub = UA_Session_getSubscriptionById(session, *subscriptionId);
    if(!sub) {
        *result = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        UA_LOG_DEBUG_SESSION(server->config.logging, session,
                             "Deleting Subscription with Id %" PRIu32
                             " failed with error code %s",
                             *subscriptionId, UA_StatusCode_name(*result));
        return;
    }

    UA_Subscription_delete(server, sub);
    *result = UA_STATUSCODE_GOOD;
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Subscription %" PRIu32 " | Subscription deleted",
                         *subscriptionId);
}

void
Service_DeleteSubscriptions(UA_Server *server, UA_Session *session,
                            const UA_DeleteSubscriptionsRequest *request,
                            UA_DeleteSubscriptionsResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing DeleteSubscriptionsRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                  (UA_ServiceOperation)Operation_DeleteSubscription, NULL,
                  &request->subscriptionIdsSize, &UA_TYPES[UA_TYPES_UINT32],
                  &response->resultsSize, &UA_TYPES[UA_TYPES_STATUSCODE]);
}

void
Service_Republish(UA_Server *server, UA_Session *session,
                  const UA_RepublishRequest *request,
                  UA_RepublishResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing RepublishRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_Subscription *sub = UA_Session_getSubscriptionById(session, request->subscriptionId);
    if(!sub) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
    Subscription_resetLifetime(sub);

    
#ifdef UA_ENABLE_DIAGNOSTICS
    sub->republishRequestCount++;
#endif

    
    UA_NotificationMessageEntry *entry;
    TAILQ_FOREACH(entry, &sub->retransmissionQueue, listEntry) {
        if(entry->message.sequenceNumber == request->retransmitSequenceNumber)
            break;
    }
    if(!entry) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADMESSAGENOTAVAILABLE;
        return;
    }

    response->responseHeader.serviceResult =
        UA_NotificationMessage_copy(&entry->message, &response->notificationMessage);

    
#ifdef UA_ENABLE_DIAGNOSTICS
    sub->republishMessageCount++;
#endif
}

static UA_StatusCode
setTransferredSequenceNumbers(const UA_Subscription *sub, UA_TransferResult *result) {
    
    result->availableSequenceNumbers = (UA_UInt32*)
        UA_Array_new(sub->retransmissionQueueSize, &UA_TYPES[UA_TYPES_UINT32]);
    if(!result->availableSequenceNumbers)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    result->availableSequenceNumbersSize = sub->retransmissionQueueSize;

    
    UA_NotificationMessageEntry *entry;
    size_t i = 0;
    TAILQ_FOREACH(entry, &sub->retransmissionQueue, listEntry) {
        result->availableSequenceNumbers[i] = entry->message.sequenceNumber;
        i++;
    }

    UA_assert(i == result->availableSequenceNumbersSize);

    return UA_STATUSCODE_GOOD;
}

static void
Operation_TransferSubscription(UA_Server *server, UA_Session *session,
                               const UA_Boolean *sendInitialValues,
                               const UA_UInt32 *subscriptionId,
                               UA_TransferResult *result) {
    UA_Subscription *sub = getSubscriptionById(server, *subscriptionId);
    if(!sub) {
        result->statusCode = UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
        return;
    }

    
#ifdef UA_ENABLE_DIAGNOSTICS
    sub->transferRequestCount++;
#endif

    
    UA_Session *oldSession = sub->session;
    if(oldSession == session) {
        result->statusCode = setTransferredSequenceNumbers(sub, result);
#ifdef UA_ENABLE_DIAGNOSTICS
        sub->transferredToSameClientCount++;
#endif
        return;
    }

    
    if(server->config.accessControl.allowTransferSubscription) {
        UA_LOCK_ASSERT(&server->serviceMutex, 1);
        UA_UNLOCK(&server->serviceMutex);
        if(!server->config.accessControl.
           allowTransferSubscription(server, &server->config.accessControl,
                                     oldSession ? &oldSession->sessionId : NULL,
                                     oldSession ? oldSession->context : NULL,
                                     &session->sessionId, session->context)) {
            UA_LOCK(&server->serviceMutex);
            result->statusCode = UA_STATUSCODE_BADUSERACCESSDENIED;
            return;
        }
        UA_LOCK(&server->serviceMutex);
    } else {
        result->statusCode = UA_STATUSCODE_BADUSERACCESSDENIED;
        return;
    }

    
    if((server->config.maxSubscriptionsPerSession != 0) &&
       (session->subscriptionsSize >= server->config.maxSubscriptionsPerSession)) {
        result->statusCode = UA_STATUSCODE_BADTOOMANYSUBSCRIPTIONS;
        return;
    }

    
    UA_Subscription *newSub = (UA_Subscription*)UA_malloc(sizeof(UA_Subscription));
    if(!newSub) {
        result->statusCode = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }

    
    result->statusCode = setTransferredSequenceNumbers(sub, result);
    if(result->statusCode != UA_STATUSCODE_GOOD) {
        UA_free(newSub);
        return;
    }

    memcpy(newSub, sub, sizeof(UA_Subscription));

    
    newSub->publishCallbackId = 0;
    result->statusCode = Subscription_setState(server, newSub, sub->state);
    if(result->statusCode != UA_STATUSCODE_GOOD) {
        UA_Array_delete(result->availableSequenceNumbers,
                        sub->retransmissionQueueSize, &UA_TYPES[UA_TYPES_UINT32]);
        result->availableSequenceNumbers = NULL;
        result->availableSequenceNumbersSize = 0;
        UA_free(newSub);
        return;
    }

    

    
    LIST_INIT(&newSub->monitoredItems);
    UA_MonitoredItem *mon, *mon_tmp;
    LIST_FOREACH_SAFE(mon, &sub->monitoredItems, listEntry, mon_tmp) {
        LIST_REMOVE(mon, listEntry);
        mon->subscription = newSub;
        LIST_INSERT_HEAD(&newSub->monitoredItems, mon, listEntry);
    }
    sub->monitoredItemsSize = 0;

    
    TAILQ_INIT(&newSub->notificationQueue);
    UA_Notification *nn, *nn_tmp;
    TAILQ_FOREACH_SAFE(nn, &sub->notificationQueue, subEntry, nn_tmp) {
        TAILQ_REMOVE(&sub->notificationQueue, nn, subEntry);
        TAILQ_INSERT_TAIL(&newSub->notificationQueue, nn, subEntry);
    }
    sub->notificationQueueSize = 0;
    sub->dataChangeNotifications = 0;
    sub->eventNotifications = 0;

    TAILQ_INIT(&newSub->retransmissionQueue);
    UA_NotificationMessageEntry *nme, *nme_tmp;
    TAILQ_FOREACH_SAFE(nme, &sub->retransmissionQueue, listEntry, nme_tmp) {
        TAILQ_REMOVE(&sub->retransmissionQueue, nme, listEntry);
        TAILQ_INSERT_TAIL(&newSub->retransmissionQueue, nme, listEntry);
        if(oldSession)
            oldSession->totalRetransmissionQueueSize -= 1;
        sub->retransmissionQueueSize -= 1;
    }
    UA_assert(sub->retransmissionQueueSize == 0);
    sub->retransmissionQueueSize = 0;

    
    UA_assert(newSub->subscriptionId == sub->subscriptionId);
    LIST_INSERT_HEAD(&server->subscriptions, newSub, serverListEntry);
    server->subscriptionsSize++;

    
    UA_Session_attachSubscription(session, newSub);

    UA_LOG_INFO_SUBSCRIPTION(server->config.logging, newSub, "Transferred to this Session");

    sub->statusChange = UA_STATUSCODE_GOODSUBSCRIPTIONTRANSFERRED;
    UA_Subscription_publish(server, sub);

    
    if(*sendInitialValues)
        UA_Subscription_resendData(server, newSub);

#ifdef UA_ENABLE_DIAGNOSTICS
    if(oldSession &&
       UA_equal(&oldSession->clientDescription, &session->clientDescription,
                &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]))
        sub->transferredToSameClientCount++;
    else
        sub->transferredToAltClientCount++;
#endif
}

void Service_TransferSubscriptions(UA_Server *server, UA_Session *session,
                                   const UA_TransferSubscriptionsRequest *request,
                                   UA_TransferSubscriptionsResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing TransferSubscriptionsRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                  (UA_ServiceOperation)Operation_TransferSubscription,
                  &request->sendInitialValues,
                  &request->subscriptionIdsSize, &UA_TYPES[UA_TYPES_UINT32],
                  &response->resultsSize, &UA_TYPES[UA_TYPES_TRANSFERRESULT]);
}

#endif 
