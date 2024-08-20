
#include "ua_server_internal.h"
#include "ua_subscription.h"
#include "itoa.h"

#ifdef UA_ENABLE_SUBSCRIPTIONS 

#define UA_MAX_RETRANSMISSIONQUEUESIZE 256





static void UA_Notification_dequeueMon(UA_Notification *n);
static void UA_Notification_enqueueSub(UA_Notification *n);
static void UA_Notification_dequeueSub(UA_Notification *n);

UA_Notification *
UA_Notification_new(void) {
    UA_Notification *n = (UA_Notification*)UA_calloc(1, sizeof(UA_Notification));
    if(n) {
        TAILQ_NEXT(n, subEntry) = UA_SUBSCRIPTION_QUEUE_SENTINEL;
    }
    return n;
}


static void
UA_Notification_delete(UA_Notification *n) {
    UA_assert(n != UA_SUBSCRIPTION_QUEUE_SENTINEL);
    UA_assert(n->mon);
    UA_Notification_dequeueMon(n);
    UA_Notification_dequeueSub(n);
    switch(n->mon->itemToMonitor.attributeId) {
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    case UA_ATTRIBUTEID_EVENTNOTIFIER:
        UA_EventFieldList_clear(&n->data.event);
        break;
#endif
    default:
        UA_MonitoredItemNotification_clear(&n->data.dataChange);
        break;
    }
    UA_free(n);
}


static void
UA_Notification_enqueueMon(UA_Server *server, UA_Notification *n) {
    UA_MonitoredItem *mon = n->mon;
    UA_assert(mon);

    
    TAILQ_INSERT_TAIL(&mon->queue, n, monEntry);
    ++mon->queueSize;

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    if(n->isOverflowEvent)
        ++mon->eventOverflows;
#endif

    
    UA_assert(mon->queueSize >= mon->eventOverflows);
    UA_assert(mon->eventOverflows <= mon->queueSize - mon->eventOverflows + 1);

    UA_MonitoredItem_ensureQueueSpace(server, mon);

    UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, mon->subscription,
                              "MonitoredItem %" PRIi32 " | "
                              "Notification enqueued (Queue size %lu / %lu)",
                              mon->monitoredItemId,
                              (long unsigned)mon->queueSize,
                              (long unsigned)mon->parameters.queueSize);
}

static void
UA_Notification_enqueueSub(UA_Notification *n) {
    UA_MonitoredItem *mon = n->mon;
    UA_assert(mon);

    UA_Subscription *sub = mon->subscription;
    UA_assert(sub);

    if(TAILQ_NEXT(n, subEntry) != UA_SUBSCRIPTION_QUEUE_SENTINEL)
        return;

    
    TAILQ_INSERT_TAIL(&sub->notificationQueue, n, subEntry);
    ++sub->notificationQueueSize;

    switch(mon->itemToMonitor.attributeId) {
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    case UA_ATTRIBUTEID_EVENTNOTIFIER:
        ++sub->eventNotifications;
        break;
#endif
    default:
        ++sub->dataChangeNotifications;
        break;
    }
}

void
UA_Notification_enqueueAndTrigger(UA_Server *server, UA_Notification *n) {
    UA_MonitoredItem *mon = n->mon;
    UA_Subscription *sub = mon->subscription;

    UA_EventLoop *el = server->config.eventLoop;
    UA_DateTime nowMonotonic = el->dateTime_nowMonotonic(el);
    if(mon->monitoringMode == UA_MONITORINGMODE_REPORTING ||
       (mon->monitoringMode == UA_MONITORINGMODE_SAMPLING &&
        mon->triggeredUntil > nowMonotonic)) {
        UA_Notification_enqueueSub(n);
        mon->triggeredUntil = UA_INT64_MIN;
        UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, mon->subscription,
                                  "Notification enqueued (Queue size %lu)",
                                  (long unsigned)mon->subscription->notificationQueueSize);
    }

    UA_Notification_enqueueMon(server, n);

    for(size_t i = mon->triggeringLinksSize - 1; i < mon->triggeringLinksSize; i--) {
        
        UA_MonitoredItem *triggeredMon =
            UA_Subscription_getMonitoredItem(sub, mon->triggeringLinks[i]);
        if(!triggeredMon) {
            UA_MonitoredItem_removeLink(sub, mon, mon->triggeringLinks[i]);
            continue;
        }

        if(triggeredMon->monitoringMode != UA_MONITORINGMODE_SAMPLING)
            continue;

        UA_Notification *n2 = TAILQ_LAST(&triggeredMon->queue, NotificationQueue);
        if(n2)
            UA_Notification_enqueueSub(n2);

        triggeredMon->triggeredUntil = nowMonotonic +
            (UA_DateTime)(sub->publishingInterval * (UA_Double)UA_DATETIME_MSEC);

        UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                                  "MonitoredItem %u triggers MonitoredItem %u",
                                  mon->monitoredItemId, triggeredMon->monitoredItemId);
    }

    if(sub == server->adminSubscription && !sub->delayedCallbackRegistered) {
        sub->delayedCallbackRegistered = true;
        sub->delayedMoreNotifications.callback =
            (UA_Callback)UA_Subscription_localPublish;
        sub->delayedMoreNotifications.application = server;
        sub->delayedMoreNotifications.context = sub;

        el = server->config.eventLoop;
        el->addDelayedCallback(el, &sub->delayedMoreNotifications);
    }
}

static void
UA_Notification_dequeueMon(UA_Notification *n) {
    UA_MonitoredItem *mon = n->mon;
    UA_assert(mon);

    
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    if(n->isOverflowEvent)
        --mon->eventOverflows;
#endif

    TAILQ_REMOVE(&mon->queue, n, monEntry);
    --mon->queueSize;

    
    UA_assert(mon->queueSize >= mon->eventOverflows);
    UA_assert(mon->eventOverflows <= mon->queueSize - mon->eventOverflows + 1);
}

void
UA_Notification_dequeueSub(UA_Notification *n) {
    if(TAILQ_NEXT(n, subEntry) == UA_SUBSCRIPTION_QUEUE_SENTINEL)
        return;

    UA_MonitoredItem *mon = n->mon;
    UA_assert(mon);
    UA_Subscription *sub = mon->subscription;
    UA_assert(sub);

    switch(mon->itemToMonitor.attributeId) {
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    case UA_ATTRIBUTEID_EVENTNOTIFIER:
        --sub->eventNotifications;
        break;
#endif
    default:
        --sub->dataChangeNotifications;
        break;
    }

    TAILQ_REMOVE(&sub->notificationQueue, n, subEntry);
    --sub->notificationQueueSize;

    
    TAILQ_NEXT(n, subEntry) = UA_SUBSCRIPTION_QUEUE_SENTINEL;
}





UA_Subscription *
UA_Subscription_new(void) {
    
    UA_Subscription *newSub = (UA_Subscription*)UA_calloc(1, sizeof(UA_Subscription));
    if(!newSub)
        return NULL;

    
    newSub->state = UA_SUBSCRIPTIONSTATE_STOPPED;

    newSub->nextSequenceNumber = 1;

    TAILQ_INIT(&newSub->retransmissionQueue);
    TAILQ_INIT(&newSub->notificationQueue);
    return newSub;
}

static void
delayedFreeSubscription(void *app, void *context) {
    UA_free(context);
}

void
UA_Subscription_delete(UA_Server *server, UA_Subscription *sub) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_EventLoop *el = server->config.eventLoop;

    
    Subscription_setState(server, sub, UA_SUBSCRIPTIONSTATE_REMOVING);

    
    if(sub->delayedCallbackRegistered) {
        el->removeDelayedCallback(el, &sub->delayedMoreNotifications);
        sub->delayedCallbackRegistered = false;
    }

    
#ifdef UA_ENABLE_DIAGNOSTICS
    if(!UA_NodeId_isNull(&sub->ns0Id))
        deleteNode(server, sub->ns0Id, true);
    UA_NodeId_clear(&sub->ns0Id);
#endif

    UA_LOG_INFO_SUBSCRIPTION(server->config.logging, sub, "Subscription deleted");

    
    if(sub->session)
        UA_Session_detachSubscription(server, sub->session, sub, true);

    
    if(sub->serverListEntry.le_prev) {
        LIST_REMOVE(sub, serverListEntry);
        UA_assert(server->subscriptionsSize > 0);
        server->subscriptionsSize--;
        server->serverDiagnosticsSummary.currentSubscriptionCount--;
    }

    
    UA_assert(server->monitoredItemsSize >= sub->monitoredItemsSize);
    UA_MonitoredItem *mon, *tmp_mon;
    LIST_FOREACH_SAFE(mon, &sub->monitoredItems, listEntry, tmp_mon) {
        UA_MonitoredItem_delete(server, mon);
    }
    UA_assert(sub->monitoredItemsSize == 0);

    
    UA_NotificationMessageEntry *nme, *nme_tmp;
    TAILQ_FOREACH_SAFE(nme, &sub->retransmissionQueue, listEntry, nme_tmp) {
        TAILQ_REMOVE(&sub->retransmissionQueue, nme, listEntry);
        UA_NotificationMessage_clear(&nme->message);
        UA_free(nme);
        if(sub->session)
            --sub->session->totalRetransmissionQueueSize;
        --sub->retransmissionQueueSize;
    }
    UA_assert(sub->retransmissionQueueSize == 0);

    sub->delayedFreePointers.callback = delayedFreeSubscription;
    sub->delayedFreePointers.application = NULL;
    sub->delayedFreePointers.context = sub;
    el->addDelayedCallback(el, &sub->delayedFreePointers);
}

void
Subscription_resetLifetime(UA_Subscription *sub) {
    sub->currentLifetimeCount = 0;
}

UA_MonitoredItem *
UA_Subscription_getMonitoredItem(UA_Subscription *sub, UA_UInt32 monitoredItemId) {
    UA_MonitoredItem *mon;
    LIST_FOREACH(mon, &sub->monitoredItems, listEntry) {
        if(mon->monitoredItemId == monitoredItemId)
            break;
    }
    return mon;
}

static void
removeOldestRetransmissionMessageFromSub(UA_Subscription *sub) {
    UA_NotificationMessageEntry *oldestEntry =
        TAILQ_LAST(&sub->retransmissionQueue, NotificationMessageQueue);
    TAILQ_REMOVE(&sub->retransmissionQueue, oldestEntry, listEntry);
    UA_NotificationMessage_clear(&oldestEntry->message);
    UA_free(oldestEntry);
    --sub->retransmissionQueueSize;
    if(sub->session)
        --sub->session->totalRetransmissionQueueSize;

#ifdef UA_ENABLE_DIAGNOSTICS
    sub->discardedMessageCount++;
#endif
}

static void
removeOldestRetransmissionMessageFromSession(UA_Session *session) {
    UA_NotificationMessageEntry *oldestEntry = NULL;
    UA_Subscription *oldestSub = NULL;
    UA_Subscription *sub;
    TAILQ_FOREACH(sub, &session->subscriptions, sessionListEntry) {
        UA_NotificationMessageEntry *first =
            TAILQ_LAST(&sub->retransmissionQueue, NotificationMessageQueue);
        if(!first)
            continue;
        if(!oldestEntry || oldestEntry->message.publishTime > first->message.publishTime) {
            oldestEntry = first;
            oldestSub = sub;
        }
    }
    UA_assert(oldestEntry);
    UA_assert(oldestSub);

    removeOldestRetransmissionMessageFromSub(oldestSub);
}

static void
UA_Subscription_addRetransmissionMessage(UA_Server *server, UA_Subscription *sub,
                                         UA_NotificationMessageEntry *entry) {
    
    UA_Session *session = sub->session;
    if(sub->retransmissionQueueSize >= UA_MAX_RETRANSMISSIONQUEUESIZE) {
        UA_LOG_WARNING_SUBSCRIPTION(server->config.logging, sub,
                                    "Subscription retransmission queue overflow");
        removeOldestRetransmissionMessageFromSub(sub);
    } else if(session && server->config.maxRetransmissionQueueSize > 0 &&
              session->totalRetransmissionQueueSize >=
              server->config.maxRetransmissionQueueSize) {
        UA_LOG_WARNING_SUBSCRIPTION(server->config.logging, sub,
                                    "Session-wide retransmission queue overflow");
        removeOldestRetransmissionMessageFromSession(sub->session);
    }

    
    TAILQ_INSERT_TAIL(&sub->retransmissionQueue, entry, listEntry);
    ++sub->retransmissionQueueSize;
    if(session)
        ++session->totalRetransmissionQueueSize;
}

UA_StatusCode
UA_Subscription_removeRetransmissionMessage(UA_Subscription *sub, UA_UInt32 sequenceNumber) {
    
    UA_NotificationMessageEntry *entry;
    TAILQ_FOREACH(entry, &sub->retransmissionQueue, listEntry) {
        if(entry->message.sequenceNumber == sequenceNumber)
            break;
    }
    if(!entry)
        return UA_STATUSCODE_BADSEQUENCENUMBERUNKNOWN;

    
    TAILQ_REMOVE(&sub->retransmissionQueue, entry, listEntry);
    --sub->retransmissionQueueSize;
    UA_NotificationMessage_clear(&entry->message);
    UA_free(entry);

    if(sub->session)
        --sub->session->totalRetransmissionQueueSize;

    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode
prepareNotificationMessage(UA_Server *server, UA_Subscription *sub,
                           UA_NotificationMessage *message,
                           size_t maxNotifications) {
    UA_assert(maxNotifications > 0);

    message->notificationData = (UA_ExtensionObject*)
        UA_Array_new(2, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
    if(!message->notificationData)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    message->notificationDataSize = 2;

    
    size_t notificationDataIdx = 0;
    size_t dcnPos = 0; 
    UA_DataChangeNotification *dcn = NULL;
    if(sub->dataChangeNotifications > 0) {
        dcn = UA_DataChangeNotification_new();
        if(!dcn) {
            UA_NotificationMessage_clear(message);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        UA_ExtensionObject_setValue(message->notificationData, dcn,
                                    &UA_TYPES[UA_TYPES_DATACHANGENOTIFICATION]);
        size_t dcnSize = sub->dataChangeNotifications;
        if(dcnSize > maxNotifications)
            dcnSize = maxNotifications;
        dcn->monitoredItems = (UA_MonitoredItemNotification*)
            UA_Array_new(dcnSize, &UA_TYPES[UA_TYPES_MONITOREDITEMNOTIFICATION]);
        if(!dcn->monitoredItems) {
            UA_NotificationMessage_clear(message); 
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        dcn->monitoredItemsSize = dcnSize;
        notificationDataIdx++;
    }

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    size_t enlPos = 0; 
    UA_EventNotificationList *enl = NULL;
    if(sub->eventNotifications > 0) {
        enl = UA_EventNotificationList_new();
        if(!enl) {
            UA_NotificationMessage_clear(message);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        UA_ExtensionObject_setValue(&message->notificationData[notificationDataIdx],
                                    enl, &UA_TYPES[UA_TYPES_EVENTNOTIFICATIONLIST]);
        size_t enlSize = sub->eventNotifications;
        if(enlSize > maxNotifications)
            enlSize = maxNotifications;
        enl->events = (UA_EventFieldList*)
            UA_Array_new(enlSize, &UA_TYPES[UA_TYPES_EVENTFIELDLIST]);
        if(!enl->events) {
            UA_NotificationMessage_clear(message);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        enl->eventsSize = enlSize;
        notificationDataIdx++;
    }
#endif

    UA_assert(notificationDataIdx > 0);
    message->notificationDataSize = notificationDataIdx;

    

    
    size_t totalNotifications = 0;
    UA_Notification *n, *n_tmp;
    TAILQ_FOREACH_SAFE(n, &sub->notificationQueue, subEntry, n_tmp) {
        if(totalNotifications >= maxNotifications)
            break;

        
        switch(n->mon->itemToMonitor.attributeId) {
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
        case UA_ATTRIBUTEID_EVENTNOTIFIER:
            UA_assert(enl != NULL); 
            enl->events[enlPos] = n->data.event;
            UA_EventFieldList_init(&n->data.event);
            enlPos++;
            break;
#endif
        default:
            UA_assert(dcn != NULL); 
            dcn->monitoredItems[dcnPos] = n->data.dataChange;
            UA_DataValue_init(&n->data.dataChange.value);
            dcnPos++;
            break;
        }

        UA_Notification *prev;
        while((prev = TAILQ_PREV(n, NotificationQueue, monEntry))) {
            UA_Notification_delete(prev);

            
            UA_assert(prev != TAILQ_PREV(n, NotificationQueue, monEntry));
        }

        
        UA_Notification_delete(n);

        totalNotifications++;
    }

    
    if(dcn) {
        dcn->monitoredItemsSize = dcnPos;
        if(dcnPos == 0) {
            UA_free(dcn->monitoredItems);
            dcn->monitoredItems = NULL;
        }
    }

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    if(enl) {
        enl->eventsSize = enlPos;
        if(enlPos == 0) {
            UA_free(enl->events);
            enl->events = NULL;
        }
    }
#endif

    return UA_STATUSCODE_GOOD;
}

static UA_UInt32
UA_Subscription_nextSequenceNumber(UA_UInt32 sequenceNumber) {
    UA_UInt32 nextSequenceNumber = sequenceNumber + 1;
    if(nextSequenceNumber == 0)
        nextSequenceNumber = 1;
    return nextSequenceNumber;
}

static void
sendStatusChangeDelete(UA_Server *server, UA_Subscription *sub,
                       UA_PublishResponseEntry *pre) {
    if(!pre) {
        UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                                  "Cannot send the StatusChange notification because "
                                  "no response is queued.");
        if(UA_StatusCode_isBad(sub->statusChange)) {
            UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                                      "Removing the subscription.");
            UA_Subscription_delete(server, sub);
        }
        return;
    }

    UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                              "Sending out a StatusChange notification and "
                              "removing the subscription");

    UA_EventLoop *el = server->config.eventLoop;

    
    UA_PublishResponse *response = &pre->response;

    UA_StatusChangeNotification scn;
    UA_StatusChangeNotification_init(&scn);
    scn.status = sub->statusChange;

    UA_ExtensionObject notificationData;
    UA_ExtensionObject_setValue(&notificationData, &scn,
                                &UA_TYPES[UA_TYPES_STATUSCHANGENOTIFICATION]);

    response->notificationMessage.notificationData = &notificationData;
    response->notificationMessage.notificationDataSize = 1;
    response->subscriptionId = sub->subscriptionId;
    response->notificationMessage.publishTime = el->dateTime_now(el);
    response->notificationMessage.sequenceNumber = sub->nextSequenceNumber;

    
    UA_assert(sub->session); 
    UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                              "Sending out a publish response");
    sendResponse(server, sub->session->channel, pre->requestId,
                 (UA_Response *)response, &UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);

    
    response->notificationMessage.notificationData = NULL;
    response->notificationMessage.notificationDataSize = 0;
    UA_PublishResponse_clear(&pre->response);
    UA_free(pre);

    
    UA_Subscription_delete(server, sub);
}

void
UA_Subscription_localPublish(UA_Server *server, UA_Subscription *sub) {
    UA_LOCK(&server->serviceMutex);
    sub->delayedCallbackRegistered = false;

    UA_Notification *n, *n_tmp;
    TAILQ_FOREACH_SAFE(n, &sub->notificationQueue, subEntry, n_tmp) {
        UA_MonitoredItem *mon = n->mon;
        UA_LocalMonitoredItem *localMon = (UA_LocalMonitoredItem*)mon;

        
        void *nodeContext = NULL;
        switch(mon->itemToMonitor.attributeId) {
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
        case UA_ATTRIBUTEID_EVENTNOTIFIER:
            
            UA_assert(n->data.event.eventFieldsSize == localMon->eventFields.mapSize);
            for(size_t i = 0; i < localMon->eventFields.mapSize; i++) {
                localMon->eventFields.map[i].value = n->data.event.eventFields[i];
            }

            
            UA_UNLOCK(&server->serviceMutex);
            localMon->callback.
                eventCallback(server, mon->monitoredItemId, localMon->context,
                              localMon->eventFields);
            UA_LOCK(&server->serviceMutex);
            break;
#endif
        default:
            getNodeContext(server, mon->itemToMonitor.nodeId, &nodeContext);
            UA_UNLOCK(&server->serviceMutex);
            localMon->callback.
                dataChangeCallback(server, mon->monitoredItemId, localMon->context,
                                   &mon->itemToMonitor.nodeId, nodeContext,
                                   mon->itemToMonitor.attributeId,
                                   &n->data.dataChange.value);
            UA_LOCK(&server->serviceMutex);
            break;
        }

        UA_Notification *prev;
        while((prev = TAILQ_PREV(n, NotificationQueue, monEntry))) {
            UA_Notification_delete(prev);

            
            UA_assert(prev != TAILQ_PREV(n, NotificationQueue, monEntry));
        }

        
        UA_Notification_delete(n);
    }

    UA_UNLOCK(&server->serviceMutex);
}

static void
delayedPublishNotifications(UA_Server *server, UA_Subscription *sub) {
    UA_LOCK(&server->serviceMutex);
    sub->delayedCallbackRegistered = false;
    UA_Subscription_publish(server, sub);
    UA_UNLOCK(&server->serviceMutex);
}

void
UA_Subscription_publish(UA_Server *server, UA_Subscription *sub) {
    UA_EventLoop *el = server->config.eventLoop;

    
    UA_PublishResponseEntry *pre = NULL;
    if(sub->session) {
        UA_DateTime nowMonotonic = el->dateTime_nowMonotonic(el);
        do {
            
            pre = UA_Session_dequeuePublishReq(sub->session);
            if(!pre)
                break;

            if(pre->maxTime < nowMonotonic) {
                UA_LOG_DEBUG_SESSION(server->config.logging, sub->session,
                                     "Publish request %u has timed out", pre->requestId);
                pre->response.responseHeader.serviceResult = UA_STATUSCODE_BADTIMEOUT;
                sendResponse(server, sub->session->channel, pre->requestId,
                             (UA_Response *)&pre->response, &UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);
                UA_PublishResponse_clear(&pre->response);
                UA_free(pre);
                pre = NULL;
            }
        } while(!pre);
    }

    
    if(pre) {
        Subscription_resetLifetime(sub);
    } else {
        UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                                  "The publish queue is empty");
        ++sub->currentLifetimeCount;
        if(sub->currentLifetimeCount > sub->lifeTimeCount) {
            UA_LOG_WARNING_SUBSCRIPTION(server->config.logging, sub,
                                        "End of subscription lifetime");
            
            sub->statusChange = UA_STATUSCODE_BADTIMEOUT;
        }
    }

    if(sub->statusChange != UA_STATUSCODE_GOOD) {
        sendStatusChangeDelete(server, sub, pre);
        return;
    }

    
    UA_UInt32 notifications = (sub->state == UA_SUBSCRIPTIONSTATE_ENABLED) ?
        sub->notificationQueueSize : 0;

    
    if(notifications > sub->notificationsPerPublish)
        notifications = sub->notificationsPerPublish;

    
    if(notifications == 0) {
        ++sub->currentKeepAliveCount;
        if(sub->currentKeepAliveCount < sub->maxKeepAliveCount) {
            if(pre)
                UA_Session_queuePublishReq(sub->session, pre, true); 
            return;
        }
        UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub, "Sending a KeepAlive");
    }

    if(!pre || !sub->session || !sub->session->channel) {
        UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                                  "Want to send a publish response but cannot. "
                                  "The subscription is late.");
        sub->late = true;
        if(pre)
            UA_Session_queuePublishReq(sub->session, pre, true); 
        return;
    }

    UA_assert(pre);
    UA_assert(sub->session); 

    
    UA_PublishResponse *response = &pre->response;
    UA_NotificationMessage *message = &response->notificationMessage;
    UA_NotificationMessageEntry *retransmission = NULL;
#ifdef UA_ENABLE_DIAGNOSTICS
    size_t priorDataChangeNotifications = sub->dataChangeNotifications;
    size_t priorEventNotifications = sub->eventNotifications;
#endif
    if(notifications > 0) {
        if(server->config.enableRetransmissionQueue) {
            
            retransmission = (UA_NotificationMessageEntry*)
                UA_malloc(sizeof(UA_NotificationMessageEntry));
            if(!retransmission) {
                UA_LOG_WARNING_SUBSCRIPTION(server->config.logging, sub,
                                            "Could not allocate memory for retransmission. "
                                            "The subscription is late.");
                sub->late = true;
                UA_Session_queuePublishReq(sub->session, pre, true); 
                return;
            }
        }

        
        UA_StatusCode retval =
            prepareNotificationMessage(server, sub, message, notifications);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING_SUBSCRIPTION(server->config.logging, sub,
                                        "Could not prepare the notification message. "
                                        "The subscription is late.");
            
            if(retransmission)
                UA_free(retransmission);
            sub->late = true;
            UA_Session_queuePublishReq(sub->session, pre, true); 
            return;
        }
    }

    

    
    response->subscriptionId = sub->subscriptionId;
    response->moreNotifications = (sub->notificationQueueSize > 0);
    message->publishTime = el->dateTime_now(el);

    message->sequenceNumber = sub->nextSequenceNumber;

    if(notifications > 0) {
        if(retransmission) {
            retransmission->message = response->notificationMessage;
            UA_Subscription_addRetransmissionMessage(server, sub, retransmission);
        }
        sub->nextSequenceNumber =
            UA_Subscription_nextSequenceNumber(sub->nextSequenceNumber);
    }

    
    UA_assert(sub->retransmissionQueueSize <= UA_MAX_RETRANSMISSIONQUEUESIZE);
    UA_UInt32 seqNumbers[UA_MAX_RETRANSMISSIONQUEUESIZE];
    response->availableSequenceNumbers = seqNumbers;
    response->availableSequenceNumbersSize = sub->retransmissionQueueSize;
    size_t i = 0;
    UA_NotificationMessageEntry *nme;
    TAILQ_FOREACH(nme, &sub->retransmissionQueue, listEntry) {
        response->availableSequenceNumbers[i] = nme->message.sequenceNumber;
        ++i;
    }
    UA_assert(i == sub->retransmissionQueueSize);

    
    UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                              "Sending out a publish response with %" PRIu32
                              " notifications", notifications);
    sendResponse(server, sub->session->channel, pre->requestId,
                 (UA_Response*)response, &UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);

    if(sub->notificationQueueSize == 0)
        sub->late = false;

    
    sub->currentKeepAliveCount = 0;

    
    if(retransmission) {
        
        UA_NotificationMessage_init(&response->notificationMessage);
    }
    response->availableSequenceNumbers = NULL;
    response->availableSequenceNumbersSize = 0;
    UA_PublishResponse_clear(&pre->response);
    UA_free(pre);

    
#ifdef UA_ENABLE_DIAGNOSTICS
    sub->publishRequestCount++;

    UA_UInt32 sentDCN = (UA_UInt32)
        (priorDataChangeNotifications - sub->dataChangeNotifications);
    UA_UInt32 sentEN = (UA_UInt32)(priorEventNotifications - sub->eventNotifications);
    sub->dataChangeNotificationsCount += sentDCN;
    sub->eventNotificationsCount += sentEN;
    sub->notificationsCount += (sentDCN + sentEN);
#endif

    UA_Boolean done = (sub->notificationQueueSize == 0);
    if(!done && !sub->delayedCallbackRegistered) {
        sub->delayedCallbackRegistered = true;

        sub->delayedMoreNotifications.callback = (UA_Callback)delayedPublishNotifications;
        sub->delayedMoreNotifications.application = server;
        sub->delayedMoreNotifications.context = sub;

        el = server->config.eventLoop;
        el->addDelayedCallback(el, &sub->delayedMoreNotifications);
    }
}

void
UA_Subscription_resendData(UA_Server *server, UA_Subscription *sub) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_assert(server);
    UA_assert(sub);

    UA_MonitoredItem *mon;
    LIST_FOREACH(mon, &sub->monitoredItems, listEntry) {
        
        if(mon->itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER)
            continue;

        
        if(mon->monitoringMode != UA_MONITORINGMODE_REPORTING)
            continue;

        if(mon->queueSize > 0)
            continue;

        
        UA_MonitoredItem_createDataChangeNotification(server, mon, &mon->lastValue);
    }
}

void
UA_Session_ensurePublishQueueSpace(UA_Server* server, UA_Session* session) {
    if(server->config.maxPublishReqPerSession == 0)
        return;

    while(session->responseQueueSize >= server->config.maxPublishReqPerSession) {
        
        UA_PublishResponseEntry *pre = UA_Session_dequeuePublishReq(session);
        UA_assert(pre != NULL); 

        UA_LOG_DEBUG_SESSION(server->config.logging, session,
                             "Sending out a publish response triggered by too many publish requests");

        
        UA_PublishResponse *response = &pre->response;
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYPUBLISHREQUESTS;
        sendResponse(server, session->channel, pre->requestId,
                     (UA_Response *)response, &UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);

        
        UA_PublishResponse_clear(response);
        UA_free(pre);
    }
}

static void
sampleAndPublishCallback(UA_Server *server, UA_Subscription *sub) {
    UA_LOCK(&server->serviceMutex);
    UA_assert(sub);

    UA_LOG_DEBUG_SUBSCRIPTION(server->config.logging, sub,
                              "Sample and Publish Callback");

    UA_MonitoredItem *mon;
    LIST_FOREACH(mon, &sub->samplingMonitoredItems, sampling.subscriptionSampling) {
        UA_MonitoredItem_sample(server, mon);
    }

    
    UA_Subscription_publish(server, sub);

    UA_UNLOCK(&server->serviceMutex);
}

UA_StatusCode
Subscription_setState(UA_Server *server, UA_Subscription *sub,
                      UA_SubscriptionState state) {
    if(state <= UA_SUBSCRIPTIONSTATE_REMOVING) {
        if(sub->publishCallbackId != 0) {
            removeCallback(server, sub->publishCallbackId);
            sub->publishCallbackId = 0;
#ifdef UA_ENABLE_DIAGNOSTICS
            sub->disableCount++;
#endif
        }
    } else if(sub->publishCallbackId == 0) {
        UA_StatusCode res =
            addRepeatedCallback(server, (UA_ServerCallback)sampleAndPublishCallback,
                                sub, sub->publishingInterval, &sub->publishCallbackId);
        if(res != UA_STATUSCODE_GOOD) {
            sub->state = UA_SUBSCRIPTIONSTATE_STOPPED;
            return res;
        }

        
        sub->currentKeepAliveCount = sub->maxKeepAliveCount;

#ifdef UA_ENABLE_DIAGNOSTICS
        sub->enableCount++;
#endif
    }

    sub->state = state;
    return UA_STATUSCODE_GOOD;
}





#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS

static const UA_NodeId eventQueueOverflowEventType =
    {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_EVENTQUEUEOVERFLOWEVENTTYPE}};

static UA_StatusCode
createEventOverflowNotification(UA_Server *server, UA_Subscription *sub,
                                UA_MonitoredItem *mon) {
    
    UA_Notification *indicator = NULL;
    if(mon->parameters.discardOldest) {
        indicator = TAILQ_FIRST(&mon->queue);
        UA_assert(indicator); 
        if(indicator->isOverflowEvent)
            return UA_STATUSCODE_GOOD;
    } else {
        indicator = TAILQ_LAST(&mon->queue, NotificationQueue);
        UA_assert(indicator); 
        UA_Notification *before = TAILQ_PREV(indicator, NotificationQueue, monEntry);
        if(before && before->isOverflowEvent)
            return UA_STATUSCODE_GOOD;
    }


    UA_EventFieldList efl;
    efl.clientHandle = mon->parameters.clientHandle;
    efl.eventFields = UA_Variant_new();
    if(!efl.eventFields)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode ret =
        UA_Variant_setScalarCopy(efl.eventFields, &eventQueueOverflowEventType,
                                 &UA_TYPES[UA_TYPES_NODEID]);
    if(ret != UA_STATUSCODE_GOOD) {
        UA_Variant_delete(efl.eventFields);
        return ret;
    }
    efl.eventFieldsSize = 1;

    
    UA_Notification *overflowNotification = UA_Notification_new();
    if(!overflowNotification) {
        UA_Variant_delete(efl.eventFields);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    
    overflowNotification->isOverflowEvent = true;
    overflowNotification->mon = mon;
    overflowNotification->data.event = efl;

    TAILQ_INSERT_BEFORE(indicator, overflowNotification, monEntry);
    ++mon->eventOverflows;
    ++mon->queueSize;

    
    UA_assert(mon->queueSize >= mon->eventOverflows);
    UA_assert(mon->eventOverflows <= mon->queueSize - mon->eventOverflows + 1);

    if(TAILQ_NEXT(indicator, subEntry) != UA_SUBSCRIPTION_QUEUE_SENTINEL) {
        
        TAILQ_INSERT_BEFORE(indicator, overflowNotification, subEntry);
    } else {
        
        if(!mon->parameters.discardOldest) {
            
            TAILQ_INSERT_TAIL(&mon->subscription->notificationQueue,
                              overflowNotification, subEntry);
        } else {
            
            while(indicator) {
                indicator = TAILQ_PREV(indicator, NotificationQueue, monEntry);
                if(!indicator) {
                    TAILQ_INSERT_TAIL(&mon->subscription->notificationQueue,
                                      overflowNotification, subEntry);
                    break;
                }
                if(TAILQ_NEXT(indicator, subEntry) != UA_SUBSCRIPTION_QUEUE_SENTINEL) {
                    TAILQ_INSERT_BEFORE(indicator, overflowNotification, subEntry);
                    break;
                }
            }
        }
    }

    ++sub->notificationQueueSize;
    ++sub->eventNotifications;

    
#ifdef UA_ENABLE_DIAGNOSTICS
    sub->eventQueueOverFlowCount++;
#endif

    return UA_STATUSCODE_GOOD;
}

#endif


static void
setOverflowInfoBits(UA_MonitoredItem *mon) {
    
    if(mon->parameters.queueSize == 1)
        return;

    UA_Notification *indicator = NULL;
    if(mon->parameters.discardOldest) {
        indicator = TAILQ_FIRST(&mon->queue);
    } else {
        indicator = TAILQ_LAST(&mon->queue, NotificationQueue);
    }
    UA_assert(indicator); 

    indicator->data.dataChange.value.hasStatus = true;
    indicator->data.dataChange.value.status |=
        (UA_STATUSCODE_INFOTYPE_DATAVALUE | UA_STATUSCODE_INFOBITS_OVERFLOW);
}


void
UA_MonitoredItem_removeOverflowInfoBits(UA_MonitoredItem *mon) {
    
    if(mon->parameters.queueSize > 1 ||
       mon->itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER)
        return;

    
    UA_Notification *n = TAILQ_FIRST(&mon->queue);
    if(!n)
        return;

    
    UA_assert(n == TAILQ_LAST(&mon->queue, NotificationQueue));

    
    n->data.dataChange.value.status &= ~(UA_StatusCode)
        (UA_STATUSCODE_INFOTYPE_DATAVALUE | UA_STATUSCODE_INFOBITS_OVERFLOW);
}





void
UA_MonitoredItem_init(UA_MonitoredItem *mon) {
    memset(mon, 0, sizeof(UA_MonitoredItem));
    TAILQ_INIT(&mon->queue);
    mon->triggeredUntil = UA_INT64_MIN;
}

static UA_StatusCode
addMonitoredItemBackpointer(UA_Server *server, UA_Session *session,
                            UA_Node *node, void *data) {
    UA_MonitoredItem *mon = (UA_MonitoredItem*)data;
    UA_assert(mon != (UA_MonitoredItem*)~0);
    mon->sampling.nodeListNext = node->head.monitoredItems;
    node->head.monitoredItems = mon;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
removeMonitoredItemBackPointer(UA_Server *server, UA_Session *session,
                               UA_Node *node, void *data) {
    if(!node->head.monitoredItems)
        return UA_STATUSCODE_GOOD;

    
    UA_MonitoredItem *remove = (UA_MonitoredItem*)data;
    if(node->head.monitoredItems == remove) {
        node->head.monitoredItems = remove->sampling.nodeListNext;
        return UA_STATUSCODE_GOOD;
    }

    UA_MonitoredItem *prev = node->head.monitoredItems;
    UA_MonitoredItem *entry = prev->sampling.nodeListNext;
    for(; entry != NULL; prev = entry, entry = entry->sampling.nodeListNext) {
        if(entry == remove) {
            prev->sampling.nodeListNext = entry->sampling.nodeListNext;
            break;
        }
    }

    return UA_STATUSCODE_GOOD;
}

void
UA_Server_registerMonitoredItem(UA_Server *server, UA_MonitoredItem *mon) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(mon->registered)
        return;
    mon->registered = true;

    
    UA_Subscription *sub = mon->subscription;
    mon->monitoredItemId = ++sub->lastMonitoredItemId;
    mon->subscription = sub;
    LIST_INSERT_HEAD(&sub->monitoredItems, mon, listEntry);
    sub->monitoredItemsSize++;
    server->monitoredItemsSize++;

    
    if(server->config.monitoredItemRegisterCallback) {
        UA_Session *session = sub->session;
        void *targetContext = NULL;
        getNodeContext(server, mon->itemToMonitor.nodeId, &targetContext);
        UA_UNLOCK(&server->serviceMutex);
        server->config.monitoredItemRegisterCallback(server,
                                                     session ? &session->sessionId : NULL,
                                                     session ? session->context : NULL,
                                                     &mon->itemToMonitor.nodeId,
                                                     targetContext,
                                                     mon->itemToMonitor.attributeId, false);
        UA_LOCK(&server->serviceMutex);
    }
}

static void
UA_Server_unregisterMonitoredItem(UA_Server *server, UA_MonitoredItem *mon) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(!mon->registered)
        return;
    mon->registered = false;

    UA_Subscription *sub = mon->subscription;
    UA_LOG_INFO_SUBSCRIPTION(server->config.logging, sub,
                             "MonitoredItem %" PRIi32 " | Deleting the MonitoredItem",
                             mon->monitoredItemId);

    
    if(server->config.monitoredItemRegisterCallback) {
        UA_Session *session = sub->session;
        void *targetContext = NULL;
        getNodeContext(server, mon->itemToMonitor.nodeId, &targetContext);
        UA_UNLOCK(&server->serviceMutex);
        server->config.monitoredItemRegisterCallback(server,
                                                     session ? &session->sessionId : NULL,
                                                     session ? session->context : NULL,
                                                     &mon->itemToMonitor.nodeId,
                                                     targetContext,
                                                     mon->itemToMonitor.attributeId, true);
        UA_LOCK(&server->serviceMutex);
    }

    
    sub->monitoredItemsSize--;
    LIST_REMOVE(mon, listEntry);
    server->monitoredItemsSize--;
}

UA_StatusCode
UA_MonitoredItem_setMonitoringMode(UA_Server *server, UA_MonitoredItem *mon,
                                   UA_MonitoringMode monitoringMode) {
    
    if(monitoringMode > UA_MONITORINGMODE_REPORTING)
        return UA_STATUSCODE_BADMONITORINGMODEINVALID;

    
    UA_MonitoringMode oldMode = mon->monitoringMode;
    mon->monitoringMode = monitoringMode;

    UA_Notification *notification;
    if(mon->monitoringMode == UA_MONITORINGMODE_DISABLED) {
        UA_Notification *notification_tmp;
        UA_MonitoredItem_unregisterSampling(server, mon);
        TAILQ_FOREACH_SAFE(notification, &mon->queue, monEntry, notification_tmp) {
            UA_Notification_delete(notification);
        }
        UA_DataValue_clear(&mon->lastValue);
        return UA_STATUSCODE_GOOD;
    }

    if(mon->monitoringMode == UA_MONITORINGMODE_REPORTING) {
        TAILQ_FOREACH(notification, &mon->queue, monEntry) {
            UA_Notification_dequeueSub(notification);
            UA_Notification_enqueueSub(notification);
        }
    } else  {
        
        TAILQ_FOREACH(notification, &mon->queue, monEntry)
            UA_Notification_dequeueSub(notification);
    }

    UA_StatusCode res = UA_MonitoredItem_registerSampling(server, mon);
    if(res != UA_STATUSCODE_GOOD) {
        mon->monitoringMode = UA_MONITORINGMODE_DISABLED;
        return res;
    }

    if(oldMode == UA_MONITORINGMODE_DISABLED &&
       mon->monitoringMode > UA_MONITORINGMODE_DISABLED &&
       mon->itemToMonitor.attributeId != UA_ATTRIBUTEID_EVENTNOTIFIER)
        UA_MonitoredItem_sample(server, mon);

    return UA_STATUSCODE_GOOD;
}

static void
delayedFreeMonitoredItem(void *app, void *context) {
    UA_free(context);
}

void
UA_MonitoredItem_delete(UA_Server *server, UA_MonitoredItem *mon) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_MonitoredItem_unregisterSampling(server, mon);

    
    if(mon->registered)
        UA_Server_unregisterMonitoredItem(server, mon);

    
    if(mon->triggeringLinksSize > 0) {
        UA_free(mon->triggeringLinks);
        mon->triggeringLinks = NULL;
        mon->triggeringLinksSize = 0;
    }

    
    UA_Notification *notification, *notification_tmp;
    TAILQ_FOREACH_SAFE(notification, &mon->queue, monEntry, notification_tmp) {
        UA_Notification_delete(notification);
    }

    
    UA_ReadValueId_clear(&mon->itemToMonitor);
    UA_MonitoringParameters_clear(&mon->parameters);

    
    UA_DataValue_clear(&mon->lastValue);

    
    if(mon->subscription == server->adminSubscription) {
        UA_LocalMonitoredItem *lm = (UA_LocalMonitoredItem*)mon;
        for(size_t i = 0; i < lm->eventFields.mapSize; i++)
            UA_Variant_init(&lm->eventFields.map[i].value);
        UA_KeyValueMap_clear(&lm->eventFields);
    }

    mon->delayedFreePointers.callback = delayedFreeMonitoredItem;
    mon->delayedFreePointers.application = NULL;
    mon->delayedFreePointers.context = mon;
    UA_EventLoop *el = server->config.eventLoop;
    el->addDelayedCallback(el, &mon->delayedFreePointers);
}

void
UA_MonitoredItem_ensureQueueSpace(UA_Server *server, UA_MonitoredItem *mon) {
    UA_assert(mon->queueSize >= mon->eventOverflows);
    UA_assert(mon->eventOverflows <= mon->queueSize - mon->eventOverflows + 1);

    
    UA_Subscription *sub = mon->subscription;
    UA_assert(sub);

    
    if(mon->queueSize - mon->eventOverflows <= mon->parameters.queueSize)
        return;

    
#if defined(UA_DEBUG) && defined(UA_ENABLE_SUBSCRIPTIONS_EVENTS)
    UA_Notification *last_del = NULL;
    (void)last_del;
#endif

    
    UA_Boolean reporting = false;
    size_t remove = mon->queueSize - mon->eventOverflows - mon->parameters.queueSize;
    while(remove > 0) {
        UA_assert(mon->queueSize - mon->eventOverflows >= 2);

        
        UA_Notification *del = NULL;
        if(mon->parameters.discardOldest) {
            
            del = TAILQ_FIRST(&mon->queue);
#if defined(UA_ENABLE_SUBSCRIPTIONS_EVENTS)
            
            while(del->isOverflowEvent) {
                del = TAILQ_NEXT(del, monEntry);
                UA_assert(del != last_del);
            }
#endif
        } else {
            del = TAILQ_LAST(&mon->queue, NotificationQueue);
            del = TAILQ_PREV(del, NotificationQueue, monEntry);
#if defined(UA_ENABLE_SUBSCRIPTIONS_EVENTS)
            
            while(del->isOverflowEvent) {
                del = TAILQ_PREV(del, NotificationQueue, monEntry);
                UA_assert(del != last_del);
            }
#endif
        }

        UA_assert(del); 

        if(TAILQ_NEXT(del, subEntry) != UA_SUBSCRIPTION_QUEUE_SENTINEL)
            reporting = true;

        if(TAILQ_NEXT(del, subEntry) != UA_SUBSCRIPTION_QUEUE_SENTINEL) {
            UA_Notification *after_del = TAILQ_NEXT(del, monEntry);
            UA_assert(after_del); 
            if(TAILQ_NEXT(after_del, subEntry) != UA_SUBSCRIPTION_QUEUE_SENTINEL) {
                TAILQ_REMOVE(&sub->notificationQueue, after_del, subEntry);
                TAILQ_INSERT_AFTER(&sub->notificationQueue, del, after_del, subEntry);
            }
        }

        remove--;

        
        UA_Notification_delete(del);

        
#ifdef UA_ENABLE_DIAGNOSTICS
        sub->monitoringQueueOverflowCount++;
#endif

        
#if defined(UA_DEBUG) && defined(UA_ENABLE_SUBSCRIPTIONS_EVENTS)
        last_del = del;
#endif
        UA_assert(del != TAILQ_FIRST(&mon->queue));
        UA_assert(del != TAILQ_LAST(&mon->queue, NotificationQueue));
        UA_assert(del != TAILQ_PREV(TAILQ_LAST(&mon->queue, NotificationQueue),
                                    NotificationQueue, monEntry));
    }

    
    if(reporting) {
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
        if(mon->itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER)
            createEventOverflowNotification(server, sub, mon);
        else
#endif
            setOverflowInfoBits(mon);
    }
}

static void
UA_MonitoredItem_lockAndSample(UA_Server *server, UA_MonitoredItem *mon) {
    UA_LOCK(&server->serviceMutex);
    UA_MonitoredItem_sample(server, mon);
    UA_UNLOCK(&server->serviceMutex);
}

UA_StatusCode
UA_MonitoredItem_registerSampling(UA_Server *server, UA_MonitoredItem *mon) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(mon->samplingType != UA_MONITOREDITEMSAMPLINGTYPE_NONE)
        return UA_STATUSCODE_GOOD;

    
    UA_Subscription *sub = mon->subscription;
    if(!sub->session)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(mon->itemToMonitor.attributeId == UA_ATTRIBUTEID_EVENTNOTIFIER ||
       mon->parameters.samplingInterval == 0.0) {
        
        res = UA_Server_editNode(server, sub->session, &mon->itemToMonitor.nodeId,
                                 0, UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID,
                                 addMonitoredItemBackpointer, mon);
        if(res == UA_STATUSCODE_GOOD)
            mon->samplingType = UA_MONITOREDITEMSAMPLINGTYPE_EVENT;
    } else if(mon->parameters.samplingInterval == sub->publishingInterval) {
        
        LIST_INSERT_HEAD(&sub->samplingMonitoredItems, mon,
                         sampling.subscriptionSampling);
        mon->samplingType = UA_MONITOREDITEMSAMPLINGTYPE_PUBLISH;
    } else {
        res = addRepeatedCallback(server,
                                  (UA_ServerCallback)UA_MonitoredItem_lockAndSample,
                                  mon, mon->parameters.samplingInterval,
                                  &mon->sampling.callbackId);
        if(res == UA_STATUSCODE_GOOD)
            mon->samplingType = UA_MONITOREDITEMSAMPLINGTYPE_CYCLIC;
    }

    return res;
}

void
UA_MonitoredItem_unregisterSampling(UA_Server *server, UA_MonitoredItem *mon) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    switch(mon->samplingType) {
    case UA_MONITOREDITEMSAMPLINGTYPE_CYCLIC:
        
        removeCallback(server, mon->sampling.callbackId);
        break;

    case UA_MONITOREDITEMSAMPLINGTYPE_EVENT: {
        UA_Server_editNode(server, &server->adminSession, &mon->itemToMonitor.nodeId,
                           0, UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID,
                           removeMonitoredItemBackPointer, mon);
        break;
    }

    case UA_MONITOREDITEMSAMPLINGTYPE_PUBLISH:
        
        LIST_REMOVE(mon, sampling.subscriptionSampling);
        break;

    case UA_MONITOREDITEMSAMPLINGTYPE_NONE:
    default:
        
        break;
    }

    mon->samplingType = UA_MONITOREDITEMSAMPLINGTYPE_NONE;
}

UA_StatusCode
UA_MonitoredItem_removeLink(UA_Subscription *sub, UA_MonitoredItem *mon, UA_UInt32 linkId) {
    
    size_t i = 0;
    for(; i < mon->triggeringLinksSize; i++) {
        if(mon->triggeringLinks[i] == linkId)
            break;
    }

    
    if(i == mon->triggeringLinksSize)
        return UA_STATUSCODE_BADMONITOREDITEMIDINVALID;

    
    mon->triggeringLinksSize--;
    if(mon->triggeringLinksSize == 0) {
        UA_free(mon->triggeringLinks);
        mon->triggeringLinks = NULL;
    } else {
        mon->triggeringLinks[i] = mon->triggeringLinks[mon->triggeringLinksSize];
        UA_UInt32 *tmpLinks = (UA_UInt32*)
            UA_realloc(mon->triggeringLinks, mon->triggeringLinksSize * sizeof(UA_UInt32));
        if(tmpLinks)
            mon->triggeringLinks = tmpLinks;
    }

    UA_MonitoredItem *mon2 = UA_Subscription_getMonitoredItem(sub, linkId);
    if(!mon2)
        return UA_STATUSCODE_BADMONITOREDITEMIDINVALID;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_MonitoredItem_addLink(UA_Subscription *sub, UA_MonitoredItem *mon, UA_UInt32 linkId) {
    
    UA_MonitoredItem *mon2 = UA_Subscription_getMonitoredItem(sub, linkId);
    if(!mon2)
        return UA_STATUSCODE_BADMONITOREDITEMIDINVALID;

    
    for(size_t i = 0 ; i < mon->triggeringLinksSize; i++) {
        if(mon->triggeringLinks[i] == linkId)
            return UA_STATUSCODE_GOOD;
    }

    
    UA_UInt32 *tmpLinkIds = (UA_UInt32*)
        UA_realloc(mon->triggeringLinks, (mon->triggeringLinksSize + 1) * sizeof(UA_UInt32));
    if(!tmpLinkIds)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    mon->triggeringLinks = tmpLinkIds;

    
    mon->triggeringLinks[mon->triggeringLinksSize] = linkId;
    mon->triggeringLinksSize++;
    return UA_STATUSCODE_GOOD;
}

#endif 
