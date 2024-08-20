
#include "ua_server_internal.h"

#ifdef UA_ENABLE_SUBSCRIPTIONS_ALARMS_CONDITIONS

typedef enum {
    UA_INACTIVE = 0,
    UA_ACTIVE,
    UA_ACTIVE_HIGHHIGH,
    UA_ACTIVE_HIGH,
    UA_ACTIVE_LOW,
    UA_ACTIVE_LOWLOW
} UA_ActiveState;

typedef struct UA_ConditionBranch {
    LIST_ENTRY(UA_ConditionBranch) listEntry;
    UA_NodeId conditionBranchId;
    UA_ByteString lastEventId;
    UA_Boolean isCallerAC;
} UA_ConditionBranch;

typedef struct UA_Condition {
    LIST_ENTRY(UA_Condition) listEntry;
    LIST_HEAD(, UA_ConditionBranch) conditionBranches;
    UA_NodeId conditionId;
    UA_UInt16 lastSeverity;
    UA_DateTime lastSeveritySourceTimeStamp;

    struct {
        UA_TwoStateVariableChangeCallback enableStateCallback;
        UA_TwoStateVariableChangeCallback ackStateCallback;
        UA_Boolean ackedRemoveBranch;
        UA_TwoStateVariableChangeCallback confirmStateCallback;
        UA_Boolean confirmedRemoveBranch;
        UA_TwoStateVariableChangeCallback activeStateCallback;
    } callbacks;

    UA_ActiveState lastActiveState;
    UA_ActiveState currentActiveState;
    UA_Boolean isLimitAlarm;
} UA_Condition;


struct UA_ConditionSource {
    LIST_ENTRY(UA_ConditionSource) listEntry;
    LIST_HEAD(, UA_Condition) conditions;
    UA_NodeId conditionSourceId;
};

#define CONDITIONOPTIONALFIELDS_SUPPORT // change array size!
#define CONDITION_SEVERITYCHANGECALLBACK_ENABLE


#define CONDITION_FIELD_EVENTID                                "EventId"
#define CONDITION_FIELD_EVENTTYPE                              "EventType"
#define CONDITION_FIELD_SOURCENODE                             "SourceNode"
#define CONDITION_FIELD_SOURCENAME                             "SourceName"
#define CONDITION_FIELD_TIME                                   "Time"
#define CONDITION_FIELD_RECEIVETIME                            "ReceiveTime"
#define CONDITION_FIELD_MESSAGE                                "Message"
#define CONDITION_FIELD_SEVERITY                               "Severity"
#define CONDITION_FIELD_CONDITIONNAME                          "ConditionName"
#define CONDITION_FIELD_BRANCHID                               "BranchId"
#define CONDITION_FIELD_RETAIN                                 "Retain"
#define CONDITION_FIELD_ENABLEDSTATE                           "EnabledState"
#define CONDITION_FIELD_TWOSTATEVARIABLE_ID                    "Id"
#define CONDITION_FIELD_QUALITY                                "Quality"
#define CONDITION_FIELD_LASTSEVERITY                           "LastSeverity"
#define CONDITION_FIELD_COMMENT                                "Comment"
#define CONDITION_FIELD_CLIENTUSERID                           "ClientUserId"
#define CONDITION_FIELD_CONDITIONVARIABLE_SOURCETIMESTAMP      "SourceTimestamp"
#define CONDITION_FIELD_DISABLE                                "Disable"
#define CONDITION_FIELD_ENABLE                                 "Enable"
#define CONDITION_FIELD_ADDCOMMENT                             "AddComment"
#define CONDITION_FIELD_CONDITIONREFRESH                       "ConditionRefresh"
#define CONDITION_FIELD_ACKEDSTATE                             "AckedState"
#define CONDITION_FIELD_CONFIRMEDSTATE                         "ConfirmedState"
#define CONDITION_FIELD_ACKNOWLEDGE                            "Acknowledge"
#define CONDITION_FIELD_CONFIRM                                "Confirm"
#define CONDITION_FIELD_ACTIVESTATE                            "ActiveState"
#define CONDITION_FIELD_INPUTNODE                              "InputNode"
#define CONDITION_FIELD_SUPPRESSEDORSHELVED                    "SuppressedOrShelved"
#define CONDITION_FIELD_NORMALSTATE                            "NormalState"
#define CONDITION_FIELD_HIGHHIGHLIMIT                          "HighHighLimit"
#define CONDITION_FIELD_HIGHLIMIT                              "HighLimit"
#define CONDITION_FIELD_LOWLIMIT                               "LowLimit"
#define CONDITION_FIELD_LOWLOWLIMIT                            "LowLowLimit"
#define CONDITION_FIELD_PROPERTY_EFFECTIVEDISPLAYNAME          "EffectiveDisplayName"
#define CONDITION_FIELD_LIMITSTATE                             "LimitState"
#define CONDITION_FIELD_CURRENTSTATE                           "CurrentState"
#define CONDITION_FIELD_HIGHHIGHSTATE                          "HighHighState"
#define CONDITION_FIELD_HIGHSTATE                              "HighState"
#define CONDITION_FIELD_LOWSTATE                               "LowState"
#define CONDITION_FIELD_LOWLOWSTATE                            "LowLowState"
#define CONDITION_FIELD_DIALOGSTATE                            "DialogState"
#define CONDITION_FIELD_PROMPT                                 "Prompt"
#define CONDITION_FIELD_RESPONSEOPTIONSET                      "ResponseOptionSet"
#define CONDITION_FIELD_DEFAULTRESPONSE                        "DefaultResponse"
#define CONDITION_FIELD_LASTRESPONSE                           "LastResponse"
#define CONDITION_FIELD_OKRESPONSE                             "OkResponse"
#define CONDITION_FIELD_CANCELRESPONSE                         "CancelResponse"
#define CONDITION_FIELD_RESPOND                                "Respond"
#define CONDITION_FIELD_ENGINEERINGUNITS                       "EngineeringUnits"
#define CONDITION_FIELD_EXPIRATION_DATE                        "ExpirationDate"

#define REFRESHEVENT_START_IDX                                 0
#define REFRESHEVENT_END_IDX                                   1
#define REFRESHEVENT_SEVERITY_DEFAULT                          100
#define EXPIRATION_LIMIT_DEFAULT_VALUE                         15

#define CONDITION_FIELD_EXPIRATION_LIMIT                       "ExpirationLimit"

#define LOCALE                                                 "en"
#define LOCALE_NULL                                             ""
#define TEXT_NULL                                               ""
#define ENABLED_TEXT                                           "Enabled"
#define DISABLED_TEXT                                          "Disabled"
#define ENABLED_MESSAGE                                        "The alarm was enabled"
#define DISABLED_MESSAGE                                       "The alarm was disabled"
#define COMMENT_MESSAGE                                        "A comment was added"
#define SEVERITY_INCREASED_MESSAGE                             "The alarm severity has increased"
#define SEVERITY_DECREASED_MESSAGE                             "The alarm severity has decreased"
#define ACKED_TEXT                                             "Acknowledged"
#define UNACKED_TEXT                                           "Unacknowledged"
#define CONFIRMED_TEXT                                         "Confirmed"
#define UNCONFIRMED_TEXT                                       "Unconfirmed"
#define ACKED_MESSAGE                                          "The alarm was acknowledged"
#define CONFIRMED_MESSAGE                                      "The alarm was confirmed"
#define ACTIVE_TEXT                                            "Active"
#define ACTIVE_HIGHHIGH_TEXT                                   "HighHigh active"
#define ACTIVE_HIGH_TEXT                                       "High active"
#define ACTIVE_LOW_TEXT                                        "Low active"
#define ACTIVE_LOWLOW_TEXT                                     "LowLow active"
#define INACTIVE_TEXT                                          "Inactive"

#define STATIC_QN(name) {0, UA_STRING_STATIC(name)}
static const UA_QualifiedName fieldEnabledStateQN = STATIC_QN(CONDITION_FIELD_ENABLEDSTATE);
static const UA_QualifiedName fieldRetainQN = STATIC_QN(CONDITION_FIELD_RETAIN);
static const UA_QualifiedName twoStateVariableIdQN = STATIC_QN(CONDITION_FIELD_TWOSTATEVARIABLE_ID);
static const UA_QualifiedName fieldMessageQN = STATIC_QN(CONDITION_FIELD_MESSAGE);
static const UA_QualifiedName fieldAckedStateQN = STATIC_QN(CONDITION_FIELD_ACKEDSTATE);
static const UA_QualifiedName fieldConfirmedStateQN = STATIC_QN(CONDITION_FIELD_CONFIRMEDSTATE);
static const UA_QualifiedName fieldActiveStateQN = STATIC_QN(CONDITION_FIELD_ACTIVESTATE);
static const UA_QualifiedName fieldTimeQN = STATIC_QN(CONDITION_FIELD_TIME);
static const UA_QualifiedName fieldSourceQN = STATIC_QN(CONDITION_FIELD_SOURCENODE);
static const UA_QualifiedName fieldLimitStateQN = STATIC_QN(CONDITION_FIELD_LIMITSTATE);
static const UA_QualifiedName fieldLowLimitQN = STATIC_QN(CONDITION_FIELD_LOWLIMIT);
static const UA_QualifiedName fieldLowLowLimitQN = STATIC_QN(CONDITION_FIELD_LOWLOWLIMIT);
static const UA_QualifiedName fieldHighLimitQN = STATIC_QN(CONDITION_FIELD_HIGHLIMIT);
static const UA_QualifiedName fieldHighHighLimitQN = STATIC_QN(CONDITION_FIELD_HIGHHIGHLIMIT);
static const UA_QualifiedName fieldEngineeringUnitsQN = STATIC_QN(CONDITION_FIELD_ENGINEERINGUNITS);
static const UA_QualifiedName fieldExpirationDateQN = STATIC_QN(CONDITION_FIELD_EXPIRATION_DATE);

static const UA_QualifiedName fieldExpirationLimitQN = STATIC_QN(CONDITION_FIELD_EXPIRATION_LIMIT);

#define CONDITION_ASSERT_RETURN_RETVAL(retval, logMessage, deleteFunction)                \
    {                                                                                     \
        if(retval != UA_STATUSCODE_GOOD) {                                                \
            UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,                  \
                         logMessage". StatusCode %s", UA_StatusCode_name(retval));        \
            deleteFunction                                                                \
            return retval;                                                                \
        }                                                                                 \
    }

#define CONDITION_ASSERT_RETURN_VOID(retval, logMessage, deleteFunction)                  \
    {                                                                                     \
        if(retval != UA_STATUSCODE_GOOD) {                                                \
            UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,                  \
                         logMessage". StatusCode %s", UA_StatusCode_name(retval));        \
            deleteFunction                                                                \
            return;                                                                       \
        }                                                                                 \
    }

static UA_StatusCode
setConditionField(UA_Server *server, const UA_NodeId condition,
                  const UA_Variant* value, const UA_QualifiedName fieldName);

static UA_StatusCode
setConditionVariableFieldProperty(UA_Server *server, const UA_NodeId condition,
                                  const UA_Variant* value,
                                  const UA_QualifiedName variableFieldName,
                                  const UA_QualifiedName variablePropertyName);

static UA_StatusCode
triggerConditionEvent(UA_Server *server, const UA_NodeId condition,
                      const UA_NodeId conditionSource, UA_ByteString *outEventId);

static UA_StatusCode
addConditionOptionalField(UA_Server *server, const UA_NodeId condition,
                          const UA_NodeId conditionType, const UA_QualifiedName fieldName,
                          UA_NodeId *outOptionalNode);

static UA_ConditionSource *
getConditionSource(UA_Server *server, const UA_NodeId *sourceId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_ConditionSource *cs;
    LIST_FOREACH(cs, &server->conditionSources, listEntry) {
        if(UA_NodeId_equal(&cs->conditionSourceId, sourceId))
            return cs;
    }
    return NULL;
}

static UA_Condition *
getCondition(UA_Server *server, const UA_NodeId *sourceId,
             const UA_NodeId *conditionId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_ConditionSource *cs = getConditionSource(server, sourceId);
    if(!cs)
        return NULL;

    UA_Condition *c;
    LIST_FOREACH(c, &cs->conditions, listEntry) {
        if(UA_NodeId_equal(&c->conditionId, conditionId))
            return c;
    }
    return NULL;
}

UA_StatusCode
UA_Server_setConditionTwoStateVariableCallback(UA_Server *server, const UA_NodeId condition,
                                               const UA_NodeId conditionSource, UA_Boolean removeBranch,
                                               UA_TwoStateVariableChangeCallback callback,
                                               UA_TwoStateVariableCallbackType callbackType) {
    UA_LOCK(&server->serviceMutex);

    
    UA_Condition *c = getCondition(server, &conditionSource, &condition);
    if(!c) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    
    switch(callbackType) {
    case UA_ENTERING_ENABLEDSTATE:
        c->callbacks.enableStateCallback = callback;
        break;
    case UA_ENTERING_ACKEDSTATE:
        c->callbacks.ackStateCallback = callback;
        c->callbacks.ackedRemoveBranch = removeBranch;
        break;
    case UA_ENTERING_CONFIRMEDSTATE:
        c->callbacks.confirmStateCallback = callback;
        c->callbacks.confirmedRemoveBranch = removeBranch;
        break;
    case UA_ENTERING_ACTIVESTATE:
        c->callbacks.activeStateCallback = callback;
        break;
    default:
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
getConditionTwoStateVariableCallback(UA_Server *server, const UA_NodeId *branch,
                                     UA_Condition *condition, UA_Boolean *removeBranch,
                                     UA_TwoStateVariableCallbackType callbackType) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_StatusCode res = UA_STATUSCODE_GOOD;

    
    UA_UNLOCK(&server->serviceMutex);

    
    switch(callbackType) {
    case UA_ENTERING_ENABLEDSTATE:
        if(condition->callbacks.enableStateCallback)
            res = condition->callbacks.enableStateCallback(server, branch);
        break;

    case UA_ENTERING_ACKEDSTATE:
        if(condition->callbacks.ackStateCallback) {
            *removeBranch = condition->callbacks.ackedRemoveBranch;
            res = condition->callbacks.ackStateCallback(server, branch);
        }
        break;

    case UA_ENTERING_CONFIRMEDSTATE:
        if(condition->callbacks.confirmStateCallback) {
            *removeBranch = condition->callbacks.confirmedRemoveBranch;
            res = condition->callbacks.confirmStateCallback(server, branch);
        }
        break;

    case UA_ENTERING_ACTIVESTATE:
        if(condition->callbacks.activeStateCallback)
            res = condition->callbacks.activeStateCallback(server, branch);
        break;

    default:
        res = UA_STATUSCODE_BADNOTFOUND;
        break;
    }
    UA_LOCK(&server->serviceMutex);

    return res;
}

static UA_StatusCode
callConditionTwoStateVariableCallback(UA_Server *server, const UA_NodeId *condition,
                                      const UA_NodeId *conditionSource, UA_Boolean *removeBranch,
                                      UA_TwoStateVariableCallbackType callbackType) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_ConditionSource *source = getConditionSource(server, conditionSource);
    if(!source)
        return UA_STATUSCODE_BADNOTFOUND;

    UA_Condition *cond;
    LIST_FOREACH(cond, &source->conditions, listEntry) {
        if(UA_NodeId_equal(&cond->conditionId, condition)) {
            return getConditionTwoStateVariableCallback(server, condition, cond,
                                                        removeBranch, callbackType);
        }
        UA_ConditionBranch *branch;
        LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
            if(!UA_NodeId_equal(&branch->conditionBranchId, condition))
                continue;
            return getConditionTwoStateVariableCallback(server, &branch->conditionBranchId,
                                                        cond, removeBranch, callbackType);
        }
    }
    return UA_STATUSCODE_BADNOTFOUND;
}

static UA_StatusCode
UA_Server_callConditionTwoStateVariableCallback(UA_Server *server, const UA_NodeId *condition,
                                                const UA_NodeId *conditionSource,
                                                UA_Boolean *removeBranch,
                                                UA_TwoStateVariableCallbackType callbackType) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = callConditionTwoStateVariableCallback(server, condition, conditionSource,
                                                              removeBranch, callbackType);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static void *
copyFieldParent(void *context, UA_ReferenceTarget *t) {
    UA_NodeId *parent = (UA_NodeId*)context;
    if(!UA_NodePointer_isLocal(t->targetId))
        return NULL;
    UA_NodeId tmpNodeId = UA_NodePointer_toNodeId(t->targetId);
    UA_StatusCode res = UA_NodeId_copy(&tmpNodeId, parent);
    return (res == UA_STATUSCODE_GOOD) ? (void*)0x1 : NULL;
}

static UA_StatusCode
getFieldParentNodeId(UA_Server *server, const UA_NodeId *field, UA_NodeId *parent) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    *parent = UA_NODEID_NULL;
    const UA_Node *fieldNode = UA_NODESTORE_GET(server, field);
    if(!fieldNode)
        return UA_STATUSCODE_BADNOTFOUND;
    for(size_t i = 0; i < fieldNode->head.referencesSize; i++) {
        UA_NodeReferenceKind *rk = &fieldNode->head.references[i];
        if(rk->referenceTypeIndex != UA_REFERENCETYPEINDEX_HASPROPERTY &&
           rk->referenceTypeIndex != UA_REFERENCETYPEINDEX_HASCOMPONENT)
            continue;
        if(!rk->isInverse)
            continue;
        
        void *success = UA_NodeReferenceKind_iterate(rk, copyFieldParent, parent);
        if(success) {
            UA_NODESTORE_RELEASE(server, (const UA_Node *)fieldNode);
            return UA_STATUSCODE_GOOD;
        }
    }
    UA_NODESTORE_RELEASE(server, (const UA_Node *)fieldNode);
    return UA_STATUSCODE_BADNOTFOUND;
}

static UA_StatusCode
UA_Server_getFieldParentNodeId(UA_Server *server, const UA_NodeId *field, UA_NodeId *parent) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = getFieldParentNodeId(server, field, parent);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}


static UA_StatusCode
getConditionFieldNodeId(UA_Server *server, const UA_NodeId *conditionNodeId,
                        const UA_QualifiedName* fieldName, UA_NodeId *outFieldNodeId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_BrowsePathResult bpr =
        browseSimplifiedBrowsePath(server, *conditionNodeId, 1, fieldName);
    if(bpr.statusCode != UA_STATUSCODE_GOOD)
        return bpr.statusCode;
    UA_StatusCode retval = UA_NodeId_copy(&bpr.targets[0].targetId.nodeId, outFieldNodeId);
    UA_BrowsePathResult_clear(&bpr);
    return retval;
}


static UA_StatusCode
getConditionFieldPropertyNodeId(UA_Server *server, const UA_NodeId *originCondition,
                                const UA_QualifiedName* variableFieldName,
                                const UA_QualifiedName* variablePropertyName,
                                UA_NodeId *outFieldPropertyNodeId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_BrowsePathResult bprConditionVariableField =
        browseSimplifiedBrowsePath(server, *originCondition, 1, variableFieldName);
    if(bprConditionVariableField.statusCode != UA_STATUSCODE_GOOD)
        return bprConditionVariableField.statusCode;

    
    UA_BrowsePathResult bprVariableFieldProperty =
        browseSimplifiedBrowsePath(server, bprConditionVariableField.targets->targetId.nodeId,
                                   1, variablePropertyName);
    if(bprVariableFieldProperty.statusCode != UA_STATUSCODE_GOOD) {
        UA_BrowsePathResult_clear(&bprConditionVariableField);
        return bprVariableFieldProperty.statusCode;
    }

    *outFieldPropertyNodeId = bprVariableFieldProperty.targets[0].targetId.nodeId;
    UA_NodeId_init(&bprVariableFieldProperty.targets[0].targetId.nodeId);
    UA_BrowsePathResult_clear(&bprConditionVariableField);
    UA_BrowsePathResult_clear(&bprVariableFieldProperty);
    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode
getNodeIdValueOfConditionField(UA_Server *server, const UA_NodeId *condition,
                               UA_QualifiedName fieldName, UA_NodeId *outNodeId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    *outNodeId = UA_NODEID_NULL;
    UA_NodeId nodeIdValue;
    UA_StatusCode retval = getConditionFieldNodeId(server, condition, &fieldName, &nodeIdValue);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Field not found",);

    
    UA_Variant tOutVariant;
    retval = readWithReadValue(server, &nodeIdValue, UA_ATTRIBUTEID_VALUE, &tOutVariant);
    if(retval != UA_STATUSCODE_GOOD ||
       !UA_Variant_hasScalarType(&tOutVariant, &UA_TYPES[UA_TYPES_NODEID])) {
        UA_NodeId_clear(&nodeIdValue);
        UA_Variant_clear(&tOutVariant);
        return retval;
    }

    *outNodeId = *(UA_NodeId*)tOutVariant.data;
    UA_NodeId_init((UA_NodeId*)tOutVariant.data);
    UA_NodeId_clear(&nodeIdValue);
    UA_Variant_clear(&tOutVariant);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Server_getNodeIdValueOfConditionField(UA_Server *server, const UA_NodeId *condition,
                                         UA_QualifiedName fieldName, UA_NodeId *outNodeId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = getNodeIdValueOfConditionField(server, condition, fieldName, outNodeId);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static UA_StatusCode
UA_Server_getConditionBranchNodeId(UA_Server *server, const UA_ByteString *eventId,
                         UA_NodeId *outConditionBranchNodeId) {
    UA_LOCK(&server->serviceMutex);

    *outConditionBranchNodeId = UA_NODEID_NULL;
    
    UA_StatusCode res = UA_STATUSCODE_BADEVENTIDUNKNOWN;
    UA_ConditionSource *source;
    LIST_FOREACH(source, &server->conditionSources, listEntry) {
        
        UA_Condition *cond;
        LIST_FOREACH(cond, &source->conditions, listEntry) {
            
            UA_ConditionBranch *branch;
            LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
                if(!UA_ByteString_equal(&branch->lastEventId, eventId))
                    continue;
                if(UA_NodeId_isNull(&branch->conditionBranchId)) {
                    res = UA_NodeId_copy(&cond->conditionId, outConditionBranchNodeId);
                    UA_UNLOCK(&server->serviceMutex);
                    return res;
                } else {
                    res = UA_NodeId_copy(&branch->conditionBranchId, outConditionBranchNodeId);
                    UA_UNLOCK(&server->serviceMutex);
                    return res;
                }
                goto out;
            }
        }
    }

 out:
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static UA_StatusCode
UA_Server_getConditionLastSeverity(UA_Server *server, const UA_NodeId *conditionSource,
                         const UA_NodeId *conditionId, UA_UInt16 *outLastSeverity,
                         UA_DateTime *outLastSeveritySourceTimeStamp) {
    UA_LOCK(&server->serviceMutex);
    UA_Condition *cond = getCondition(server, conditionSource, conditionId);
    if(!cond) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    *outLastSeverity = cond->lastSeverity;
    *outLastSeveritySourceTimeStamp = cond->lastSeveritySourceTimeStamp;
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Server_updateConditionLastSeverity(UA_Server *server, const UA_NodeId *conditionSource,
                                      const UA_NodeId *conditionId, UA_UInt16 lastSeverity,
                                      UA_DateTime lastSeveritySourceTimeStamp) {
    UA_LOCK(&server->serviceMutex);
    UA_Condition *cond = getCondition(server, conditionSource, conditionId);
    if(!cond) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    cond->lastSeverity = lastSeverity;
    cond->lastSeveritySourceTimeStamp =  lastSeveritySourceTimeStamp;
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Server_getConditionActiveState(UA_Server *server, const UA_NodeId *conditionSource,
                                  const UA_NodeId *conditionId, UA_ActiveState *outLastActiveState,
                                  UA_ActiveState *outCurrentActiveState, UA_Boolean *outIsLimitAlarm) {
    UA_LOCK(&server->serviceMutex);
    UA_Condition *cond = getCondition(server, conditionSource, conditionId);
    if(!cond) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    *outLastActiveState = cond->lastActiveState;
    *outCurrentActiveState = cond->currentActiveState;
    *outIsLimitAlarm = cond->isLimitAlarm;
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Server_updateConditionActiveState(UA_Server *server, const UA_NodeId *conditionSource,
                                     const UA_NodeId *conditionId, const UA_ActiveState lastActiveState,
                                     const UA_ActiveState currentActiveState, UA_Boolean isLimitAlarm) {
    UA_LOCK(&server->serviceMutex);
    UA_Condition *cond = getCondition(server, conditionSource, conditionId);
    if(!cond) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNOTFOUND;
    }
    cond->lastActiveState = lastActiveState;
    cond->currentActiveState = currentActiveState;
    cond->isLimitAlarm = isLimitAlarm;
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
updateConditionLastEventId(UA_Server *server, const UA_NodeId *triggeredEvent,
                           const UA_NodeId *conditionSource,
                           const UA_ByteString *lastEventId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_Condition *cond = getCondition(server, conditionSource, triggeredEvent);
    if(!cond) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        return UA_STATUSCODE_BADNOTFOUND;
    }

    UA_ConditionBranch *branch;
    LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
        if(UA_NodeId_isNull(&branch->conditionBranchId)) {
            
            UA_ByteString_clear(&branch->lastEventId);
            return UA_ByteString_copy(lastEventId, &branch->lastEventId);
        }
    }
    UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                 "Condition Branch not implemented");
    return UA_STATUSCODE_BADNOTFOUND;
}

static void
setIsCallerAC(UA_Server *server, const UA_NodeId *condition,
              const UA_NodeId *conditionSource, UA_Boolean isCallerAC) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_Condition *cond = getCondition(server, conditionSource, condition);
    if(!cond) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        return;
    }

    UA_ConditionBranch *branch;
    LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
        if(UA_NodeId_isNull(&branch->conditionBranchId)) {
            branch->isCallerAC = isCallerAC;
            return;
        }
    }
    UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                 "Condition Branch not implemented");
}

UA_Boolean
isConditionOrBranch(UA_Server *server, const UA_NodeId *condition,
                    const UA_NodeId *conditionSource, UA_Boolean *isCallerAC) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_Condition *cond = getCondition(server, conditionSource, condition);
    if(!cond) {
        UA_LOG_DEBUG(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        return false;
    }

    UA_ConditionBranch *branch;
    LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
        if(UA_NodeId_isNull(&branch->conditionBranchId)) {
            *isCallerAC = branch->isCallerAC;
            return true;
        }
    }
    UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                 "Condition Branch not implemented");
    return false;
}

static UA_Boolean
isRetained(UA_Server *server, const UA_NodeId *condition) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_NodeId retainNodeId;
    UA_StatusCode retval = getConditionFieldNodeId(server, condition, &fieldRetainQN, &retainNodeId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Retain not found. StatusCode %s", UA_StatusCode_name(retval));
        return false; //TODO maybe a better error handling?
    }

    
    UA_Variant tOutVariant;
    retval = readWithReadValue(server, &retainNodeId, UA_ATTRIBUTEID_VALUE, &tOutVariant);
    if(retval != UA_STATUSCODE_GOOD ||
       !UA_Variant_hasScalarType(&tOutVariant, &UA_TYPES[UA_TYPES_BOOLEAN])) {
          UA_NodeId_clear(&retainNodeId);
          return false;
    }

    if(*(UA_Boolean *)tOutVariant.data == true) {
        UA_NodeId_clear(&retainNodeId);
        UA_Variant_clear(&tOutVariant);
        return true;
    }

    UA_NodeId_clear(&retainNodeId);
    UA_Variant_clear(&tOutVariant);
    return false;
}

static UA_Boolean
UA_Server_isRetained(UA_Server *server, const UA_NodeId *condition) {
    UA_LOCK(&server->serviceMutex);
    UA_Boolean res = isRetained(server, condition);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static UA_Boolean
isTwoStateVariableInTrueState(UA_Server *server, const UA_NodeId *condition,
                              const UA_QualifiedName *twoStateVariable) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_NodeId twoStateVariableIdNodeId;
    UA_StatusCode retval = getConditionFieldPropertyNodeId(server, condition, twoStateVariable,
                                                           &twoStateVariableIdQN,
                                                           &twoStateVariableIdNodeId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "TwoStateVariable/Id not found. StatusCode %s", UA_StatusCode_name(retval));
        return false; //TODO maybe a better error handling?
    }

    
    UA_Variant tOutVariant;
    retval = readWithReadValue(server, &twoStateVariableIdNodeId, UA_ATTRIBUTEID_VALUE, &tOutVariant);
    if(retval != UA_STATUSCODE_GOOD ||
       !UA_Variant_hasScalarType(&tOutVariant, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        UA_NodeId_clear(&twoStateVariableIdNodeId);
        return false;
    }

    UA_NodeId_clear(&twoStateVariableIdNodeId);

    if(*(UA_Boolean *)tOutVariant.data == true) {
      UA_Variant_clear(&tOutVariant);
      return true;
    }

    UA_Variant_clear(&tOutVariant);
    return false;
}

static UA_Boolean
UA_Server_isTwoStateVariableInTrueState(UA_Server *server, const UA_NodeId *condition,
                                        const UA_QualifiedName *twoStateVariable) {
    UA_LOCK(&server->serviceMutex);
    UA_Boolean res = isTwoStateVariableInTrueState(server, condition, twoStateVariable);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static UA_StatusCode
enteringDisabledState(UA_Server *server, const UA_NodeId *conditionId,
                      const UA_NodeId *conditionSource) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_Condition *cond = getCondition(server, conditionSource, conditionId);
    if(!cond) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        return UA_STATUSCODE_BADNOTFOUND;
    }

    
    UA_ConditionBranch *branch;
    LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
        UA_NodeId triggeredNode;
        if(UA_NodeId_isNull(&branch->conditionBranchId))
            //disable main Condition Branch (BranchId == NULL)
            triggeredNode = cond->conditionId;
        else //disable all branches
            triggeredNode = branch->conditionBranchId;

        UA_LocalizedText message = UA_LOCALIZEDTEXT(LOCALE, DISABLED_MESSAGE);
        UA_LocalizedText enableText = UA_LOCALIZEDTEXT(LOCALE, DISABLED_TEXT);
        UA_Variant value;
        UA_Variant_setScalar(&value, &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        UA_StatusCode retval = setConditionField(server, triggeredNode, &value, fieldMessageQN);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition Message failed",);

        UA_Variant_setScalar(&value, &enableText, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = setConditionField(server, triggeredNode, &value, fieldEnabledStateQN);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition EnabledState text failed",);

        UA_Boolean retain = false;
        UA_Variant_setScalar(&value, &retain, &UA_TYPES[UA_TYPES_BOOLEAN]);
        retval = setConditionField(server, triggeredNode, &value, fieldRetainQN);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition Retain failed",);

        
        UA_ByteString lastEventId = UA_BYTESTRING_NULL;
        
        setIsCallerAC(server, &triggeredNode, conditionSource, true);
        
        retval = triggerEvent(server, triggeredNode, *conditionSource, &lastEventId, false);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Triggering condition event failed",);
        setIsCallerAC(server, &triggeredNode, conditionSource, false);

        
        retval = updateConditionLastEventId(server, &triggeredNode, conditionSource, &lastEventId);
        UA_ByteString_clear(&lastEventId);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "updating condition event failed",);
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Server_enteringDisabledState(UA_Server *server, const UA_NodeId *conditionId,
                                const UA_NodeId *conditionSource) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = enteringDisabledState(server, conditionId, conditionSource);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static UA_StatusCode
enteringEnabledState(UA_Server *server,
                     const UA_NodeId *conditionId,
                     const UA_NodeId *conditionSource) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_Condition *cond = getCondition(server, conditionSource, conditionId);
    if(!cond) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Entry not found in list!");
        return UA_STATUSCODE_BADNOTFOUND;
    }

    
    UA_ConditionBranch *branch;
    LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
        UA_NodeId triggeredNode;
        UA_NodeId_init(&triggeredNode);
        if(UA_NodeId_isNull(&branch->conditionBranchId)) //enable main Condition
            triggeredNode = cond->conditionId;
        else //enable branches
            triggeredNode = branch->conditionBranchId;

        UA_LocalizedText message = UA_LOCALIZEDTEXT(LOCALE, ENABLED_MESSAGE);
        UA_LocalizedText enableText = UA_LOCALIZEDTEXT(LOCALE, ENABLED_TEXT);
        UA_Variant value;
        UA_Variant_setScalar(&value, &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        UA_StatusCode retval = setConditionField(server, triggeredNode,
                                                           &value, fieldMessageQN);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "set Condition Message failed",);

        UA_Variant_setScalar(&value, &enableText, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = setConditionField(server, triggeredNode, &value, fieldEnabledStateQN);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "set Condition EnabledState text failed",);

        
        UA_Boolean removeBranch = false;//not used
        retval = callConditionTwoStateVariableCallback(server, &triggeredNode,
                                                       conditionSource, &removeBranch,
                                                       UA_ENTERING_ENABLEDSTATE);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "calling condition callback failed",);

        
        //Condition Nodes should not be deleted after triggering the event
        retval = triggerConditionEvent(server, triggeredNode, *conditionSource, NULL);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "triggering condition event failed",);
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Server_enteringEnabledState(UA_Server *server, const UA_NodeId *conditionId,
                               const UA_NodeId *conditionSource) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = enteringEnabledState(server, conditionId, conditionSource);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static void
afterWriteCallbackEnabledStateChange(UA_Server *server,
                                     const UA_NodeId *sessionId, void *sessionContext,
                                     const UA_NodeId *nodeId, void *nodeContext,
                                     const UA_NumericRange *range, const UA_DataValue *data) {
    UA_NodeId twoStateVariableNode;
    UA_StatusCode retval = UA_Server_getFieldParentNodeId(server, nodeId, &twoStateVariableNode);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent TwoStateVariable found for given EnabledState/Id",);

    UA_NodeId conditionNode;
    retval = UA_Server_getFieldParentNodeId(server, &twoStateVariableNode, &conditionNode);
    UA_NodeId_clear(&twoStateVariableNode);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent Condition found for given EnabledState",);

    
    UA_NodeId conditionSource;
    retval = UA_Server_getNodeIdValueOfConditionField(server, &conditionNode, fieldSourceQN,
                                                      &conditionSource);
    CONDITION_ASSERT_RETURN_VOID(retval, "ConditionSource not found",
                                 UA_NodeId_clear(&conditionNode););

    
    retval = UA_Server_writeObjectProperty_scalar(server, conditionNode, fieldTimeQN,
                                                  (const UA_DateTime*)&data->sourceTimestamp,
                                                  &UA_TYPES[UA_TYPES_DATETIME]);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set enabling/disabling Time failed",
                                 UA_NodeId_clear(&conditionNode);
                                 UA_NodeId_clear(&conditionSource););

    if(false == (*((UA_Boolean *)data->value.data))) {
        
        retval = UA_Server_enteringDisabledState(server, &conditionNode, &conditionSource);
        UA_NodeId_clear(&conditionNode);
        CONDITION_ASSERT_RETURN_VOID(retval, "Entering disabled state failed",
                                     UA_NodeId_clear(&conditionSource););
    } else {
        
        retval = UA_Server_enteringEnabledState(server, &conditionNode, &conditionSource);
        UA_NodeId_clear(&conditionNode);
        CONDITION_ASSERT_RETURN_VOID(retval, "Entering enabled state failed",
                                     UA_NodeId_clear(&conditionSource););
    }

    UA_NodeId_clear(&conditionSource);
}

static void
afterWriteCallbackAckedStateChange(UA_Server *server,
                                   const UA_NodeId *sessionId, void *sessionContext,
                                   const UA_NodeId *nodeId, void *nodeContext,
                                   const UA_NumericRange *range, const UA_DataValue *data) {
    
    UA_NodeId twoStateVariableNode;
    UA_StatusCode retval = UA_Server_getFieldParentNodeId(server, nodeId, &twoStateVariableNode);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent TwoStateVariable found for given AckedState/Id",);

    UA_NodeId conditionNode;
    retval = UA_Server_getFieldParentNodeId(server, &twoStateVariableNode, &conditionNode);
    UA_NodeId_clear(&twoStateVariableNode);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent Condition found for given AckedState",);

    if(*((UA_Boolean *)data->value.data) == false) {
        
        retval = UA_Server_writeObjectProperty_scalar(server, conditionNode, fieldTimeQN,
                                                      &data->sourceTimestamp,
                                                      &UA_TYPES[UA_TYPES_DATETIME]);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set deactivating Time failed",
                                     UA_NodeId_clear(&conditionNode););

        
        UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, UNACKED_TEXT);
        UA_Variant value;
        UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = UA_Server_setConditionField(server, conditionNode, &value, fieldAckedStateQN);
        UA_NodeId_clear(&conditionNode);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition AckedState failed",);
        return;
    }

    
    if(!UA_Server_isTwoStateVariableInTrueState(server, &conditionNode, &fieldEnabledStateQN) ||
       !UA_Server_isRetained(server, &conditionNode)) {
        
        UA_Boolean idValue = false;
        UA_Variant value;
        UA_Variant_setScalar(&value, &idValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
        retval = UA_Server_setConditionVariableFieldProperty(server, conditionNode, &value,
                                                   fieldAckedStateQN, twoStateVariableIdQN);
        UA_NodeId_clear(&conditionNode);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set AckedState/Id failed",);
        return;
    }

    
    UA_LocalizedText message = UA_LOCALIZEDTEXT(LOCALE, ACKED_MESSAGE);
    UA_Variant value;
    UA_Variant_setScalar(&value, &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = UA_Server_setConditionField(server, conditionNode, &value, fieldMessageQN);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition Message failed",
                                 UA_NodeId_clear(&conditionNode););

    
    UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, ACKED_TEXT);
    UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = UA_Server_setConditionField(server, conditionNode, &value, fieldAckedStateQN);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition AckedState failed",
                                 UA_NodeId_clear(&conditionNode););

    
    UA_NodeId conditionSource;
    retval = UA_Server_getNodeIdValueOfConditionField(server, &conditionNode, fieldSourceQN,
                                                      &conditionSource);
    CONDITION_ASSERT_RETURN_VOID(retval, "ConditionSource not found",
                                 UA_NodeId_clear(&conditionNode););

    
    UA_Boolean removeBranch = false;
    retval = UA_Server_callConditionTwoStateVariableCallback(server, &conditionNode, &conditionSource,
                                                             &removeBranch, UA_ENTERING_ACKEDSTATE);
    CONDITION_ASSERT_RETURN_VOID(retval, "Calling condition callback failed",
                                 UA_NodeId_clear(&conditionNode);
                                 UA_NodeId_clear(&conditionSource););

    
    //Condition Nodes should not be deleted after triggering the event
    retval = UA_Server_triggerConditionEvent(server, conditionNode, conditionSource, NULL);
    CONDITION_ASSERT_RETURN_VOID(retval, "Triggering condition event failed",
                                 UA_NodeId_clear(&conditionNode);
                                 UA_NodeId_clear(&conditionSource););

    UA_NodeId_clear(&conditionNode);
    UA_NodeId_clear(&conditionSource);
}

#ifdef CONDITIONOPTIONALFIELDS_SUPPORT

static void
afterWriteCallbackConfirmedStateChange(UA_Server *server,
                                       const UA_NodeId *sessionId, void *sessionContext,
                                       const UA_NodeId *nodeId, void *nodeContext,
                                       const UA_NumericRange *range, const UA_DataValue *data) {
    UA_Variant value;
    UA_NodeId twoStateVariableNode;
    UA_StatusCode retval = UA_Server_getFieldParentNodeId(server, nodeId, &twoStateVariableNode);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent TwoStateVariable found for given ConfirmedState/Id",);

    UA_NodeId conditionNode;
    retval = UA_Server_getFieldParentNodeId(server, &twoStateVariableNode, &conditionNode);
    UA_NodeId_clear(&twoStateVariableNode);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent Condition found for given ConfirmedState",);

    if(*((UA_Boolean *)data->value.data) == false) {
        
        retval = UA_Server_writeObjectProperty_scalar(server, conditionNode, fieldTimeQN,
                                                      &data->sourceTimestamp,
                                                      &UA_TYPES[UA_TYPES_DATETIME]);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set deactivating Time failed",
                                     UA_NodeId_clear(&conditionNode););

        
        UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, UNCONFIRMED_TEXT);
        UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = UA_Server_setConditionField(server, conditionNode, &value, fieldConfirmedStateQN);
        UA_NodeId_clear(&conditionNode);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition ConfirmedState failed",);
        return;
    }

    
    if(!UA_Server_isTwoStateVariableInTrueState(server, &conditionNode, &fieldEnabledStateQN) ||
       !UA_Server_isRetained(server, &conditionNode)) {
        
        UA_Boolean idValue = false;
        UA_Variant_setScalar(&value, &idValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
        retval = UA_Server_setConditionVariableFieldProperty(server, conditionNode, &value,
                                                   fieldConfirmedStateQN, twoStateVariableIdQN);
        UA_NodeId_clear(&conditionNode);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set ConfirmedState/Id failed",);
        return;
    }

    
    retval = UA_Server_writeObjectProperty_scalar(server, conditionNode, fieldTimeQN,
                                                  &data->sourceTimestamp, &UA_TYPES[UA_TYPES_DATETIME]);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set Confirming Time failed",
                                 UA_NodeId_clear(&conditionNode););

    
    UA_LocalizedText message = UA_LOCALIZEDTEXT(LOCALE, CONFIRMED_MESSAGE);
    UA_Variant_setScalar(&value, &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = UA_Server_setConditionField(server, conditionNode, &value, fieldMessageQN);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition Message failed",
                                 UA_NodeId_clear(&conditionNode););

    
    UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, CONFIRMED_TEXT);
    UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = UA_Server_setConditionField(server, conditionNode, &value, fieldConfirmedStateQN);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition ConfirmedState failed",
                                 UA_NodeId_clear(&conditionNode););

    
    UA_NodeId conditionSource;
    retval = UA_Server_getNodeIdValueOfConditionField(server, &conditionNode,
                                                      fieldSourceQN, &conditionSource);
    CONDITION_ASSERT_RETURN_VOID(retval, "ConditionSource not found",
                                 UA_NodeId_clear(&conditionNode););

    
    UA_Boolean removeBranch = false;
    retval = UA_Server_callConditionTwoStateVariableCallback(server, &conditionNode,
                                                             &conditionSource, &removeBranch,
                                                             UA_ENTERING_CONFIRMEDSTATE);
    CONDITION_ASSERT_RETURN_VOID(retval, "Calling condition callback failed",
                                 UA_NodeId_clear(&conditionNode);
                                 UA_NodeId_clear(&conditionSource););

    
    //Condition Nodes should not be deleted after triggering the event
    retval = UA_Server_triggerConditionEvent(server, conditionNode, conditionSource, NULL);
    CONDITION_ASSERT_RETURN_VOID(retval, "Triggering condition event failed",
                                 UA_NodeId_clear(&conditionNode);
                                 UA_NodeId_clear(&conditionSource););
}
#endif 

static void
afterWriteCallbackActiveStateChange(UA_Server *server,
                                    const UA_NodeId *sessionId, void *sessionContext,
                                    const UA_NodeId *nodeId, void *nodeContext,
                                    const UA_NumericRange *range, const UA_DataValue *data) {
    UA_Variant value;
    UA_NodeId twoStateVariableNode;
    UA_StatusCode retval = UA_Server_getFieldParentNodeId(server, nodeId, &twoStateVariableNode);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent TwoStateVariable found for given ActiveState/Id",);

    UA_NodeId conditionNode;
    retval = UA_Server_getFieldParentNodeId(server, &twoStateVariableNode, &conditionNode);
    UA_NodeId_clear(&twoStateVariableNode);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent Condition found for given ActiveState",);

    
    UA_NodeId conditionSource;
    retval = UA_Server_getNodeIdValueOfConditionField(server, &conditionNode,
                                                      fieldSourceQN, &conditionSource);
    CONDITION_ASSERT_RETURN_VOID(retval, "ConditionSource not found",
                                 UA_NodeId_clear(&conditionNode););

    UA_ActiveState lastActiveState = UA_INACTIVE;
    UA_ActiveState currentActiveState = UA_INACTIVE;
    UA_Boolean isLimitalarm = false;

    retval = UA_Server_getConditionActiveState(server, &conditionSource, &conditionNode,
                                               &lastActiveState, &currentActiveState,
                                               &isLimitalarm);
    CONDITION_ASSERT_RETURN_VOID(retval, "ActiveState transition check failed",
                                 UA_NodeId_clear(&conditionNode);
                                 UA_NodeId_clear(&conditionSource););

    if(isLimitalarm == false) {
      if(*((UA_Boolean *)data->value.data) == true) {
        retval = UA_Server_updateConditionActiveState(server, &conditionSource, &conditionNode,
                                                      currentActiveState, UA_ACTIVE, false);
        CONDITION_ASSERT_RETURN_VOID(retval, "Updating ActiveState failed",
                                     UA_NodeId_clear(&conditionNode);
                                     UA_NodeId_clear(&conditionSource););
      } else {
        retval = UA_Server_updateConditionActiveState(server, &conditionSource, &conditionNode,
                                                      currentActiveState, UA_INACTIVE, false);
        CONDITION_ASSERT_RETURN_VOID(retval, "Updating ActiveState failed",
                                     UA_NodeId_clear(&conditionNode);
                                     UA_NodeId_clear(&conditionSource););
      }

      retval = UA_Server_getConditionActiveState(server, &conditionSource, &conditionNode,
                                                 &lastActiveState, &currentActiveState,
                                                 &isLimitalarm);
      CONDITION_ASSERT_RETURN_VOID(retval, "ActiveState transition check failed",
                                   UA_NodeId_clear(&conditionNode);
                                   UA_NodeId_clear(&conditionSource););
    }

    if(*((UA_Boolean *)data->value.data) == true &&
       (lastActiveState != currentActiveState)) {

        
        if(UA_Server_isTwoStateVariableInTrueState(server, &conditionNode, &fieldEnabledStateQN) &&
           UA_Server_isRetained(server, &conditionNode)) {
            
            retval = UA_Server_writeObjectProperty_scalar(server, conditionNode, fieldTimeQN,
                                                          &data->sourceTimestamp,
                                                          &UA_TYPES[UA_TYPES_DATETIME]);
            CONDITION_ASSERT_RETURN_VOID(retval, "Set activating Time failed",
                                         UA_NodeId_clear(&conditionNode);
                                         UA_NodeId_clear(&conditionSource););

            
            UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, ACTIVE_TEXT);
            UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
            retval = UA_Server_setConditionField(server, conditionNode, &value, fieldActiveStateQN);
            CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition ActiveState failed",
                                         UA_NodeId_clear(&conditionNode);
                                         UA_NodeId_clear(&conditionSource););

            
            UA_Boolean removeBranch = false;//not used
            retval = UA_Server_callConditionTwoStateVariableCallback(server, &conditionNode,
                                                                     &conditionSource, &removeBranch,
                                                                     UA_ENTERING_ACTIVESTATE);
            CONDITION_ASSERT_RETURN_VOID(retval, "Calling condition callback failed",
                                         UA_NodeId_clear(&conditionNode);
                                         UA_NodeId_clear(&conditionSource););

            
            //Condition Nodes should not be deleted after triggering the event
            retval = UA_Server_triggerConditionEvent(server, conditionNode, conditionSource, NULL);
            UA_NodeId_clear(&conditionNode);
            UA_NodeId_clear(&conditionSource);
            CONDITION_ASSERT_RETURN_VOID(retval, "Triggering condition event failed",);
        } else {
            UA_Boolean idValue = false;
            UA_Variant_setScalar(&value, &idValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
            retval = UA_Server_setConditionVariableFieldProperty(server, conditionNode, &value,
                                                                 fieldActiveStateQN,
                                                                 twoStateVariableIdQN);
            UA_NodeId_clear(&conditionSource);
            UA_NodeId_clear(&conditionNode);
            CONDITION_ASSERT_RETURN_VOID(retval, "Set ActiveState/Id failed",);
        }
        return;
    }

    if((*((UA_Boolean *)data->value.data) == false) &&
       (lastActiveState != currentActiveState)) {
        
        UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, INACTIVE_TEXT);
        UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = UA_Server_setConditionField(server, conditionNode, &value, fieldActiveStateQN);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition ActiveState failed",
                                     UA_NodeId_clear(&conditionNode);
                                     UA_NodeId_clear(&conditionSource););

        
        retval = UA_Server_writeObjectProperty_scalar(server, conditionNode, fieldTimeQN,
                                                      &data->sourceTimestamp,
                                                      &UA_TYPES[UA_TYPES_DATETIME]);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set deactivating Time failed",
                                     UA_NodeId_clear(&conditionNode);
                                     UA_NodeId_clear(&conditionSource););

        retval = UA_Server_updateConditionActiveState(server, &conditionSource, &conditionNode,
                                                      currentActiveState, UA_INACTIVE, isLimitalarm);
        UA_NodeId_clear(&conditionSource);
        UA_NodeId_clear(&conditionNode);
        CONDITION_ASSERT_RETURN_VOID(retval, "Set ActiveState failed",);
    }
}

static void
afterWriteCallbackQualityChange(UA_Server *server,
                                const UA_NodeId *sessionId, void *sessionContext,
                                const UA_NodeId *nodeId, void *nodeContext,
                                const UA_NumericRange *range, const UA_DataValue *data) {
    //TODO
}

static void
afterWriteCallbackSeverityChange(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *nodeId, void *nodeContext,
                                 const UA_NumericRange *range, const UA_DataValue *data) {
    UA_QualifiedName fieldLastSeverity = UA_QUALIFIEDNAME(0, CONDITION_FIELD_LASTSEVERITY);
    UA_QualifiedName fieldSourceTimeStamp =
        UA_QUALIFIEDNAME(0, CONDITION_FIELD_CONDITIONVARIABLE_SOURCETIMESTAMP);
    UA_Variant value;

    UA_NodeId condition;
    UA_StatusCode retval = UA_Server_getFieldParentNodeId(server, nodeId, &condition);
    CONDITION_ASSERT_RETURN_VOID(retval, "No Parent Condition found for given Severity Field",);

    
    UA_NodeId conditionSource;
    retval = UA_Server_getNodeIdValueOfConditionField(server, &condition,
                                                      fieldSourceQN, &conditionSource);
    CONDITION_ASSERT_RETURN_VOID(retval, "ConditionSource not found",
                                 UA_NodeId_clear(&condition););

    UA_UInt16 lastSeverity;
    UA_DateTime lastSeveritySourceTimeStamp;
    retval = UA_Server_getConditionLastSeverity(server, &conditionSource, &condition,
                                                &lastSeverity, &lastSeveritySourceTimeStamp);
    CONDITION_ASSERT_RETURN_VOID(retval, "Get Condition LastSeverity failed",
                                 UA_NodeId_clear(&condition);
                                 UA_NodeId_clear(&conditionSource););

    
    UA_LocalizedText message;
    if(lastSeverity < (*(UA_UInt16 *)data->value.data))
        message = UA_LOCALIZEDTEXT(LOCALE, SEVERITY_INCREASED_MESSAGE);
    else
        message = UA_LOCALIZEDTEXT(LOCALE, SEVERITY_DECREASED_MESSAGE);

    
    UA_Variant_setScalar(&value, &lastSeverity, &UA_TYPES[UA_TYPES_UINT16]);
    retval = UA_Server_setConditionField(server, condition, &value, fieldLastSeverity);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition LAstSeverity failed",
                                 UA_NodeId_clear(&condition);
                                 UA_NodeId_clear(&conditionSource););

    
    UA_Variant_setScalar(&value, &lastSeveritySourceTimeStamp, &UA_TYPES[UA_TYPES_DATETIME]);
    retval = UA_Server_setConditionVariableFieldProperty(server, condition, &value,
                                               fieldLastSeverity, fieldSourceTimeStamp);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set LastSeverity SourceTimestamp failed",
                                 UA_NodeId_clear(&condition);
                                 UA_NodeId_clear(&conditionSource););

    
    lastSeverity = *(UA_UInt16 *)data->value.data;
    lastSeveritySourceTimeStamp = data->sourceTimestamp;
    retval = UA_Server_updateConditionLastSeverity(server, &conditionSource, &condition,
                                                   lastSeverity, lastSeveritySourceTimeStamp);
    CONDITION_ASSERT_RETURN_VOID(retval, "Update Condition LastSeverity failed",
                                 UA_NodeId_clear(&condition);
    UA_NodeId_clear(&conditionSource););

    
    UA_Variant_setScalar(&value, (void*)(uintptr_t)((const UA_DateTime*)&data->sourceTimestamp),
                         &UA_TYPES[UA_TYPES_DATETIME]);
    retval = UA_Server_setConditionField(server, condition, &value, fieldTimeQN);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition Time failed",
                                 UA_NodeId_clear(&condition););

    
    UA_Variant_setScalar(&value, &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = UA_Server_setConditionField(server, condition, &value, fieldMessageQN);
    CONDITION_ASSERT_RETURN_VOID(retval, "Set Condition Message failed",
                                 UA_NodeId_clear(&condition););

#ifdef CONDITION_SEVERITYCHANGECALLBACK_ENABLE
    
    if(UA_Server_isRetained(server, &condition)) {
        
        //Condition Nodes should not be deleted after triggering the event
        retval = UA_Server_triggerConditionEvent(server, condition, conditionSource, NULL);
        CONDITION_ASSERT_RETURN_VOID(retval, "Triggering condition event failed",
                                     UA_NodeId_clear(&condition);
        UA_NodeId_clear(&conditionSource););
    }
#endif 
    UA_NodeId_clear(&conditionSource);
    UA_NodeId_clear(&condition);
}

static UA_StatusCode
disableMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                      void *sessionContext, const UA_NodeId *methodId,
                      void *methodContext, const UA_NodeId *objectId,
                      void *objectContext, size_t inputSize,
                      const UA_Variant *input, size_t outputSize, UA_Variant *output) {
    UA_NodeId conditionTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE);
    if(UA_NodeId_equal(objectId, &conditionTypeNodeId)) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Cannot call method of ConditionType Node. StatusCode %s",
                       UA_StatusCode_name(UA_STATUSCODE_BADNODEIDINVALID));
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    
    if(!UA_Server_isTwoStateVariableInTrueState(server, objectId, &fieldEnabledStateQN))
        return UA_STATUSCODE_BADCONDITIONALREADYDISABLED;

    UA_Variant value;
    UA_Boolean idValue = false;
    UA_Variant_setScalar(&value, &idValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_StatusCode retval =
        UA_Server_setConditionVariableFieldProperty(server, *objectId, &value,
                                                    fieldEnabledStateQN, twoStateVariableIdQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Disable Condition failed",);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
enableMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_NodeId *methodId,
                     void *methodContext, const UA_NodeId *objectId,
                     void *objectContext, size_t inputSize,
                     const UA_Variant *input, size_t outputSize,
                     UA_Variant *output) {
    UA_NodeId conditionTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE);
    if(UA_NodeId_equal(objectId, &conditionTypeNodeId)) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Cannot call method of ConditionType Node. StatusCode %s",
                       UA_StatusCode_name(UA_STATUSCODE_BADNODEIDINVALID));
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    
    if(UA_Server_isTwoStateVariableInTrueState(server, objectId, &fieldEnabledStateQN))
        return UA_STATUSCODE_BADCONDITIONALREADYENABLED;

    UA_Variant value;
    UA_Boolean idValue = true;
    UA_Variant_setScalar(&value, &idValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_StatusCode retval =
        UA_Server_setConditionVariableFieldProperty(server, *objectId, &value,
                                                    fieldEnabledStateQN, twoStateVariableIdQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Enable Condition failed",);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
addCommentMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                         void *sessionContext, const UA_NodeId *methodId,
                         void *methodContext, const UA_NodeId *objectId,
                         void *objectContext, size_t inputSize,
                         const UA_Variant *input, size_t outputSize,
                         UA_Variant *output) {
    UA_EventLoop *el = server->config.eventLoop;

    UA_QualifiedName fieldComment = UA_QUALIFIEDNAME(0, CONDITION_FIELD_COMMENT);
    UA_QualifiedName fieldSourceTimeStamp =
        UA_QUALIFIEDNAME(0, CONDITION_FIELD_CONDITIONVARIABLE_SOURCETIMESTAMP);
    UA_LocalizedText message;
    UA_NodeId triggerEvent;
    UA_Variant value;
    UA_DateTime fieldSourceTimeStampValue = el->dateTime_now(el);

    UA_NodeId conditionTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE);
    if(UA_NodeId_equal(objectId, &conditionTypeNodeId)) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Cannot call method of ConditionType Node. StatusCode %s",
                       UA_StatusCode_name(UA_STATUSCODE_BADNODEIDINVALID));
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    UA_StatusCode retval =
        UA_Server_getConditionBranchNodeId(server, (UA_ByteString *)input[0].data,
                                           &triggerEvent);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "ConditionId based on EventId not found",);

    
    if(!UA_Server_isRetained(server, &triggerEvent))
        return UA_STATUSCODE_BADCONDITIONDISABLED;

    
    UA_Variant_setScalar(&value, &fieldSourceTimeStampValue, &UA_TYPES[UA_TYPES_DATETIME]);
    retval = UA_Server_setConditionVariableFieldProperty(server, triggerEvent, &value,
                                                         fieldComment, fieldSourceTimeStamp);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition EnabledState text failed",
                                   UA_NodeId_clear(&triggerEvent););

    
    retval = UA_Server_writeObjectProperty_scalar(server, triggerEvent, fieldTimeQN,
                                                  &fieldSourceTimeStampValue,
                                                  &UA_TYPES[UA_TYPES_DATETIME]);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set enabling/disabling Time failed",
                                   UA_NodeId_clear(&triggerEvent););

    
    message = UA_LOCALIZEDTEXT(LOCALE, COMMENT_MESSAGE);
    UA_Variant_setScalar(&value, &message, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = UA_Server_setConditionField(server, triggerEvent, &value, fieldMessageQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition Message failed",
                                   UA_NodeId_clear(&triggerEvent););

    
    UA_LocalizedText *inputComment = (UA_LocalizedText *)input[1].data;
    UA_String nullString = UA_STRING_NULL;
    if(!UA_ByteString_equal(&inputComment->locale, &nullString) &&
       !UA_ByteString_equal(&inputComment->text, &nullString)) {
        UA_Variant_setScalar(&value, inputComment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = UA_Server_setConditionField(server, triggerEvent, &value, fieldComment);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition Comment failed",
                                       UA_NodeId_clear(&triggerEvent););
    }

    
    UA_NodeId conditionSource;
    retval = UA_Server_getNodeIdValueOfConditionField(server, &triggerEvent,
                                                      fieldSourceQN, &conditionSource);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "ConditionSource not found",
                                   UA_NodeId_clear(&triggerEvent););

    
    //Condition Nodes should not be deleted after triggering the event
    retval = UA_Server_triggerConditionEvent(server, triggerEvent, conditionSource, NULL);
    UA_NodeId_clear(&conditionSource);
    UA_NodeId_clear(&triggerEvent);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Triggering condition event failed",);
    return retval;
}

static UA_StatusCode
acknowledgeMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                          void *sessionContext, const UA_NodeId *methodId,
                          void *methodContext, const UA_NodeId *objectId,
                          void *objectContext, size_t inputSize,
                          const UA_Variant *input, size_t outputSize,
                          UA_Variant *output) {
    UA_QualifiedName fieldComment = UA_QUALIFIEDNAME(0, CONDITION_FIELD_COMMENT);
    UA_Variant value;

    UA_NodeId conditionTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE);
    if(UA_NodeId_equal(objectId, &conditionTypeNodeId)) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Cannot call method of ConditionType Node. StatusCode %s",
                       UA_StatusCode_name(UA_STATUSCODE_BADNODEIDINVALID));
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    
    UA_NodeId conditionNode;
    UA_StatusCode retval =
        UA_Server_getConditionBranchNodeId(server, (UA_ByteString *)input[0].data,
                                           &conditionNode);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "ConditionId based on EventId not found",);

    
    if(!UA_Server_isRetained(server, &conditionNode))
        return UA_STATUSCODE_BADCONDITIONDISABLED;

    
    if(UA_Server_isTwoStateVariableInTrueState(server, &conditionNode, &fieldAckedStateQN))
        return UA_STATUSCODE_BADCONDITIONBRANCHALREADYACKED;

    
    UA_NodeId eventType;
    retval = UA_Server_getNodeIdValueOfConditionField(server, &conditionNode,
                                                      UA_QUALIFIEDNAME(0, CONDITION_FIELD_EVENTTYPE),
                                                      &eventType);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "EventType not found",
                                   UA_NodeId_clear(&conditionNode););

    
    UA_NodeId AcknowledgeableConditionTypeId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE);
    UA_LOCK(&server->serviceMutex);
    UA_Boolean found = isNodeInTree_singleRef(server, &eventType, &AcknowledgeableConditionTypeId,
                                              UA_REFERENCETYPEINDEX_HASSUBTYPE);
    UA_UNLOCK(&server->serviceMutex);
    if(!found) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Condition Type must be a subtype of AcknowledgeableConditionType!");
        UA_NodeId_clear(&conditionNode);
        UA_NodeId_clear(&eventType);
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    UA_NodeId_clear(&eventType);

    
    UA_LocalizedText *inputComment = (UA_LocalizedText *)input[1].data;
    UA_String nullString = UA_STRING_NULL;
    if(!UA_ByteString_equal(&inputComment->locale, &nullString) &&
       !UA_ByteString_equal(&inputComment->text, &nullString)) {
        UA_Variant_setScalar(&value, inputComment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = UA_Server_setConditionField(server, conditionNode, &value, fieldComment);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition Comment failed",
                                       UA_NodeId_clear(&conditionNode););
    }

    
    UA_Boolean idValue = true;
    UA_Variant_setScalar(&value, &idValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
    retval = UA_Server_setConditionVariableFieldProperty(server, conditionNode, &value,
                                               fieldAckedStateQN, twoStateVariableIdQN);
    UA_NodeId_clear(&conditionNode);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Acknowledge Condition failed",);
    return retval;
}

#ifdef CONDITIONOPTIONALFIELDS_SUPPORT
static UA_StatusCode
confirmMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                      void *sessionContext, const UA_NodeId *methodId,
                      void *methodContext, const UA_NodeId *objectId,
                      void *objectContext, size_t inputSize,
                      const UA_Variant *input, size_t outputSize,
                      UA_Variant *output) {
    UA_QualifiedName fieldComment = UA_QUALIFIEDNAME(0, CONDITION_FIELD_COMMENT);
    UA_Variant value;

    UA_NodeId conditionTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE);
    if(UA_NodeId_equal(objectId, &conditionTypeNodeId)) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Cannot call method of ConditionType Node. StatusCode %s",
                       UA_StatusCode_name(UA_STATUSCODE_BADNODEIDINVALID));
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    
    UA_NodeId conditionNode;
    UA_StatusCode retval =
        UA_Server_getConditionBranchNodeId(server, (UA_ByteString *)input[0].data,
                                           &conditionNode);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "ConditionId based on EventId not found",);

    
    if(!UA_Server_isRetained(server, &conditionNode))
        return UA_STATUSCODE_BADCONDITIONDISABLED;

    
    if(UA_Server_isTwoStateVariableInTrueState(server, &conditionNode, &fieldConfirmedStateQN))
        return UA_STATUSCODE_BADCONDITIONBRANCHALREADYCONFIRMED;

    
    UA_NodeId eventType;
    retval = UA_Server_getNodeIdValueOfConditionField(server, &conditionNode,
                                                      UA_QUALIFIEDNAME(0, CONDITION_FIELD_EVENTTYPE),
                                                      &eventType);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "EventType not found",
                                   UA_NodeId_clear(&conditionNode););

    
    UA_NodeId AcknowledgeableConditionTypeId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE);
    UA_LOCK(&server->serviceMutex);
    UA_Boolean found = isNodeInTree_singleRef(server, &eventType, &AcknowledgeableConditionTypeId,
                                              UA_REFERENCETYPEINDEX_HASSUBTYPE);
    UA_UNLOCK(&server->serviceMutex);
    if(!found) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Condition Type must be a subtype of AcknowledgeableConditionType!");
        UA_NodeId_clear(&conditionNode);
        UA_NodeId_clear(&eventType);
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    UA_NodeId_clear(&eventType);

    
    UA_LocalizedText *inputComment = (UA_LocalizedText *)input[1].data;
    UA_String nullString = UA_STRING_NULL;
    if(!UA_ByteString_equal(&inputComment->locale, &nullString) &&
       !UA_ByteString_equal(&inputComment->text, &nullString)) {
        UA_Variant_setScalar(&value, inputComment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = UA_Server_setConditionField(server, conditionNode, &value, fieldComment);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition Comment failed",
                                       UA_NodeId_clear(&conditionNode););
    }

    
    UA_Boolean idValue = true;
    UA_Variant_setScalar(&value, &idValue, &UA_TYPES[UA_TYPES_BOOLEAN]);
    retval = UA_Server_setConditionVariableFieldProperty(server, conditionNode, &value,
                                                         fieldConfirmedStateQN,
                                                         twoStateVariableIdQN);
    UA_NodeId_clear(&conditionNode);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Acknowledge Condition failed",);
    return retval;
}
#endif 

static UA_StatusCode
setRefreshMethodEventFields(UA_Server *server, const UA_NodeId *refreshEventNodId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_QualifiedName fieldSeverity = UA_QUALIFIEDNAME(0, CONDITION_FIELD_SEVERITY);
    UA_QualifiedName fieldSourceName = UA_QUALIFIEDNAME(0, CONDITION_FIELD_SOURCENAME);
    UA_QualifiedName fieldReceiveTime = UA_QUALIFIEDNAME(0, CONDITION_FIELD_RECEIVETIME);
    UA_QualifiedName fieldEventId = UA_QUALIFIEDNAME(0, CONDITION_FIELD_EVENTID);
    UA_String sourceNameString = UA_STRING("Server"); //server is the source of Refresh Events
    UA_UInt16 severityValue = REFRESHEVENT_SEVERITY_DEFAULT;
    UA_ByteString eventId  = UA_BYTESTRING_NULL;
    UA_Variant value;

    
    UA_Variant_setScalar(&value, &severityValue, &UA_TYPES[UA_TYPES_UINT16]);
    UA_StatusCode retval = setConditionField(server, *refreshEventNodId,
                                             &value, fieldSeverity);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set RefreshEvent Severity failed",);

    
    UA_Variant_setScalar(&value, &sourceNameString, &UA_TYPES[UA_TYPES_STRING]);
    retval = setConditionField(server, *refreshEventNodId, &value, fieldSourceName);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set RefreshEvent Source failed",);

    
    UA_EventLoop *el = server->config.eventLoop;
    UA_DateTime fieldReceiveTimeValue = el->dateTime_now(el);
    UA_Variant_setScalar(&value, &fieldReceiveTimeValue, &UA_TYPES[UA_TYPES_DATETIME]);
    retval = setConditionField(server, *refreshEventNodId, &value, fieldReceiveTime);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set RefreshEvent ReceiveTime failed",);

    
    retval = generateEventId(&eventId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Generating EventId failed",);

    UA_Variant_setScalar(&value, &eventId, &UA_TYPES[UA_TYPES_BYTESTRING]);
    retval = setConditionField(server, *refreshEventNodId, &value, fieldEventId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set RefreshEvent EventId failed",);

    UA_ByteString_clear(&eventId);

    return retval;
}

static UA_StatusCode
createRefreshMethodEvents(UA_Server *server, UA_NodeId *outRefreshStartNodId,
                          UA_NodeId *outRefreshEndNodId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_NodeId refreshStartEventTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_REFRESHSTARTEVENTTYPE);
    UA_NodeId refreshEndEventTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_REFRESHENDEVENTTYPE);

    
    UA_StatusCode retval = createEvent(server, refreshStartEventTypeNodeId, outRefreshStartNodId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "CreateEvent RefreshStart failed",);

    
    retval = createEvent(server, refreshEndEventTypeNodeId, outRefreshEndNodId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "CreateEvent RefreshEnd failed",);

    return retval;
}

static UA_StatusCode
setRefreshMethodEvents(UA_Server *server, const UA_NodeId *refreshStartNodId,
                       const UA_NodeId *refreshEndNodId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_StatusCode retval = setRefreshMethodEventFields(server, refreshStartNodId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set standard Fields of RefreshStartEvent failed",);

    
    retval = setRefreshMethodEventFields(server, refreshEndNodId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set standard Fields of RefreshEndEvent failed",);

    return retval;
}

static UA_Boolean
isConditionSourceInMonitoredItem(UA_Server *server, const UA_MonitoredItem *monitoredItem,
                                 const UA_NodeId *conditionSource){
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_ReferenceTypeSet refs = UA_REFTYPESET(UA_REFERENCETYPEINDEX_ORGANIZES);
    refs = UA_ReferenceTypeSet_union(refs, UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASCOMPONENT));
    refs = UA_ReferenceTypeSet_union(refs, UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASEVENTSOURCE));
    refs = UA_ReferenceTypeSet_union(refs, UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASNOTIFIER));
    return isNodeInTree(server, conditionSource, &monitoredItem->itemToMonitor.nodeId, &refs);
}

static UA_StatusCode
refreshLogic(UA_Server *server, const UA_NodeId *refreshStartNodId,
             const UA_NodeId *refreshEndNodId, UA_MonitoredItem *monitoredItem) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_assert(monitoredItem != NULL);

    
    UA_EventLoop *el = server->config.eventLoop;
    UA_DateTime fieldTimeValue = el->dateTime_now(el);
    UA_StatusCode retval =
        writeObjectProperty_scalar(server, *refreshStartNodId, fieldTimeQN,
                                   &fieldTimeValue, &UA_TYPES[UA_TYPES_DATETIME]);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Write Object Property scalar failed",);

    retval = UA_MonitoredItem_addEvent(server, monitoredItem, refreshStartNodId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Events: Could not add the event to a listening node",);

    
    
    UA_ConditionSource *source;
    LIST_FOREACH(source, &server->conditionSources, listEntry) {
        UA_NodeId conditionSource = source->conditionSourceId;
        UA_NodeId serverObjectNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
        if(!UA_NodeId_equal(&monitoredItem->itemToMonitor.nodeId, &conditionSource) &&
           !UA_NodeId_equal(&monitoredItem->itemToMonitor.nodeId, &serverObjectNodeId) &&
           !isConditionSourceInMonitoredItem(server, monitoredItem, &conditionSource))
            continue;

        
        UA_Condition *cond;
        LIST_FOREACH(cond, &source->conditions, listEntry) {
            
            UA_ConditionBranch *branch;
            LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
                if(UA_ByteString_equal(&branch->lastEventId, &UA_BYTESTRING_NULL))
                    continue;

                UA_NodeId triggeredNode;
                if(UA_NodeId_isNull(&branch->conditionBranchId))
                    triggeredNode = cond->conditionId;
                else
                    triggeredNode = branch->conditionBranchId;

                
                if(!isRetained(server, &triggeredNode))
                    continue;

                
                retval = UA_MonitoredItem_addEvent(server, monitoredItem, &triggeredNode);
                CONDITION_ASSERT_RETURN_RETVAL(retval, "Events: Could not add the event to a listening node",);
            }
        }
    }

    
    fieldTimeValue = el->dateTime_now(el);
    retval = writeObjectProperty_scalar(server, *refreshEndNodId, fieldTimeQN,
                                        &fieldTimeValue, &UA_TYPES[UA_TYPES_DATETIME]);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Write Object Property scalar failed",);
    return UA_MonitoredItem_addEvent(server, monitoredItem, refreshEndNodId);
}

static UA_StatusCode
refresh2MethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                      void *sessionContext, const UA_NodeId *methodId,
                      void *methodContext, const UA_NodeId *objectId,
                      void *objectContext, size_t inputSize,
                      const UA_Variant *input, size_t outputSize,
                      UA_Variant *output) {
    UA_LOCK(&server->serviceMutex);
    //TODO implement logic for subscription array
    
    UA_Session *session = getSessionById(server, sessionId);
    UA_Subscription *subscription =
        UA_Session_getSubscriptionById(session, *((UA_UInt32 *)input[0].data));
    if(!subscription) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
    }

    
    UA_StatusCode retval = setRefreshMethodEvents(server,
                                                  &server->refreshEvents[REFRESHEVENT_START_IDX],
                                                  &server->refreshEvents[REFRESHEVENT_END_IDX]);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Create Event RefreshStart or RefreshEnd failed",
                                   UA_UNLOCK(&server->serviceMutex););

    UA_MonitoredItem *monitoredItem =
        UA_Subscription_getMonitoredItem(subscription, *((UA_UInt32 *)input[1].data));
    if(!monitoredItem) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADMONITOREDITEMIDINVALID;
    }

    //TODO when there are a lot of monitoreditems (not only events)?
    retval = refreshLogic(server, &server->refreshEvents[REFRESHEVENT_START_IDX],
                          &server->refreshEvents[REFRESHEVENT_END_IDX], monitoredItem);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Could not refresh Condition",
                                   UA_UNLOCK(&server->serviceMutex););
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
refreshMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                      void *sessionContext, const UA_NodeId *methodId,
                      void *methodContext, const UA_NodeId *objectId,
                      void *objectContext, size_t inputSize,
                      const UA_Variant *input, size_t outputSize,
                      UA_Variant *output) {
    UA_LOCK(&server->serviceMutex);

    //TODO implement logic for subscription array
    
    UA_Session *session = getSessionById(server, sessionId);
    UA_Subscription *subscription =
        UA_Session_getSubscriptionById(session, *((UA_UInt32 *)input[0].data));
    if(!subscription) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
    }

    
    UA_StatusCode retval =
        setRefreshMethodEvents(server, &server->refreshEvents[REFRESHEVENT_START_IDX],
                               &server->refreshEvents[REFRESHEVENT_END_IDX]);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Create Event RefreshStart or RefreshEnd failed",
                                   UA_UNLOCK(&server->serviceMutex););

    //TODO when there are a lot of monitoreditems (not only events)?
    UA_MonitoredItem *monitoredItem = NULL;
    LIST_FOREACH(monitoredItem, &subscription->monitoredItems, listEntry) {
        retval = refreshLogic(server, &server->refreshEvents[REFRESHEVENT_START_IDX],
                              &server->refreshEvents[REFRESHEVENT_END_IDX], monitoredItem);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Could not refresh Condition",
                                       UA_UNLOCK(&server->serviceMutex););
    }
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}





static UA_StatusCode
setConditionInConditionList(UA_Server *server, const UA_NodeId *conditionNodeId,
                            UA_ConditionSource *conditionSourceEntry) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_Condition *conditionListEntry = (UA_Condition*)UA_malloc(sizeof(UA_Condition));
    if(!conditionListEntry)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memset(conditionListEntry, 0, sizeof(UA_Condition));

    
    UA_StatusCode retval = UA_NodeId_copy(conditionNodeId, &conditionListEntry->conditionId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(conditionListEntry);
        return retval;
    }

    UA_ConditionBranch *conditionBranchListEntry;
    conditionBranchListEntry = (UA_ConditionBranch*)UA_malloc(sizeof(UA_ConditionBranch));
    if(!conditionBranchListEntry) {
        UA_free(conditionListEntry);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    memset(conditionBranchListEntry, 0, sizeof(UA_ConditionBranch));
    LIST_INSERT_HEAD(&conditionSourceEntry->conditions, conditionListEntry, listEntry);
    LIST_INSERT_HEAD(&conditionListEntry->conditionBranches, conditionBranchListEntry, listEntry);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
appendConditionEntry(UA_Server *server, const UA_NodeId *conditionNodeId,
                     const UA_NodeId *conditionSourceNodeId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_ConditionSource *source = getConditionSource(server, conditionSourceNodeId);
    if(source)
        return setConditionInConditionList(server, conditionNodeId, source);

    
    UA_ConditionSource *conditionSourceListEntry;
    conditionSourceListEntry = (UA_ConditionSource*)UA_malloc(sizeof(UA_ConditionSource));
    if(!conditionSourceListEntry)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memset(conditionSourceListEntry, 0, sizeof(UA_ConditionSource));

    
    UA_StatusCode retval = UA_NodeId_copy(conditionSourceNodeId,
                                          &conditionSourceListEntry->conditionSourceId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(conditionSourceListEntry);
        return retval;
    }

    LIST_INSERT_HEAD(&server->conditionSources, conditionSourceListEntry, listEntry);
    return setConditionInConditionList(server, conditionNodeId, conditionSourceListEntry);
}

static void
deleteAllBranchesFromCondition(UA_Condition *cond) {
    UA_ConditionBranch *branch, *tmp_branch;
    LIST_FOREACH_SAFE(branch, &cond->conditionBranches, listEntry, tmp_branch) {
        UA_NodeId_clear(&branch->conditionBranchId);
        UA_ByteString_clear(&branch->lastEventId);
        LIST_REMOVE(branch, listEntry);
        UA_free(branch);
    }
}

static void
deleteCondition(UA_Condition *cond) {
    deleteAllBranchesFromCondition(cond);
    UA_NodeId_clear(&cond->conditionId);
    LIST_REMOVE(cond, listEntry);
    UA_free(cond);
}

void
UA_ConditionList_delete(UA_Server *server) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_ConditionSource *source, *tmp_source;
    LIST_FOREACH_SAFE(source, &server->conditionSources, listEntry, tmp_source) {
        UA_Condition *cond, *tmp_cond;
        LIST_FOREACH_SAFE(cond, &source->conditions, listEntry, tmp_cond) {
            deleteCondition(cond);
        }
        UA_NodeId_clear(&source->conditionSourceId);
        LIST_REMOVE(source, listEntry);
        UA_free(source);
    }
    
    UA_NodeId_clear(&server->refreshEvents[REFRESHEVENT_START_IDX]);
    UA_NodeId_clear(&server->refreshEvents[REFRESHEVENT_END_IDX]);
}

UA_StatusCode
UA_getConditionId(UA_Server *server, const UA_NodeId *conditionNodeId,
                  UA_NodeId *outConditionId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_ConditionSource *source;
    LIST_FOREACH(source, &server->conditionSources, listEntry) {
        
        UA_Condition *cond;
        LIST_FOREACH(cond, &source->conditions, listEntry) {
            if(UA_NodeId_equal(&cond->conditionId, conditionNodeId)) {
                *outConditionId = cond->conditionId;
                return UA_STATUSCODE_GOOD;
            }
            
            UA_ConditionBranch *branch;
            LIST_FOREACH(branch, &cond->conditionBranches, listEntry) {
                if(UA_NodeId_equal(&branch->conditionBranchId, conditionNodeId)) {
                    *outConditionId = cond->conditionId;
                    return UA_STATUSCODE_GOOD;
                }
            }
        }
    }
    return UA_STATUSCODE_BADNOTFOUND;
}

static UA_Boolean
doesHasEventSourceReferenceExist(UA_Server *server, const UA_NodeId nodeToCheck) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_NodeId hasEventSourceId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASEVENTSOURCE);
    const UA_Node* node = UA_NODESTORE_GET(server, &nodeToCheck);
    if(!node)
        return false;
    for(size_t i = 0; i < node->head.referencesSize; i++) {
        UA_Byte refTypeIndex = node->head.references[i].referenceTypeIndex;
        if((refTypeIndex == UA_REFERENCETYPEINDEX_HASEVENTSOURCE ||
            isNodeInTree_singleRef(server, UA_NODESTORE_GETREFERENCETYPEID(server, refTypeIndex),
                                   &hasEventSourceId, UA_REFERENCETYPEINDEX_HASSUBTYPE)) &&
           (node->head.references[i].isInverse == true)) {
            UA_NODESTORE_RELEASE(server, node);
            return true;
        }
    }
    UA_NODESTORE_RELEASE(server, node);
    return false;
}

static UA_StatusCode
setStandardConditionFields(UA_Server *server, const UA_NodeId* condition,
                           const UA_NodeId* conditionType, const UA_NodeId* conditionSource,
                           const UA_QualifiedName* conditionName) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    
    UA_Variant value;
    UA_Variant_setScalar(&value, (void*)(uintptr_t)conditionType, &UA_TYPES[UA_TYPES_NODEID]);
    UA_StatusCode retval = setConditionField(server, *condition, &value,
                                             UA_QUALIFIEDNAME(0,CONDITION_FIELD_EVENTTYPE));
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set EventType Field failed",);

    
    UA_Variant_setScalar(&value, (void*)(uintptr_t)&conditionName->name,
                         &UA_TYPES[UA_TYPES_STRING]);
    retval = setConditionField(server, *condition, &value,
                               UA_QUALIFIEDNAME(0,CONDITION_FIELD_CONDITIONNAME));
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set ConditionName Field failed",);

    
    UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, DISABLED_TEXT);
    UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = setConditionField(server, *condition, &value,
                               UA_QUALIFIEDNAME(0,CONDITION_FIELD_ENABLEDSTATE));
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set EnabledState Field failed",);

    
    UA_Boolean stateId = false;
    UA_Variant_setScalar(&value, &stateId, &UA_TYPES[UA_TYPES_BOOLEAN]);
    retval = setConditionVariableFieldProperty(server, *condition, &value,
                                               UA_QUALIFIEDNAME(0,CONDITION_FIELD_ENABLEDSTATE),
                                               twoStateVariableIdQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set EnabledState/Id Field failed",);

    
    UA_Variant_setScalar(&value, &stateId, &UA_TYPES[UA_TYPES_BOOLEAN]);
    retval = setConditionField(server, *condition, &value, fieldRetainQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Retain Field failed",);

    
    const UA_Node *conditionSourceNode = UA_NODESTORE_GET(server, conditionSource);
    if(!conditionSourceNode) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Couldn't find ConditionSourceNode. StatusCode %s", UA_StatusCode_name(retval));
        return UA_STATUSCODE_BADNOTFOUND;
    }

    
    UA_Variant_setScalar(&value, (void*)(uintptr_t)&conditionSourceNode->head.browseName.name,
                         &UA_TYPES[UA_TYPES_STRING]);
    retval = setConditionField(server, *condition, &value,
                               UA_QUALIFIEDNAME(0,CONDITION_FIELD_SOURCENAME));
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Set SourceName Field failed. StatusCode %s",
                     UA_StatusCode_name(retval));
        UA_NODESTORE_RELEASE(server, conditionSourceNode);
        return retval;
    }

    
    UA_Variant_setScalar(&value, (void*)(uintptr_t)&conditionSourceNode->head.nodeId,
                         &UA_TYPES[UA_TYPES_NODEID]);
    retval = setConditionField(server, *condition, &value, fieldSourceQN);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Set SourceNode Field failed. StatusCode %s", UA_StatusCode_name(retval));
        UA_NODESTORE_RELEASE(server, conditionSourceNode);
        return retval;
    }

    UA_NODESTORE_RELEASE(server, conditionSourceNode);

    
    UA_StatusCode qualityValue = UA_STATUSCODE_GOOD;
    UA_Variant_setScalar(&value, &qualityValue, &UA_TYPES[UA_TYPES_STATUSCODE]);
    retval = setConditionField(server, *condition, &value,
                               UA_QUALIFIEDNAME(0,CONDITION_FIELD_QUALITY));
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Quality Field failed",);

    
    UA_UInt16 severityValue = 0;
    UA_Variant_setScalar(&value, &severityValue, &UA_TYPES[UA_TYPES_UINT16]);
    retval = setConditionField(server, *condition, &value,
                               UA_QUALIFIEDNAME(0,CONDITION_FIELD_SEVERITY));
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Severity Field failed",);

    

    
    UA_NodeId acknowledgeableConditionTypeId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE);
    if(!isNodeInTree_singleRef(server, conditionType, &acknowledgeableConditionTypeId,
                               UA_REFERENCETYPEINDEX_HASSUBTYPE))
        return UA_STATUSCODE_GOOD;

    
    text = UA_LOCALIZEDTEXT(LOCALE, UNACKED_TEXT);
    UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = setConditionField(server, *condition, &value, fieldAckedStateQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set AckedState Field failed",);

    UA_Variant_setScalar(&value, &stateId, &UA_TYPES[UA_TYPES_BOOLEAN]);
    retval = setConditionVariableFieldProperty(server, *condition, &value,
                                               fieldAckedStateQN, twoStateVariableIdQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set AckedState/Id Field failed",);

#ifdef CONDITIONOPTIONALFIELDS_SUPPORT
    
    retval = addConditionOptionalField(server, *condition, acknowledgeableConditionTypeId,
                                       fieldConfirmedStateQN, NULL);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding ConfirmedState optional Field failed",);

    
    text = UA_LOCALIZEDTEXT(LOCALE, UNCONFIRMED_TEXT);
    UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval = setConditionField(server, *condition, &value, fieldConfirmedStateQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set ConfirmedState Field failed",);

    UA_Variant_setScalar(&value, &stateId, &UA_TYPES[UA_TYPES_BOOLEAN]);
    retval = setConditionVariableFieldProperty(server, *condition, &value,
                                               fieldConfirmedStateQN,
                                               twoStateVariableIdQN);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set EnabledState/Id Field failed",);

    
    UA_NodeId certificateConditionTypeId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_CERTIFICATEEXPIRATIONALARMTYPE);
    if(isNodeInTree_singleRef(server, conditionType, &certificateConditionTypeId,
                               UA_REFERENCETYPEINDEX_HASSUBTYPE)) {
        retval = addConditionOptionalField(server, *condition, certificateConditionTypeId,
                                           fieldExpirationLimitQN, NULL);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding Expiration Limit optional field failed",);

        
        UA_Duration defaultValue = EXPIRATION_LIMIT_DEFAULT_VALUE;
        retval |= writeObjectProperty_scalar(server, *condition, fieldExpirationLimitQN,
                                             &defaultValue, &UA_TYPES[UA_TYPES_DURATION]);

    }

#endif 

    
    UA_NodeId alarmConditionTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ALARMCONDITIONTYPE);
    if(isNodeInTree_singleRef(server, conditionType, &alarmConditionTypeId,
                              UA_REFERENCETYPEINDEX_HASSUBTYPE)) {
        
        text = UA_LOCALIZEDTEXT(LOCALE, INACTIVE_TEXT);
        UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        retval = setConditionField(server, *condition, &value,
                                   UA_QUALIFIEDNAME(0,CONDITION_FIELD_ACTIVESTATE));
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set ActiveState Field failed",);
    }

#ifdef CONDITIONOPTIONALFIELDS_SUPPORT
    
    UA_NodeId LimitAlarmTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_LIMITALARMTYPE);
    if(!isNodeInTree_singleRef(server, conditionType, &LimitAlarmTypeId,
                               UA_REFERENCETYPEINDEX_HASSUBTYPE))
        return retval;

    
    retval = addConditionOptionalField(server, *condition, LimitAlarmTypeId,
                                       fieldLowLimitQN, NULL);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding LowLimit optional Field failed",);

    
    retval = addConditionOptionalField(server, *condition, LimitAlarmTypeId,
                                       fieldHighLimitQN, NULL);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding HighLimit optional Field failed",);

    
    retval = addConditionOptionalField(server, *condition, LimitAlarmTypeId,
                                       fieldHighHighLimitQN, NULL);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding HighLimit optional Field failed",);

    
    retval = addConditionOptionalField(server, *condition, LimitAlarmTypeId,
                                       fieldLowLowLimitQN, NULL);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding LowLowLimit optional Field failed",);

    
    UA_NodeId RateOfChangeAlarmTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_EXCLUSIVERATEOFCHANGEALARMTYPE);
    if(!isNodeInTree_singleRef(server, conditionType, &RateOfChangeAlarmTypeId,
                               UA_REFERENCETYPEINDEX_HASSUBTYPE))
        return retval;

    retval = addConditionOptionalField(server, *condition, RateOfChangeAlarmTypeId,
                                       fieldEngineeringUnitsQN, NULL);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding EngineeringUnit optional Field failed",);

#endif 

    return retval;
}


static UA_StatusCode
setTwoStateVariableCallbacks(UA_Server *server, const UA_NodeId* condition,
                             const UA_NodeId* conditionType) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_NodeId twoStateVariableIdNodeId = UA_NODEID_NULL;
    UA_StatusCode retval = getConditionFieldPropertyNodeId(server, condition, &fieldEnabledStateQN,
                                                           &twoStateVariableIdQN,
                                                           &twoStateVariableIdNodeId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Id Property of TwoStateVariable not found",);

    UA_ValueCallback callback;
    callback.onRead = NULL;
    callback.onWrite = afterWriteCallbackEnabledStateChange;
    retval = setVariableNode_valueCallback(server, twoStateVariableIdNodeId, callback);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set EnabledState Callback failed",
                                   UA_NodeId_clear(&twoStateVariableIdNodeId););

    
    
    UA_NodeId acknowledgeableConditionTypeId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE);
    if(isNodeInTree_singleRef(server, conditionType, &acknowledgeableConditionTypeId,
                              UA_REFERENCETYPEINDEX_HASSUBTYPE)) {
        UA_NodeId_clear(&twoStateVariableIdNodeId);
        retval = getConditionFieldPropertyNodeId(server, condition, &fieldAckedStateQN,
                                                 &twoStateVariableIdQN, &twoStateVariableIdNodeId);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Id Property of TwoStateVariable not found",);

        callback.onWrite = afterWriteCallbackAckedStateChange;
        retval = setVariableNode_valueCallback(server, twoStateVariableIdNodeId, callback);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set AckedState Callback failed",
                                       UA_NodeId_clear(&twoStateVariableIdNodeId););

#ifdef CONDITIONOPTIONALFIELDS_SUPPORT
        
        callback.onWrite = afterWriteCallbackConfirmedStateChange;
        UA_NodeId_clear(&twoStateVariableIdNodeId);
        retval = getConditionFieldPropertyNodeId(server, condition, &fieldConfirmedStateQN,
                                                 &twoStateVariableIdQN, &twoStateVariableIdNodeId);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Id Property of TwoStateVariable not found",);

        
        UA_NodeId hasComponent = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
        UA_NodeId confirm = UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_CONFIRM);
        retval = addRef(server, *condition, hasComponent, confirm, true);
        CONDITION_ASSERT_RETURN_RETVAL(retval,
                                       "Adding HasComponent Reference to Confirm Method failed",
                                       UA_NodeId_clear(&twoStateVariableIdNodeId););

        retval = setVariableNode_valueCallback(server, twoStateVariableIdNodeId, callback);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding ConfirmedState/Id callback failed",
                                       UA_NodeId_clear(&twoStateVariableIdNodeId););
#endif 

        
        
        UA_NodeId alarmConditionTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ALARMCONDITIONTYPE);
        if(isNodeInTree_singleRef(server, conditionType, &alarmConditionTypeId,
                                  UA_REFERENCETYPEINDEX_HASSUBTYPE)) {
            UA_NodeId_clear(&twoStateVariableIdNodeId);
            retval = getConditionFieldPropertyNodeId(server, condition, &fieldActiveStateQN,
                                                     &twoStateVariableIdQN, &twoStateVariableIdNodeId);
            CONDITION_ASSERT_RETURN_RETVAL(retval, "Id Property of TwoStateVariable not found",);

            callback.onWrite = afterWriteCallbackActiveStateChange;
            retval = setVariableNode_valueCallback(server, twoStateVariableIdNodeId,
                                                             callback);
            CONDITION_ASSERT_RETURN_RETVAL(retval, "Set ActiveState Callback failed",
                                           UA_NodeId_clear(&twoStateVariableIdNodeId););
        }
    }

    UA_NodeId_clear(&twoStateVariableIdNodeId);
    return retval;
}


static UA_StatusCode
setConditionVariableCallbacks(UA_Server *server, const UA_NodeId *condition,
                              const UA_NodeId *conditionType) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_QualifiedName conditionVariableName[2] = {
        UA_QUALIFIEDNAME(0, CONDITION_FIELD_QUALITY),
        UA_QUALIFIEDNAME(0, CONDITION_FIELD_SEVERITY)
    };// extend array with other fields when needed

    UA_BrowsePathResult bpr =
        browseSimplifiedBrowsePath(server, *condition, 1, &conditionVariableName[0]);
    if(bpr.statusCode != UA_STATUSCODE_GOOD)
        return bpr.statusCode;
    UA_ValueCallback callback ;
    callback.onRead = NULL;
    callback.onWrite = afterWriteCallbackQualityChange;
    retval = setVariableNode_valueCallback(server, bpr.targets[0].targetId.nodeId,
                                           callback);
    UA_BrowsePathResult_clear(&bpr);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    bpr = browseSimplifiedBrowsePath(server, *condition, 1, &conditionVariableName[1]);
    if(bpr.statusCode != UA_STATUSCODE_GOOD)
        return bpr.statusCode;
    callback.onWrite = afterWriteCallbackSeverityChange;
    retval = setVariableNode_valueCallback(server, bpr.targets[0].targetId.nodeId,
                                           callback);
    UA_BrowsePathResult_clear(&bpr);
    return retval;
}

static UA_StatusCode
setConditionMethodCallbacks(UA_Server *server, const UA_NodeId* condition,
                            const UA_NodeId* conditionType) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_NodeId methodId[7] = {
        {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_CONDITIONTYPE_DISABLE}},
        {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_CONDITIONTYPE_ENABLE}},
        {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_CONDITIONTYPE_ADDCOMMENT}},
        {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH}},
        {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH2}},
        {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE}}
#ifdef CONDITIONOPTIONALFIELDS_SUPPORT
        ,{0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_CONFIRM}}
#endif
    };

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= setMethodNode_callback(server, methodId[0], disableMethodCallback);
    retval |= setMethodNode_callback(server, methodId[1], enableMethodCallback);
    retval |= setMethodNode_callback(server, methodId[2], addCommentMethodCallback);
    retval |= setMethodNode_callback(server, methodId[3], refreshMethodCallback);
    retval |= setMethodNode_callback(server, methodId[4], refresh2MethodCallback);
    retval |= setMethodNode_callback(server, methodId[5], acknowledgeMethodCallback);
#ifdef CONDITIONOPTIONALFIELDS_SUPPORT
    retval |= setMethodNode_callback(server, methodId[6], confirmMethodCallback);
#endif

    return retval;
}

static UA_StatusCode
setStandardConditionCallbacks(UA_Server *server, const UA_NodeId* condition,
                              const UA_NodeId* conditionType) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_StatusCode retval = setTwoStateVariableCallbacks(server, condition, conditionType);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set TwoStateVariable Callback failed",);

    retval = setConditionVariableCallbacks(server, condition, conditionType);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set ConditionVariable Callback failed",);

    
    if(LIST_EMPTY(&server->conditionSources)) {
        retval = setConditionMethodCallbacks(server, condition, conditionType);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Method Callback failed",);

        // Create RefreshEvents
        if(UA_NodeId_isNull(&server->refreshEvents[REFRESHEVENT_START_IDX]) &&
           UA_NodeId_isNull(&server->refreshEvents[REFRESHEVENT_END_IDX])) {
            retval = createRefreshMethodEvents(server, &server->refreshEvents[REFRESHEVENT_START_IDX],
                                               &server->refreshEvents[REFRESHEVENT_END_IDX]);
            CONDITION_ASSERT_RETURN_RETVAL(retval, "Create RefreshEvents failed",);
        }
    }

    return retval;
}

static UA_StatusCode
addCondition_finish(UA_Server *server, const UA_NodeId conditionId,
                    const UA_NodeId conditionType, const UA_QualifiedName conditionName,
                    const UA_NodeId conditionSource, const UA_NodeId hierarchialReferenceType) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_StatusCode retval = addNode_finish(server, &server->adminSession, &conditionId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Finish node failed",);

    
    UA_NodeId serverObject = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    if(!doesHasEventSourceReferenceExist(server, conditionSource) &&
       !UA_NodeId_equal(&serverObject, &conditionSource)) {
         UA_NodeId hasHasEventSourceId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASEVENTSOURCE);
         retval = addRef(server, serverObject, hasHasEventSourceId, conditionSource, true);
          CONDITION_ASSERT_RETURN_RETVAL(retval, "Creating HasHasEventSource Reference "
                                         "to the Server Object failed",);
    }

    UA_NodeId hasCondition = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCONDITION);
    if(!UA_NodeId_isNull(&hierarchialReferenceType)) {
        // only Check hierarchialReferenceType
        retval = addRef(server, conditionSource, hierarchialReferenceType, conditionId, true);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Creating hierarchical Reference to "
                                       "ConditionSource failed",);

        retval = addRef(server, conditionSource, hasCondition, conditionId, true);
        CONDITION_ASSERT_RETURN_RETVAL(retval, "Creating HasCondition Reference failed",);
    } else {
        retval = addRef(server, conditionSource, hasCondition, conditionType, true);
        if(retval != UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED)
            CONDITION_ASSERT_RETURN_RETVAL(retval, "Creating HasCondition Reference failed",);
    }

    
    retval = setStandardConditionFields(server, &conditionId, &conditionType,
                                        &conditionSource, &conditionName);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set standard Condition Fields failed",);

    
    retval = setStandardConditionCallbacks(server, &conditionId, &conditionType);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Set Condition callbacks failed",);

    UA_NodeId refreshStartEventTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_REFRESHSTARTEVENTTYPE);
    UA_NodeId refreshEndEventTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_REFRESHENDEVENTTYPE);

    UA_Boolean startAbstract = false;
    UA_Boolean endAbstract = false;
    readWithReadValue(server, &refreshStartEventTypeNodeId,
                      UA_ATTRIBUTEID_ISABSTRACT, &startAbstract);
    readWithReadValue(server, &refreshEndEventTypeNodeId,
                      UA_ATTRIBUTEID_ISABSTRACT, &endAbstract);

    UA_Boolean inner = (startAbstract == false && endAbstract == false);
    if(inner) {
        writeIsAbstractAttribute(server, refreshStartEventTypeNodeId, false);
        writeIsAbstractAttribute(server, refreshEndEventTypeNodeId, false);
    }

    
    return appendConditionEntry(server, &conditionId, &conditionSource);
}

UA_StatusCode
UA_Server_createCondition(UA_Server *server,
                          const UA_NodeId conditionId, const UA_NodeId conditionType,
                          const UA_QualifiedName conditionName,
                          const UA_NodeId conditionSource,
                          const UA_NodeId hierarchialReferenceType,
                          UA_NodeId *outNodeId) {
    if(!outNodeId) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "outNodeId cannot be NULL!");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_StatusCode retval = UA_Server_addCondition_begin(server, conditionId, conditionType,
                                                        conditionName, outNodeId);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_LOCK(&server->serviceMutex);
    retval = addCondition_finish(server, *outNodeId, conditionType, conditionName,
                               conditionSource, hierarchialReferenceType);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}

UA_StatusCode
UA_Server_addCondition_begin(UA_Server *server, const UA_NodeId conditionId,
                             const UA_NodeId conditionType,
                             const UA_QualifiedName conditionName, UA_NodeId *outNodeId) {
    if(!outNodeId) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "outNodeId cannot be NULL!");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    
    UA_NodeId conditionTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE);
    UA_LOCK(&server->serviceMutex);
    UA_Boolean found = isNodeInTree_singleRef(server, &conditionType, &conditionTypeId,
                                              UA_REFERENCETYPEINDEX_HASSUBTYPE);
    UA_UNLOCK(&server->serviceMutex);
    if(!found) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                     "Condition Type must be a subtype of ConditionType!");
        return UA_STATUSCODE_BADNOMATCH;
    }

    
    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.displayName.locale = UA_STRING("en");
    oAttr.displayName.text = conditionName.name;
    UA_StatusCode retval =
        UA_Server_addNode_begin(server, UA_NODECLASS_OBJECT, conditionId,
                                UA_NODEID_NULL, UA_NODEID_NULL, conditionName,
                                conditionType, &oAttr, &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES],
                                NULL, outNodeId);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Adding Condition failed", );
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_addCondition_finish(UA_Server *server, const UA_NodeId conditionId,
                              const UA_NodeId conditionSource,
                              const UA_NodeId hierarchialReferenceType) {
    UA_LOCK(&server->serviceMutex);

    const UA_Node *node = UA_NODESTORE_GET(server, &conditionId);

    if(!node) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    }

    const UA_Node *type = getNodeType(server, &node->head);
    if(!type) {
        UA_NODESTORE_RELEASE(server, node);
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
    }

    UA_StatusCode retval;
    retval = addCondition_finish(server, conditionId, type->head.nodeId, node->head.browseName,
                                 conditionSource, hierarchialReferenceType);

    UA_NODESTORE_RELEASE(server, type);
    UA_NODESTORE_RELEASE(server, node);

    UA_UNLOCK(&server->serviceMutex);
    return retval;
}

#ifdef CONDITIONOPTIONALFIELDS_SUPPORT

static UA_StatusCode
addOptionalVariableField(UA_Server *server, const UA_NodeId *originCondition,
                         const UA_QualifiedName *fieldName,
                         const UA_VariableNode *optionalVariableFieldNode,
                         UA_NodeId *outOptionalVariable) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_VariableAttributes vAttr = UA_VariableAttributes_default;
    vAttr.valueRank = optionalVariableFieldNode->valueRank;
    vAttr.displayName = UA_Session_getNodeDisplayName(&server->adminSession,
                                                      &optionalVariableFieldNode->head);
    vAttr.dataType = optionalVariableFieldNode->dataType;

    
    const UA_Node *type = getNodeType(server, &optionalVariableFieldNode->head);
    if(!type) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Invalid VariableType. StatusCode %s",
                       UA_StatusCode_name(UA_STATUSCODE_BADTYPEDEFINITIONINVALID));
        return UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
    }

    
    UA_NodeId referenceToParent;
    UA_NodeId propertyTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE);
    if(UA_NodeId_equal(&type->head.nodeId, &propertyTypeNodeId))
        referenceToParent = UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    else
        referenceToParent = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);

    
    UA_NodeId optionalVariable = {originCondition->namespaceIndex, UA_NODEIDTYPE_NUMERIC, {0}};
    UA_StatusCode retval =
        addNode(server, UA_NODECLASS_VARIABLE, optionalVariable,
                *originCondition, referenceToParent, *fieldName,
                type->head.nodeId, &vAttr, &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES],
                NULL, outOptionalVariable);
    UA_NODESTORE_RELEASE(server, type);
    return retval;
}

static UA_StatusCode
addOptionalObjectField(UA_Server *server, const UA_NodeId *originCondition,
                       const UA_QualifiedName* fieldName,
                       const UA_ObjectNode *optionalObjectFieldNode,
                       UA_NodeId *outOptionalObject) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.displayName = UA_Session_getNodeDisplayName(&server->adminSession,
                                                      &optionalObjectFieldNode->head);

    
    const UA_Node *type = getNodeType(server, &optionalObjectFieldNode->head);
    if(!type) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Invalid ObjectType. StatusCode %s",
                       UA_StatusCode_name(UA_STATUSCODE_BADTYPEDEFINITIONINVALID));
        return UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
    }

    
    UA_NodeId referenceToParent;
    UA_NodeId propertyTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE);
    if(UA_NodeId_equal(&type->head.nodeId, &propertyTypeNodeId))
        referenceToParent = UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    else
        referenceToParent = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);

    UA_NodeId optionalObject = {originCondition->namespaceIndex, UA_NODEIDTYPE_NUMERIC, {0}};
    UA_StatusCode retval = addNode(server, UA_NODECLASS_OBJECT, optionalObject,
                                   *originCondition, referenceToParent, *fieldName,
                                   type->head.nodeId, &oAttr, &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES],
                                   NULL, outOptionalObject);
    UA_NODESTORE_RELEASE(server, type);
    return retval;
}

#endif 

static UA_StatusCode
addConditionOptionalField(UA_Server *server, const UA_NodeId condition,
                          const UA_NodeId conditionType, const UA_QualifiedName fieldName,
                          UA_NodeId *outOptionalNode) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

#ifdef CONDITIONOPTIONALFIELDS_SUPPORT
    UA_BrowsePathResult bpr = browseSimplifiedBrowsePath(server, conditionType, 1, &fieldName);
    if(bpr.statusCode != UA_STATUSCODE_GOOD)
        return bpr.statusCode;

    
    UA_NodeId optionalFieldNodeId = bpr.targets[0].targetId.nodeId;
    const UA_Node *optionalFieldNode = UA_NODESTORE_GET(server, &optionalFieldNodeId);
    if(NULL == optionalFieldNode) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Couldn't find optional Field Node in ConditionType. StatusCode %s",
                       UA_StatusCode_name(UA_STATUSCODE_BADNOTFOUND));
        UA_BrowsePathResult_clear(&bpr);
        return UA_STATUSCODE_BADNOTFOUND;
    }

    switch(optionalFieldNode->head.nodeClass) {
        case UA_NODECLASS_VARIABLE: {
            UA_StatusCode retval =
                addOptionalVariableField(server, &condition, &fieldName,
                                         (const UA_VariableNode *)optionalFieldNode, outOptionalNode);
            if(retval != UA_STATUSCODE_GOOD) {
                UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                             "Adding Condition Optional Variable Field failed. StatusCode %s",
                             UA_StatusCode_name(retval));
            }
            UA_BrowsePathResult_clear(&bpr);
            UA_NODESTORE_RELEASE(server, optionalFieldNode);
            return retval;
        }
        case UA_NODECLASS_OBJECT:{
          UA_StatusCode retval =
              addOptionalObjectField(server, &condition, &fieldName,
                                     (const UA_ObjectNode *)optionalFieldNode, outOptionalNode);
          if(retval != UA_STATUSCODE_GOOD) {
              UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                           "Adding Condition Optional Object Field failed. StatusCode %s",
                           UA_StatusCode_name(retval));
          }
          UA_BrowsePathResult_clear(&bpr);
          UA_NODESTORE_RELEASE(server, optionalFieldNode);
          return retval;
        }
        case UA_NODECLASS_METHOD:
            UA_BrowsePathResult_clear(&bpr);
            UA_NODESTORE_RELEASE(server, optionalFieldNode);
            return UA_STATUSCODE_BADNOTSUPPORTED;
        default:
            UA_BrowsePathResult_clear(&bpr);
            UA_NODESTORE_RELEASE(server, optionalFieldNode);
            return UA_STATUSCODE_BADNOTSUPPORTED;
    }

#else
    UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_USERLAND,
                 "Adding Condition Optional Fields disabled. StatusCode %s",
                 UA_StatusCode_name(UA_STATUSCODE_BADNOTSUPPORTED));
    return UA_STATUSCODE_BADNOTSUPPORTED;
#endif 
}

UA_StatusCode
UA_Server_addConditionOptionalField(UA_Server *server, const UA_NodeId condition,
                                    const UA_NodeId conditionType, const UA_QualifiedName fieldName,
                                    UA_NodeId *outOptionalNode) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = addConditionOptionalField(server, condition, conditionType,
                                                  fieldName, outOptionalNode);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}


static UA_StatusCode
setConditionField(UA_Server *server, const UA_NodeId condition,
                  const UA_Variant* value, const UA_QualifiedName fieldName) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(value->arrayLength != 0 || value->data <= UA_EMPTY_ARRAY_SENTINEL) {
      //TODO implement logic for array variants!
      CONDITION_ASSERT_RETURN_RETVAL(UA_STATUSCODE_BADNOTIMPLEMENTED,
                                     "Set Condition Field with Array value not implemented",);
    }

    UA_BrowsePathResult bpr = browseSimplifiedBrowsePath(server, condition, 1, &fieldName);
    if(bpr.statusCode != UA_STATUSCODE_GOOD)
        return bpr.statusCode;

    UA_StatusCode retval = writeValueAttribute(server, bpr.targets[0].targetId.nodeId, value);
    UA_BrowsePathResult_clear(&bpr);

    return retval;
}


UA_StatusCode
UA_Server_setConditionField(UA_Server *server, const UA_NodeId condition,
                            const UA_Variant* value, const UA_QualifiedName fieldName) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = setConditionField(server, condition, value, fieldName);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}

static UA_StatusCode
setConditionVariableFieldProperty(UA_Server *server, const UA_NodeId condition,
                                  const UA_Variant* value,
                                  const UA_QualifiedName variableFieldName,
                                  const UA_QualifiedName variablePropertyName) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(value->arrayLength != 0 || value->data <= UA_EMPTY_ARRAY_SENTINEL) {
        //TODO implement logic for array variants!
        CONDITION_ASSERT_RETURN_RETVAL(UA_STATUSCODE_BADNOTIMPLEMENTED,
                                       "Set Property of Condition Field with Array value not implemented",);
    }

    
    UA_BrowsePathResult bprConditionVariableField =
        browseSimplifiedBrowsePath(server, condition, 1, &variableFieldName);
    if(bprConditionVariableField.statusCode != UA_STATUSCODE_GOOD)
        return bprConditionVariableField.statusCode;

    
    UA_BrowsePathResult bprVariableFieldProperty =
        browseSimplifiedBrowsePath(server, bprConditionVariableField.targets->targetId.nodeId,
                                   1, &variablePropertyName);
    if(bprVariableFieldProperty.statusCode != UA_STATUSCODE_GOOD) {
        UA_BrowsePathResult_clear(&bprConditionVariableField);
        return bprVariableFieldProperty.statusCode;
    }

    UA_StatusCode retval =
        writeValueAttribute(server, bprVariableFieldProperty.targets[0].targetId.nodeId, value);
    UA_BrowsePathResult_clear(&bprConditionVariableField);
    UA_BrowsePathResult_clear(&bprVariableFieldProperty);
    return retval;
}


UA_StatusCode
UA_Server_setConditionVariableFieldProperty(UA_Server *server, const UA_NodeId condition,
                                            const UA_Variant* value,
                                            const UA_QualifiedName variableFieldName,
                                            const UA_QualifiedName variablePropertyName) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = setConditionVariableFieldProperty(server, condition, value,
                                                          variableFieldName, variablePropertyName);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static UA_StatusCode
triggerConditionEvent(UA_Server *server, const UA_NodeId condition,
                      const UA_NodeId conditionSource, UA_ByteString *outEventId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_ByteString eventId = UA_BYTESTRING_NULL;
    UA_QualifiedName enabledStateField = UA_QUALIFIEDNAME(0, CONDITION_FIELD_ENABLEDSTATE);
    if(!isTwoStateVariableInTrueState(server, &condition, &enabledStateField)) {
        UA_LOG_WARNING(server->config.logging, UA_LOGCATEGORY_USERLAND,
                       "Cannot trigger condition event when "
                       CONDITION_FIELD_ENABLEDSTATE"."
                       CONDITION_FIELD_TWOSTATEVARIABLE_ID" is false.");
        return UA_STATUSCODE_BADCONDITIONALREADYDISABLED;
    }

    setIsCallerAC(server, &condition, &conditionSource, true);

    
    //Condition Nodes should not be deleted after triggering the event
    UA_StatusCode retval = triggerEvent(server, condition, conditionSource, &eventId, false);
    CONDITION_ASSERT_RETURN_RETVAL(retval, "Triggering condition event failed",);

    setIsCallerAC(server, &condition, &conditionSource, false);

    
    retval = updateConditionLastEventId(server, &condition, &conditionSource, &eventId);
    if(outEventId)
        *outEventId = eventId;
    else
        UA_ByteString_clear(&eventId);
    return retval;
}

UA_StatusCode
UA_Server_triggerConditionEvent(UA_Server *server, const UA_NodeId condition,
                                const UA_NodeId conditionSource, UA_ByteString *outEventId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = triggerConditionEvent(server, condition, conditionSource, outEventId);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_Server_deleteCondition(UA_Server *server, const UA_NodeId condition,
                          const UA_NodeId conditionSource) {
    
    UA_Boolean found = false; 
    UA_ConditionSource *source, *tmp_source;

    UA_LOCK(&server->serviceMutex);
    LIST_FOREACH_SAFE(source, &server->conditionSources, listEntry, tmp_source) {
        if(!UA_NodeId_equal(&source->conditionSourceId, &conditionSource))
            continue;

        
        UA_Condition *cond, *tmp_cond;
        LIST_FOREACH_SAFE(cond, &source->conditions, listEntry, tmp_cond) {
            if(!UA_NodeId_equal(&cond->conditionId, &condition))
                continue;
            deleteCondition(cond);
            found = true;
            break;
        }

        if(LIST_EMPTY(&source->conditions)){
            UA_NodeId_clear(&source->conditionSourceId);
            LIST_REMOVE(source, listEntry);
            UA_free(source);
        }
        break;
    }
    UA_UNLOCK(&server->serviceMutex);

    if(!found)
        return UA_STATUSCODE_BADNOTFOUND;

    
    return UA_Server_deleteNode(server, condition, true);
}

static UA_StatusCode
getLowLimit(UA_Server *server, UA_NodeId conditionId, UA_Double *lowLimit) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_Variant value;
    UA_StatusCode retval =
        readObjectProperty(server, conditionId,
                           UA_QUALIFIEDNAME(0, CONDITION_FIELD_LOWLIMIT), &value);
    *lowLimit = *(UA_Double*) value.data;
    return retval;
}

static UA_StatusCode
getLowLowLimit(UA_Server *server, UA_NodeId conditionId, UA_Double *lowLowLimit) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_Variant value;
    UA_StatusCode retval =
        readObjectProperty(server, conditionId,
                           UA_QUALIFIEDNAME(0, CONDITION_FIELD_LOWLOWLIMIT), &value);
    *lowLowLimit = *(UA_Double*) value.data;
    return retval;
}

static UA_StatusCode
getHighLimit(UA_Server *server, UA_NodeId conditionId, UA_Double *highLimit) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_Variant value;
    UA_StatusCode retval =
        readObjectProperty(server, conditionId,
                           UA_QUALIFIEDNAME(0, CONDITION_FIELD_HIGHLIMIT), &value);
    *highLimit = *(UA_Double*) value.data;
    return retval;
}

static UA_StatusCode
getHighHighLimit(UA_Server *server, UA_NodeId conditionId, UA_Double *highHighLimit) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_Variant value;
    UA_StatusCode retval =
        readObjectProperty(server, conditionId,
                           UA_QUALIFIEDNAME(0, CONDITION_FIELD_HIGHHIGHLIMIT), &value);
    *highHighLimit = *(UA_Double*) value.data;
    return retval;
}

static UA_StatusCode
setLimitState(UA_Server *server, const UA_NodeId conditionId,
              UA_Double limitValue) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_NodeId limitState;
    UA_Double lowLowLimit;
    UA_Double lowLimit;
    UA_Double highLimit;
    UA_Double highHighLimit;
    UA_Variant value;
    UA_QualifiedName currentStateField = UA_QUALIFIEDNAME(0,"CurrentState");
    UA_QualifiedName currentStateIdField = UA_QUALIFIEDNAME(0,"Id");
    UA_StatusCode retval = getConditionFieldNodeId(server, &conditionId,
                                                   &fieldLimitStateQN, &limitState);

    retval |= getHighHighLimit(server, conditionId, &highHighLimit);
    if(retval == UA_STATUSCODE_GOOD) {
        if(limitValue >= highHighLimit) {
            UA_NodeId highHighLimitId;
            retval |= getConditionFieldNodeId(server, &conditionId,
                                              &fieldHighHighLimitQN, &highHighLimitId);
            UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, ACTIVE_HIGHHIGH_TEXT);
            UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
            retval |= setConditionField(server, limitState, &value, currentStateField);
            UA_Variant_setScalar(&value, &highHighLimitId, &UA_TYPES[UA_TYPES_NODEID]);
            retval |= setConditionVariableFieldProperty(server, limitState, &value,
                                                        currentStateField, currentStateIdField);
            return retval;
        }
    }

    retval |= getHighLimit(server, conditionId, &highLimit);
    if(retval == UA_STATUSCODE_GOOD) {
        if(limitValue >= highLimit) {
            UA_NodeId highLimitId;
            retval |= getConditionFieldNodeId(server, &conditionId, &fieldHighLimitQN, &highLimitId);
            UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, ACTIVE_HIGH_TEXT);
            UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
            retval |= setConditionField(server, limitState, &value, currentStateField);

            UA_Variant_setScalar(&value, &highLimitId, &UA_TYPES[UA_TYPES_NODEID]);
            retval |= setConditionVariableFieldProperty(server, limitState, &value,
                                                        currentStateField,
                                                        currentStateIdField);
            return retval;
        }
    }

    retval |= getLowLowLimit(server, conditionId, &lowLowLimit);
    if(retval == UA_STATUSCODE_GOOD) {
        if(limitValue <= lowLowLimit) {
            UA_NodeId lowLowLimitId;
            retval |= getConditionFieldNodeId(server, &conditionId,
                                              &fieldLowLowLimitQN, &lowLowLimitId);
            UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, ACTIVE_LOWLOW_TEXT);
            UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
            retval |= setConditionField(server, limitState, &value, currentStateField);
            UA_Variant_setScalar(&value, &lowLowLimitId, &UA_TYPES[UA_TYPES_NODEID]);
            retval |= setConditionVariableFieldProperty(server, limitState, &value,
                                                        currentStateField,
                                                        currentStateIdField);
            return retval;
        }
    }

    retval |= getLowLimit(server, conditionId, &lowLimit);
    if(retval == UA_STATUSCODE_GOOD) {
        if(limitValue <= lowLimit) {
            UA_NodeId lowLimitId;
            retval |= getConditionFieldNodeId(server, &conditionId, &fieldLowLimitQN, &lowLimitId);
            UA_LocalizedText text = UA_LOCALIZEDTEXT(LOCALE, ACTIVE_LOW_TEXT);
            UA_Variant_setScalar(&value, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
            retval |= setConditionField(server, limitState, &value, currentStateField);
            UA_Variant_setScalar(&value, &lowLimitId, &UA_TYPES[UA_TYPES_NODEID]);
            retval |= setConditionVariableFieldProperty(server, limitState, &value,
                                                        currentStateField,
                                                        currentStateIdField);
            return retval;
        }
    }

    UA_LocalizedText textNull = UA_LOCALIZEDTEXT(LOCALE_NULL, TEXT_NULL);
    UA_Variant_setScalar(&value, &textNull, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    retval |= setConditionField(server, limitState, &value, currentStateField);

    UA_NodeId nodeIdNull = UA_NODEID_NULL;
    UA_Variant_setScalar(&value, &nodeIdNull, &UA_TYPES[UA_TYPES_NODEID]);
    retval |= setConditionVariableFieldProperty(server, limitState, &value,
                                                currentStateField,
                                                currentStateIdField);
    return retval;
}

UA_StatusCode
UA_Server_setLimitState(UA_Server *server, const UA_NodeId conditionId,
                        UA_Double limitValue) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = setLimitState(server, conditionId, limitValue);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}


UA_StatusCode
UA_Server_setExpirationDate(UA_Server *server, const UA_NodeId conditionId,
                            UA_ByteString  cert) {
    UA_StatusCode retval;
    if(cert.data == NULL){
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                    "No Certificate found.");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_CertificateGroup *cv = &server->config.sessionPKI;
    UA_DateTime getExpiryDateAndTime = 0;
    if(cv == NULL) {
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                    "Certificate verification is not registered");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    retval = UA_CertificateUtils_getExpirationDate(&cert, &getExpiryDateAndTime);
    if(retval != UA_STATUSCODE_GOOD || getExpiryDateAndTime == 0){
        UA_LOG_ERROR(server->config.logging, UA_LOGCATEGORY_SERVER,
                    "Failed to get certificate expiration date");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    retval = UA_Server_writeObjectProperty_scalar(server, conditionId,
                                                  fieldExpirationDateQN,
                                                  &getExpiryDateAndTime,
                                                  &UA_TYPES[UA_TYPES_DATETIME]);
    return retval;
}
#endif 
