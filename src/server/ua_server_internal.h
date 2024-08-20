
#ifndef UA_SERVER_INTERNAL_H_
#define UA_SERVER_INTERNAL_H_

#define UA_INTERNAL
#include <opcua/server.h>
#include <opcua/plugin/nodestore.h>

#include "ua_session.h"
#include "ua_services.h"
#include "ua_server_async.h"
#include "util/ua_util_internal.h"
#include "ziptree.h"

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_PUBSUB
#include "ua_pubsub.h"
#endif

#ifdef UA_ENABLE_DISCOVERY
struct UA_DiscoveryManager;
typedef struct UA_DiscoveryManager UA_DiscoveryManager;
#endif

#ifdef UA_ENABLE_SUBSCRIPTIONS
#include "ua_subscription.h"

typedef struct {
    UA_MonitoredItem monitoredItem;
    void *context;
    union {
        UA_Server_DataChangeNotificationCallback dataChangeCallback;
        UA_Server_EventNotificationCallback eventCallback;
    } callback;

    UA_KeyValueMap eventFields;
} UA_LocalMonitoredItem;

#endif 






typedef struct UA_ServerComponent {
    UA_UInt64 identifier;
    UA_String name;
    ZIP_ENTRY(UA_ServerComponent) treeEntry;
    UA_LifecycleState state;

    
    UA_StatusCode (*start)(UA_Server *server,
                           struct UA_ServerComponent *sc);

    void (*stop)(UA_Server *server,
                 struct UA_ServerComponent *sc);

    
    UA_StatusCode (*free)(UA_Server *server,
                          struct UA_ServerComponent *sc);

    void (*notifyState)(UA_Server *server, struct UA_ServerComponent *sc,
                        UA_LifecycleState state);
} UA_ServerComponent;

enum ZIP_CMP
cmpServerComponent(const UA_UInt64 *a, const UA_UInt64 *b);

typedef ZIP_HEAD(UA_ServerComponentTree, UA_ServerComponent) UA_ServerComponentTree;

ZIP_FUNCTIONS(UA_ServerComponentTree, UA_ServerComponent, treeEntry,
              UA_UInt64, identifier, cmpServerComponent)

void
addServerComponent(UA_Server *server, UA_ServerComponent *sc,
                   UA_UInt64 *identifier);

UA_ServerComponent *
getServerComponentByName(UA_Server *server, UA_String name);





typedef struct session_list_entry {
    UA_DelayedCallback cleanupCallback;
    LIST_ENTRY(session_list_entry) pointers;
    UA_Session session;
} session_list_entry;

struct UA_Server {
    
    UA_ServerConfig config;

    
    UA_DateTime startTime;

    UA_LifecycleState state;
    UA_UInt64 houseKeepingCallbackId;

    UA_UInt64 serverComponentIds; 
    UA_ServerComponentTree serverComponents;

#if UA_MULTITHREADING >= 100
    UA_AsyncManager asyncManager;
#endif

    
    LIST_HEAD(session_list, session_list_entry) sessions;
    UA_UInt32 sessionCount;
    UA_UInt32 activeSessionCount;

    UA_Session adminSession;

    
    TAILQ_HEAD(, UA_SecureChannel) channels;
    UA_UInt32 lastChannelId;
    UA_UInt32 lastTokenId;

    
    size_t namespacesSize;
    UA_String *namespaces;

    UA_Boolean bootstrapNS0;

    
#ifdef UA_ENABLE_SUBSCRIPTIONS
    UA_Subscription *adminSubscription;

    size_t subscriptionsSize;  
    size_t monitoredItemsSize; 
    UA_UInt32 lastSubscriptionId; 

# ifdef UA_ENABLE_SUBSCRIPTIONS_ALARMS_CONDITIONS
    LIST_HEAD(, UA_ConditionSource) conditionSources;
    UA_NodeId refreshEvents[2];
# endif
#endif

    
#ifdef UA_ENABLE_PUBSUB
    UA_PubSubManager pubSubManager;
#endif

#if UA_MULTITHREADING >= 100
    UA_Lock serviceMutex;
#endif

    
    UA_SecureChannelStatistics secureChannelStatistics;
    UA_ServerDiagnosticsSummaryDataType serverDiagnosticsSummary;
};





enum ZIP_CMP
cmpRefTargetId(const void *a, const void *b);

enum ZIP_CMP
cmpRefTargetName(const void *a, const void *b);


typedef ZIP_HEAD(UA_ReferenceIdTree, UA_ReferenceTargetTreeElem) UA_ReferenceIdTree;
ZIP_FUNCTIONS(UA_ReferenceIdTree, UA_ReferenceTargetTreeElem, idTreeEntry,
              UA_ReferenceTargetTreeElem, target, cmpRefTargetId)

typedef ZIP_HEAD(UA_ReferenceNameTree, UA_ReferenceTargetTreeElem) UA_ReferenceNameTree;
ZIP_FUNCTIONS(UA_ReferenceNameTree, UA_ReferenceTargetTreeElem, nameTreeEntry,
              UA_ReferenceTarget, target, cmpRefTargetName)





void
serverNetworkCallback(UA_ConnectionManager *cm, uintptr_t connectionId,
                      void *application, void **connectionContext,
                      UA_ConnectionState state,
                      const UA_KeyValueMap *params,
                      UA_ByteString msg);

UA_StatusCode
sendServiceFault(UA_Server *server, UA_SecureChannel *channel, UA_UInt32 requestId,
                 UA_UInt32 requestHandle, UA_StatusCode statusCode);

UA_SecurityPolicy *
getSecurityPolicyByUri(const UA_Server *server,
                       const UA_ByteString *securityPolicyUri);





UA_StatusCode
getNamespaceByName(UA_Server *server, const UA_String namespaceUri,
                   size_t *foundIndex);

UA_StatusCode
getNamespaceByIndex(UA_Server *server, const size_t namespaceIndex,
                    UA_String *foundUri);

UA_StatusCode
getBoundSession(UA_Server *server, const UA_SecureChannel *channel,
                const UA_NodeId *token, UA_Session **session);

UA_StatusCode
UA_Server_createSession(UA_Server *server, UA_SecureChannel *channel,
                        const UA_CreateSessionRequest *request, UA_Session **session);

void
UA_Server_removeSession(UA_Server *server, session_list_entry *sentry,
                        UA_ShutdownReason shutdownReason);

UA_StatusCode
UA_Server_removeSessionByToken(UA_Server *server, const UA_NodeId *token,
                               UA_ShutdownReason shutdownReason);

void
UA_Server_cleanupSessions(UA_Server *server, UA_DateTime nowMonotonic);

UA_Session *
getSessionByToken(UA_Server *server, const UA_NodeId *token);

UA_Session *
getSessionById(UA_Server *server, const UA_NodeId *sessionId);





typedef UA_StatusCode (*UA_EditNodeCallback)(UA_Server*, UA_Session*,
                                             UA_Node *node, void*);
UA_StatusCode
UA_Server_editNode(UA_Server *server, UA_Session *session, const UA_NodeId *nodeId,
                   UA_UInt32 attributeMask, UA_ReferenceTypeSet references,
                   UA_BrowseDirection referenceDirections,
                   UA_EditNodeCallback callback, void *data);





void setServerLifecycleState(UA_Server *server, UA_LifecycleState state);

void setupNs1Uri(UA_Server *server);
UA_UInt16 addNamespace(UA_Server *server, const UA_String name);

UA_Boolean
UA_Node_hasSubTypeOrInstances(const UA_NodeHead *head);


UA_Boolean
isNodeInTree(UA_Server *server, const UA_NodeId *leafNode,
             const UA_NodeId *nodeToFind, const UA_ReferenceTypeSet *relevantRefs);


UA_Boolean
isNodeInTree_singleRef(UA_Server *server, const UA_NodeId *leafNode,
                       const UA_NodeId *nodeToFind, const UA_Byte relevantRefTypeIndex);

UA_StatusCode
browseRecursive(UA_Server *server, size_t startNodesSize, const UA_NodeId *startNodes,
                UA_BrowseDirection browseDirection, const UA_ReferenceTypeSet *refTypes,
                UA_UInt32 nodeClassMask, UA_Boolean includeStartNodes,
                size_t *resultsSize, UA_ExpandedNodeId **results);

UA_StatusCode
referenceTypeIndices(UA_Server *server, const UA_NodeId *refType,
                     UA_ReferenceTypeSet *indices, UA_Boolean includeSubtypes);


UA_StatusCode
getParentTypeAndInterfaceHierarchy(UA_Server *server, const UA_NodeId *typeNode,
                                   UA_NodeId **typeHierarchy, size_t *typeHierarchySize);


UA_StatusCode
getAllInterfaceChildNodeIds(UA_Server *server, const UA_NodeId *objectNode, const UA_NodeId *objectTypeNode,
                                   UA_NodeId **interfaceChildNodes, size_t *interfaceChildNodesSize);

#ifdef UA_ENABLE_SUBSCRIPTIONS_ALARMS_CONDITIONS

UA_StatusCode
UA_getConditionId(UA_Server *server, const UA_NodeId *conditionNodeId,
                  UA_NodeId *outConditionId);

void
UA_ConditionList_delete(UA_Server *server);

UA_Boolean
isConditionOrBranch(UA_Server *server,
                    const UA_NodeId *condition,
                    const UA_NodeId *conditionSource,
                    UA_Boolean *isCallerAC);

#endif 

const UA_Node *
getNodeType(UA_Server *server, const UA_NodeHead *nodeHead);


UA_Boolean
UA_Server_processRequest(UA_Server *server, UA_SecureChannel *channel,
                         UA_UInt32 requestId, UA_ServiceDescription *sd,
                         const UA_Request *request, UA_Response *response);

UA_StatusCode
sendResponse(UA_Server *server, UA_SecureChannel *channel, UA_UInt32 requestId,
             UA_Response *response, const UA_DataType *responseType);

typedef void (*UA_ServiceOperation)(UA_Server *server, UA_Session *session,
                                    const void *context,
                                    const void *requestOperation,
                                    void *responseOperation);

UA_StatusCode
UA_Server_processServiceOperations(UA_Server *server, UA_Session *session,
                                   UA_ServiceOperation operationCallback,
                                   const void *context,
                                   const size_t *requestOperations,
                                   const UA_DataType *requestOperationsType,
                                   size_t *responseOperations,
                                   const UA_DataType *responseOperationsType)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;




UA_StatusCode
deleteNode(UA_Server *server, const UA_NodeId nodeId,
           UA_Boolean deleteReferences);

UA_StatusCode
addRef(UA_Server *server, const UA_NodeId sourceId,
       const UA_NodeId referenceTypeId, const UA_NodeId targetId,
       UA_Boolean forward);

UA_StatusCode
deleteReference(UA_Server *server, const UA_NodeId sourceNodeId,
                const UA_NodeId referenceTypeId, UA_Boolean isForward,
                const UA_ExpandedNodeId targetNodeId,
                UA_Boolean deleteBidirectional);

UA_StatusCode
addRefWithSession(UA_Server *server, UA_Session *session, const UA_NodeId *sourceId,
                  const UA_NodeId *referenceTypeId, const UA_NodeId *targetId,
                  UA_Boolean forward);

UA_StatusCode
setVariableNode_dataSource(UA_Server *server, const UA_NodeId nodeId,
                           const UA_DataSource dataSource);

UA_StatusCode
setVariableNode_valueCallback(UA_Server *server, const UA_NodeId nodeId,
                              const UA_ValueCallback callback);

UA_StatusCode
setMethodNode_callback(UA_Server *server, const UA_NodeId methodNodeId,
                       UA_MethodCallback methodCallback);

UA_StatusCode
setNodeTypeLifecycle(UA_Server *server, UA_NodeId nodeId,
                     UA_NodeTypeLifecycle lifecycle);

void
Operation_Write(UA_Server *server, UA_Session *session, void *context,
                const UA_WriteValue *wv, UA_StatusCode *result);

UA_StatusCode
writeAttribute(UA_Server *server, UA_Session *session,
               const UA_NodeId *nodeId, const UA_AttributeId attributeId,
               const void *attr, const UA_DataType *attr_type);

#define UA_WRITEATTRIBUTEFUNCS(ATTR, ATTRID, TYPE, TYPENAME)            \
    static UA_INLINE UA_StatusCode                                      \
    write##ATTR##Attribute(UA_Server *server, const UA_NodeId nodeId,   \
                           const TYPE value) {                          \
        return writeAttribute(server, &server->adminSession, &nodeId,   \
                              ATTRID, &value, &UA_TYPES[UA_TYPES_##TYPENAME]); \
    }                                                                   \
    static UA_INLINE UA_StatusCode                                      \
    write##ATTR##AttributeWithSession(UA_Server *server, UA_Session *session, \
                                      const UA_NodeId nodeId, const TYPE value) { \
        return writeAttribute(server, session, &nodeId, ATTRID, &value, \
                              &UA_TYPES[UA_TYPES_##TYPENAME]);          \
    }

static UA_INLINE UA_StatusCode
writeValueAttribute(UA_Server *server, const UA_NodeId nodeId,
                    const UA_Variant *value) {
    return writeAttribute(server, &server->adminSession, &nodeId,
                          UA_ATTRIBUTEID_VALUE, value, &UA_TYPES[UA_TYPES_VARIANT]);
}

UA_WRITEATTRIBUTEFUNCS(IsAbstract, UA_ATTRIBUTEID_ISABSTRACT, UA_Boolean, BOOLEAN)
UA_WRITEATTRIBUTEFUNCS(ValueRank, UA_ATTRIBUTEID_VALUERANK, UA_Int32, INT32)
UA_WRITEATTRIBUTEFUNCS(AccessLevel, UA_ATTRIBUTEID_ACCESSLEVEL, UA_Byte, BYTE)
UA_WRITEATTRIBUTEFUNCS(MinimumSamplingInterval, UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL,
                       UA_Double, DOUBLE)

void
Operation_Read(UA_Server *server, UA_Session *session, UA_TimestampsToReturn *ttr,
               const UA_ReadValueId *rvi, UA_DataValue *dv);

UA_DataValue
readWithSession(UA_Server *server, UA_Session *session,
                const UA_ReadValueId *item,
                UA_TimestampsToReturn timestampsToReturn);

UA_StatusCode
readWithReadValue(UA_Server *server, const UA_NodeId *nodeId,
                  const UA_AttributeId attributeId, void *v);

UA_StatusCode
readObjectProperty(UA_Server *server, const UA_NodeId objectId,
                   const UA_QualifiedName propertyName,
                   UA_Variant *value);

UA_BrowsePathResult
translateBrowsePathToNodeIds(UA_Server *server, const UA_BrowsePath *browsePath);

#ifdef UA_ENABLE_SUBSCRIPTIONS

UA_Subscription *
getSubscriptionById(UA_Server *server, UA_UInt32 subscriptionId);

#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS

UA_StatusCode
createEvent(UA_Server *server, const UA_NodeId eventType,
            UA_NodeId *outNodeId);

UA_StatusCode
triggerEvent(UA_Server *server, const UA_NodeId eventNodeId,
             const UA_NodeId origin, UA_ByteString *outEventId,
             const UA_Boolean deleteEventNode);

UA_StatusCode
filterEvent(UA_Server *server, UA_Session *session,
            const UA_NodeId *eventNode, UA_EventFilter *filter,
            UA_EventFieldList *efl, UA_EventFilterResult *result);

#endif 

#endif 

UA_SecurityPolicy *
getDefaultEncryptedSecurityPolicy(UA_Server *server);

UA_StatusCode
setCurrentEndPointsArray(UA_Server *server, const UA_String endpointURL,
                         UA_String *profileUris, size_t profileUrisSize,
                         UA_EndpointDescription **arr, size_t *arrSize);

UA_BrowsePathResult
browseSimplifiedBrowsePath(UA_Server *server, const UA_NodeId origin,
                           size_t browsePathSize, const UA_QualifiedName *browsePath);

UA_StatusCode
writeObjectProperty(UA_Server *server, const UA_NodeId objectId,
                    const UA_QualifiedName propertyName, const UA_Variant value);

UA_StatusCode
writeObjectProperty_scalar(UA_Server *server, const UA_NodeId objectId,
                                     const UA_QualifiedName propertyName,
                                     const void *value, const UA_DataType *type);

UA_StatusCode
getNodeContext(UA_Server *server, UA_NodeId nodeId, void **nodeContext);

UA_StatusCode
setNodeContext(UA_Server *server, UA_NodeId nodeId, void *nodeContext);

void
removeCallback(UA_Server *server, UA_UInt64 callbackId);

UA_StatusCode
changeRepeatedCallbackInterval(UA_Server *server, UA_UInt64 callbackId,
                               UA_Double interval_ms);

UA_StatusCode
addRepeatedCallback(UA_Server *server, UA_ServerCallback callback,
                    void *data, UA_Double interval_ms, UA_UInt64 *callbackId);

#ifdef UA_ENABLE_DISCOVERY
UA_ServerComponent *
UA_DiscoveryManager_new(UA_Server *server);
#endif

UA_ServerComponent *
UA_BinaryProtocolManager_new(UA_Server *server);






#define UA_REFTREE_INITIAL_SIZE 16

typedef struct RefEntry {
    ZIP_ENTRY(RefEntry) zipfields;
    const UA_ExpandedNodeId *target;
    UA_UInt32 targetHash; 
} RefEntry;

ZIP_HEAD(RefHead, RefEntry);
typedef struct RefHead RefHead;

typedef struct {
    UA_ExpandedNodeId *targets;
    RefHead head;
    size_t capacity; 
    size_t size;     
} RefTree;

UA_StatusCode UA_FUNC_ATTR_WARN_UNUSED_RESULT
RefTree_init(RefTree *rt);

void RefTree_clear(RefTree *rt);

UA_StatusCode UA_FUNC_ATTR_WARN_UNUSED_RESULT
RefTree_addNodeId(RefTree *rt, const UA_NodeId *target, UA_Boolean *duplicate);

UA_Boolean
RefTree_contains(RefTree *rt, const UA_ExpandedNodeId *target);

UA_Boolean
RefTree_containsNodeId(RefTree *rt, const UA_NodeId *target);





void
ReadWithNode(const UA_Node *node, UA_Server *server, UA_Session *session,
             UA_TimestampsToReturn timestampsToReturn,
             const UA_ReadValueId *id, UA_DataValue *v);

UA_StatusCode
readValueAttribute(UA_Server *server, UA_Session *session,
                   const UA_VariableNode *vn, UA_DataValue *v);

UA_Boolean
compatibleValue(UA_Server *server, UA_Session *session, const UA_NodeId *targetDataTypeId,
                UA_Int32 targetValueRank, size_t targetArrayDimensionsSize,
                const UA_UInt32 *targetArrayDimensions, const UA_Variant *value,
                const UA_NumericRange *range, const char **reason);


UA_Boolean
compatibleDataTypes(UA_Server *server, const UA_NodeId *dataType,
                    const UA_NodeId *constraintDataType);


void
adjustValueType(UA_Server *server, UA_Variant *value,
                const UA_NodeId *targetDataTypeId);

UA_Boolean
compatibleValueDataType(UA_Server *server, const UA_DataType *dataType,
                        const UA_NodeId *constraintDataType);


UA_Boolean
compatibleArrayDimensions(size_t constraintArrayDimensionsSize,
                          const UA_UInt32 *constraintArrayDimensions,
                          size_t testArrayDimensionsSize,
                          const UA_UInt32 *testArrayDimensions);

UA_Boolean
compatibleValueArrayDimensions(const UA_Variant *value, size_t targetArrayDimensionsSize,
                               const UA_UInt32 *targetArrayDimensions);

UA_Boolean
compatibleValueRankArrayDimensions(UA_Server *server, UA_Session *session,
                                   UA_Int32 valueRank, size_t arrayDimensionsSize);

UA_Boolean
compatibleValueRanks(UA_Int32 valueRank, UA_Int32 constraintValueRank);

struct BrowseOpts {
    UA_UInt32 maxReferences;
    UA_Boolean recursive;
};

void
Operation_Browse(UA_Server *server, UA_Session *session, const UA_UInt32 *maxrefs,
                 const UA_BrowseDescription *descr, UA_BrowseResult *result);





UA_StatusCode
addNode(UA_Server *server, const UA_NodeClass nodeClass,
        const UA_NodeId requestedNewNodeId,
        const UA_NodeId parentNodeId, const UA_NodeId referenceTypeId,
        const UA_QualifiedName browseName, const UA_NodeId typeDefinition,
        const void *attr, const UA_DataType *attributeType,
        void *nodeContext, UA_NodeId *outNewNodeId);

UA_StatusCode
addMethodNode(UA_Server *server, const UA_NodeId requestedNewNodeId,
              const UA_NodeId parentNodeId, const UA_NodeId referenceTypeId,
              const UA_QualifiedName browseName,
              const UA_MethodAttributes *attr, UA_MethodCallback method,
              size_t inputArgumentsSize, const UA_Argument *inputArguments,
              const UA_NodeId inputArgumentsRequestedNewNodeId,
              UA_NodeId *inputArgumentsOutNewNodeId,
              size_t outputArgumentsSize, const UA_Argument *outputArguments,
              const UA_NodeId outputArgumentsRequestedNewNodeId,
              UA_NodeId *outputArgumentsOutNewNodeId,
              void *nodeContext, UA_NodeId *outNewNodeId);

UA_StatusCode
addNode_begin(UA_Server *server, const UA_NodeClass nodeClass,
              const UA_NodeId requestedNewNodeId, const UA_NodeId parentNodeId,
              const UA_NodeId referenceTypeId, const UA_QualifiedName browseName,
              const UA_NodeId typeDefinition, const void *attr,
              const UA_DataType *attributeType, void *nodeContext,
              UA_NodeId *outNewNodeId);


UA_StatusCode
addNode_raw(UA_Server *server, UA_Session *session, void *nodeContext,
            const UA_AddNodesItem *item, UA_NodeId *outNewNodeId);


UA_StatusCode
addNode_addRefs(UA_Server *server, UA_Session *session, const UA_NodeId *nodeId,
                const UA_NodeId *parentNodeId, const UA_NodeId *referenceTypeId,
                const UA_NodeId *typeDefinitionId);


UA_StatusCode
addNode_finish(UA_Server *server, UA_Session *session, const UA_NodeId *nodeId);





UA_StatusCode initNS0(UA_Server *server);

#ifdef UA_ENABLE_DIAGNOSTICS
void createSessionObject(UA_Server *server, UA_Session *session);

void createSubscriptionObject(UA_Server *server, UA_Session *session,
                              UA_Subscription *sub);

UA_StatusCode
readDiagnostics(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext,
                const UA_NodeId *nodeId, void *nodeContext, UA_Boolean sourceTimestamp,
                const UA_NumericRange *range, UA_DataValue *value);

UA_StatusCode
readSubscriptionDiagnosticsArray(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *nodeId, void *nodeContext,
                                 UA_Boolean sourceTimestamp,
                                 const UA_NumericRange *range, UA_DataValue *value);

UA_StatusCode
readSessionDiagnosticsArray(UA_Server *server,
                            const UA_NodeId *sessionId, void *sessionContext,
                            const UA_NodeId *nodeId, void *nodeContext,
                            UA_Boolean sourceTimestamp,
                            const UA_NumericRange *range, UA_DataValue *value);

UA_StatusCode
readSessionSecurityDiagnostics(UA_Server *server,
                               const UA_NodeId *sessionId, void *sessionContext,
                               const UA_NodeId *nodeId, void *nodeContext,
                               UA_Boolean sourceTimestamp,
                               const UA_NumericRange *range, UA_DataValue *value);
#endif





#define UA_NODESTORE_NEW(server, nodeClass)                             \
    server->config.nodestore.newNode(server->config.nodestore.context, nodeClass)

#define UA_NODESTORE_DELETE(server, node)                               \
    server->config.nodestore.deleteNode(server->config.nodestore.context, node)


static UA_INLINE const UA_Node *
UA_NODESTORE_GET(UA_Server *server, const UA_NodeId *nodeId) {
    return server->config.nodestore.
        getNode(server->config.nodestore.context, nodeId, UA_NODEATTRIBUTESMASK_ALL,
                UA_REFERENCETYPESET_ALL, UA_BROWSEDIRECTION_BOTH);
}


static UA_INLINE UA_Node *
UA_NODESTORE_GET_EDIT(UA_Server *server, const UA_NodeId *nodeId) {
    return server->config.nodestore.
        getEditNode(server->config.nodestore.context, nodeId,
                    UA_NODEATTRIBUTESMASK_ALL, UA_REFERENCETYPESET_ALL,
                    UA_BROWSEDIRECTION_BOTH);
}


static UA_INLINE const UA_Node *
UA_NODESTORE_GETFROMREF(UA_Server *server, UA_NodePointer target) {
    return server->config.nodestore.
        getNodeFromPtr(server->config.nodestore.context, target, UA_NODEATTRIBUTESMASK_ALL,
                       UA_REFERENCETYPESET_ALL, UA_BROWSEDIRECTION_BOTH);
}

#define UA_NODESTORE_GET_SELECTIVE(server, nodeid, attrMask, refs, refDirs) \
    server->config.nodestore.getNode(server->config.nodestore.context,      \
                                     nodeid, attrMask, refs, refDirs)

#define UA_NODESTORE_GET_EDIT_SELECTIVE(server, nodeid, attrMask, refs, refDirs) \
    server->config.nodestore.getEditNode(server->config.nodestore.context,       \
                                         nodeid, attrMask, refs, refDirs)

#define UA_NODESTORE_GETFROMREF_SELECTIVE(server, target, attrMask, refs, refDirs) \
    server->config.nodestore.getNodeFromPtr(server->config.nodestore.context,      \
                                            target, attrMask, refs, refDirs)

#define UA_NODESTORE_RELEASE(server, node)                              \
    server->config.nodestore.releaseNode(server->config.nodestore.context, node)

#define UA_NODESTORE_GETCOPY(server, nodeid, outnode)                      \
    server->config.nodestore.getNodeCopy(server->config.nodestore.context, \
                                         nodeid, outnode)

#define UA_NODESTORE_INSERT(server, node, addedNodeId)                    \
    server->config.nodestore.insertNode(server->config.nodestore.context, \
                                        node, addedNodeId)

#define UA_NODESTORE_REPLACE(server, node)                              \
    server->config.nodestore.replaceNode(server->config.nodestore.context, node)

#define UA_NODESTORE_REMOVE(server, nodeId)                             \
    server->config.nodestore.removeNode(server->config.nodestore.context, nodeId)

#define UA_NODESTORE_GETREFERENCETYPEID(server, index)                  \
    server->config.nodestore.getReferenceTypeId(server->config.nodestore.context, \
                                                index)




UA_LocalizedText
UA_Session_getNodeDisplayName(const UA_Session *session,
                              const UA_NodeHead *head);

UA_LocalizedText
UA_Session_getNodeDescription(const UA_Session *session,
                              const UA_NodeHead *head);

UA_StatusCode
UA_Node_insertOrUpdateDisplayName(UA_NodeHead *head,
                                  const UA_LocalizedText *value);

UA_StatusCode
UA_Node_insertOrUpdateDescription(UA_NodeHead *head,
                                  const UA_LocalizedText *value);

_UA_END_DECLS

#endif 
