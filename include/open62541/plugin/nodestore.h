
#ifndef UA_NODESTORE_H_
#define UA_NODESTORE_H_


#include <opcua/util.h>

_UA_BEGIN_DECLS


#ifdef UA_ENABLE_SUBSCRIPTIONS
struct UA_MonitoredItem;
typedef struct UA_MonitoredItem UA_MonitoredItem;
#endif


typedef struct {
    
    UA_StatusCode (*constructor)(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *nodeId, void **nodeContext);

    void (*destructor)(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionContext,
                       const UA_NodeId *nodeId, void *nodeContext);

    UA_Boolean (*createOptionalChild)(UA_Server *server,
                                      const UA_NodeId *sessionId,
                                      void *sessionContext,
                                      const UA_NodeId *sourceNodeId,
                                      const UA_NodeId *targetParentNodeId,
                                      const UA_NodeId *referenceTypeId);

    UA_StatusCode (*generateChildNodeId)(UA_Server *server,
                                         const UA_NodeId *sessionId, void *sessionContext,
                                         const UA_NodeId *sourceNodeId,
                                         const UA_NodeId *targetParentNodeId,
                                         const UA_NodeId *referenceTypeId,
                                         UA_NodeId *targetNodeId);
} UA_GlobalNodeLifecycle;

typedef struct {
    
    UA_StatusCode (*constructor)(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *typeNodeId, void *typeNodeContext,
                                 const UA_NodeId *nodeId, void **nodeContext);

    
    void (*destructor)(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionContext,
                       const UA_NodeId *typeNodeId, void *typeNodeContext,
                       const UA_NodeId *nodeId, void **nodeContext);
} UA_NodeTypeLifecycle;

#define UA_REFERENCETYPEINDEX_REFERENCES 0
#define UA_REFERENCETYPEINDEX_HASSUBTYPE 1
#define UA_REFERENCETYPEINDEX_AGGREGATES 2
#define UA_REFERENCETYPEINDEX_HIERARCHICALREFERENCES 3
#define UA_REFERENCETYPEINDEX_NONHIERARCHICALREFERENCES 4
#define UA_REFERENCETYPEINDEX_HASCHILD 5
#define UA_REFERENCETYPEINDEX_ORGANIZES 6
#define UA_REFERENCETYPEINDEX_HASEVENTSOURCE 7
#define UA_REFERENCETYPEINDEX_HASMODELLINGRULE 8
#define UA_REFERENCETYPEINDEX_HASENCODING 9
#define UA_REFERENCETYPEINDEX_HASDESCRIPTION 10
#define UA_REFERENCETYPEINDEX_HASTYPEDEFINITION 11
#define UA_REFERENCETYPEINDEX_GENERATESEVENT 12
#define UA_REFERENCETYPEINDEX_HASPROPERTY 13
#define UA_REFERENCETYPEINDEX_HASCOMPONENT 14
#define UA_REFERENCETYPEINDEX_HASNOTIFIER 15
#define UA_REFERENCETYPEINDEX_HASORDEREDCOMPONENT 16
#define UA_REFERENCETYPEINDEX_HASINTERFACE 17


#define UA_REFERENCETYPESET_MAX 128
typedef struct {
    UA_UInt32 bits[UA_REFERENCETYPESET_MAX / 32];
} UA_ReferenceTypeSet;

UA_EXPORT extern const UA_ReferenceTypeSet UA_REFERENCETYPESET_NONE;
UA_EXPORT extern const UA_ReferenceTypeSet UA_REFERENCETYPESET_ALL;

static UA_INLINE void
UA_ReferenceTypeSet_init(UA_ReferenceTypeSet *set) {
    memset(set, 0, sizeof(UA_ReferenceTypeSet));
}

static UA_INLINE UA_ReferenceTypeSet
UA_REFTYPESET(UA_Byte index) {
    UA_Byte i = index / 32, j = index % 32;
    UA_ReferenceTypeSet set;
    UA_ReferenceTypeSet_init(&set);
    set.bits[i] |= ((UA_UInt32)1) << j;
    return set;
}

static UA_INLINE UA_ReferenceTypeSet
UA_ReferenceTypeSet_union(const UA_ReferenceTypeSet setA,
                          const UA_ReferenceTypeSet setB) {
    UA_ReferenceTypeSet set;
    for(size_t i = 0; i < UA_REFERENCETYPESET_MAX / 32; i++)
        set.bits[i] = setA.bits[i] | setB.bits[i];
    return set;
}

static UA_INLINE UA_Boolean
UA_ReferenceTypeSet_contains(const UA_ReferenceTypeSet *set, UA_Byte index) {
    UA_Byte i = index / 32, j = index % 32;
    return !!(set->bits[i] & (((UA_UInt32)1) << j));
}



struct UA_NodeHead;
typedef struct UA_NodeHead UA_NodeHead;


typedef union {
    uintptr_t immediate;                 
    const UA_NodeId *id;                 
    const UA_ExpandedNodeId *expandedId; 
    const UA_NodeHead *node;             
} UA_NodePointer;

static UA_INLINE void
UA_NodePointer_init(UA_NodePointer *np) { np->immediate = 0; }


void UA_EXPORT
UA_NodePointer_clear(UA_NodePointer *np);


UA_StatusCode UA_EXPORT
UA_NodePointer_copy(UA_NodePointer in, UA_NodePointer *out);


UA_Boolean UA_EXPORT
UA_NodePointer_isLocal(UA_NodePointer np);

UA_Order UA_EXPORT
UA_NodePointer_order(UA_NodePointer p1, UA_NodePointer p2);

static UA_INLINE UA_Boolean
UA_NodePointer_equal(UA_NodePointer p1, UA_NodePointer p2) {
    return (UA_NodePointer_order(p1, p2) == UA_ORDER_EQ);
}

UA_NodePointer UA_EXPORT
UA_NodePointer_fromNodeId(const UA_NodeId *id);

UA_NodePointer UA_EXPORT
UA_NodePointer_fromExpandedNodeId(const UA_ExpandedNodeId *id);


UA_ExpandedNodeId UA_EXPORT
UA_NodePointer_toExpandedNodeId(UA_NodePointer np);

UA_NodeId UA_EXPORT
UA_NodePointer_toNodeId(UA_NodePointer np);


typedef struct {
    UA_NodePointer targetId;  
} UA_ReferenceTarget;

typedef struct UA_ReferenceTargetTreeElem {
    UA_ReferenceTarget target;   
    UA_UInt32 targetIdHash;      
    struct {
        struct UA_ReferenceTargetTreeElem *left;
        struct UA_ReferenceTargetTreeElem *right;
    } idTreeEntry;
    struct {
        struct UA_ReferenceTargetTreeElem *left;
        struct UA_ReferenceTargetTreeElem *right;
    } nameTreeEntry;
} UA_ReferenceTargetTreeElem;


typedef struct {
    union {
        UA_ReferenceTarget *array;

        struct {
            UA_ReferenceTargetTreeElem *idRoot;   
            UA_ReferenceTargetTreeElem *nameRoot; 
        } tree;
    } targets;
    size_t targetsSize;
    UA_Boolean hasRefTree; 
    UA_Byte referenceTypeIndex;
    UA_Boolean isInverse;
} UA_NodeReferenceKind;

typedef void *
(*UA_NodeReferenceKind_iterateCallback)(void *context, UA_ReferenceTarget *target);

UA_EXPORT void *
UA_NodeReferenceKind_iterate(UA_NodeReferenceKind *rk,
                             UA_NodeReferenceKind_iterateCallback callback,
                             void *context);


UA_EXPORT const UA_ReferenceTarget *
UA_NodeReferenceKind_findTarget(const UA_NodeReferenceKind *rk,
                                const UA_ExpandedNodeId *targetId);

UA_EXPORT UA_StatusCode
UA_NodeReferenceKind_switch(UA_NodeReferenceKind *rk);


typedef struct UA_LocalizedTextListEntry {
    struct UA_LocalizedTextListEntry *next;
    UA_LocalizedText localizedText;
} UA_LocalizedTextListEntry;


struct UA_NodeHead {
    UA_NodeId nodeId;
    UA_NodeClass nodeClass;
    UA_QualifiedName browseName;

    UA_LocalizedTextListEntry *displayName;
    UA_LocalizedTextListEntry *description;

    UA_UInt32 writeMask;
    size_t referencesSize;
    UA_NodeReferenceKind *references;

    
    void *context;
    UA_Boolean constructed; 
#ifdef UA_ENABLE_SUBSCRIPTIONS
#endif
};


typedef enum {
    UA_VALUESOURCE_DATA,
    UA_VALUESOURCE_DATASOURCE
} UA_ValueSource;

typedef struct {
    void (*onRead)(UA_Server *server, const UA_NodeId *sessionId,
                   void *sessionContext, const UA_NodeId *nodeid,
                   void *nodeContext, const UA_NumericRange *range,
                   const UA_DataValue *value);

    void (*onWrite)(UA_Server *server, const UA_NodeId *sessionId,
                    void *sessionContext, const UA_NodeId *nodeId,
                    void *nodeContext, const UA_NumericRange *range,
                    const UA_DataValue *data);
} UA_ValueCallback;

typedef struct {
    UA_StatusCode (*read)(UA_Server *server, const UA_NodeId *sessionId,
                          void *sessionContext, const UA_NodeId *nodeId,
                          void *nodeContext, UA_Boolean includeSourceTimeStamp,
                          const UA_NumericRange *range, UA_DataValue *value);

    UA_StatusCode (*write)(UA_Server *server, const UA_NodeId *sessionId,
                           void *sessionContext, const UA_NodeId *nodeId,
                           void *nodeContext, const UA_NumericRange *range,
                           const UA_DataValue *value);
} UA_DataSource;

typedef struct {
    UA_StatusCode (*notificationRead)(UA_Server *server, const UA_NodeId *sessionId,
                                      void *sessionContext, const UA_NodeId *nodeid,
                                      void *nodeContext, const UA_NumericRange *range);

    UA_StatusCode (*userWrite)(UA_Server *server, const UA_NodeId *sessionId,
                               void *sessionContext, const UA_NodeId *nodeId,
                               void *nodeContext, const UA_NumericRange *range,
                               const UA_DataValue *data);
} UA_ExternalValueCallback;

typedef enum {
    UA_VALUEBACKENDTYPE_NONE,
    UA_VALUEBACKENDTYPE_INTERNAL,
    UA_VALUEBACKENDTYPE_DATA_SOURCE_CALLBACK,
    UA_VALUEBACKENDTYPE_EXTERNAL
} UA_ValueBackendType;

typedef struct {
    UA_ValueBackendType backendType;
    union {
        struct {
            UA_DataValue value;
            UA_ValueCallback callback;
        } internal;
        UA_DataSource dataSource;
        struct {
            UA_DataValue **value;
            UA_ExternalValueCallback callback;
        } external;
    } backend;
} UA_ValueBackend;

#define UA_NODE_VARIABLEATTRIBUTES                                      \
                                    \
    UA_NodeId dataType;                                                 \
    UA_Int32 valueRank;                                                 \
    size_t arrayDimensionsSize;                                         \
    UA_UInt32 *arrayDimensions;                                         \
                                                                        \
    UA_ValueBackend valueBackend;                                       \
                                                                        \
                                                 \
    UA_ValueSource valueSource;                                         \
    union {                                                             \
        struct {                                                        \
            UA_DataValue value;                                         \
            UA_ValueCallback callback;                                  \
        } data;                                                         \
        UA_DataSource dataSource;                                       \
    } value;

typedef struct {
    UA_NodeHead head;
    UA_NODE_VARIABLEATTRIBUTES
    UA_Byte accessLevel;
    UA_Double minimumSamplingInterval;
    UA_Boolean historizing;

    
} UA_VariableNode;


typedef struct {
    UA_NodeHead head;
    UA_NODE_VARIABLEATTRIBUTES
    UA_Boolean isAbstract;

    
    UA_NodeTypeLifecycle lifecycle;
} UA_VariableTypeNode;


typedef UA_StatusCode
(*UA_MethodCallback)(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_NodeId *methodId,
                     void *methodContext, const UA_NodeId *objectId,
                     void *objectContext, size_t inputSize,
                     const UA_Variant *input, size_t outputSize,
                     UA_Variant *output);

typedef struct {
    UA_NodeHead head;
    UA_Boolean executable;

    
    UA_MethodCallback method;
#if UA_MULTITHREADING >= 100
    UA_Boolean async; 
#endif
} UA_MethodNode;


typedef struct {
    UA_NodeHead head;
    UA_Byte eventNotifier;
} UA_ObjectNode;


typedef struct {
    UA_NodeHead head;
    UA_Boolean isAbstract;

    
    UA_NodeTypeLifecycle lifecycle;
} UA_ObjectTypeNode;


typedef struct {
    UA_NodeHead head;
    UA_Boolean isAbstract;
    UA_Boolean symmetric;
    UA_LocalizedText inverseName;

    
    UA_Byte referenceTypeIndex;
    UA_ReferenceTypeSet subTypes; 
} UA_ReferenceTypeNode;


typedef struct {
    UA_NodeHead head;
    UA_Boolean isAbstract;
} UA_DataTypeNode;


typedef struct {
    UA_NodeHead head;
    UA_Byte eventNotifier;
    UA_Boolean containsNoLoops;
} UA_ViewNode;


typedef union {
    UA_NodeHead head;
    UA_VariableNode variableNode;
    UA_VariableTypeNode variableTypeNode;
    UA_MethodNode methodNode;
    UA_ObjectNode objectNode;
    UA_ObjectTypeNode objectTypeNode;
    UA_ReferenceTypeNode referenceTypeNode;
    UA_DataTypeNode dataTypeNode;
    UA_ViewNode viewNode;
} UA_Node;


typedef void (*UA_NodestoreVisitor)(void *visitorCtx, const UA_Node *node);

typedef struct {
    
    void *context;
    void (*clear)(void *nsCtx);

    UA_Node * (*newNode)(void *nsCtx, UA_NodeClass nodeClass);

    void (*deleteNode)(void *nsCtx, UA_Node *node);

    const UA_Node * (*getNode)(void *nsCtx, const UA_NodeId *nodeId,
                               UA_UInt32 attributeMask,
                               UA_ReferenceTypeSet references,
                               UA_BrowseDirection referenceDirections);

    const UA_Node * (*getNodeFromPtr)(void *nsCtx, UA_NodePointer ptr,
                                      UA_UInt32 attributeMask,
                                      UA_ReferenceTypeSet references,
                                      UA_BrowseDirection referenceDirections);

    UA_Node * (*getEditNode)(void *nsCtx, const UA_NodeId *nodeId,
                             UA_UInt32 attributeMask,
                             UA_ReferenceTypeSet references,
                             UA_BrowseDirection referenceDirections);

    UA_Node * (*getEditNodeFromPtr)(void *nsCtx, UA_NodePointer ptr,
                                    UA_UInt32 attributeMask,
                                    UA_ReferenceTypeSet references,
                                    UA_BrowseDirection referenceDirections);

    void (*releaseNode)(void *nsCtx, const UA_Node *node);

    UA_StatusCode (*getNodeCopy)(void *nsCtx, const UA_NodeId *nodeId,
                                 UA_Node **outNode);

    UA_StatusCode (*insertNode)(void *nsCtx, UA_Node *node,
                                UA_NodeId *addedNodeId);

    UA_StatusCode (*replaceNode)(void *nsCtx, UA_Node *node);

    
    UA_StatusCode (*removeNode)(void *nsCtx, const UA_NodeId *nodeId);

    const UA_NodeId * (*getReferenceTypeId)(void *nsCtx, UA_Byte refTypeIndex);

    
    void (*iterate)(void *nsCtx, UA_NodestoreVisitor visitor,
                    void *visitorCtx);
} UA_Nodestore;

UA_StatusCode UA_EXPORT
UA_Node_setAttributes(UA_Node *node, const void *attributes,
                      const UA_DataType *attributeType);


UA_StatusCode UA_EXPORT
UA_Node_copy(const UA_Node *src, UA_Node *dst);


UA_EXPORT UA_Node *
UA_Node_copy_alloc(const UA_Node *src);


UA_StatusCode UA_EXPORT
UA_Node_addReference(UA_Node *node, UA_Byte refTypeIndex, UA_Boolean isForward,
                     const UA_ExpandedNodeId *targetNodeId,
                     UA_UInt32 targetBrowseNameHash);


UA_StatusCode UA_EXPORT
UA_Node_deleteReference(UA_Node *node, UA_Byte refTypeIndex, UA_Boolean isForward,
                        const UA_ExpandedNodeId *targetNodeId);

void UA_EXPORT
UA_Node_deleteReferencesSubset(UA_Node *node, const UA_ReferenceTypeSet *keepSet);


void UA_EXPORT
UA_Node_deleteReferences(UA_Node *node);


void UA_EXPORT
UA_Node_clear(UA_Node *node);

_UA_END_DECLS

#endif 
