
#include <opcua/types.h>
#include <opcua/plugin/nodestore_default.h>
#include "ziptree.h"

#ifndef container_of
#define container_of(ptr, type, member) \
    (type *)((uintptr_t)ptr - offsetof(type,member))
#endif

struct NodeEntry;
typedef struct NodeEntry NodeEntry;

struct NodeEntry {
    ZIP_ENTRY(NodeEntry) zipfields;
    UA_UInt32 nodeIdHash;
    UA_UInt16 refCount; 
    UA_Boolean deleted; 
    UA_NodeId nodeId; 
};


static enum ZIP_CMP
cmpNodeId(const void *a, const void *b) {
    const NodeEntry *aa = (const NodeEntry*)a;
    const NodeEntry *bb = (const NodeEntry*)b;

    
    if(aa->nodeIdHash < bb->nodeIdHash)
        return ZIP_CMP_LESS;
    if(aa->nodeIdHash > bb->nodeIdHash)
        return ZIP_CMP_MORE;

    
    return (enum ZIP_CMP)UA_NodeId_order(&aa->nodeId, &bb->nodeId);
}

ZIP_HEAD(NodeTree, NodeEntry);
typedef struct NodeTree NodeTree;

typedef struct {
    NodeTree root;

    
    UA_NodeId referenceTypeIds[UA_REFERENCETYPESET_MAX];
    UA_Byte referenceTypeCounter;
} ZipContext;

ZIP_FUNCTIONS(NodeTree, NodeEntry, zipfields, NodeEntry, zipfields, cmpNodeId)

static NodeEntry *
newEntry(UA_NodeClass nodeClass) {
    size_t size = sizeof(NodeEntry) - sizeof(UA_NodeId);
    switch(nodeClass) {
    case UA_NODECLASS_OBJECT:
        size += sizeof(UA_ObjectNode);
        break;
    case UA_NODECLASS_VARIABLE:
        size += sizeof(UA_VariableNode);
        break;
    case UA_NODECLASS_METHOD:
        size += sizeof(UA_MethodNode);
        break;
    case UA_NODECLASS_OBJECTTYPE:
        size += sizeof(UA_ObjectTypeNode);
        break;
    case UA_NODECLASS_VARIABLETYPE:
        size += sizeof(UA_VariableTypeNode);
        break;
    case UA_NODECLASS_REFERENCETYPE:
        size += sizeof(UA_ReferenceTypeNode);
        break;
    case UA_NODECLASS_DATATYPE:
        size += sizeof(UA_DataTypeNode);
        break;
    case UA_NODECLASS_VIEW:
        size += sizeof(UA_ViewNode);
        break;
    default:
        return NULL;
    }
    NodeEntry *entry = (NodeEntry*)UA_calloc(1, size);
    if(!entry)
        return NULL;
    UA_Node *node = (UA_Node*)&entry->nodeId;
    node->head.nodeClass = nodeClass;
    return entry;
}

static void
deleteEntry(NodeEntry *entry) {
    UA_Node_clear((UA_Node*)&entry->nodeId);
    UA_free(entry);
}

static void
cleanupEntry(NodeEntry *entry) {
    if(entry->refCount > 0)
        return;
    if(entry->deleted) {
        deleteEntry(entry);
        return;
    }
    UA_NodeHead *head = (UA_NodeHead*)&entry->nodeId;
    for(size_t i = 0; i < head->referencesSize; i++) {
        UA_NodeReferenceKind *rk = &head->references[i];
        if(rk->targetsSize > 16 && !rk->hasRefTree)
            UA_NodeReferenceKind_switch(rk);
    }
}






static UA_Node *
zipNsNewNode(void *nsCtx, UA_NodeClass nodeClass) {
    NodeEntry *entry = newEntry(nodeClass);
    if(!entry)
        return NULL;
    return (UA_Node*)&entry->nodeId;
}


static void
zipNsDeleteNode(void *nsCtx, UA_Node *node) {
    deleteEntry(container_of(node, NodeEntry, nodeId));
}

static const UA_Node *
zipNsGetNode(void *nsCtx, const UA_NodeId *nodeId,
             UA_UInt32 attributeMask,
             UA_ReferenceTypeSet references,
             UA_BrowseDirection referenceDirections) {
    ZipContext *ns = (ZipContext*)nsCtx;
    NodeEntry dummy;
    dummy.nodeIdHash = UA_NodeId_hash(nodeId);
    dummy.nodeId = *nodeId;
    NodeEntry *entry = ZIP_FIND(NodeTree, &ns->root, &dummy);
    if(!entry)
        return NULL;
    ++entry->refCount;
    return (const UA_Node*)&entry->nodeId;
}

static const UA_Node *
zipNsGetNodeFromPtr(void *nsCtx, UA_NodePointer ptr,
                    UA_UInt32 attributeMask,
                    UA_ReferenceTypeSet references,
                    UA_BrowseDirection referenceDirections) {
    if(!UA_NodePointer_isLocal(ptr))
        return NULL;
    UA_NodeId id = UA_NodePointer_toNodeId(ptr);
    return zipNsGetNode(nsCtx, &id, attributeMask,
                        references, referenceDirections);
}

static void
zipNsReleaseNode(void *nsCtx, const UA_Node *node) {
    if(!node)
        return;
    NodeEntry *entry = container_of(node, NodeEntry, nodeId);
    UA_assert(entry->refCount > 0);
    --entry->refCount;
    cleanupEntry(entry);
}

static UA_StatusCode
zipNsGetNodeCopy(void *nsCtx, const UA_NodeId *nodeId,
                 UA_Node **outNode) {
    const UA_Node *node =
        zipNsGetNode(nsCtx, nodeId, UA_NODEATTRIBUTESMASK_ALL,
                     UA_REFERENCETYPESET_ALL, UA_BROWSEDIRECTION_BOTH);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;

    
    NodeEntry *ne = newEntry(node->head.nodeClass);
    if(!ne) {
        zipNsReleaseNode(nsCtx, node);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    
    UA_Node *nnode = (UA_Node*)&ne->nodeId;
    UA_StatusCode retval = UA_Node_copy(node, nnode);
    zipNsReleaseNode(nsCtx, node);
    if(retval != UA_STATUSCODE_GOOD) {
        deleteEntry(ne);
        return retval;
    }

    ne->orig = container_of(node, NodeEntry, nodeId);
    *outNode = nnode;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
zipNsInsertNode(void *nsCtx, UA_Node *node, UA_NodeId *addedNodeId) {
    NodeEntry *entry = container_of(node, NodeEntry, nodeId);
    ZipContext *ns = (ZipContext*)nsCtx;

    
    NodeEntry dummy;
    memset(&dummy, 0, sizeof(NodeEntry));
    dummy.nodeId = node->head.nodeId;
    if(node->head.nodeId.identifierType == UA_NODEIDTYPE_NUMERIC &&
       node->head.nodeId.identifier.numeric == 0) {
        do { 
            UA_UInt32 numId = UA_UInt32_random();
#if SIZE_MAX <= UA_UINT32_MAX
            if(numId >= (0x01 << 24))
                numId = numId % (0x01 << 24);
#endif
            node->head.nodeId.identifier.numeric = numId;
            dummy.nodeId.identifier.numeric = numId;
            dummy.nodeIdHash = UA_NodeId_hash(&node->head.nodeId);
        } while(ZIP_FIND(NodeTree, &ns->root, &dummy));
    } else {
        dummy.nodeIdHash = UA_NodeId_hash(&node->head.nodeId);
        if(ZIP_FIND(NodeTree, &ns->root, &dummy)) { 
            deleteEntry(entry);
            return UA_STATUSCODE_BADNODEIDEXISTS;
        }
    }

    
    if(addedNodeId) {
        UA_StatusCode retval = UA_NodeId_copy(&node->head.nodeId, addedNodeId);
        if(retval != UA_STATUSCODE_GOOD) {
            deleteEntry(entry);
            return retval;
        }
    }

    
    if(node->head.nodeClass == UA_NODECLASS_REFERENCETYPE) {
        UA_ReferenceTypeNode *refNode = &node->referenceTypeNode;
        if(ns->referenceTypeCounter >= UA_REFERENCETYPESET_MAX) {
            deleteEntry(entry);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        UA_StatusCode retval =
            UA_NodeId_copy(&node->head.nodeId, &ns->referenceTypeIds[ns->referenceTypeCounter]);
        if(retval != UA_STATUSCODE_GOOD) {
            deleteEntry(entry);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        
        refNode->referenceTypeIndex = ns->referenceTypeCounter;
        refNode->subTypes = UA_REFTYPESET(ns->referenceTypeCounter);

        ns->referenceTypeCounter++;
    }

    
    entry->nodeIdHash = dummy.nodeIdHash;
    ZIP_INSERT(NodeTree, &ns->root, entry);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
zipNsReplaceNode(void *nsCtx, UA_Node *node) {
    
    const UA_Node *oldNode =
        zipNsGetNode(nsCtx, &node->head.nodeId, UA_NODEATTRIBUTESMASK_ALL,
                     UA_REFERENCETYPESET_ALL, UA_BROWSEDIRECTION_BOTH);
    if(!oldNode) {
        deleteEntry(container_of(node, NodeEntry, nodeId));
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    }

    
    NodeEntry *entry = container_of(node, NodeEntry, nodeId);
    NodeEntry *oldEntry = container_of(oldNode, NodeEntry, nodeId);
    if(oldEntry != entry->orig) {
        
        deleteEntry(entry);
        zipNsReleaseNode(nsCtx, oldNode);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    ZipContext *ns = (ZipContext*)nsCtx;
    ZIP_REMOVE(NodeTree, &ns->root, oldEntry);
    entry->nodeIdHash = oldEntry->nodeIdHash;
    ZIP_INSERT(NodeTree, &ns->root, entry);
    oldEntry->deleted = true;

    zipNsReleaseNode(nsCtx, oldNode);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
zipNsRemoveNode(void *nsCtx, const UA_NodeId *nodeId) {
    ZipContext *ns = (ZipContext*)nsCtx;
    NodeEntry dummy;
    dummy.nodeIdHash = UA_NodeId_hash(nodeId);
    dummy.nodeId = *nodeId;
    NodeEntry *entry = ZIP_FIND(NodeTree, &ns->root, &dummy);
    if(!entry)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    ZIP_REMOVE(NodeTree, &ns->root, entry);
    entry->deleted = true;
    cleanupEntry(entry);
    return UA_STATUSCODE_GOOD;
}

static const UA_NodeId *
zipNsGetReferenceTypeId(void *nsCtx, UA_Byte refTypeIndex) {
    ZipContext *ns = (ZipContext*)nsCtx;
    if(refTypeIndex >= ns->referenceTypeCounter)
        return NULL;
    return &ns->referenceTypeIds[refTypeIndex];
}

struct VisitorData {
    UA_NodestoreVisitor visitor;
    void *visitorContext;
};

static void *
nodeVisitor(void *data, NodeEntry *entry) {
    struct VisitorData *d = (struct VisitorData*)data;
    d->visitor(d->visitorContext, (UA_Node*)&entry->nodeId);
    return NULL;
}

static void
zipNsIterate(void *nsCtx, UA_NodestoreVisitor visitor,
             void *visitorCtx) {
    struct VisitorData d;
    d.visitor = visitor;
    d.visitorContext = visitorCtx;
    ZipContext *ns = (ZipContext*)nsCtx;
    ZIP_ITER(NodeTree, &ns->root, nodeVisitor, &d);
}

static void *
deleteNodeVisitor(void *data, NodeEntry *entry) {
    deleteEntry(entry);
    return NULL;
}





static void
zipNsClear(void *nsCtx) {
    if (!nsCtx)
        return;
    ZipContext *ns = (ZipContext*)nsCtx;
    ZIP_ITER(NodeTree, &ns->root, deleteNodeVisitor, NULL);

    
    for(size_t i = 0; i < ns->referenceTypeCounter; i++)
        UA_NodeId_clear(&ns->referenceTypeIds[i]);

    UA_free(ns);
}

UA_StatusCode
UA_Nodestore_ZipTree(UA_Nodestore *ns) {
    
    ZipContext *ctx = (ZipContext*)UA_malloc(sizeof(ZipContext));
    if(!ctx)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    ZIP_INIT(&ctx->root);
    ctx->referenceTypeCounter = 0;

    
    ns->context = (void*)ctx;
    ns->clear = zipNsClear;
    ns->newNode = zipNsNewNode;
    ns->deleteNode = zipNsDeleteNode;
    ns->getNode = zipNsGetNode;
    ns->getNodeFromPtr = zipNsGetNodeFromPtr;
    ns->releaseNode = zipNsReleaseNode;
    ns->getNodeCopy = zipNsGetNodeCopy;
    ns->insertNode = zipNsInsertNode;
    ns->replaceNode = zipNsReplaceNode;
    ns->removeNode = zipNsRemoveNode;
    ns->getReferenceTypeId = zipNsGetReferenceTypeId;
    ns->iterate = zipNsIterate;

    ns->getEditNode =
        (UA_Node * (*)(void *nsCtx, const UA_NodeId *nodeId,
                       UA_UInt32 attributeMask,
                       UA_ReferenceTypeSet references,
                       UA_BrowseDirection referenceDirections))zipNsGetNode;
    ns->getEditNodeFromPtr =
        (UA_Node * (*)(void *nsCtx, UA_NodePointer ptr,
                       UA_UInt32 attributeMask,
                       UA_ReferenceTypeSet references,
                       UA_BrowseDirection referenceDirections))zipNsGetNodeFromPtr;

    return UA_STATUSCODE_GOOD;
}
