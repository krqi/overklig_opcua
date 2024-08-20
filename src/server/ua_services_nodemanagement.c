
#include "ua_server_internal.h"
#include "ua_services.h"





UA_StatusCode
UA_Server_getNodeContext(UA_Server *server, UA_NodeId nodeId,
                         void **nodeContext) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = getNodeContext(server, nodeId, nodeContext);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}

UA_StatusCode
getNodeContext(UA_Server *server, UA_NodeId nodeId,
               void **nodeContext) {
    const UA_Node *node = UA_NODESTORE_GET(server, &nodeId);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    *nodeContext = node->head.context;
    UA_NODESTORE_RELEASE(server, node);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
setDeconstructedNode(UA_Server *server, UA_Session *session,
                     UA_NodeHead *head, void *context) {
    head->constructed = false;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
setConstructedNodeContext(UA_Server *server, UA_Session *session,
                          UA_NodeHead *head, void *context) {
    head->context = context;
    head->constructed = true;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
setNodeContext(UA_Server *server, UA_NodeId nodeId, void *nodeContext) {
    UA_Node *node =
        UA_NODESTORE_GET_EDIT_SELECTIVE(server, &nodeId, UA_NODEATTRIBUTESMASK_NONE,
                                        UA_REFERENCETYPESET_NONE,
                                        UA_BROWSEDIRECTION_INVALID);
    if(!node)
        return UA_STATUSCODE_BADNODEIDINVALID;
    node->head.context = nodeContext;
    UA_NODESTORE_RELEASE(server, node);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_setNodeContext(UA_Server *server, UA_NodeId nodeId,
                         void *nodeContext) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = setNodeContext(server, nodeId, nodeContext);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}

static UA_StatusCode
checkSetIsDynamicVariable(UA_Server *server, UA_Session *session,
                          const UA_NodeId *nodeId);





#define UA_PARENT_REFERENCES_COUNT 2

const UA_NodeId parentReferences[UA_PARENT_REFERENCES_COUNT] = {
    {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_HASSUBTYPE}},
    {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_HASCOMPONENT}}
};

static void
logAddNode(const UA_Logger *logger, UA_Session *session,
           const UA_NodeId *nodeId, const char *msg) {
    UA_LOG_INFO_SESSION(logger, session, "AddNode (%N): %s", *nodeId, msg);
}

static UA_StatusCode
checkParentReference(UA_Server *server, UA_Session *session, const UA_NodeHead *head,
                     const UA_NodeId *parentNodeId, const UA_NodeId *referenceTypeId) {
    if((head->nodeClass == UA_NODECLASS_OBJECT ||
        head->nodeClass == UA_NODECLASS_VARIABLE) &&
       UA_NodeId_isNull(parentNodeId) && UA_NodeId_isNull(referenceTypeId))
        return UA_STATUSCODE_GOOD;

    
    const UA_Node *parent = UA_NODESTORE_GET(server, parentNodeId);
    if(!parent) {
        logAddNode(server->config.logging, session, &head->nodeId,
                   "Parent node not found");
        return UA_STATUSCODE_BADPARENTNODEIDINVALID;
    }

    UA_NodeClass parentNodeClass = parent->head.nodeClass;
    UA_NODESTORE_RELEASE(server, parent);

    
    const UA_Node *referenceType = UA_NODESTORE_GET(server, referenceTypeId);
    if(!referenceType) {
        logAddNode(server->config.logging, session, &head->nodeId,
                   "Reference type to the parent not found");
        return UA_STATUSCODE_BADREFERENCETYPEIDINVALID;
    }

    
    if(referenceType->head.nodeClass != UA_NODECLASS_REFERENCETYPE) {
        logAddNode(server->config.logging, session, &head->nodeId,
                   "Reference type to the parent is not a ReferenceTypeNode");
        UA_NODESTORE_RELEASE(server, referenceType);
        return UA_STATUSCODE_BADREFERENCETYPEIDINVALID;
    }

    
    UA_Boolean referenceTypeIsAbstract = referenceType->referenceTypeNode.isAbstract;
    UA_NODESTORE_RELEASE(server, referenceType);
    if(referenceTypeIsAbstract == true) {
        logAddNode(server->config.logging, session, &head->nodeId,
                   "Abstract reference type to the parent not allowed");
        return UA_STATUSCODE_BADREFERENCENOTALLOWED;
    }

    
    if(head->nodeClass == UA_NODECLASS_DATATYPE ||
       head->nodeClass == UA_NODECLASS_VARIABLETYPE ||
       head->nodeClass == UA_NODECLASS_OBJECTTYPE ||
       head->nodeClass == UA_NODECLASS_REFERENCETYPE) {
        
        if(referenceType->referenceTypeNode.referenceTypeIndex !=
           UA_REFERENCETYPEINDEX_HASSUBTYPE) {
            logAddNode(server->config.logging, session, &head->nodeId,
                       "Type nodes need to have a HasSubType reference to the parent");
            return UA_STATUSCODE_BADREFERENCENOTALLOWED;
        }
        
        if(parentNodeClass != head->nodeClass) {
            logAddNode(server->config.logging, session, &head->nodeId,
                       "Type nodes needs to be of the same node "
                       "type as their parent");
            return UA_STATUSCODE_BADPARENTNODEIDINVALID;
        }
        return UA_STATUSCODE_GOOD;
    }

    
    const UA_NodeId hierarchRefs = UA_NS0ID(HIERARCHICALREFERENCES);
    if(!isNodeInTree_singleRef(server, referenceTypeId, &hierarchRefs,
                               UA_REFERENCETYPEINDEX_HASSUBTYPE)) {
        logAddNode(server->config.logging, session, &head->nodeId,
                   "Reference type to the parent is not hierarchical");
        return UA_STATUSCODE_BADREFERENCETYPEIDINVALID;
    }

    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode
setDefaultValue(UA_Server *server, const UA_VariableNode *node) {
    
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    const UA_DataType *type = UA_Server_findDataType(server, &node->dataType);
    if(!type) {
        UA_ReferenceTypeSet refs = UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASSUBTYPE);
        UA_ExpandedNodeId *typeCandidates = NULL;
        size_t typeCandidatesSize = 0;
        res = browseRecursive(server, 1, &node->dataType,
                              UA_BROWSEDIRECTION_BOTH, &refs,
                              UA_NODECLASS_DATATYPE, false,
                              &typeCandidatesSize, &typeCandidates);
        if(res != UA_STATUSCODE_GOOD)
            return res;

        for(size_t i = 0; i < typeCandidatesSize; i++) {
            if(UA_NodeId_equal(&UA_TYPES[UA_TYPES_VARIANT].typeId,
                               &typeCandidates[i].nodeId))
                continue;

            if(UA_NodeId_equal(&UA_TYPES[UA_TYPES_EXTENSIONOBJECT].typeId,
                               &typeCandidates[i].nodeId))
                continue;

            
            type = UA_Server_findDataType(server, &typeCandidates[i].nodeId);
            if(type)
                break;
        }

        UA_Array_delete(typeCandidates, typeCandidatesSize,
                        &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
        if(!type)
            return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    
    UA_Variant val;
    UA_Variant_init(&val);
    if(node->valueRank < 0) {
        
        void *data = UA_new(type);
        if(!data)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        UA_Variant_setScalar(&val, data, type);
    } else {
        UA_Variant_setArray(&val, NULL, 0, type);
    }

    
    res = writeAttribute(server, &server->adminSession, &node->head.nodeId,
                         UA_ATTRIBUTEID_VALUE, &val, &UA_TYPES[UA_TYPES_VARIANT]);

    
    UA_Variant_clear(&val);
    return res;
}

static UA_StatusCode
typeCheckVariableNode(UA_Server *server, UA_Session *session,
                      const UA_VariableNode *node,
                      const UA_VariableTypeNode *vt) {
    
    if(!compatibleDataTypes(server, &node->dataType, &vt->dataType)) {
        logAddNode(server->config.logging, session, &node->head.nodeId,
                   "The value of is incompatible with "
                   "the datatype of the VariableType");
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    
    if(!compatibleValueRankArrayDimensions(server, session, node->valueRank,
                                           node->arrayDimensionsSize)) {
        logAddNode(server->config.logging, session, &node->head.nodeId,
                   "The value rank of is incompatible with its array dimensions");
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    
    if(!compatibleValueRanks(node->valueRank, vt->valueRank)) {
        logAddNode(server->config.logging, session, &node->head.nodeId,
                   "The value rank is incompatible "
                   "with the value rank of the VariableType");
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    
    if(!compatibleArrayDimensions(vt->arrayDimensionsSize, vt->arrayDimensions,
                                  node->arrayDimensionsSize, node->arrayDimensions)) {
        logAddNode(server->config.logging, session, &node->head.nodeId,
                   "The array dimensions are incompatible with the "
                   "array dimensions of the VariableType");
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    if(server->bootstrapNS0)
        return UA_STATUSCODE_GOOD;

    UA_DataValue value;
    UA_DataValue_init(&value);
    UA_StatusCode retval = readValueAttribute(server, session, node, &value);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    const char *reason;
    if(node->valueSource == UA_VALUESOURCE_DATA && value.hasValue) {
        if(!compatibleValue(server, session, &node->dataType, node->valueRank,
                            node->arrayDimensionsSize, node->arrayDimensions,
                            &value.value, NULL, &reason)) {
            retval = writeAttribute(server, session, &node->head.nodeId,
                                    UA_ATTRIBUTEID_VALUE, &value.value,
                                    &UA_TYPES[UA_TYPES_VARIANT]);
        }
        UA_DataValue_clear(&value);
        return retval;
    }

    
    if(!value.hasValue &&
       !UA_NodeId_equal(&node->dataType, &UA_TYPES[UA_TYPES_VARIANT].typeId)) {
        
        if(server->config.allowEmptyVariables != UA_RULEHANDLING_ACCEPT)
            UA_LOG_DEBUG_SESSION(server->config.logging, session,
                                 "AddNode (%N): The value is empty. "
                                 "But this is only allowed for BaseDataType. "
                                 "Create a matching default value.",
                                 node->head.nodeId);

        
        if(server->config.allowEmptyVariables == UA_RULEHANDLING_ABORT)
            retval = UA_STATUSCODE_BADTYPEMISMATCH;

        
        if(server->config.allowEmptyVariables == UA_RULEHANDLING_DEFAULT) {
            retval = setDefaultValue(server, node);
            if(retval != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO_SESSION(server->config.logging, session,
                                    "AddNode (%N): Could not create a default value "
                                    "with StatusCode %s", node->head.nodeId,
                                    UA_StatusCode_name(retval));
            }
        }
        return retval;
    }

    
    if(retval == UA_STATUSCODE_GOOD &&
       !compatibleValue(server, session, &node->dataType, node->valueRank,
                        node->arrayDimensionsSize, node->arrayDimensions,
                        &value.value, NULL, &reason)) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "AddNode (%N): The VariableNode value has "
                            "failed the type check with reason %s. ",
                            node->head.nodeId, reason);
        retval = UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_DataValue_clear(&value);
    return retval;
}





static const UA_NodeId baseDataVariableType =
    {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_BASEDATAVARIABLETYPE}};
static const UA_NodeId baseObjectType =
    {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_BASEOBJECTTYPE}};
static const UA_NodeId hasTypeDefinition =
    {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_HASTYPEDEFINITION}};

static UA_StatusCode
useVariableTypeAttributes(UA_Server *server, UA_Session *session,
                          const UA_VariableNode *node,
                          const UA_VariableTypeNode *vt) {
    UA_ReadValueId item;
    UA_ReadValueId_init(&item);
    item.nodeId = node->head.nodeId;
    item.attributeId = UA_ATTRIBUTEID_VALUE;
    UA_DataValue dv = readWithSession(server, session, &item,
                                      UA_TIMESTAMPSTORETURN_NEITHER);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(dv.hasValue && !dv.value.type) {
        UA_DataValue v;
        UA_DataValue_init(&v);
        retval = readValueAttribute(server, session, (const UA_VariableNode*)vt, &v);
        if(retval == UA_STATUSCODE_GOOD && v.hasValue) {
            retval = writeAttribute(server, session, &node->head.nodeId,
                                    UA_ATTRIBUTEID_VALUE, &v.value,
                                    &UA_TYPES[UA_TYPES_VARIANT]);
        }
        UA_DataValue_clear(&v);

        if(retval != UA_STATUSCODE_GOOD) {
            logAddNode(server->config.logging, session, &node->head.nodeId,
                       "The default content of the VariableType could "
                       "not be used. This may happen if the VariableNode "
                       "makes additional restrictions.");
            retval = UA_STATUSCODE_GOOD;
        }
    }
    UA_DataValue_clear(&dv);

    
    if(UA_NodeId_isNull(&node->dataType)) {
        logAddNode(server->config.logging, session, &node->head.nodeId,
                   "No datatype given; Copy the datatype attribute "
                   "from the TypeDefinition");
        retval = writeAttribute(server, session, &node->head.nodeId,
                                UA_ATTRIBUTEID_DATATYPE, &vt->dataType,
                                &UA_TYPES[UA_TYPES_NODEID]);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }

    
    if(node->arrayDimensionsSize == 0 && vt->arrayDimensionsSize > 0) {
        UA_Variant v;
        UA_Variant_init(&v);
        UA_Variant_setArray(&v, vt->arrayDimensions, vt->arrayDimensionsSize,
                            &UA_TYPES[UA_TYPES_UINT32]);
        retval = writeAttribute(server, session, &node->head.nodeId,
                                UA_ATTRIBUTEID_ARRAYDIMENSIONS, &v,
                                &UA_TYPES[UA_TYPES_VARIANT]);
    }

    return retval;
}

static UA_StatusCode
findChildByBrowsename(UA_Server *server, UA_Session *session,
                      const UA_NodeId *searchInstance,
                      const UA_QualifiedName *browseName,
                      UA_NodeId *outInstanceNodeId) {
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *searchInstance;
    bd.referenceTypeId = UA_NS0ID(AGGREGATES);
    bd.includeSubtypes = true;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_OBJECT | UA_NODECLASS_VARIABLE | UA_NODECLASS_METHOD;
    bd.resultMask = UA_BROWSERESULTMASK_BROWSENAME;

    UA_BrowseResult br;
    UA_BrowseResult_init(&br);
    UA_UInt32 maxrefs = 0;
    Operation_Browse(server, session, &maxrefs, &bd, &br);
    if(br.statusCode != UA_STATUSCODE_GOOD)
        return br.statusCode;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < br.referencesSize; ++i) {
        UA_ReferenceDescription *rd = &br.references[i];
        if(rd->browseName.namespaceIndex == browseName->namespaceIndex &&
           UA_String_equal(&rd->browseName.name, &browseName->name)) {
            retval = UA_NodeId_copy(&rd->nodeId.nodeId, outInstanceNodeId);
            break;
        }
    }

    UA_BrowseResult_clear(&br);
    return retval;
}

static const UA_ExpandedNodeId mandatoryId =
    {{0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_MODELLINGRULE_MANDATORY}}, {0, NULL}, 0};

static UA_Boolean
isMandatoryChild(UA_Server *server, UA_Session *session,
                 const UA_NodeId *childNodeId) {
    
    const UA_Node *child = UA_NODESTORE_GET(server, childNodeId);
    if(!child)
        return false;

    
    UA_Boolean found = false;
    for(size_t i = 0; i < child->head.referencesSize; ++i) {
        UA_NodeReferenceKind *rk = &child->head.references[i];
        if(rk->referenceTypeIndex != UA_REFERENCETYPEINDEX_HASMODELLINGRULE)
            continue;
        if(rk->isInverse)
            continue;

        if(UA_NodeReferenceKind_findTarget(rk, &mandatoryId)) {
            found = true;
            break;
        }
    }

    UA_NODESTORE_RELEASE(server, child);
    return found;
}

static UA_StatusCode
copyAllChildren(UA_Server *server, UA_Session *session,
                const UA_NodeId *source, const UA_NodeId *destination);

static void
Operation_addReference(UA_Server *server, UA_Session *session, void *context,
                       const UA_AddReferencesItem *item, UA_StatusCode *retval);

UA_StatusCode
addRefWithSession(UA_Server *server, UA_Session *session, const UA_NodeId *sourceId,
                  const UA_NodeId *referenceTypeId, const UA_NodeId *targetId,
                  UA_Boolean forward) {
    UA_AddReferencesItem ref_item;
    UA_AddReferencesItem_init(&ref_item);
    ref_item.sourceNodeId = *sourceId;
    ref_item.referenceTypeId = *referenceTypeId;
    ref_item.isForward = forward;
    ref_item.targetNodeId.nodeId = *targetId;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    Operation_addReference(server, session, NULL, &ref_item, &retval);
    return retval;
}

UA_StatusCode
addRef(UA_Server *server, const UA_NodeId sourceId,
       const UA_NodeId referenceTypeId, const UA_NodeId targetId,
       UA_Boolean forward) {
    return addRefWithSession(server, &server->adminSession, &sourceId,
                             &referenceTypeId, &targetId, forward);
}

static UA_StatusCode
addInterfaceChildren(UA_Server *server, UA_Session *session,
                     const UA_NodeId *nodeId, const UA_NodeId *typeId) {
    
    UA_NodeId *hierarchy = NULL;
    size_t hierarchySize = 0;
    UA_StatusCode retval = getAllInterfaceChildNodeIds(server, nodeId, typeId,
                                                       &hierarchy, &hierarchySize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    for(size_t i = 0; i < hierarchySize; ++i) {
        retval = copyAllChildren(server, session, &hierarchy[i], nodeId);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_Array_delete(hierarchy, hierarchySize, &UA_TYPES[UA_TYPES_NODEID]);
            return retval;
        }
    }

    for(size_t i = 0; i < hierarchySize; ++i) {
        UA_NodeId refId = UA_NS0ID(HASINTERFACE);
        retval = addRef(server, *nodeId, refId, hierarchy[i], true);

        
        if(retval == UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED) {
            retval = UA_STATUSCODE_GOOD;
        } else if(retval != UA_STATUSCODE_GOOD) {
            break;
        }
    }

    UA_Array_delete(hierarchy, hierarchySize, &UA_TYPES[UA_TYPES_NODEID]);
    return retval;
}

static UA_StatusCode
copyChild(UA_Server *server, UA_Session *session,
          const UA_NodeId *destinationNodeId,
          const UA_ReferenceDescription *rd) {
    UA_assert(session);
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_NodeId existingChild = UA_NODEID_NULL;
    UA_StatusCode retval = findChildByBrowsename(server, session, destinationNodeId,
                                                 &rd->browseName, &existingChild);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    if(!UA_NodeId_isNull(&existingChild)) {
        if(rd->nodeClass == UA_NODECLASS_VARIABLE ||
           rd->nodeClass == UA_NODECLASS_OBJECT)
            retval = copyAllChildren(server, session, &rd->nodeId.nodeId, &existingChild);
        UA_NodeId_clear(&existingChild);
        return retval;
    }

    if(!isMandatoryChild(server, session, &rd->nodeId.nodeId)) {
        if(!server->config.nodeLifecycle.createOptionalChild)
            return UA_STATUSCODE_GOOD;
        UA_UNLOCK(&server->serviceMutex);
        UA_Boolean createChild = server->config.nodeLifecycle.
            createOptionalChild(server, &session->sessionId, session->context,
                                &rd->nodeId.nodeId, destinationNodeId, &rd->referenceTypeId);
        UA_LOCK(&server->serviceMutex);
        if(!createChild)
            return UA_STATUSCODE_GOOD;
    }

    
    if(rd->nodeClass == UA_NODECLASS_METHOD) {
        UA_AddReferencesItem newItem;
        UA_AddReferencesItem_init(&newItem);
        newItem.sourceNodeId = *destinationNodeId;
        newItem.referenceTypeId = rd->referenceTypeId;
        newItem.isForward = true;
        newItem.targetNodeId = rd->nodeId;
        newItem.targetNodeClass = UA_NODECLASS_METHOD;
        Operation_addReference(server, session, NULL, &newItem, &retval);
        return retval;
    }

    
    if(rd->nodeClass == UA_NODECLASS_VARIABLE ||
       rd->nodeClass == UA_NODECLASS_OBJECT) {
        
        UA_Node *node;
        retval = UA_NODESTORE_GETCOPY(server, &rd->nodeId.nodeId, &node);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;

        
        node->head.context = NULL;
        node->head.constructed = false;
#ifdef UA_ENABLE_SUBSCRIPTIONS
        node->head.monitoredItems = NULL;
#endif

        if(node->head.nodeClass == UA_NODECLASS_VARIABLE ||
           node->head.nodeClass == UA_NODECLASS_VARIABLETYPE) {
            if(node->variableNode.valueSource != UA_VALUESOURCE_DATA)
                memset(&node->variableNode.value, 0, sizeof(node->variableNode.value));
            node->variableNode.valueSource = UA_VALUESOURCE_DATA;
            memset(&node->variableNode.valueBackend, 0, sizeof(UA_ValueBackend));
        }

        
        UA_NodeId_clear(&node->head.nodeId);
        node->head.nodeId.namespaceIndex = destinationNodeId->namespaceIndex;

        if(server->config.nodeLifecycle.generateChildNodeId) {
            UA_UNLOCK(&server->serviceMutex);
            retval = server->config.nodeLifecycle.
                generateChildNodeId(server, &session->sessionId, session->context,
                                    &rd->nodeId.nodeId, destinationNodeId,
                                    &rd->referenceTypeId, &node->head.nodeId);
            UA_LOCK(&server->serviceMutex);
            if(retval != UA_STATUSCODE_GOOD) {
                UA_NODESTORE_DELETE(server, node);
                return retval;
            }
        }

        
        
        const UA_NodeId nodeId_typesFolder= UA_NS0ID(TYPESFOLDER);
        const UA_ReferenceTypeSet reftypes_aggregates =
            UA_REFTYPESET(UA_REFERENCETYPEINDEX_AGGREGATES);
        UA_ReferenceTypeSet reftypes_skipped;
        if(server->config.modellingRulesOnInstances ||
           isNodeInTree(server, destinationNodeId,
                        &nodeId_typesFolder, &reftypes_aggregates)) {
            reftypes_skipped = UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASMODELLINGRULE);
        } else {
            UA_ReferenceTypeSet_init(&reftypes_skipped);
        }
        reftypes_skipped = UA_ReferenceTypeSet_union(reftypes_skipped, UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASINTERFACE));
        UA_Node_deleteReferencesSubset(node, &reftypes_skipped);

        
        UA_NodeId newNodeId = UA_NODEID_NULL;
        retval = UA_NODESTORE_INSERT(server, node, &newNodeId);
        
        if(retval != UA_STATUSCODE_GOOD)
            return retval;

        
        retval = addNode_addRefs(server, session, &newNodeId, destinationNodeId,
                                 &rd->referenceTypeId, &rd->typeDefinition.nodeId);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_NODESTORE_REMOVE(server, &newNodeId);
            UA_NodeId_clear(&newNodeId);
            return retval;
        }

        if (rd->nodeClass == UA_NODECLASS_VARIABLE) {
            retval = checkSetIsDynamicVariable(server, session, &newNodeId);

            if(retval != UA_STATUSCODE_GOOD) {
                UA_NODESTORE_REMOVE(server, &newNodeId);
                return retval;
            }
        }

        retval = copyAllChildren(server, session, &rd->nodeId.nodeId, &newNodeId);
        if(retval != UA_STATUSCODE_GOOD) {
            deleteNode(server, newNodeId, true);
            return retval;
        }

        retval = addNode_finish(server, session, &newNodeId);
        if(retval != UA_STATUSCODE_GOOD) {
            deleteNode(server, newNodeId, true);
            return retval;
        }

        UA_NodeId_clear(&newNodeId);
    }

    return retval;
}


static UA_StatusCode
copyAllChildren(UA_Server *server, UA_Session *session,
                const UA_NodeId *source, const UA_NodeId *destination) {
    
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *source;
    bd.referenceTypeId = UA_NS0ID(AGGREGATES);
    bd.includeSubtypes = true;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_OBJECT | UA_NODECLASS_VARIABLE | UA_NODECLASS_METHOD;
    bd.resultMask = UA_BROWSERESULTMASK_REFERENCETYPEID | UA_BROWSERESULTMASK_NODECLASS |
        UA_BROWSERESULTMASK_BROWSENAME | UA_BROWSERESULTMASK_TYPEDEFINITION;

    UA_BrowseResult br;
    UA_BrowseResult_init(&br);
    UA_UInt32 maxrefs = 0;
    Operation_Browse(server, session, &maxrefs, &bd, &br);
    if(br.statusCode != UA_STATUSCODE_GOOD)
        return br.statusCode;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < br.referencesSize; ++i) {
        UA_ReferenceDescription *rd = &br.references[i];
        retval = copyChild(server, session, destination, rd);
        if(retval != UA_STATUSCODE_GOOD)
            break;
    }

    UA_BrowseResult_clear(&br);
    return retval;
}

static UA_StatusCode
addTypeChildren(UA_Server *server, UA_Session *session,
                const UA_NodeId *nodeId, const UA_NodeId *typeId) {
    
    UA_NodeId *hierarchy = NULL;
    size_t hierarchySize = 0;
    UA_StatusCode retval = getParentTypeAndInterfaceHierarchy(server, typeId,
                                                              &hierarchy, &hierarchySize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    UA_assert(hierarchySize < 1000);

    
    for(size_t i = 0; i < hierarchySize; ++i) {
        retval = copyAllChildren(server, session, &hierarchy[i], nodeId);
        if(retval != UA_STATUSCODE_GOOD)
            break;
    }

    UA_Array_delete(hierarchy, hierarchySize, &UA_TYPES[UA_TYPES_NODEID]);
    return retval;
}





static const UA_NodeId hasSubtype = {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_HASSUBTYPE}};

UA_StatusCode
addNode_addRefs(UA_Server *server, UA_Session *session, const UA_NodeId *nodeId,
                const UA_NodeId *parentNodeId, const UA_NodeId *referenceTypeId,
                const UA_NodeId *typeDefinitionId) {
    
    const UA_Node *type = NULL;
    const UA_Node *node = UA_NODESTORE_GET(server, nodeId);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;

    
    const UA_NodeHead *head = &node->head;
    if(head->nodeClass == UA_NODECLASS_VARIABLETYPE ||
       head->nodeClass == UA_NODECLASS_OBJECTTYPE ||
       head->nodeClass == UA_NODECLASS_REFERENCETYPE ||
       head->nodeClass == UA_NODECLASS_DATATYPE) {
        if(UA_NodeId_equal(referenceTypeId, &UA_NODEID_NULL))
            referenceTypeId = &hasSubtype;
        const UA_Node *parentNode = UA_NODESTORE_GET(server, parentNodeId);
        if(parentNode) {
            if(parentNode->head.nodeClass == head->nodeClass)
                typeDefinitionId = parentNodeId;
            UA_NODESTORE_RELEASE(server, parentNode);
        }
    }

    UA_StatusCode retval;
    
    if(UA_NodeId_equal(nodeId, parentNodeId)) {
        logAddNode(server->config.logging, session, nodeId,
                   "A node cannot have itself as parent");
        retval = UA_STATUSCODE_BADINVALIDARGUMENT;
        goto cleanup;
    }


    
    retval = checkParentReference(server, session, head, parentNodeId, referenceTypeId);
    if(retval != UA_STATUSCODE_GOOD) {
        logAddNode(server->config.logging, session, nodeId,
                   "The parent reference for is invalid");
        goto cleanup;
    }

    
    if((head->nodeClass == UA_NODECLASS_VARIABLE ||
        head->nodeClass == UA_NODECLASS_OBJECT) &&
       UA_NodeId_isNull(typeDefinitionId)) {
        logAddNode(server->config.logging, session, nodeId,
                   "No TypeDefinition. Use the default "
                   "TypeDefinition for the Variable/Object");
        if(head->nodeClass == UA_NODECLASS_VARIABLE)
            typeDefinitionId = &baseDataVariableType;
        else
            typeDefinitionId = &baseObjectType;
    }

    if(!UA_NodeId_isNull(typeDefinitionId)) {
        
        type = UA_NODESTORE_GET(server, typeDefinitionId);
        if(!type) {
            logAddNode(server->config.logging, session, nodeId, "Node type not found");
            retval = UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
            goto cleanup;
        }

        UA_Boolean typeOk = false;
        const UA_NodeHead *typeHead = &type->head;
        switch(head->nodeClass) {
            case UA_NODECLASS_DATATYPE:
                typeOk = typeHead->nodeClass == UA_NODECLASS_DATATYPE;
                break;
            case UA_NODECLASS_METHOD:
                typeOk = typeHead->nodeClass == UA_NODECLASS_METHOD;
                break;
            case UA_NODECLASS_OBJECT:
            case UA_NODECLASS_OBJECTTYPE:
                typeOk = typeHead->nodeClass == UA_NODECLASS_OBJECTTYPE;
                break;
            case UA_NODECLASS_REFERENCETYPE:
                typeOk = typeHead->nodeClass == UA_NODECLASS_REFERENCETYPE;
                break;
            case UA_NODECLASS_VARIABLE:
            case UA_NODECLASS_VARIABLETYPE:
                typeOk = typeHead->nodeClass == UA_NODECLASS_VARIABLETYPE;
                break;
            case UA_NODECLASS_VIEW:
                typeOk = typeHead->nodeClass == UA_NODECLASS_VIEW;
                break;
            default:
                typeOk = false;
        }
        if(!typeOk) {
            logAddNode(server->config.logging, session, nodeId,
                       "Type does not match the NodeClass");
            retval = UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
            goto cleanup;
        }

        if(head->nodeClass == UA_NODECLASS_VARIABLE &&
           type->variableTypeNode.isAbstract) {
            
            UA_ReferenceTypeSet refTypes1, refTypes2;
            retval |= referenceTypeIndices(server, &parentReferences[0], &refTypes1, true);
            retval |= referenceTypeIndices(server, &parentReferences[1], &refTypes2, true);
            UA_ReferenceTypeSet refTypes = UA_ReferenceTypeSet_union(refTypes1, refTypes2);
            if(retval != UA_STATUSCODE_GOOD)
                goto cleanup;

            const UA_NodeId variableTypes = UA_NS0ID(BASEDATAVARIABLETYPE);
            const UA_NodeId objectTypes = UA_NS0ID(BASEOBJECTTYPE);
            if(!isNodeInTree(server, parentNodeId, &variableTypes, &refTypes) &&
               !isNodeInTree(server, parentNodeId, &objectTypes, &refTypes)) {
                logAddNode(server->config.logging, session, nodeId,
                           "Type of variable node must be a "
                           "VariableType and cannot be abstract");
                retval = UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
                goto cleanup;
            }
        }

        if(head->nodeClass == UA_NODECLASS_OBJECT &&
           type->objectTypeNode.isAbstract) {
            
            UA_ReferenceTypeSet refTypes1, refTypes2;
            retval |= referenceTypeIndices(server, &parentReferences[0], &refTypes1, true);
            retval |= referenceTypeIndices(server, &parentReferences[1], &refTypes2, true);
            UA_ReferenceTypeSet refTypes = UA_ReferenceTypeSet_union(refTypes1, refTypes2);
            if(retval != UA_STATUSCODE_GOOD)
                goto cleanup;


            const UA_NodeId objectTypes = UA_NS0ID(BASEOBJECTTYPE);
            UA_Boolean isInBaseObjectType =
                isNodeInTree(server, parentNodeId, &objectTypes, &refTypes);

            const UA_NodeId eventTypes = UA_NS0ID(BASEEVENTTYPE);
            UA_Boolean isInBaseEventType =
                isNodeInTree_singleRef(server, &type->head.nodeId, &eventTypes,
                                       UA_REFERENCETYPEINDEX_HASSUBTYPE);

            if(!isInBaseObjectType &&
               !(isInBaseEventType && UA_NodeId_isNull(parentNodeId))) {
                logAddNode(server->config.logging, session, nodeId,
                           "Type of ObjectNode must be ObjectType and not be abstract");
                retval = UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
                goto cleanup;
            }
        }
    }

    
    if(!UA_NodeId_isNull(parentNodeId)) {
        if(UA_NodeId_isNull(referenceTypeId)) {
            logAddNode(server->config.logging, session, nodeId,
                       "Reference to parent cannot be null");
            retval = UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
            goto cleanup;
        }

        retval = addRefWithSession(server, session, &head->nodeId, referenceTypeId,
                                   parentNodeId, false);
        if(retval != UA_STATUSCODE_GOOD) {
            logAddNode(server->config.logging, session, nodeId,
                       "Adding reference to parent failed");
            goto cleanup;
        }
    }

    
    if(head->nodeClass == UA_NODECLASS_VARIABLE ||
       head->nodeClass == UA_NODECLASS_OBJECT) {
        UA_assert(type != NULL); 
        retval = addRefWithSession(server, session, &head->nodeId, &hasTypeDefinition,
                                   &type->head.nodeId, true);
        if(retval != UA_STATUSCODE_GOOD) {
            logAddNode(server->config.logging, session, nodeId,
                       "Adding a reference to the type definition failed");
        }
    }

 cleanup:
    UA_NODESTORE_RELEASE(server, node);
    if(type)
        UA_NODESTORE_RELEASE(server, type);
    return retval;
}

UA_StatusCode
addNode_raw(UA_Server *server, UA_Session *session, void *nodeContext,
            const UA_AddNodesItem *item, UA_NodeId *outNewNodeId) {
    
    if(session != &server->adminSession && server->config.accessControl.allowAddNode) {
        UA_LOCK_ASSERT(&server->serviceMutex, 1);
        UA_UNLOCK(&server->serviceMutex);
        if(!server->config.accessControl.
           allowAddNode(server, &server->config.accessControl,
                        &session->sessionId, session->context, item)) {
            UA_LOCK(&server->serviceMutex);
            return UA_STATUSCODE_BADUSERACCESSDENIED;
        }
        UA_LOCK(&server->serviceMutex);
    }

    
    if(item->requestedNewNodeId.nodeId.namespaceIndex >= server->namespacesSize) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "AddNode: Namespace invalid");
        return UA_STATUSCODE_BADNODEIDINVALID;
    }

    if(item->nodeAttributes.encoding != UA_EXTENSIONOBJECT_DECODED &&
       item->nodeAttributes.encoding != UA_EXTENSIONOBJECT_DECODED_NODELETE) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "AddNode: Node attributes invalid");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    UA_Node *node = UA_NODESTORE_NEW(server, item->nodeClass);
    if(!node) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "AddNode: Node could not create a node "
                            "in the nodestore");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    UA_NodeId tmpOutId = UA_NODEID_NULL;
    
    node->head.context = nodeContext;
    UA_StatusCode retval =
        UA_NodeId_copy(&item->requestedNewNodeId.nodeId, &node->head.nodeId);
    if(retval != UA_STATUSCODE_GOOD)
        goto create_error;

    retval = UA_QualifiedName_copy(&item->browseName, &node->head.browseName);
    if(retval != UA_STATUSCODE_GOOD)
        goto create_error;

    retval = UA_Node_setAttributes(node, item->nodeAttributes.content.decoded.data,
                                   item->nodeAttributes.content.decoded.type);
    if(retval != UA_STATUSCODE_GOOD)
        goto create_error;

    
    if(node->head.nodeClass == UA_NODECLASS_VARIABLE &&
       !node->variableNode.value.data.value.hasSourceTimestamp) {
        UA_EventLoop *el = server->config.eventLoop;
        node->variableNode.value.data.value.sourceTimestamp = el->dateTime_now(el);
        node->variableNode.value.data.value.hasSourceTimestamp = true;
    }

    
    if(!outNewNodeId)
        outNewNodeId = &tmpOutId;
    retval = UA_NODESTORE_INSERT(server, node, outNewNodeId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "AddNode: Node could not add the new node "
                            "to the nodestore with error code %s",
                            UA_StatusCode_name(retval));
        return retval;
    }

    if(outNewNodeId == &tmpOutId)
        UA_NodeId_clear(&tmpOutId);

    return UA_STATUSCODE_GOOD;

create_error:
    UA_LOG_INFO_SESSION(server->config.logging, session,
                        "AddNode: Node could not create a node "
                        "with error code %s", UA_StatusCode_name(retval));
    UA_NODESTORE_DELETE(server, node);
    return retval;
}

static UA_StatusCode
findDefaultInstanceBrowseNameNode(UA_Server *server, UA_NodeId startingNode,
                                  UA_NodeId *foundId) {
    UA_NodeId_init(foundId);
    UA_RelativePathElement rpe;
    UA_RelativePathElement_init(&rpe);
    rpe.referenceTypeId = UA_NS0ID(HASPROPERTY);
    rpe.targetName = UA_QUALIFIEDNAME(0, "DefaultInstanceBrowseName");
    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = startingNode;
    bp.relativePath.elementsSize = 1;
    bp.relativePath.elements = &rpe;
    UA_BrowsePathResult bpr = translateBrowsePathToNodeIds(server, &bp);
    UA_StatusCode retval = bpr.statusCode;
    if(retval == UA_STATUSCODE_GOOD && bpr.targetsSize > 0)
        retval = UA_NodeId_copy(&bpr.targets[0].targetId.nodeId, foundId);
    UA_BrowsePathResult_clear(&bpr);
    return retval;
}

static UA_StatusCode
checkSetBrowseName(UA_Server *server, UA_Session *session, UA_AddNodesItem *item) {
    
    if(!UA_QualifiedName_isNull(&item->browseName))
        return UA_STATUSCODE_GOOD;

    
    if(item->nodeClass != UA_NODECLASS_OBJECT)
        return UA_STATUSCODE_BADBROWSENAMEINVALID;

    UA_NodeId defaultBrowseNameNode;
    UA_StatusCode retval =
        findDefaultInstanceBrowseNameNode(server, item->typeDefinition.nodeId,
                                          &defaultBrowseNameNode);
    if(retval != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADBROWSENAMEINVALID;

    UA_Variant defaultBrowseName;
    retval = readWithReadValue(server, &defaultBrowseNameNode,
                               UA_ATTRIBUTEID_VALUE, &defaultBrowseName);
    UA_NodeId_clear(&defaultBrowseNameNode);
    if(retval != UA_STATUSCODE_GOOD)
        return UA_STATUSCODE_BADBROWSENAMEINVALID;

    if(UA_Variant_hasScalarType(&defaultBrowseName, &UA_TYPES[UA_TYPES_QUALIFIEDNAME])) {
        item->browseName = *(UA_QualifiedName*)defaultBrowseName.data;
        UA_QualifiedName_init((UA_QualifiedName*)defaultBrowseName.data);
    } else {
        retval = UA_STATUSCODE_BADBROWSENAMEINVALID;
    }

    UA_Variant_clear(&defaultBrowseName);
    return retval;
}


static UA_StatusCode
Operation_addNode_begin(UA_Server *server, UA_Session *session, void *nodeContext,
                        const UA_AddNodesItem *item, const UA_NodeId *parentNodeId,
                        const UA_NodeId *referenceTypeId, UA_NodeId *outNewNodeId) {
    
    UA_NodeId newId;
    if(!outNewNodeId) {
        UA_NodeId_init(&newId);
        outNewNodeId = &newId;
    }

    UA_Boolean noBrowseName = UA_QualifiedName_isNull(&item->browseName);
    UA_StatusCode retval =
        checkSetBrowseName(server, session, (UA_AddNodesItem*)(uintptr_t)item);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    retval = addNode_raw(server, session, nodeContext, item, outNewNodeId);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    retval = addNode_addRefs(server, session, outNewNodeId, parentNodeId,
                             referenceTypeId, &item->typeDefinition.nodeId);
    if(retval != UA_STATUSCODE_GOOD)
        deleteNode(server, *outNewNodeId, true);

    if(outNewNodeId == &newId)
        UA_NodeId_clear(&newId);

 cleanup:
    if(noBrowseName)
        UA_QualifiedName_clear((UA_QualifiedName*)(uintptr_t)&item->browseName);
    return retval;
}


static UA_StatusCode
recursiveCallConstructors(UA_Server *server, UA_Session *session,
                          const UA_NodeId *nodeId, const UA_Node *type) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *nodeId;
    bd.referenceTypeId = UA_NS0ID(AGGREGATES);
    bd.includeSubtypes = true;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;

    UA_BrowseResult br;
    UA_BrowseResult_init(&br);
    UA_UInt32 maxrefs = 0;
    Operation_Browse(server, session, &maxrefs, &bd, &br);
    if(br.statusCode != UA_STATUSCODE_GOOD)
        return br.statusCode;

    
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < br.referencesSize; ++i) {
        UA_ReferenceDescription *rd = &br.references[i];
        if(!UA_ExpandedNodeId_isLocal(&rd->nodeId))
            continue;
        const UA_Node *target = UA_NODESTORE_GET(server, &rd->nodeId.nodeId);
        if(!target)
            continue;
        if(target->head.constructed) {
            UA_NODESTORE_RELEASE(server, target);
            continue;
        }

        const UA_Node *targetType = NULL;
        if(target->head.nodeClass == UA_NODECLASS_VARIABLE ||
           target->head.nodeClass == UA_NODECLASS_OBJECT) {
            targetType = getNodeType(server, &target->head);
            if(!targetType) {
                UA_NODESTORE_RELEASE(server, target);
                retval = UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
                break;
            }
        }

        UA_NODESTORE_RELEASE(server, target);
        retval = recursiveCallConstructors(server, session, &rd->nodeId.nodeId, targetType);

        if(targetType)
            UA_NODESTORE_RELEASE(server, targetType);
        if(retval != UA_STATUSCODE_GOOD)
            break;
    }

    UA_BrowseResult_clear(&br);

    
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    const UA_Node *node = UA_NODESTORE_GET(server, nodeId);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    void *context = node->head.context;
    UA_NODESTORE_RELEASE(server, node);

    
    if(server->config.nodeLifecycle.constructor) {
        UA_UNLOCK(&server->serviceMutex);
        retval = server->config.nodeLifecycle.
            constructor(server, &session->sessionId,
                        session->context, nodeId, &context);
        UA_LOCK(&server->serviceMutex);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }

    
    const UA_NodeTypeLifecycle *lifecycle = NULL;
    if(type && node->head.nodeClass == UA_NODECLASS_OBJECT)
        lifecycle = &type->objectTypeNode.lifecycle;
    else if(type && node->head.nodeClass == UA_NODECLASS_VARIABLE)
        lifecycle = &type->variableTypeNode.lifecycle;
    if(lifecycle && lifecycle->constructor) {
        UA_UNLOCK(&server->serviceMutex);
        retval = lifecycle->constructor(server, &session->sessionId,
                                        session->context, &type->head.nodeId,
                                        type->head.context, nodeId, &context);
        UA_LOCK(&server->serviceMutex);
        if(retval != UA_STATUSCODE_GOOD)
            goto global_destructor;
    }

    
    retval = UA_Server_editNode(server, &server->adminSession, nodeId,
                                0, UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID,
                                (UA_EditNodeCallback)setConstructedNodeContext, context);
    if(retval != UA_STATUSCODE_GOOD)
        goto local_destructor;

    
    return retval;

    
  local_destructor:
    if(lifecycle && lifecycle->destructor) {
        UA_UNLOCK(&server->serviceMutex);
        lifecycle->destructor(server, &session->sessionId, session->context,
                              &type->head.nodeId, type->head.context, nodeId, &context);
        UA_LOCK(&server->serviceMutex);
    }

  global_destructor:
    if(server->config.nodeLifecycle.destructor) {
        UA_UNLOCK(&server->serviceMutex);
        server->config.nodeLifecycle.destructor(server, &session->sessionId,
                                                session->context, nodeId, context);
        UA_LOCK(&server->serviceMutex);
    }
    return retval;
}


static UA_StatusCode
addReferenceTypeSubtype(UA_Server *server, UA_Session *session,
                        UA_Node *node, void *context) {
    node->referenceTypeNode.subTypes =
        UA_ReferenceTypeSet_union(node->referenceTypeNode.subTypes,
                                  *(UA_ReferenceTypeSet*)context);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
setReferenceTypeSubtypes(UA_Server *server, const UA_ReferenceTypeNode *node) {
    
    size_t parentsSize = 0;
    UA_ExpandedNodeId *parents = NULL;
    UA_ReferenceTypeSet reftypes_subtype = UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASSUBTYPE);
    UA_StatusCode res =
        browseRecursive(server, 1, &node->head.nodeId, UA_BROWSEDIRECTION_INVERSE,
                        &reftypes_subtype, UA_NODECLASS_UNSPECIFIED,
                        false, &parentsSize, &parents);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    
    const UA_ReferenceTypeSet *newRefSet = &node->subTypes;
    for(size_t i = 0; i < parentsSize; i++) {
        UA_Server_editNode(server, &server->adminSession, &parents[i].nodeId,
                           0, UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID,
                           addReferenceTypeSubtype, (void*)(uintptr_t)newRefSet);
    }

    UA_Array_delete(parents, parentsSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
setVariableNodeDynamic(UA_Server *server, const UA_NodeId *nodeId,
                       UA_Boolean isDynamic) {
    UA_Node *node =
        UA_NODESTORE_GET_EDIT_SELECTIVE(server, nodeId, 0, UA_REFERENCETYPESET_NONE,
                                        UA_BROWSEDIRECTION_INVALID);
    if(!node)
        return UA_STATUSCODE_BADNODEIDINVALID;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(node->head.nodeClass == UA_NODECLASS_VARIABLE)
        ((UA_VariableNode*)node)->isDynamic = isDynamic;
    else
        res = UA_STATUSCODE_BADINTERNALERROR;
    UA_NODESTORE_RELEASE(server, node);
    return res;
}

static UA_StatusCode
checkSetIsDynamicVariable(UA_Server *server, UA_Session *session,
                          const UA_NodeId *nodeId) {
    
    UA_ReferenceTypeSet reftypes_hierarchical;
    UA_ReferenceTypeSet_init(&reftypes_hierarchical);
    UA_NodeId hierarchicalRefs = UA_NS0ID(HIERARCHICALREFERENCES);
    UA_StatusCode res =
        referenceTypeIndices(server, &hierarchicalRefs, &reftypes_hierarchical, true);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    
    UA_NodeId serverNodeId = UA_NS0ID(SERVER);
    if(isNodeInTree(server, nodeId, &serverNodeId, &reftypes_hierarchical))
        return UA_STATUSCODE_GOOD;

    
    UA_NodeId typesNodeId = UA_NS0ID(TYPESFOLDER);
    if(isNodeInTree(server, nodeId, &typesNodeId, &reftypes_hierarchical))
        return UA_STATUSCODE_GOOD;

    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = *nodeId;
    bd.browseDirection = UA_BROWSEDIRECTION_INVERSE;
    bd.referenceTypeId = UA_NS0ID(HASPROPERTY);
    bd.includeSubtypes = false;
    bd.nodeClassMask = UA_NODECLASS_METHOD;
    UA_BrowseResult br;
    UA_BrowseResult_init(&br);
    UA_UInt32 maxrefs = 0;
    Operation_Browse(server, session, &maxrefs, &bd, &br);
    UA_Boolean hasParentMethod = (br.referencesSize > 0);
    UA_BrowseResult_clear(&br);
    if(hasParentMethod)
        return UA_STATUSCODE_GOOD;

    
    return setVariableNodeDynamic(server, nodeId, true);
}

UA_StatusCode
UA_Server_setVariableNodeDynamic(UA_Server *server, const UA_NodeId nodeId,
                                 UA_Boolean isDynamic) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = setVariableNodeDynamic(server, &nodeId, isDynamic);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}


UA_StatusCode
addNode_finish(UA_Server *server, UA_Session *session, const UA_NodeId *nodeId) {
    
    const UA_Node *type = NULL;
    const UA_Node *node = UA_NODESTORE_GET(server, nodeId);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;

    
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(node->head.nodeClass == UA_NODECLASS_REFERENCETYPE) {
        retval = setReferenceTypeSubtypes(server, &node->referenceTypeNode);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    if(node->head.nodeClass == UA_NODECLASS_VARIABLE) {
        for(size_t i = 0; i < node->head.referencesSize; i++) {
            if(node->head.references[i].referenceTypeIndex ==
               UA_REFERENCETYPEINDEX_HASSUBTYPE) {
                UA_LOG_INFO_SESSION(server->config.logging, session,
                                    "AddNode (%N): Variable not allowed "
                                    "to have HasSubType reference",
                                    node->head.nodeId);
                retval = UA_STATUSCODE_BADREFERENCENOTALLOWED;
                goto cleanup;
            }
        }
    }

    if(node->head.nodeClass == UA_NODECLASS_VARIABLE) {
        retval = checkSetIsDynamicVariable(server, session, nodeId);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    
    if(node->head.nodeClass == UA_NODECLASS_VARIABLE ||
       node->head.nodeClass == UA_NODECLASS_VARIABLETYPE ||
       node->head.nodeClass == UA_NODECLASS_OBJECT) {
        type = getNodeType(server, &node->head);
        if(!type) {
            if(server->bootstrapNS0)
                goto constructor;
            logAddNode(server->config.logging, session, &node->head.nodeId,
                       "Node type not found");
            retval = UA_STATUSCODE_BADTYPEDEFINITIONINVALID;
            goto cleanup;
        }
    }

    
    if(node->head.nodeClass == UA_NODECLASS_VARIABLE ||
       node->head.nodeClass == UA_NODECLASS_VARIABLETYPE) {
        retval = useVariableTypeAttributes(server, session,
                                           &node->variableNode,
                                           &type->variableTypeNode);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_INFO_SESSION(server->config.logging, session,
                                "AddNode (%N): Using attributes for from "
                                "the variable type failed with error code %s",
                                node->head.nodeId, UA_StatusCode_name(retval));
            goto cleanup;
        }

        UA_NODESTORE_RELEASE(server, node);
        node = UA_NODESTORE_GET(server, nodeId);
        if(!node || (node->head.nodeClass != UA_NODECLASS_VARIABLE &&
                     node->head.nodeClass != UA_NODECLASS_VARIABLETYPE)) {
            retval = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }

        retval = typeCheckVariableNode(server, session, &node->variableNode,
                                       &type->variableTypeNode);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_INFO_SESSION(server->config.logging, session,
                                "AddNode (%N): Type-checking failed with error code %s",
                                node->head.nodeId, UA_StatusCode_name(retval));
            goto cleanup;
        }
    }

    
    if(node->head.nodeClass == UA_NODECLASS_VARIABLE ||
       node->head.nodeClass == UA_NODECLASS_OBJECT) {
        retval = addTypeChildren(server, session, nodeId, &type->head.nodeId);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_INFO_SESSION(server->config.logging, session,
                                "AddNode (%N): Adding child nodes "
                                "failed with error code %s",
                                node->head.nodeId, UA_StatusCode_name(retval));
            goto cleanup;
        }
    }

    
    if(node->head.nodeClass == UA_NODECLASS_OBJECT) {
        retval = addInterfaceChildren(server, session, nodeId, &type->head.nodeId);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_INFO_SESSION(server->config.logging, session,
                                "AddNode (%N): Adding child nodes "
                                "interface failed with error code %s",
                                node->head.nodeId, UA_StatusCode_name(retval));
            goto cleanup;
        }
    }

    
 constructor:
    if(!node->head.constructed)
        retval = recursiveCallConstructors(server, session, nodeId, type);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "AddNode (%N): Calling the node constructor(s) "
                            "failed with error code %s",
                            node->head.nodeId, UA_StatusCode_name(retval));
    }

 cleanup:
    if(type)
        UA_NODESTORE_RELEASE(server, type);
    if(node)
        UA_NODESTORE_RELEASE(server, node);
    if(retval != UA_STATUSCODE_GOOD)
        deleteNode(server, *nodeId, true);
    return retval;
}

static void
Operation_addNode(UA_Server *server, UA_Session *session, void *nodeContext,
                  const UA_AddNodesItem *item, UA_AddNodesResult *result) {
    result->statusCode =
        Operation_addNode_begin(server, session, nodeContext,
                                item, &item->parentNodeId.nodeId,
                                &item->referenceTypeId, &result->addedNodeId);
    if(result->statusCode != UA_STATUSCODE_GOOD)
        return;

    
    result->statusCode = addNode_finish(server, session, &result->addedNodeId);

    
    if(result->statusCode != UA_STATUSCODE_GOOD)
        UA_NodeId_clear(&result->addedNodeId);
}

void
Service_AddNodes(UA_Server *server, UA_Session *session,
                 const UA_AddNodesRequest *request,
                 UA_AddNodesResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session, "Processing AddNodesRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(server->config.maxNodesPerNodeManagement != 0 &&
       request->nodesToAddSize > server->config.maxNodesPerNodeManagement) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_addNode, NULL,
                                           &request->nodesToAddSize,
                                           &UA_TYPES[UA_TYPES_ADDNODESITEM],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_ADDNODESRESULT]);
}

UA_StatusCode
addNode(UA_Server *server, const UA_NodeClass nodeClass, const UA_NodeId requestedNewNodeId,
        const UA_NodeId parentNodeId, const UA_NodeId referenceTypeId,
        const UA_QualifiedName browseName, const UA_NodeId typeDefinition,
        const void *attr, const UA_DataType *attributeType,
        void *nodeContext, UA_NodeId *outNewNodeId) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_AddNodesItem item;
    UA_AddNodesItem_init(&item);
    item.nodeClass = nodeClass;
    item.requestedNewNodeId.nodeId = requestedNewNodeId;
    item.browseName = browseName;
    item.parentNodeId.nodeId = parentNodeId;
    item.referenceTypeId = referenceTypeId;
    item.typeDefinition.nodeId = typeDefinition;
    UA_ExtensionObject_setValueNoDelete(&item.nodeAttributes,
                                        (void*)(uintptr_t)attr, attributeType);

    
    UA_AddNodesResult result;
    UA_AddNodesResult_init(&result);
    Operation_addNode(server, &server->adminSession, nodeContext, &item, &result);
    if(outNewNodeId)
        *outNewNodeId = result.addedNodeId;
    else
        UA_NodeId_clear(&result.addedNodeId);
    return result.statusCode;
}

UA_StatusCode
__UA_Server_addNode(UA_Server *server, const UA_NodeClass nodeClass,
                    const UA_NodeId *requestedNewNodeId,
                    const UA_NodeId *parentNodeId,
                    const UA_NodeId *referenceTypeId,
                    const UA_QualifiedName browseName,
                    const UA_NodeId *typeDefinition,
                    const UA_NodeAttributes *attr,
                    const UA_DataType *attributeType,
                    void *nodeContext, UA_NodeId *outNewNodeId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode reval =
        addNode(server, nodeClass, *requestedNewNodeId, *parentNodeId,
                *referenceTypeId, browseName, *typeDefinition, attr,
                attributeType, nodeContext, outNewNodeId);
    UA_UNLOCK(&server->serviceMutex);
    return reval;
}

UA_StatusCode
addNode_begin(UA_Server *server, const UA_NodeClass nodeClass,
              const UA_NodeId requestedNewNodeId, const UA_NodeId parentNodeId,
              const UA_NodeId referenceTypeId, const UA_QualifiedName browseName,
              const UA_NodeId typeDefinition, const void *attr,
              const UA_DataType *attributeType, void *nodeContext,
              UA_NodeId *outNewNodeId) {
    UA_AddNodesItem item;
    UA_AddNodesItem_init(&item);
    item.nodeClass = nodeClass;
    item.requestedNewNodeId.nodeId = requestedNewNodeId;
    item.browseName = browseName;
    item.typeDefinition.nodeId = typeDefinition;
    UA_ExtensionObject_setValueNoDelete(&item.nodeAttributes,
                                        (void*)(uintptr_t)attr, attributeType);
    return Operation_addNode_begin(server, &server->adminSession, nodeContext, &item,
                                   &parentNodeId, &referenceTypeId, outNewNodeId);
}

UA_StatusCode
UA_Server_addNode_begin(UA_Server *server, const UA_NodeClass nodeClass,
                        const UA_NodeId requestedNewNodeId, const UA_NodeId parentNodeId,
                        const UA_NodeId referenceTypeId, const UA_QualifiedName browseName,
                        const UA_NodeId typeDefinition, const void *attr,
                        const UA_DataType *attributeType, void *nodeContext,
                        UA_NodeId *outNewNodeId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res =
        addNode_begin(server, nodeClass, requestedNewNodeId, parentNodeId,
                      referenceTypeId, browseName, typeDefinition, attr,
                      attributeType, nodeContext, outNewNodeId);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

UA_StatusCode
UA_Server_addNode_finish(UA_Server *server, const UA_NodeId nodeId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = addNode_finish(server, &server->adminSession, &nodeId);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}





static void
Operation_deleteReference(UA_Server *server, UA_Session *session, void *context,
                          const UA_DeleteReferencesItem *item, UA_StatusCode *retval);

struct RemoveIncomingContext {
    UA_Server *server;
    UA_Session *session;
    UA_DeleteReferencesItem *item;
};

static void *
removeIncomingReferencesCallback(void *context, UA_ReferenceTarget *t) {
    struct RemoveIncomingContext *ctx = (struct RemoveIncomingContext *)context;
    if(!UA_NodePointer_isLocal(t->targetId))
        return NULL;
    UA_StatusCode dummy;
    ctx->item->sourceNodeId = UA_NodePointer_toNodeId(t->targetId);
    Operation_deleteReference(ctx->server, ctx->session, NULL, ctx->item, &dummy);
    return NULL;
}


static void
removeIncomingReferences(UA_Server *server, UA_Session *session,
                         const UA_NodeHead *head) {
    UA_DeleteReferencesItem item;
    UA_DeleteReferencesItem_init(&item);
    item.targetNodeId.nodeId = head->nodeId;
    item.deleteBidirectional = false;

    struct RemoveIncomingContext ctx;
    ctx.server = server;
    ctx.session = session;
    ctx.item = &item;

    for(size_t i = 0; i < head->referencesSize; ++i) {
        UA_NodeReferenceKind *rk = &head->references[i];
        item.isForward = rk->isInverse;
        item.referenceTypeId =
            *UA_NODESTORE_GETREFERENCETYPEID(server, rk->referenceTypeIndex);
        UA_NodeReferenceKind_iterate(rk, removeIncomingReferencesCallback, &ctx);
    }
}

static void *
checkTargetInRefTree(void *context, UA_ReferenceTarget *t) {
    RefTree *refTree = (RefTree*)context;
    if(!UA_NodePointer_isLocal(t->targetId))
        return NULL;
    UA_NodeId tmpId = UA_NodePointer_toNodeId(t->targetId);
    if(!RefTree_containsNodeId(refTree, &tmpId))
        return (void*)0x1;
    return NULL;
}


static UA_Boolean
hasParentRef(const UA_NodeHead *head, const UA_ReferenceTypeSet *refSet,
             RefTree *refTree) {
    for(size_t i = 0; i < head->referencesSize; i++) {
        UA_NodeReferenceKind *rk = &head->references[i];
        if(!rk->isInverse)
            continue;
        if(!UA_ReferenceTypeSet_contains(refSet, rk->referenceTypeIndex))
            continue;
        if(UA_NodeReferenceKind_iterate(rk, checkTargetInRefTree, refTree) != NULL)
            return true;
    }
    return false;
}

static void
deconstructNodeSet(UA_Server *server, UA_Session *session,
                   UA_ReferenceTypeSet *hierarchRefsSet, RefTree *refTree) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    for(size_t i = 0; i < refTree->size; i++) {
        const UA_Node *member = UA_NODESTORE_GET(server, &refTree->targets[i].nodeId);
        if(!member)
            continue;

        
        void *context = member->head.context; 
        if(member->head.nodeClass == UA_NODECLASS_OBJECT ||
           member->head.nodeClass == UA_NODECLASS_VARIABLE) {
            const UA_Node *type = getNodeType(server, &member->head);
            if(type) {
               
               const UA_NodeTypeLifecycle *lifecycle;
               if(member->head.nodeClass == UA_NODECLASS_OBJECT)
                  lifecycle = &type->objectTypeNode.lifecycle;
               else
                  lifecycle = &type->variableTypeNode.lifecycle;

               
               if(lifecycle->destructor) {
                  UA_UNLOCK(&server->serviceMutex);
                  lifecycle->destructor(server,
                                        &session->sessionId, session->context,
                                        &type->head.nodeId, type->head.context,
                                        &member->head.nodeId, &context);
                  UA_LOCK(&server->serviceMutex);
               }

               
               UA_NODESTORE_RELEASE(server, type);
            }
        }

        
        if(server->config.nodeLifecycle.destructor) {
            UA_UNLOCK(&server->serviceMutex);
            server->config.nodeLifecycle.destructor(server, &session->sessionId,
                                                    session->context,
                                                    &member->head.nodeId, context);
            UA_LOCK(&server->serviceMutex);
        }

        
        UA_NODESTORE_RELEASE(server, member);

        
        UA_Server_editNode(server, &server->adminSession, &refTree->targets[i].nodeId,
                           0, UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID,
                           (UA_EditNodeCallback)setDeconstructedNode, NULL);
    }
}

struct DeleteChildrenContext {
    UA_Server *server;
    const UA_ReferenceTypeSet *hierarchRefsSet;
    RefTree *refTree;
    UA_StatusCode res;
};

static void *
deleteChildrenCallback(void *context, UA_ReferenceTarget *t) {
    struct DeleteChildrenContext *ctx = (struct DeleteChildrenContext*)context;

    
    const UA_Node *child = UA_NODESTORE_GETFROMREF(ctx->server, t->targetId);
    if(!child)
        return NULL;

    
    if(!hasParentRef(&child->head, ctx->hierarchRefsSet, ctx->refTree))
        ctx->res = RefTree_addNodeId(ctx->refTree, &child->head.nodeId, NULL);

    UA_NODESTORE_RELEASE(ctx->server, child);
    return (ctx->res == UA_STATUSCODE_GOOD) ? NULL : (void*)0x01;
}

static UA_StatusCode
autoDeleteChildren(UA_Server *server, UA_Session *session, RefTree *refTree,
                   const UA_ReferenceTypeSet *hierarchRefsSet, const UA_NodeHead *head){
    struct DeleteChildrenContext ctx;
    ctx.server = server;
    ctx.hierarchRefsSet = hierarchRefsSet;
    ctx.refTree = refTree;
    ctx.res = UA_STATUSCODE_GOOD;

    for(size_t i = 0; i < head->referencesSize; ++i) {
        
        UA_NodeReferenceKind *rk = &head->references[i];
        if(!UA_ReferenceTypeSet_contains(hierarchRefsSet, rk->referenceTypeIndex))
            continue;

        
        if(rk->isInverse)
            continue;

        
        UA_NodeReferenceKind_iterate(rk, deleteChildrenCallback, &ctx);
        if(ctx.res != UA_STATUSCODE_GOOD)
            return ctx.res;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
buildDeleteNodeSet(UA_Server *server, UA_Session *session,
                   const UA_ReferenceTypeSet *hierarchRefsSet,
                   const UA_NodeId *initial, UA_Boolean removeTargetRefs,
                   RefTree *refTree) {
    
    UA_StatusCode res = RefTree_addNodeId(refTree, initial, NULL);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    size_t pos = 0;
    while(pos < refTree->size) {
        const UA_Node *member = UA_NODESTORE_GET(server, &refTree->targets[pos].nodeId);
        pos++;
        if(!member)
            continue;
        res |= autoDeleteChildren(server, session, refTree, hierarchRefsSet, &member->head);
        UA_NODESTORE_RELEASE(server, member);
    }
    return res;
}

static void
deleteNodeSet(UA_Server *server, UA_Session *session,
              const UA_ReferenceTypeSet *hierarchRefsSet,
              UA_Boolean removeTargetRefs, RefTree *refTree) {
    
    for(size_t i = refTree->size; i > 0; --i) {
        const UA_Node *member = UA_NODESTORE_GET(server, &refTree->targets[i-1].nodeId);
        if(!member)
            continue;
        UA_NODESTORE_RELEASE(server, member);
        if(removeTargetRefs)
            removeIncomingReferences(server, session, &member->head);
        UA_NODESTORE_REMOVE(server, &member->head.nodeId);
    }
}

static void
deleteNodeOperation(UA_Server *server, UA_Session *session, void *context,
                    const UA_DeleteNodesItem *item, UA_StatusCode *result) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(session != &server->adminSession && server->config.accessControl.allowDeleteNode) {
        UA_UNLOCK(&server->serviceMutex);
        if(!server->config.accessControl.
           allowDeleteNode(server, &server->config.accessControl,
                           &session->sessionId, session->context, item)) {
            UA_LOCK(&server->serviceMutex);
            *result = UA_STATUSCODE_BADUSERACCESSDENIED;
            return;
        }
        UA_LOCK(&server->serviceMutex);
    }

    const UA_Node *node = UA_NODESTORE_GET(server, &item->nodeId);
    if(!node) {
        *result = UA_STATUSCODE_BADNODEIDUNKNOWN;
        return;
    }

    if(UA_Node_hasSubTypeOrInstances(&node->head)) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "DeleteNode (%N): Cannot delete a type node with "
                            "active instances or subtypes", node->head.nodeId);
        UA_NODESTORE_RELEASE(server, node);
        *result = UA_STATUSCODE_BADINTERNALERROR;
        return;
    }

    
    

    
    UA_NODESTORE_RELEASE(server, node);

    UA_ReferenceTypeSet hierarchRefsSet;
    UA_NodeId hr = UA_NS0ID(HIERARCHICALREFERENCES);
    *result = referenceTypeIndices(server, &hr, &hierarchRefsSet, true);
    if(*result != UA_STATUSCODE_GOOD)
        return;

    RefTree refTree;
    *result = RefTree_init(&refTree);
    if(*result != UA_STATUSCODE_GOOD)
        return;
    *result = buildDeleteNodeSet(server, session, &hierarchRefsSet, &item->nodeId,
                                 item->deleteTargetReferences, &refTree);
    if(*result != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "DeleteNode: Incomplete lookup of nodes. "
                               "Still deleting what we have.");
    }

    
    deconstructNodeSet(server, session, &hierarchRefsSet, &refTree);
    deleteNodeSet(server, session, &hierarchRefsSet,
                  item->deleteTargetReferences, &refTree);
    RefTree_clear(&refTree);
}

void
Service_DeleteNodes(UA_Server *server, UA_Session *session,
                    const UA_DeleteNodesRequest *request,
                    UA_DeleteNodesResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing DeleteNodesRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(server->config.maxNodesPerNodeManagement != 0 &&
       request->nodesToDeleteSize > server->config.maxNodesPerNodeManagement) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)deleteNodeOperation,
                                           NULL, &request->nodesToDeleteSize,
                                           &UA_TYPES[UA_TYPES_DELETENODESITEM],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_STATUSCODE]);
}

UA_StatusCode
UA_Server_deleteNode(UA_Server *server, const UA_NodeId nodeId,
                     UA_Boolean deleteReferences) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = deleteNode(server, nodeId, deleteReferences);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}

UA_StatusCode
deleteNode(UA_Server *server, const UA_NodeId nodeId,
           UA_Boolean deleteReferences) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_DeleteNodesItem item;
    item.deleteTargetReferences = deleteReferences;
    item.nodeId = nodeId;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    deleteNodeOperation(server, &server->adminSession, NULL, &item, &retval);
    return retval;
}





static void
Operation_addReference(UA_Server *server, UA_Session *session, void *context,
                       const UA_AddReferencesItem *item, UA_StatusCode *retval) {
    (void)context;
    UA_assert(session);
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(session != &server->adminSession && server->config.accessControl.allowAddReference) {
        UA_UNLOCK(&server->serviceMutex);
        if (!server->config.accessControl.
                allowAddReference(server, &server->config.accessControl,
                                  &session->sessionId, session->context, item)) {
            UA_LOCK(&server->serviceMutex);
            *retval = UA_STATUSCODE_BADUSERACCESSDENIED;
            return;
        }
        UA_LOCK(&server->serviceMutex);
    }

    
    if(item->targetServerUri.length > 0) {
        *retval = UA_STATUSCODE_BADNOTIMPLEMENTED;
        return;
    }

    
    const UA_Node *refType = UA_NODESTORE_GET(server, &item->referenceTypeId);
    if(!refType) {
        UA_LOG_DEBUG_SESSION(server->config.logging, session,
                             "Cannot add reference - ReferenceType %N unknown",
                             item->referenceTypeId);
        *retval = UA_STATUSCODE_BADREFERENCETYPEIDINVALID;
        return;
    }
    if(refType->head.nodeClass != UA_NODECLASS_REFERENCETYPE) {
        UA_LOG_DEBUG_SESSION(server->config.logging, session,
                             "Cannot add reference - ReferenceType %N with wrong NodeClass",
                             item->referenceTypeId);
        UA_NODESTORE_RELEASE(server, refType);
        *retval = UA_STATUSCODE_BADREFERENCETYPEIDINVALID;
        return;
    }
    UA_Byte refTypeIndex = refType->referenceTypeNode.referenceTypeIndex;
    UA_NODESTORE_RELEASE(server, refType);

    UA_Node *targetNode = NULL;
    if(UA_ExpandedNodeId_isLocal(&item->targetNodeId)) {
        if(UA_NodeId_equal(&item->targetNodeId.nodeId, &item->sourceNodeId)) {
            *retval = UA_STATUSCODE_GOOD;
            UA_LOG_INFO_SESSION(server->config.logging, session,
                                "Cannot add reference - source and target %N are identical",
                                item->targetNodeId.nodeId);
            return;
        }
        targetNode =
            UA_NODESTORE_GET_EDIT_SELECTIVE(server, &item->targetNodeId.nodeId,
                                            UA_NODEATTRIBUTESMASK_BROWSENAME,
                                            UA_REFTYPESET(refTypeIndex),
                                            (!item->isForward) ?
                                            UA_BROWSEDIRECTION_FORWARD : UA_BROWSEDIRECTION_INVERSE);
        if(!targetNode) {
            UA_LOG_DEBUG_SESSION(server->config.logging, session,
                                 "Cannot add reference - target %N does not exist",
                                 item->targetNodeId.nodeId);
            *retval = UA_STATUSCODE_BADTARGETNODEIDINVALID;
            return;
        }
    }

    UA_Node *sourceNode =
        UA_NODESTORE_GET_EDIT_SELECTIVE(server, &item->sourceNodeId,
                                        UA_NODEATTRIBUTESMASK_BROWSENAME,
                                        UA_REFTYPESET(refTypeIndex),
                                        item->isForward ?
                                        UA_BROWSEDIRECTION_FORWARD : UA_BROWSEDIRECTION_INVERSE);
    if(!sourceNode) {
        if(targetNode)
            UA_NODESTORE_RELEASE(server, targetNode);
        *retval = UA_STATUSCODE_BADSOURCENODEIDINVALID;
        return;
    }

    
    UA_UInt32 targetNameHash = UA_QualifiedName_hash(&targetNode->head.browseName);
    *retval = UA_Node_addReference(sourceNode, refTypeIndex, item->isForward,
                                   &item->targetNodeId, targetNameHash);
    UA_Boolean firstExisted = false;
    if(*retval == UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED) {
        *retval = UA_STATUSCODE_GOOD;
        firstExisted = true;
    }
    if(*retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    if(targetNode) {
        UA_ExpandedNodeId expSourceId;
        UA_ExpandedNodeId_init(&expSourceId);
        expSourceId.nodeId = item->sourceNodeId;
        UA_UInt32 sourceNameHash = UA_QualifiedName_hash(&sourceNode->head.browseName);
        *retval = UA_Node_addReference(targetNode, refTypeIndex, !item->isForward,
                                       &expSourceId, sourceNameHash);

        
        if(*retval == UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED) {
            if(!firstExisted)
                *retval = UA_STATUSCODE_GOOD;
            goto cleanup;
        }

        
        if(*retval != UA_STATUSCODE_GOOD)
            UA_Node_deleteReference(sourceNode, refTypeIndex, item->isForward, &item->targetNodeId);
    }

 cleanup:
    if(targetNode)
        UA_NODESTORE_RELEASE(server, targetNode);
    UA_NODESTORE_RELEASE(server, sourceNode);
}

void
Service_AddReferences(UA_Server *server, UA_Session *session,
                      const UA_AddReferencesRequest *request,
                      UA_AddReferencesResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing AddReferencesRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_assert(session);

    if(server->config.maxNodesPerNodeManagement != 0 &&
       request->referencesToAddSize > server->config.maxNodesPerNodeManagement) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_addReference,
                                           NULL, &request->referencesToAddSize,
                                           &UA_TYPES[UA_TYPES_ADDREFERENCESITEM],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_STATUSCODE]);
}

UA_StatusCode
UA_Server_addReference(UA_Server *server, const UA_NodeId sourceId,
                       const UA_NodeId refTypeId,
                       const UA_ExpandedNodeId targetId,
                       UA_Boolean isForward) {
    UA_AddReferencesItem item;
    UA_AddReferencesItem_init(&item);
    item.sourceNodeId = sourceId;
    item.referenceTypeId = refTypeId;
    item.isForward = isForward;
    item.targetNodeId = targetId;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_LOCK(&server->serviceMutex);
    Operation_addReference(server, &server->adminSession, NULL, &item, &retval);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}





static void
Operation_deleteReference(UA_Server *server, UA_Session *session, void *context,
                          const UA_DeleteReferencesItem *item, UA_StatusCode *retval) {
    
    if(session != &server->adminSession &&
       server->config.accessControl.allowDeleteReference) {
        UA_LOCK_ASSERT(&server->serviceMutex, 1);
        UA_UNLOCK(&server->serviceMutex);
        if (!server->config.accessControl.
                allowDeleteReference(server, &server->config.accessControl,
                                     &session->sessionId, session->context, item)){
            UA_LOCK(&server->serviceMutex);
            *retval = UA_STATUSCODE_BADUSERACCESSDENIED;
            return;
        }
        UA_LOCK(&server->serviceMutex);
    }

    
    const UA_Node *refType =
        UA_NODESTORE_GET_SELECTIVE(server, &item->referenceTypeId,
                                   0, UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID);
    if(!refType) {
        *retval = UA_STATUSCODE_BADREFERENCETYPEIDINVALID;
        return;
    }

    if(refType->head.nodeClass != UA_NODECLASS_REFERENCETYPE) {
        UA_NODESTORE_RELEASE(server, refType);
        *retval = UA_STATUSCODE_BADREFERENCETYPEIDINVALID;
        return;
    }

    UA_Byte refTypeIndex = refType->referenceTypeNode.referenceTypeIndex;
    UA_NODESTORE_RELEASE(server, refType);

    // TODO: Check consistency constraints, remove the references.

    
    UA_Node *firstNode =
        UA_NODESTORE_GET_EDIT_SELECTIVE(server, &item->sourceNodeId, 0,
                                        UA_REFTYPESET(refTypeIndex),
                                        item->isForward ?
                                        UA_BROWSEDIRECTION_FORWARD : UA_BROWSEDIRECTION_INVERSE);
    if(firstNode) {
        *retval = UA_Node_deleteReference(firstNode, refTypeIndex, item->isForward, &item->targetNodeId);
    } else {
        *retval = UA_STATUSCODE_BADNODEIDUNKNOWN;
    }
    UA_NODESTORE_RELEASE(server, firstNode);
    if(*retval != UA_STATUSCODE_GOOD)
        return;

    if(!item->deleteBidirectional || item->targetNodeId.serverIndex != 0)
        return;

    
    if(UA_ExpandedNodeId_isLocal(&item->targetNodeId)) {
        UA_ExpandedNodeId target2;
        UA_ExpandedNodeId_init(&target2);
        target2.nodeId = item->sourceNodeId;
        UA_Node *secondNode =
            UA_NODESTORE_GET_EDIT_SELECTIVE(server, &item->targetNodeId.nodeId, 0,
                                            UA_REFTYPESET(refTypeIndex),
                                            (!item->isForward) ?
                                            UA_BROWSEDIRECTION_FORWARD : UA_BROWSEDIRECTION_INVERSE);
        if(secondNode) {
            *retval = UA_Node_deleteReference(secondNode, refTypeIndex, !item->isForward, &target2);
            UA_NODESTORE_RELEASE(server, secondNode);
        }
    }
}

void
Service_DeleteReferences(UA_Server *server, UA_Session *session,
                         const UA_DeleteReferencesRequest *request,
                         UA_DeleteReferencesResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing DeleteReferencesRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(server->config.maxNodesPerNodeManagement != 0 &&
       request->referencesToDeleteSize > server->config.maxNodesPerNodeManagement) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_deleteReference,
                                           NULL, &request->referencesToDeleteSize,
                                           &UA_TYPES[UA_TYPES_DELETEREFERENCESITEM],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_STATUSCODE]);
}

UA_StatusCode
deleteReference(UA_Server *server, const UA_NodeId sourceNodeId,
                const UA_NodeId referenceTypeId, UA_Boolean isForward,
                const UA_ExpandedNodeId targetNodeId,
                UA_Boolean deleteBidirectional) {
    UA_DeleteReferencesItem item;
    item.sourceNodeId = sourceNodeId;
    item.referenceTypeId = referenceTypeId;
    item.isForward = isForward;
    item.targetNodeId = targetNodeId;
    item.deleteBidirectional = deleteBidirectional;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    Operation_deleteReference(server, &server->adminSession, NULL, &item, &retval);
    return retval;
}

UA_StatusCode
UA_Server_deleteReference(UA_Server *server, const UA_NodeId sourceNodeId,
                          const UA_NodeId referenceTypeId, UA_Boolean isForward,
                          const UA_ExpandedNodeId targetNodeId,
                          UA_Boolean deleteBidirectional) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = deleteReference(server, sourceNodeId, referenceTypeId,
                                        isForward, targetNodeId, deleteBidirectional);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}





static UA_StatusCode
setValueCallback(UA_Server *server, UA_Session *session,
                 UA_VariableNode *node, const UA_ValueCallback *callback) {
    if(node->head.nodeClass != UA_NODECLASS_VARIABLE)
        return UA_STATUSCODE_BADNODECLASSINVALID;
    node->value.data.callback = *callback;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
setVariableNode_valueCallback(UA_Server *server, const UA_NodeId nodeId,
                              const UA_ValueCallback callback) {
    return UA_Server_editNode(server, &server->adminSession, &nodeId,
                              UA_NODEATTRIBUTESMASK_VALUE, UA_REFERENCETYPESET_NONE,
                              UA_BROWSEDIRECTION_INVALID,
                              (UA_EditNodeCallback)setValueCallback,
                              (UA_ValueCallback *)(uintptr_t) &callback);
}

UA_StatusCode
UA_Server_setVariableNode_valueCallback(UA_Server *server,
                                        const UA_NodeId nodeId,
                                        const UA_ValueCallback callback) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = UA_Server_editNode(server, &server->adminSession, &nodeId,
                                              UA_NODEATTRIBUTESMASK_VALUE, UA_REFERENCETYPESET_NONE,
                                              UA_BROWSEDIRECTION_INVALID,
                                              (UA_EditNodeCallback)setValueCallback,
                                              (UA_ValueCallback *)(uintptr_t) &callback);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}





UA_StatusCode
UA_Server_addDataSourceVariableNode(UA_Server *server, const UA_NodeId requestedNewNodeId,
                                    const UA_NodeId parentNodeId,
                                    const UA_NodeId referenceTypeId,
                                    const UA_QualifiedName browseName,
                                    const UA_NodeId typeDefinition,
                                    const UA_VariableAttributes attr,
                                    const UA_DataSource dataSource,
                                    void *nodeContext, UA_NodeId *outNewNodeId) {
    UA_AddNodesItem item;
    UA_AddNodesItem_init(&item);
    item.nodeClass = UA_NODECLASS_VARIABLE;
    item.requestedNewNodeId.nodeId = requestedNewNodeId;
    item.browseName = browseName;
    UA_ExpandedNodeId typeDefinitionId;
    UA_ExpandedNodeId_init(&typeDefinitionId);
    typeDefinitionId.nodeId = typeDefinition;
    item.typeDefinition = typeDefinitionId;
    UA_ExtensionObject_setValueNoDelete(&item.nodeAttributes, (void*)(uintptr_t)&attr,
                                        &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES]);
    UA_NodeId newNodeId;
    if(!outNewNodeId) {
        newNodeId = UA_NODEID_NULL;
        outNewNodeId = &newNodeId;
    }

    UA_LOCK(&server->serviceMutex);
    
    UA_StatusCode retval = addNode_raw(server, &server->adminSession, nodeContext,
                                       &item, outNewNodeId);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    retval = setVariableNode_dataSource(server, *outNewNodeId, dataSource);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    retval = addNode_addRefs(server, &server->adminSession, outNewNodeId, &parentNodeId,
                             &referenceTypeId, &typeDefinition);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    
    retval = addNode_finish(server, &server->adminSession, outNewNodeId);

 cleanup:
    UA_UNLOCK(&server->serviceMutex);
    if(outNewNodeId == &newNodeId)
        UA_NodeId_clear(&newNodeId);

    return retval;
}

static UA_StatusCode
setDataSource(UA_Server *server, UA_Session *session,
              UA_VariableNode *node, const UA_DataSource *dataSource) {
    if(node->head.nodeClass != UA_NODECLASS_VARIABLE)
        return UA_STATUSCODE_BADNODECLASSINVALID;
    if(node->valueSource == UA_VALUESOURCE_DATA)
        UA_DataValue_clear(&node->value.data.value);
    node->value.dataSource = *dataSource;
    node->valueSource = UA_VALUESOURCE_DATASOURCE;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
setVariableNode_dataSource(UA_Server *server, const UA_NodeId nodeId,
                           const UA_DataSource dataSource) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    return UA_Server_editNode(server, &server->adminSession, &nodeId,
                              UA_NODEATTRIBUTESMASK_VALUE, UA_REFERENCETYPESET_NONE,
                              UA_BROWSEDIRECTION_INVALID,
                              (UA_EditNodeCallback)setDataSource,
                              
                              (UA_DataSource *) (uintptr_t)&dataSource);
}

UA_StatusCode
UA_Server_setVariableNode_dataSource(UA_Server *server, const UA_NodeId nodeId,
                                     const UA_DataSource dataSource) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = setVariableNode_dataSource(server, nodeId, dataSource);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}




static UA_StatusCode
setExternalValueSource(UA_Server *server, UA_Session *session,
                 UA_VariableNode *node, const UA_ValueBackend *externalValueSource) {
    if(node->head.nodeClass != UA_NODECLASS_VARIABLE)
        return UA_STATUSCODE_BADNODECLASSINVALID;
    node->valueBackend.backendType = UA_VALUEBACKENDTYPE_EXTERNAL;
    node->valueBackend.backend.external.value =
        externalValueSource->backend.external.value;
    node->valueBackend.backend.external.callback.notificationRead =
        externalValueSource->backend.external.callback.notificationRead;
    node->valueBackend.backend.external.callback.userWrite =
        externalValueSource->backend.external.callback.userWrite;
    return UA_STATUSCODE_GOOD;
}




static UA_StatusCode
setDataSourceCallback(UA_Server *server, UA_Session *session,
                 UA_VariableNode *node, const UA_DataSource *dataSource) {
    if(node->head.nodeClass != UA_NODECLASS_VARIABLE)
        return UA_STATUSCODE_BADNODECLASSINVALID;
    node->valueBackend.backendType = UA_VALUEBACKENDTYPE_DATA_SOURCE_CALLBACK;
    node->valueBackend.backend.dataSource.read = dataSource->read;
    node->valueBackend.backend.dataSource.write = dataSource->write;
    return UA_STATUSCODE_GOOD;
}





UA_StatusCode
UA_Server_setVariableNode_valueBackend(UA_Server *server, const UA_NodeId nodeId,
                                       const UA_ValueBackend valueBackend){
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_LOCK(&server->serviceMutex);
    switch(valueBackend.backendType){
        case UA_VALUEBACKENDTYPE_NONE:
            UA_UNLOCK(&server->serviceMutex);
            return UA_STATUSCODE_BADCONFIGURATIONERROR;
        case UA_VALUEBACKENDTYPE_DATA_SOURCE_CALLBACK:
            retval = UA_Server_editNode(server, &server->adminSession, &nodeId,
                                        UA_NODEATTRIBUTESMASK_VALUE, UA_REFERENCETYPESET_NONE,
                                        UA_BROWSEDIRECTION_INVALID,
                                        (UA_EditNodeCallback) setDataSourceCallback,
                                        (UA_DataSource *)(uintptr_t) &valueBackend.backend.dataSource);
            break;
        case UA_VALUEBACKENDTYPE_INTERNAL:
            break;
        case UA_VALUEBACKENDTYPE_EXTERNAL:
            retval = UA_Server_editNode(server, &server->adminSession, &nodeId,
                                        UA_NODEATTRIBUTESMASK_VALUE, UA_REFERENCETYPESET_NONE,
                                        UA_BROWSEDIRECTION_INVALID,
                                        (UA_EditNodeCallback) setExternalValueSource,
                
                                        (UA_ValueCallback *)(uintptr_t) &valueBackend);
            break;
    }


    // UA_StatusCode retval = UA_Server_editNode(server, &server->adminSession, &nodeId,
    // (UA_EditNodeCallback)setValueCallback,
    
    // (UA_ValueCallback *)(uintptr_t) &callback);


    UA_UNLOCK(&server->serviceMutex);
    return retval;
}






#ifdef UA_ENABLE_METHODCALLS

static const UA_NodeId hasproperty = {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_HASPROPERTY}};
static const UA_NodeId propertytype = {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_PROPERTYTYPE}};

static UA_StatusCode
UA_Server_addMethodNodeEx_finish(UA_Server *server, const UA_NodeId nodeId,
                                 UA_MethodCallback method,
                                 const size_t inputArgumentsSize,
                                 const UA_Argument *inputArguments,
                                 const UA_NodeId inputArgumentsRequestedNewNodeId,
                                 UA_NodeId *inputArgumentsOutNewNodeId,
                                 const size_t outputArgumentsSize,
                                 const UA_Argument *outputArguments,
                                 const UA_NodeId outputArgumentsRequestedNewNodeId,
                                 UA_NodeId *outputArgumentsOutNewNodeId) {
    
    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = nodeId;
    bd.referenceTypeId = UA_NS0ID(HASPROPERTY);
    bd.includeSubtypes = false;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.nodeClassMask = UA_NODECLASS_VARIABLE;
    bd.resultMask = UA_BROWSERESULTMASK_BROWSENAME;

    UA_BrowseResult br;
    UA_BrowseResult_init(&br);
    UA_UInt32 maxrefs = 0;
    Operation_Browse(server, &server->adminSession, &maxrefs, &bd, &br);

    UA_StatusCode retval = br.statusCode;
    if(retval != UA_STATUSCODE_GOOD) {
        deleteNode(server, nodeId, true);
        UA_BrowseResult_clear(&br);
        return retval;
    }

    
    UA_NodeId inputArgsId = UA_NODEID_NULL;
    UA_NodeId outputArgsId = UA_NODEID_NULL;
    const UA_QualifiedName inputArgsName = UA_QUALIFIEDNAME(0, "InputArguments");
    const UA_QualifiedName outputArgsName = UA_QUALIFIEDNAME(0, "OutputArguments");
    for(size_t i = 0; i < br.referencesSize; i++) {
        UA_ReferenceDescription *rd = &br.references[i];
        if(rd->browseName.namespaceIndex == 0 &&
           UA_String_equal(&rd->browseName.name, &inputArgsName.name))
            inputArgsId = rd->nodeId.nodeId;
        else if(rd->browseName.namespaceIndex == 0 &&
                UA_String_equal(&rd->browseName.name, &outputArgsName.name))
            outputArgsId = rd->nodeId.nodeId;
    }

    
    if(inputArgumentsSize > 0 && UA_NodeId_isNull(&inputArgsId)) {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        char *name = "InputArguments";
        attr.displayName = UA_LOCALIZEDTEXT("", name);
        attr.dataType = UA_TYPES[UA_TYPES_ARGUMENT].typeId;
        attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
        UA_UInt32 inputArgsSize32 = (UA_UInt32)inputArgumentsSize;
        attr.arrayDimensions = &inputArgsSize32;
        attr.arrayDimensionsSize = 1;
        UA_Variant_setArray(&attr.value, (void *)(uintptr_t)inputArguments,
                            inputArgumentsSize, &UA_TYPES[UA_TYPES_ARGUMENT]);
        retval = addNode(server, UA_NODECLASS_VARIABLE, inputArgumentsRequestedNewNodeId,
                         nodeId, hasproperty, UA_QUALIFIEDNAME(0, name),
                         propertytype, &attr, &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES],
                         NULL, &inputArgsId);
        if(retval != UA_STATUSCODE_GOOD)
            goto error;
    }

    
    if(outputArgumentsSize > 0 && UA_NodeId_isNull(&outputArgsId)) {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        char *name = "OutputArguments";
        attr.displayName = UA_LOCALIZEDTEXT("", name);
        attr.dataType = UA_TYPES[UA_TYPES_ARGUMENT].typeId;
        attr.valueRank = UA_VALUERANK_ONE_DIMENSION;
        UA_UInt32 outputArgsSize32 = (UA_UInt32)outputArgumentsSize;
        attr.arrayDimensions = &outputArgsSize32;
        attr.arrayDimensionsSize = 1;
        UA_Variant_setArray(&attr.value, (void *)(uintptr_t)outputArguments,
                            outputArgumentsSize, &UA_TYPES[UA_TYPES_ARGUMENT]);
        retval = addNode(server, UA_NODECLASS_VARIABLE, outputArgumentsRequestedNewNodeId,
                         nodeId, hasproperty, UA_QUALIFIEDNAME(0, name),
                         propertytype, &attr, &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES],
                         NULL, &outputArgsId);
        if(retval != UA_STATUSCODE_GOOD)
            goto error;
    }

    retval = setMethodNode_callback(server, nodeId, method);
    if(retval != UA_STATUSCODE_GOOD)
        goto error;

    
    retval = addNode_finish(server, &server->adminSession, &nodeId);
    if(retval != UA_STATUSCODE_GOOD)
        goto error;

    if(inputArgumentsOutNewNodeId != NULL) {
        UA_NodeId_copy(&inputArgsId, inputArgumentsOutNewNodeId);
    }
    if(outputArgumentsOutNewNodeId != NULL) {
        UA_NodeId_copy(&outputArgsId, outputArgumentsOutNewNodeId);
    }
    UA_BrowseResult_clear(&br);
    return retval;

error:
    deleteNode(server, nodeId, true);
    deleteNode(server, inputArgsId, true);
    deleteNode(server, outputArgsId, true);
    UA_BrowseResult_clear(&br);
    return retval;
}

UA_StatusCode
UA_Server_addMethodNode_finish(UA_Server *server, const UA_NodeId nodeId,
                               UA_MethodCallback method,
                               size_t inputArgumentsSize,
                               const UA_Argument* inputArguments,
                               size_t outputArgumentsSize,
                               const UA_Argument* outputArguments) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval =
        UA_Server_addMethodNodeEx_finish(server, nodeId, method,
                                         inputArgumentsSize, inputArguments,
                                         UA_NODEID_NULL, NULL,
                                         outputArgumentsSize, outputArguments,
                                         UA_NODEID_NULL, NULL);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}

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
              void *nodeContext, UA_NodeId *outNewNodeId) {
    UA_AddNodesItem item;
    UA_AddNodesItem_init(&item);
    item.nodeClass = UA_NODECLASS_METHOD;
    item.requestedNewNodeId.nodeId = requestedNewNodeId;
    item.browseName = browseName;
    UA_ExtensionObject_setValueNoDelete(&item.nodeAttributes, (void*)(uintptr_t)attr,
                                        &UA_TYPES[UA_TYPES_METHODATTRIBUTES]);
    UA_NodeId newId;
    if(!outNewNodeId) {
        UA_NodeId_init(&newId);
        outNewNodeId = &newId;
    }
    UA_StatusCode retval = Operation_addNode_begin(server, &server->adminSession,
                                                   nodeContext, &item, &parentNodeId,
                                                   &referenceTypeId, outNewNodeId);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_Server_addMethodNodeEx_finish(server, *outNewNodeId, method,
                                              inputArgumentsSize, inputArguments,
                                              inputArgumentsRequestedNewNodeId,
                                              inputArgumentsOutNewNodeId,
                                              outputArgumentsSize, outputArguments,
                                              outputArgumentsRequestedNewNodeId,
                                              outputArgumentsOutNewNodeId);
    if(outNewNodeId == &newId)
        UA_NodeId_clear(&newId);
    return retval;
}

UA_StatusCode
UA_Server_addMethodNodeEx(UA_Server *server, const UA_NodeId requestedNewNodeId,
                          const UA_NodeId parentNodeId,
                          const UA_NodeId referenceTypeId,
                          const UA_QualifiedName browseName,
                          const UA_MethodAttributes attr, UA_MethodCallback method,
                          size_t inputArgumentsSize, const UA_Argument *inputArguments,
                          const UA_NodeId inputArgumentsRequestedNewNodeId,
                          UA_NodeId *inputArgumentsOutNewNodeId,
                          size_t outputArgumentsSize, const UA_Argument *outputArguments,
                          const UA_NodeId outputArgumentsRequestedNewNodeId,
                          UA_NodeId *outputArgumentsOutNewNodeId,
                          void *nodeContext, UA_NodeId *outNewNodeId) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = addMethodNode(server, requestedNewNodeId,
                                      parentNodeId, referenceTypeId,
                                      browseName, &attr, method,
                                      inputArgumentsSize, inputArguments,
                                      inputArgumentsRequestedNewNodeId,
                                      inputArgumentsOutNewNodeId,
                                      outputArgumentsSize,
                                      outputArguments,
                                      outputArgumentsRequestedNewNodeId,
                                      outputArgumentsOutNewNodeId,
                                      nodeContext, outNewNodeId);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}

static UA_StatusCode
editMethodCallback(UA_Server *server, UA_Session* session,
                   UA_Node *node, UA_MethodCallback methodCallback) {
    if(node->head.nodeClass != UA_NODECLASS_METHOD)
        return UA_STATUSCODE_BADNODECLASSINVALID;
    node->methodNode.method = methodCallback;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
setMethodNode_callback(UA_Server *server,
                       const UA_NodeId methodNodeId,
                       UA_MethodCallback methodCallback) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    return UA_Server_editNode(server, &server->adminSession, &methodNodeId,
                              0, UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID,
                              (UA_EditNodeCallback)editMethodCallback,
                              (void*)(uintptr_t)methodCallback);
}

UA_StatusCode
UA_Server_setMethodNodeCallback(UA_Server *server,
                                const UA_NodeId methodNodeId,
                                UA_MethodCallback methodCallback) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retVal = setMethodNode_callback(server, methodNodeId, methodCallback);
    UA_UNLOCK(&server->serviceMutex);
    return retVal;
}

UA_StatusCode
UA_Server_getMethodNodeCallback(UA_Server *server,
                                const UA_NodeId methodNodeId,
                                UA_MethodCallback *outMethodCallback) {
    UA_LOCK(&server->serviceMutex);
    const UA_Node *node = UA_NODESTORE_GET(server, &methodNodeId);
    if(!node) {
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    }

    if(node->head.nodeClass != UA_NODECLASS_METHOD) {
        UA_NODESTORE_RELEASE(server, node);
        UA_UNLOCK(&server->serviceMutex);
        return UA_STATUSCODE_BADNODECLASSINVALID;
    }

    *outMethodCallback = node->methodNode.method;
    UA_NODESTORE_RELEASE(server, node);
    UA_UNLOCK(&server->serviceMutex);
    return UA_STATUSCODE_GOOD;
}

#endif





void UA_EXPORT
UA_Server_setAdminSessionContext(UA_Server *server,
                                 void *context) {
    server->adminSession.context = context;
}

static UA_StatusCode
setNodeTypeLifecycleCallback(UA_Server *server, UA_Session *session,
                             UA_Node *node, UA_NodeTypeLifecycle *lifecycle) {
    if(node->head.nodeClass == UA_NODECLASS_OBJECTTYPE) {
        node->objectTypeNode.lifecycle = *lifecycle;
    } else if(node->head.nodeClass == UA_NODECLASS_VARIABLETYPE) {
        node->variableTypeNode.lifecycle = *lifecycle;
    } else {
        return UA_STATUSCODE_BADNODECLASSINVALID;
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
setNodeTypeLifecycle(UA_Server *server, UA_NodeId nodeId,
                     UA_NodeTypeLifecycle lifecycle) {
    return UA_Server_editNode(server, &server->adminSession, &nodeId,
                              0, UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID,
                              (UA_EditNodeCallback)setNodeTypeLifecycleCallback,
                              &lifecycle);
}

UA_StatusCode
UA_Server_setNodeTypeLifecycle(UA_Server *server, UA_NodeId nodeId,
                               UA_NodeTypeLifecycle lifecycle) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = setNodeTypeLifecycle(server, nodeId, lifecycle);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}
