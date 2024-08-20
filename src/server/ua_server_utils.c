
#include "ua_server_internal.h"

const UA_DataType *
UA_Server_findDataType(UA_Server *server, const UA_NodeId *typeId) {
    return UA_findDataTypeWithCustom(typeId, server->config.customDataTypes);
}





static void *
returnFirstType(void *context, UA_ReferenceTarget *t) {
    UA_Server *server = (UA_Server*)context;
    return (void*)(uintptr_t)UA_NODESTORE_GETFROMREF(server, t->targetId);
}

const UA_Node *
getNodeType(UA_Server *server, const UA_NodeHead *head) {
    
    UA_Byte parentRefIndex;
    UA_Boolean inverse;
    switch(head->nodeClass) {
    case UA_NODECLASS_OBJECT:
        parentRefIndex = UA_REFERENCETYPEINDEX_HASTYPEDEFINITION;
        inverse = false;
        break;
    case UA_NODECLASS_VARIABLE:
        parentRefIndex = UA_REFERENCETYPEINDEX_HASTYPEDEFINITION;
        inverse = false;
        break;
    case UA_NODECLASS_OBJECTTYPE:
    case UA_NODECLASS_VARIABLETYPE:
    case UA_NODECLASS_REFERENCETYPE:
    case UA_NODECLASS_DATATYPE:
        parentRefIndex = UA_REFERENCETYPEINDEX_HASSUBTYPE;
        inverse = true;
        break;
    default:
        return NULL;
    }

    
    for(size_t i = 0; i < head->referencesSize; ++i) {
        UA_NodeReferenceKind *rk = &head->references[i];
        if(rk->isInverse != inverse)
            continue;
        if(rk->referenceTypeIndex != parentRefIndex)
            continue;
        const UA_Node *type = (const UA_Node*)
            UA_NodeReferenceKind_iterate(rk, returnFirstType, server);
        if(type)
            return type;
    }

    return NULL;
}

UA_Boolean
UA_Node_hasSubTypeOrInstances(const UA_NodeHead *head) {
    for(size_t i = 0; i < head->referencesSize; ++i) {
        if(head->references[i].isInverse == false &&
           head->references[i].referenceTypeIndex == UA_REFERENCETYPEINDEX_HASSUBTYPE)
            return true;
        if(head->references[i].isInverse == true &&
           head->references[i].referenceTypeIndex == UA_REFERENCETYPEINDEX_HASTYPEDEFINITION)
            return true;
    }
    return false;
}

UA_StatusCode
getParentTypeAndInterfaceHierarchy(UA_Server *server, const UA_NodeId *typeNode,
                                   UA_NodeId **typeHierarchy, size_t *typeHierarchySize) {
    UA_ReferenceTypeSet reftypes_subtype =
        UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASSUBTYPE);
    UA_ExpandedNodeId *subTypes = NULL;
    size_t subTypesSize = 0;
    UA_StatusCode retval = browseRecursive(server, 1, typeNode,
                                           UA_BROWSEDIRECTION_INVERSE,
                                           &reftypes_subtype, UA_NODECLASS_UNSPECIFIED,
                                           false, &subTypesSize, &subTypes);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_assert(subTypesSize < 1000);

    UA_ReferenceTypeSet reftypes_interface =
        UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASINTERFACE);
    UA_ExpandedNodeId *interfaces = NULL;
    size_t interfacesSize = 0;
    retval = browseRecursive(server, 1, typeNode, UA_BROWSEDIRECTION_FORWARD,
                             &reftypes_interface, UA_NODECLASS_UNSPECIFIED,
                             false, &interfacesSize, &interfaces);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Array_delete(subTypes, subTypesSize, &UA_TYPES[UA_TYPES_NODEID]);
        return retval;
    }

    UA_assert(interfacesSize < 1000);

    UA_NodeId *hierarchy = (UA_NodeId*)
        UA_malloc(sizeof(UA_NodeId) * (1 + subTypesSize + interfacesSize));
    if(!hierarchy) {
        UA_Array_delete(subTypes, subTypesSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
        UA_Array_delete(interfaces, interfacesSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    retval = UA_NodeId_copy(typeNode, hierarchy);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(hierarchy);
        UA_Array_delete(subTypes, subTypesSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
        UA_Array_delete(interfaces, interfacesSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    for(size_t i = 0; i < subTypesSize; i++) {
        hierarchy[i+1] = subTypes[i].nodeId;
        UA_NodeId_init(&subTypes[i].nodeId);
    }
    for(size_t i = 0; i < interfacesSize; i++) {
        hierarchy[i+1+subTypesSize] = interfaces[i].nodeId;
        UA_NodeId_init(&interfaces[i].nodeId);
    }

    *typeHierarchy = hierarchy;
    *typeHierarchySize = subTypesSize + interfacesSize + 1;

    UA_assert(*typeHierarchySize < 1000);

    UA_Array_delete(subTypes, subTypesSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
    UA_Array_delete(interfaces, interfacesSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
getAllInterfaceChildNodeIds(UA_Server *server, const UA_NodeId *objectNode,
                            const UA_NodeId *objectTypeNode,
                            UA_NodeId **interfaceChildNodes,
                            size_t *interfaceChildNodesSize) {
    if(interfaceChildNodesSize == NULL || interfaceChildNodes == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;
    *interfaceChildNodesSize = 0;
    *interfaceChildNodes = NULL;

    UA_ExpandedNodeId *hasInterfaceCandidates = NULL;
    size_t hasInterfaceCandidatesSize = 0;
    UA_ReferenceTypeSet reftypes_subtype =
        UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASSUBTYPE);

    UA_StatusCode retval =
        browseRecursive(server, 1, objectTypeNode, UA_BROWSEDIRECTION_INVERSE,
                        &reftypes_subtype, UA_NODECLASS_OBJECTTYPE,
                        true, &hasInterfaceCandidatesSize,
                        &hasInterfaceCandidates);

    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_ExpandedNodeId *resizedHasInterfaceCandidates = (UA_ExpandedNodeId*)
        UA_realloc(hasInterfaceCandidates,
                   (hasInterfaceCandidatesSize + 1) * sizeof(UA_ExpandedNodeId));

    if(!resizedHasInterfaceCandidates) {
        if(hasInterfaceCandidates)
            UA_Array_delete(hasInterfaceCandidates, hasInterfaceCandidatesSize,
                            &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    hasInterfaceCandidates = resizedHasInterfaceCandidates;
    hasInterfaceCandidatesSize += 1;
    UA_ExpandedNodeId_init(&hasInterfaceCandidates[hasInterfaceCandidatesSize - 1]);

    UA_ExpandedNodeId_init(&hasInterfaceCandidates[hasInterfaceCandidatesSize - 1]);
    UA_NodeId_copy(objectNode, &hasInterfaceCandidates[hasInterfaceCandidatesSize - 1].nodeId);

    size_t outputIndex = 0;

    for(size_t i = 0; i < hasInterfaceCandidatesSize; ++i) {
        UA_ReferenceTypeSet reftypes_interface =
            UA_REFTYPESET(UA_REFERENCETYPEINDEX_HASINTERFACE);
        UA_ExpandedNodeId *interfaceChildren = NULL;
        size_t interfacesChildrenSize = 0;
        retval = browseRecursive(server, 1, &hasInterfaceCandidates[i].nodeId,
                                 UA_BROWSEDIRECTION_FORWARD,
                                 &reftypes_interface, UA_NODECLASS_OBJECTTYPE,
                                 false, &interfacesChildrenSize, &interfaceChildren);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_Array_delete(hasInterfaceCandidates, hasInterfaceCandidatesSize,
                            &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
            if(*interfaceChildNodesSize) {
                UA_Array_delete(*interfaceChildNodes, *interfaceChildNodesSize,
                                &UA_TYPES[UA_TYPES_NODEID]);
                *interfaceChildNodesSize = 0;
            }
            return retval;
        }

        UA_assert(interfacesChildrenSize < 1000);

        if(interfacesChildrenSize == 0) {
            continue;
        }

        if(!*interfaceChildNodes) {
            *interfaceChildNodes = (UA_NodeId*)
                UA_calloc(interfacesChildrenSize, sizeof(UA_NodeId));
            *interfaceChildNodesSize = interfacesChildrenSize;

            if(!*interfaceChildNodes) {
                UA_Array_delete(interfaceChildren, interfacesChildrenSize,
                                &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
                UA_Array_delete(hasInterfaceCandidates, hasInterfaceCandidatesSize,
                                &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
                return UA_STATUSCODE_BADOUTOFMEMORY;
            }
        } else {
            UA_NodeId *resizedInterfaceChildNodes = (UA_NodeId*)
                UA_realloc(*interfaceChildNodes,
                           ((*interfaceChildNodesSize + interfacesChildrenSize) * sizeof(UA_NodeId)));

            if(!resizedInterfaceChildNodes) {
                UA_Array_delete(hasInterfaceCandidates, hasInterfaceCandidatesSize,
                                &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
                UA_Array_delete(interfaceChildren, interfacesChildrenSize,
                                &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
                return UA_STATUSCODE_BADOUTOFMEMORY;
            }

            const size_t oldSize = *interfaceChildNodesSize;
            *interfaceChildNodesSize += interfacesChildrenSize;
            *interfaceChildNodes = resizedInterfaceChildNodes;

            for(size_t j = oldSize; j < *interfaceChildNodesSize; ++j)
                UA_NodeId_init(&(*interfaceChildNodes)[j]);
        }

        for(size_t j = 0; j < interfacesChildrenSize; j++) {
            (*interfaceChildNodes)[outputIndex++] = interfaceChildren[j].nodeId;
        }

        UA_assert(*interfaceChildNodesSize < 1000);
        UA_Array_delete(interfaceChildren, interfacesChildrenSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
    }

    UA_Array_delete(hasInterfaceCandidates, hasInterfaceCandidatesSize, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);

    return UA_STATUSCODE_GOOD;
}


UA_StatusCode
UA_Server_editNode(UA_Server *server, UA_Session *session, const UA_NodeId *nodeId,
                   UA_UInt32 attributeMask, UA_ReferenceTypeSet references,
                   UA_BrowseDirection referenceDirections,
                   UA_EditNodeCallback callback, void *data) {
    UA_Node *node =
        UA_NODESTORE_GET_EDIT_SELECTIVE(server, nodeId, attributeMask,
                                        references, referenceDirections);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    UA_StatusCode retval = callback(server, session, node, data);
    UA_NODESTORE_RELEASE(server, node);
    return retval;
}

UA_StatusCode
UA_Server_processServiceOperations(UA_Server *server, UA_Session *session,
                                   UA_ServiceOperation operationCallback,
                                   const void *context, const size_t *requestOperations,
                                   const UA_DataType *requestOperationsType,
                                   size_t *responseOperations,
                                   const UA_DataType *responseOperationsType) {
    size_t ops = *requestOperations;
    if(ops == 0)
        return UA_STATUSCODE_BADNOTHINGTODO;

    
    void **respPos = (void**)((uintptr_t)responseOperations + sizeof(size_t));
    *respPos = UA_Array_new(ops, responseOperationsType);
    if(!(*respPos))
        return UA_STATUSCODE_BADOUTOFMEMORY;

    *responseOperations = ops;
    uintptr_t respOp = (uintptr_t)*respPos;
    
    uintptr_t reqOp = *(uintptr_t*)((uintptr_t)requestOperations + sizeof(size_t));
    for(size_t i = 0; i < ops; i++) {
        operationCallback(server, session, context, (void*)reqOp, (void*)respOp);
        reqOp += requestOperationsType->memSize;
        respOp += responseOperationsType->memSize;
    }
    return UA_STATUSCODE_GOOD;
}


const UA_NodeId subtypeId = {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_HASSUBTYPE}};
const UA_NodeId hierarchicalReferences = {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_HIERARCHICALREFERENCES}};





const UA_ObjectAttributes UA_ObjectAttributes_default = {
    0,                      
    {{0, NULL}, {0, NULL}}, 
    {{0, NULL}, {0, NULL}}, 
    0, 0,                   
    0                       
};

const UA_VariableAttributes UA_VariableAttributes_default = {
    0,                           
    {{0, NULL}, {0, NULL}},      
    {{0, NULL}, {0, NULL}},      
    0, 0,                        
    {NULL, UA_VARIANT_DATA,
     0, NULL, 0, NULL},          
    {0, UA_NODEIDTYPE_NUMERIC,
     {UA_NS0ID_BASEDATATYPE}},   
    UA_VALUERANK_ANY,            
    0, NULL,                     
    UA_ACCESSLEVELMASK_READ |    
    UA_ACCESSLEVELMASK_STATUSWRITE |
    UA_ACCESSLEVELMASK_TIMESTAMPWRITE,
    0,                           
    0.0,                         
    false                        
};

const UA_MethodAttributes UA_MethodAttributes_default = {
    0,                      
    {{0, NULL}, {0, NULL}}, 
    {{0, NULL}, {0, NULL}}, 
    0, 0,                   
    true, true              
};

const UA_ObjectTypeAttributes UA_ObjectTypeAttributes_default = {
    0,                      
    {{0, NULL}, {0, NULL}}, 
    {{0, NULL}, {0, NULL}}, 
    0, 0,                   
    false                   
};

const UA_VariableTypeAttributes UA_VariableTypeAttributes_default = {
    0,                           
    {{0, NULL}, {0, NULL}},      
    {{0, NULL}, {0, NULL}},      
    0, 0,                        
    {NULL, UA_VARIANT_DATA,
     0, NULL, 0, NULL},          
    {0, UA_NODEIDTYPE_NUMERIC,
     {UA_NS0ID_BASEDATATYPE}},   
    UA_VALUERANK_ANY,            
    0, NULL,                     
    false                        
};

const UA_ReferenceTypeAttributes UA_ReferenceTypeAttributes_default = {
    0,                      
    {{0, NULL}, {0, NULL}}, 
    {{0, NULL}, {0, NULL}}, 
    0, 0,                   
    false,                  
    false,                  
    {{0, NULL}, {0, NULL}}  
};

const UA_DataTypeAttributes UA_DataTypeAttributes_default = {
    0,                      
    {{0, NULL}, {0, NULL}}, 
    {{0, NULL}, {0, NULL}}, 
    0, 0,                   
    false                   
};

const UA_ViewAttributes UA_ViewAttributes_default = {
    0,                      
    {{0, NULL}, {0, NULL}}, 
    {{0, NULL}, {0, NULL}}, 
    0, 0,                   
    false,                  
    0                       
};

