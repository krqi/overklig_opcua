
#include "ua_server_internal.h"
#include "ua_types_encoding_binary.h"
#include "ua_services.h"

#ifdef UA_ENABLE_HISTORIZING
#include <opcua/plugin/historydatabase.h>
#endif

static const UA_NodeAttributesMask attr2mask[28] = {
    UA_NODEATTRIBUTESMASK_NODEID,
    UA_NODEATTRIBUTESMASK_NODECLASS,
    UA_NODEATTRIBUTESMASK_BROWSENAME,
    UA_NODEATTRIBUTESMASK_DISPLAYNAME,
    UA_NODEATTRIBUTESMASK_DESCRIPTION,
    UA_NODEATTRIBUTESMASK_WRITEMASK,
    UA_NODEATTRIBUTESMASK_USERWRITEMASK,
    UA_NODEATTRIBUTESMASK_ISABSTRACT,
    UA_NODEATTRIBUTESMASK_SYMMETRIC,
    UA_NODEATTRIBUTESMASK_INVERSENAME,
    UA_NODEATTRIBUTESMASK_CONTAINSNOLOOPS,
    UA_NODEATTRIBUTESMASK_EVENTNOTIFIER,
    UA_NODEATTRIBUTESMASK_VALUE,
    UA_NODEATTRIBUTESMASK_DATATYPE,
    UA_NODEATTRIBUTESMASK_VALUERANK,
    UA_NODEATTRIBUTESMASK_ARRAYDIMENSIONS,
    UA_NODEATTRIBUTESMASK_ACCESSLEVEL,
    UA_NODEATTRIBUTESMASK_USERACCESSLEVEL,
    UA_NODEATTRIBUTESMASK_MINIMUMSAMPLINGINTERVAL,
    UA_NODEATTRIBUTESMASK_HISTORIZING,
    UA_NODEATTRIBUTESMASK_EXECUTABLE,
    UA_NODEATTRIBUTESMASK_USEREXECUTABLE,
    UA_NODEATTRIBUTESMASK_DATATYPEDEFINITION,
    UA_NODEATTRIBUTESMASK_ROLEPERMISSIONS,
    UA_NODEATTRIBUTESMASK_ROLEPERMISSIONS,
    UA_NODEATTRIBUTESMASK_ACCESSRESTRICTIONS,
    UA_NODEATTRIBUTESMASK_ACCESSLEVEL
};

static UA_UInt32
attributeId2AttributeMask(UA_AttributeId id) {
    if(UA_UNLIKELY(id > UA_ATTRIBUTEID_ACCESSLEVELEX))
        return UA_NODEATTRIBUTESMASK_NONE;
    return attr2mask[id];
}






static UA_UInt32
getUserWriteMask(UA_Server *server, const UA_Session *session,
                 const UA_NodeHead *head) {
    if(session == &server->adminSession)
        return 0xFFFFFFFF; 
    UA_UInt32 mask = head->writeMask;
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_UNLOCK(&server->serviceMutex);
    mask &= server->config.accessControl.
        getUserRightsMask(server, &server->config.accessControl,
                          session ? &session->sessionId : NULL,
                          session ? session->context : NULL,
                          &head->nodeId, head->context);
    UA_LOCK(&server->serviceMutex);
    return mask;
}

static UA_Byte
getUserAccessLevel(UA_Server *server, const UA_Session *session,
                   const UA_VariableNode *node) {
    if(session == &server->adminSession)
        return 0xFF; 
    UA_Byte retval = node->accessLevel;
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_UNLOCK(&server->serviceMutex);
    retval &= server->config.accessControl.
        getUserAccessLevel(server, &server->config.accessControl,
                           session ? &session->sessionId : NULL,
                           session ? session->context : NULL,
                           &node->head.nodeId, node->head.context);
    UA_LOCK(&server->serviceMutex);
    return retval;
}

static UA_Boolean
getUserExecutable(UA_Server *server, const UA_Session *session,
                  const UA_MethodNode *node) {
    if(session == &server->adminSession)
        return true; 
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_UNLOCK(&server->serviceMutex);
    UA_Boolean userExecutable = node->executable;
    userExecutable &=
        server->config.accessControl.
        getUserExecutable(server, &server->config.accessControl,
                          session ? &session->sessionId : NULL,
                          session ? session->context : NULL,
                          &node->head.nodeId, node->head.context);
    UA_LOCK(&server->serviceMutex);
    return userExecutable;
}





static UA_StatusCode
readIsAbstractAttribute(const UA_Node *node, UA_Variant *v) {
    const UA_Boolean *isAbstract;
    switch(node->head.nodeClass) {
    case UA_NODECLASS_REFERENCETYPE:
        isAbstract = &node->referenceTypeNode.isAbstract;
        break;
    case UA_NODECLASS_OBJECTTYPE:
        isAbstract = &node->objectTypeNode.isAbstract;
        break;
    case UA_NODECLASS_VARIABLETYPE:
        isAbstract = &node->variableTypeNode.isAbstract;
        break;
    case UA_NODECLASS_DATATYPE:
        isAbstract = &node->dataTypeNode.isAbstract;
        break;
    default:
        return UA_STATUSCODE_BADATTRIBUTEIDINVALID;
    }

    return UA_Variant_setScalarCopy(v, isAbstract, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_StatusCode
readValueAttributeFromNode(UA_Server *server, UA_Session *session,
                           const UA_VariableNode *vn, UA_DataValue *v,
                           UA_NumericRange *rangeptr) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    
    if(vn->value.data.callback.onRead) {
        UA_UNLOCK(&server->serviceMutex);
        vn->value.data.callback.onRead(server,
                                       session ? &session->sessionId : NULL,
                                       session ? session->context : NULL,
                                       &vn->head.nodeId, vn->head.context, rangeptr,
                                       &vn->value.data.value);
        UA_LOCK(&server->serviceMutex);
        vn = (const UA_VariableNode*)
            UA_NODESTORE_GET_SELECTIVE(server, &vn->head.nodeId,
                                       UA_NODEATTRIBUTESMASK_VALUE,
                                       UA_REFERENCETYPESET_NONE,
                                       UA_BROWSEDIRECTION_INVALID);
        if(!vn)
            return UA_STATUSCODE_BADNODEIDUNKNOWN;
    }

    
    UA_StatusCode retval;
    if(!rangeptr) {
        retval = UA_DataValue_copy(&vn->value.data.value, v);
    } else {
        *v = vn->value.data.value; 
        UA_Variant_init(&v->value);
        retval = UA_Variant_copyRange(&vn->value.data.value.value, &v->value, *rangeptr);
    }

    
    if(vn->value.data.callback.onRead)
        UA_NODESTORE_RELEASE(server, (const UA_Node *)vn);
    return retval;
}

static UA_StatusCode
readValueAttributeFromDataSource(UA_Server *server, UA_Session *session,
                                 const UA_VariableNode *vn, UA_DataValue *v,
                                 UA_TimestampsToReturn timestamps,
                                 UA_NumericRange *rangeptr) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    if(!vn->value.dataSource.read)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_Boolean sourceTimeStamp = (timestamps == UA_TIMESTAMPSTORETURN_SOURCE ||
                                  timestamps == UA_TIMESTAMPSTORETURN_BOTH);
    UA_DataValue v2;
    UA_DataValue_init(&v2);
    UA_UNLOCK(&server->serviceMutex);
    UA_StatusCode retval = vn->value.dataSource.
        read(server,
             session ? &session->sessionId : NULL,
             session ? session->context : NULL,
             &vn->head.nodeId, vn->head.context,
             sourceTimeStamp, rangeptr, &v2);
    UA_LOCK(&server->serviceMutex);
    if(v2.hasValue && v2.value.storageType == UA_VARIANT_DATA_NODELETE) {
        retval = UA_DataValue_copy(&v2, v);
        UA_DataValue_clear(&v2);
    } else {
        *v = v2;
    }
    return retval;
}

static UA_StatusCode
readValueAttributeComplete(UA_Server *server, UA_Session *session,
                           const UA_VariableNode *vn, UA_TimestampsToReturn timestamps,
                           const UA_String *indexRange, UA_DataValue *v) {
    UA_EventLoop *el = server->config.eventLoop;

    
    UA_NumericRange range;
    UA_NumericRange *rangeptr = NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(indexRange && indexRange->length > 0) {
        retval = UA_NumericRange_parse(&range, *indexRange);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        rangeptr = &range;
    }

    switch(vn->valueBackend.backendType) {
        case UA_VALUEBACKENDTYPE_INTERNAL:
            retval = readValueAttributeFromNode(server, session, vn, v, rangeptr);
            //TODO change old structure to value backend
            break;
        case UA_VALUEBACKENDTYPE_DATA_SOURCE_CALLBACK:
            retval = readValueAttributeFromDataSource(server, session, vn, v,
                                                      timestamps, rangeptr);
            //TODO change old structure to value backend
            break;
        case UA_VALUEBACKENDTYPE_EXTERNAL:
            if(!vn->valueBackend.backend.external.callback.notificationRead) {
                retval = UA_STATUSCODE_BADNOTREADABLE;
                break;
            }
            retval = vn->valueBackend.backend.external.callback.
                notificationRead(server,
                                 session ? &session->sessionId : NULL,
                                 session ? session->context : NULL,
                                 &vn->head.nodeId, vn->head.context, rangeptr);
            if(retval != UA_STATUSCODE_GOOD)
                break;

            
            if(rangeptr)
                retval = UA_DataValue_copyVariantRange(
                    *vn->valueBackend.backend.external.value, v, *rangeptr);
            else
                retval = UA_DataValue_copy(*vn->valueBackend.backend.external.value, v);
            break;
        case UA_VALUEBACKENDTYPE_NONE:
            
            if(vn->valueSource == UA_VALUESOURCE_DATA)
                retval = readValueAttributeFromNode(server, session, vn, v, rangeptr);
            else
                retval = readValueAttributeFromDataSource(server, session, vn, v,
                                                          timestamps, rangeptr);
            
            break;
    }

    if(!v->hasSourceTimestamp) {
        v->sourceTimestamp = el->dateTime_now(el);
        v->hasSourceTimestamp = true;
    }

    
    if(rangeptr)
        UA_free(range.dimensions);
    return retval;
}

UA_StatusCode
readValueAttribute(UA_Server *server, UA_Session *session,
                   const UA_VariableNode *vn, UA_DataValue *v) {
    return readValueAttributeComplete(server, session, vn,
                                      UA_TIMESTAMPSTORETURN_NEITHER, NULL, v);
}

static const UA_String binEncoding = {sizeof("Default Binary")-1, (UA_Byte*)"Default Binary"};
static const UA_String xmlEncoding = {sizeof("Default XML")-1, (UA_Byte*)"Default XML"};
static const UA_String jsonEncoding = {sizeof("Default JSON")-1, (UA_Byte*)"Default JSON"};

#define CHECK_NODECLASS(CLASS)                                  \
    if(!(node->head.nodeClass & (CLASS))) {                     \
        retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;           \
        break;                                                  \
    }

#ifdef UA_ENABLE_TYPEDESCRIPTION
static const UA_DataType *
findDataType(const UA_Node *node, const UA_DataTypeArray *customTypes) {
    for(size_t i = 0; i < UA_TYPES_COUNT; ++i) {
        if(UA_NodeId_equal(&UA_TYPES[i].typeId, &node->head.nodeId)) {
            return &UA_TYPES[i];
        }
    }

    // lookup custom type
    while(customTypes) {
        for(size_t i = 0; i < customTypes->typesSize; ++i) {
            if(UA_NodeId_equal(&customTypes->types[i].typeId, &node->head.nodeId))
                return &customTypes->types[i];
        }
        customTypes = customTypes->next;
    }
    return NULL;
}

static UA_StatusCode
getStructureDefinition(const UA_DataType *type, UA_StructureDefinition *def) {
    UA_StatusCode retval =
        UA_NodeId_copy(&type->binaryEncodingId, &def->defaultEncodingId);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    switch(type->typeKind) {
        case UA_DATATYPEKIND_STRUCTURE:
            def->structureType = UA_STRUCTURETYPE_STRUCTURE;
            def->baseDataType = UA_NS0ID(STRUCTURE);
            break;
        case UA_DATATYPEKIND_OPTSTRUCT:
            def->structureType = UA_STRUCTURETYPE_STRUCTUREWITHOPTIONALFIELDS;
            def->baseDataType = UA_NS0ID(STRUCTURE);
            break;
        case UA_DATATYPEKIND_UNION:
            def->structureType = UA_STRUCTURETYPE_UNION;
            def->baseDataType = UA_NS0ID(UNION);
            break;
        default:
            return UA_STATUSCODE_BADENCODINGERROR;
    }
    def->fieldsSize = type->membersSize;
    def->fields = (UA_StructureField *)
        UA_calloc(def->fieldsSize, sizeof(UA_StructureField));
    if(!def->fields) {
        UA_NodeId_clear(&def->defaultEncodingId);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    for(size_t cnt = 0; cnt < def->fieldsSize; cnt++) {
        const UA_DataTypeMember *m = &type->members[cnt];
        def->fields[cnt].valueRank = (m->isArray) ? UA_VALUERANK_ONE_DIMENSION : UA_VALUERANK_SCALAR;
        def->fields[cnt].arrayDimensions = NULL;
        def->fields[cnt].arrayDimensionsSize = 0;
        def->fields[cnt].name = UA_STRING((char *)(uintptr_t)m->memberName);
        def->fields[cnt].description.locale = UA_STRING_NULL;
        def->fields[cnt].description.text = UA_STRING_NULL;
        def->fields[cnt].dataType = m->memberType->typeId;
        def->fields[cnt].maxStringLength = 0;
        def->fields[cnt].isOptional = m->isOptional;
    }
    return UA_STATUSCODE_GOOD;
}
#endif

void
ReadWithNode(const UA_Node *node, UA_Server *server, UA_Session *session,
             UA_TimestampsToReturn timestampsToReturn,
             const UA_ReadValueId *id, UA_DataValue *v) {
    UA_LOG_TRACE_SESSION(server->config.logging, session,
                         "Read attribute %"PRIi32 " of Node %N",
                         id->attributeId, node->head.nodeId);

    
    if(id->dataEncoding.name.length > 0 &&
       !UA_String_equal(&binEncoding, &id->dataEncoding.name)) {
        if(UA_String_equal(&xmlEncoding, &id->dataEncoding.name) ||
           UA_String_equal(&jsonEncoding, &id->dataEncoding.name))
           v->status = UA_STATUSCODE_BADDATAENCODINGUNSUPPORTED;
        else
           v->status = UA_STATUSCODE_BADDATAENCODINGINVALID;
        v->hasStatus = true;
        return;
    }

    
    if(id->indexRange.length > 0 && id->attributeId != UA_ATTRIBUTEID_VALUE) {
        v->hasStatus = true;
        v->status = UA_STATUSCODE_BADINDEXRANGENODATA;
        return;
    }

    
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    switch(id->attributeId) {
    case UA_ATTRIBUTEID_NODEID:
        retval = UA_Variant_setScalarCopy(&v->value, &node->head.nodeId,
                                          &UA_TYPES[UA_TYPES_NODEID]);
        break;
    case UA_ATTRIBUTEID_NODECLASS:
        retval = UA_Variant_setScalarCopy(&v->value, &node->head.nodeClass,
                                          &UA_TYPES[UA_TYPES_NODECLASS]);
        break;
    case UA_ATTRIBUTEID_BROWSENAME:
        retval = UA_Variant_setScalarCopy(&v->value, &node->head.browseName,
                                          &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
        break;
    case UA_ATTRIBUTEID_DISPLAYNAME: {
        UA_LocalizedText lt = UA_Session_getNodeDisplayName(session, &node->head);
        retval = UA_Variant_setScalarCopy(&v->value, &lt,
                                          &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        break;
    }
    case UA_ATTRIBUTEID_DESCRIPTION: {
        UA_LocalizedText lt = UA_Session_getNodeDescription(session, &node->head);
        retval = UA_Variant_setScalarCopy(&v->value, &lt,
                                          &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        break;
    }
    case UA_ATTRIBUTEID_WRITEMASK:
        retval = UA_Variant_setScalarCopy(&v->value, &node->head.writeMask,
                                          &UA_TYPES[UA_TYPES_UINT32]);
        break;
    case UA_ATTRIBUTEID_USERWRITEMASK: {
        UA_UInt32 userWriteMask = getUserWriteMask(server, session, &node->head);
        retval = UA_Variant_setScalarCopy(&v->value, &userWriteMask,
                                          &UA_TYPES[UA_TYPES_UINT32]);
        break; }
    case UA_ATTRIBUTEID_ISABSTRACT:
        retval = readIsAbstractAttribute(node, &v->value);
        break;
    case UA_ATTRIBUTEID_SYMMETRIC:
        CHECK_NODECLASS(UA_NODECLASS_REFERENCETYPE);
        retval = UA_Variant_setScalarCopy(&v->value, &node->referenceTypeNode.symmetric,
                                          &UA_TYPES[UA_TYPES_BOOLEAN]);
        break;
    case UA_ATTRIBUTEID_INVERSENAME:
        CHECK_NODECLASS(UA_NODECLASS_REFERENCETYPE);
        if(node->referenceTypeNode.symmetric) {
            
            retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;
            break;
        }
        retval = UA_Variant_setScalarCopy(&v->value, &node->referenceTypeNode.inverseName,
                                          &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        break;
    case UA_ATTRIBUTEID_CONTAINSNOLOOPS:
        CHECK_NODECLASS(UA_NODECLASS_VIEW);
        retval = UA_Variant_setScalarCopy(&v->value, &node->viewNode.containsNoLoops,
                                          &UA_TYPES[UA_TYPES_BOOLEAN]);
        break;
    case UA_ATTRIBUTEID_EVENTNOTIFIER:
        CHECK_NODECLASS(UA_NODECLASS_VIEW | UA_NODECLASS_OBJECT);
        if(node->head.nodeClass == UA_NODECLASS_VIEW) {
            retval = UA_Variant_setScalarCopy(&v->value, &node->viewNode.eventNotifier,
                                              &UA_TYPES[UA_TYPES_BYTE]);
        } else {
            retval = UA_Variant_setScalarCopy(&v->value, &node->objectNode.eventNotifier,
                                              &UA_TYPES[UA_TYPES_BYTE]);
        }
        break;
    case UA_ATTRIBUTEID_VALUE: {
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        if(node->head.nodeClass == UA_NODECLASS_VARIABLE) {
            UA_Byte accessLevel = getUserAccessLevel(server, session, &node->variableNode);
            if(!(accessLevel & (UA_ACCESSLEVELMASK_READ))) {
                retval = UA_STATUSCODE_BADUSERACCESSDENIED;
                break;
            }
        }
        retval = readValueAttributeComplete(server, session, &node->variableNode,
                                            timestampsToReturn, &id->indexRange, v);
        break;
    }
    case UA_ATTRIBUTEID_DATATYPE:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        retval = UA_Variant_setScalarCopy(&v->value, &node->variableTypeNode.dataType,
                                          &UA_TYPES[UA_TYPES_NODEID]);
        break;
    case UA_ATTRIBUTEID_VALUERANK:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        retval = UA_Variant_setScalarCopy(&v->value, &node->variableTypeNode.valueRank,
                                          &UA_TYPES[UA_TYPES_INT32]);
        break;
    case UA_ATTRIBUTEID_ARRAYDIMENSIONS:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        retval = UA_Variant_setArrayCopy(&v->value, node->variableTypeNode.arrayDimensions,
                                         node->variableTypeNode.arrayDimensionsSize,
                                         &UA_TYPES[UA_TYPES_UINT32]);
        break;
    case UA_ATTRIBUTEID_ACCESSLEVEL:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        retval = UA_Variant_setScalarCopy(&v->value, &node->variableNode.accessLevel,
                                          &UA_TYPES[UA_TYPES_BYTE]);
        break;
    case UA_ATTRIBUTEID_ACCESSLEVELEX:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        const UA_Byte accessLevel = *((const UA_Byte*)(&node->variableNode.accessLevel));
        UA_UInt32 accessLevelEx = accessLevel & 0xFF;
        retval = UA_Variant_setScalarCopy(&v->value, &accessLevelEx,
                                          &UA_TYPES[UA_TYPES_UINT32]);

        break;
    case UA_ATTRIBUTEID_USERACCESSLEVEL: {
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        UA_Byte userAccessLevel = getUserAccessLevel(server, session, &node->variableNode);
        retval = UA_Variant_setScalarCopy(&v->value, &userAccessLevel,
                                          &UA_TYPES[UA_TYPES_BYTE]);
        break; }
    case UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        retval = UA_Variant_setScalarCopy(&v->value,
                                          &node->variableNode.minimumSamplingInterval,
                                          &UA_TYPES[UA_TYPES_DOUBLE]);
        break;
    case UA_ATTRIBUTEID_HISTORIZING:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        retval = UA_Variant_setScalarCopy(&v->value, &node->variableNode.historizing,
                                          &UA_TYPES[UA_TYPES_BOOLEAN]);
        break;
    case UA_ATTRIBUTEID_EXECUTABLE:
        CHECK_NODECLASS(UA_NODECLASS_METHOD);
        retval = UA_Variant_setScalarCopy(&v->value, &node->methodNode.executable,
                          &UA_TYPES[UA_TYPES_BOOLEAN]);
        break;
    case UA_ATTRIBUTEID_USEREXECUTABLE: {
        CHECK_NODECLASS(UA_NODECLASS_METHOD);
        UA_Boolean userExecutable =
            getUserExecutable(server, session, &node->methodNode);
        retval = UA_Variant_setScalarCopy(&v->value, &userExecutable,
                                          &UA_TYPES[UA_TYPES_BOOLEAN]);
        break; }
    case UA_ATTRIBUTEID_DATATYPEDEFINITION: {
        CHECK_NODECLASS(UA_NODECLASS_DATATYPE);

#ifdef UA_ENABLE_TYPEDESCRIPTION
        const UA_DataType *type =
            findDataType(node, server->config.customDataTypes);
        if(!type) {
            retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;
            break;
        }

        if(UA_DATATYPEKIND_STRUCTURE == type->typeKind ||
           UA_DATATYPEKIND_OPTSTRUCT == type->typeKind ||
           UA_DATATYPEKIND_UNION == type->typeKind) {
            UA_StructureDefinition def;
            retval = getStructureDefinition(type, &def);
            if(UA_STATUSCODE_GOOD!=retval)
                break;
            retval = UA_Variant_setScalarCopy(&v->value, &def,
                                              &UA_TYPES[UA_TYPES_STRUCTUREDEFINITION]);
            UA_free(def.fields);
            break;
        }
#endif
        retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;
        break; }

    case UA_ATTRIBUTEID_ROLEPERMISSIONS:
    case UA_ATTRIBUTEID_USERROLEPERMISSIONS:
    case UA_ATTRIBUTEID_ACCESSRESTRICTIONS:
        
        retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;
        break;

    default:
        retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;
    }

    
    if(retval == UA_STATUSCODE_GOOD) {
        v->hasValue = true;
    } else {
        v->hasStatus = true;
        v->status = retval;
    }

    
    if(timestampsToReturn == UA_TIMESTAMPSTORETURN_SERVER ||
       timestampsToReturn == UA_TIMESTAMPSTORETURN_BOTH) {
        UA_EventLoop *el = server->config.eventLoop;
        v->serverTimestamp = el->dateTime_now(el);
        v->hasServerTimestamp = true;
        v->hasServerPicoseconds = false;
    } else {
        v->hasServerTimestamp = false;
        v->hasServerPicoseconds = false;
    }

    
    if(timestampsToReturn == UA_TIMESTAMPSTORETURN_SERVER ||
       timestampsToReturn == UA_TIMESTAMPSTORETURN_NEITHER) {
        v->hasSourceTimestamp = false;
        v->hasSourcePicoseconds = false;
    }
}

void
Operation_Read(UA_Server *server, UA_Session *session, UA_TimestampsToReturn *ttr,
               const UA_ReadValueId *rvi, UA_DataValue *dv) {
    
    const UA_Node *node =
        UA_NODESTORE_GET_SELECTIVE(server, &rvi->nodeId,
                                   attributeId2AttributeMask((UA_AttributeId)rvi->attributeId),
                                   UA_REFERENCETYPESET_NONE,
                                   UA_BROWSEDIRECTION_INVALID);
    if(!node) {
        dv->hasStatus = true;
        dv->status = UA_STATUSCODE_BADNODEIDUNKNOWN;
        return;
    }

    
    ReadWithNode(node, server, session, *ttr, rvi, dv);
    UA_NODESTORE_RELEASE(server, node);
}

void
Service_Read(UA_Server *server, UA_Session *session,
             const UA_ReadRequest *request, UA_ReadResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logging, session, "Processing ReadRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    if(request->timestampsToReturn > UA_TIMESTAMPSTORETURN_NEITHER) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTIMESTAMPSTORETURNINVALID;
        return;
    }

    
    if(request->maxAge < 0) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADMAXAGEINVALID;
        return;
    }

    
    if(server->config.maxNodesPerRead != 0 &&
       request->nodesToReadSize > server->config.maxNodesPerRead) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_Read,
                                           &request->timestampsToReturn,
                                           &request->nodesToReadSize,
                                           &UA_TYPES[UA_TYPES_READVALUEID],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_DATAVALUE]);
}

UA_DataValue
readWithSession(UA_Server *server, UA_Session *session,
                const UA_ReadValueId *item,
                UA_TimestampsToReturn timestampsToReturn) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_DataValue dv;
    UA_DataValue_init(&dv);

    if(!session) {
        dv.hasStatus = true;
        dv.status = UA_STATUSCODE_BADUSERACCESSDENIED;
        return dv;
    }

    Operation_Read(server, session, &timestampsToReturn, item, &dv);
    return dv;
}

UA_StatusCode
readWithReadValue(UA_Server *server, const UA_NodeId *nodeId,
                  const UA_AttributeId attributeId, void *v) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_ReadValueId item;
    UA_ReadValueId_init(&item);
    item.nodeId = *nodeId;
    item.attributeId = attributeId;
    UA_DataValue dv = readWithSession(server, &server->adminSession,
                                      &item, UA_TIMESTAMPSTORETURN_NEITHER);

    
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(dv.hasStatus)
        retval = dv.status;
    else if(!dv.hasValue)
        retval = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(retval != UA_STATUSCODE_GOOD) {
        UA_DataValue_clear(&dv);
        return retval;
    }

    if(attributeId == UA_ATTRIBUTEID_VALUE ||
       attributeId == UA_ATTRIBUTEID_ARRAYDIMENSIONS) {
        
        memcpy(v, &dv.value, sizeof(UA_Variant));
    } else {
        
        memcpy(v, dv.value.data, dv.value.type->memSize);
        UA_free(dv.value.data);
    }
    return retval;
}


UA_DataValue
UA_Server_read(UA_Server *server, const UA_ReadValueId *item,
               UA_TimestampsToReturn timestamps) {
    UA_LOCK(&server->serviceMutex);
    UA_DataValue dv = readWithSession(server, &server->adminSession, item, timestamps);
    UA_UNLOCK(&server->serviceMutex);
    return dv;
}

UA_StatusCode
__UA_Server_read(UA_Server *server, const UA_NodeId *nodeId,
                 const UA_AttributeId attributeId, void *v) {
   UA_LOCK(&server->serviceMutex);
   UA_StatusCode retval = readWithReadValue(server, nodeId, attributeId, v);
   UA_UNLOCK(&server->serviceMutex);
   return retval;
}

UA_StatusCode
readObjectProperty(UA_Server *server, const UA_NodeId objectId,
                   const UA_QualifiedName propertyName,
                   UA_Variant *value) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_RelativePathElement rpe;
    UA_RelativePathElement_init(&rpe);
    rpe.referenceTypeId = UA_NS0ID(HASPROPERTY);
    rpe.isInverse = false;
    rpe.includeSubtypes = false;
    rpe.targetName = propertyName;

    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = objectId;
    bp.relativePath.elementsSize = 1;
    bp.relativePath.elements = &rpe;

    UA_StatusCode retval;
    UA_BrowsePathResult bpr = translateBrowsePathToNodeIds(server, &bp);
    if(bpr.statusCode != UA_STATUSCODE_GOOD || bpr.targetsSize < 1) {
        retval = bpr.statusCode;
        UA_BrowsePathResult_clear(&bpr);
        return retval;
    }

    
    retval = readWithReadValue(server, &bpr.targets[0].targetId.nodeId,
                               UA_ATTRIBUTEID_VALUE, value);

    UA_BrowsePathResult_clear(&bpr);
    return retval;
}


UA_StatusCode
UA_Server_readObjectProperty(UA_Server *server, const UA_NodeId objectId,
                             const UA_QualifiedName propertyName,
                             UA_Variant *value) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = readObjectProperty(server, objectId, propertyName, value);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}





UA_Boolean
compatibleValueDataType(UA_Server *server, const UA_DataType *dataType,
                        const UA_NodeId *constraintDataType) {
    if(compatibleDataTypes(server, &dataType->typeId, constraintDataType))
        return true;

    UA_Boolean abstract = false;
    UA_StatusCode res = readWithReadValue(server, &dataType->typeId,
                                          UA_ATTRIBUTEID_ISABSTRACT, &abstract);
    if(res != UA_STATUSCODE_GOOD || abstract)
        return false;

    if(isNodeInTree_singleRef(server, constraintDataType, &dataType->typeId,
                              UA_REFERENCETYPEINDEX_HASSUBTYPE))
        return true;

    return false;
}

UA_Boolean
compatibleDataTypes(UA_Server *server, const UA_NodeId *dataType,
                    const UA_NodeId *constraintDataType) {
    
    if(UA_NodeId_isNull(dataType))
       return false;

    
    if(UA_NodeId_isNull(constraintDataType) ||
       UA_NodeId_equal(constraintDataType, &UA_TYPES[UA_TYPES_VARIANT].typeId))
        return true;

    
    if(UA_NodeId_equal(dataType, constraintDataType))
        return true;

    
    if(isNodeInTree_singleRef(server, dataType, constraintDataType,
                              UA_REFERENCETYPEINDEX_HASSUBTYPE))
        return true;

    return false;
}

UA_Boolean
compatibleValueRankArrayDimensions(UA_Server *server, UA_Session *session,
                                   UA_Int32 valueRank, size_t arrayDimensionsSize) {
    
    if(valueRank < UA_VALUERANK_SCALAR_OR_ONE_DIMENSION) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "The ValueRank is invalid (< -3)");
        return false;
    }

    if(valueRank <= UA_VALUERANK_ONE_OR_MORE_DIMENSIONS) {
        if(arrayDimensionsSize > 0) {
            UA_LOG_INFO_SESSION(server->config.logging, session,
                                "No ArrayDimensions can be defined for a ValueRank <= 0");
            return false;
        }
        return true;
    }

    if(arrayDimensionsSize != (size_t)valueRank) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "The number of ArrayDimensions is not equal to "
                            "the (positive) ValueRank");
        return false;
    }
    return true;
}

UA_Boolean
compatibleValueRanks(UA_Int32 valueRank, UA_Int32 constraintValueRank) {
    
    switch(constraintValueRank) {
        if(valueRank != UA_VALUERANK_SCALAR && valueRank != UA_VALUERANK_ONE_DIMENSION)
            return false;
        break;
        break;
    case UA_VALUERANK_SCALAR: 
        if(valueRank != UA_VALUERANK_SCALAR)
            return false;
        break;
        if(valueRank < (UA_Int32) UA_VALUERANK_ONE_OR_MORE_DIMENSIONS)
            return false;
        break;
        if(valueRank != constraintValueRank)
            return false;
        break;
    }
    return true;
}

static UA_Boolean
compatibleValueRankValue(UA_Int32 valueRank, const UA_Variant *value) {
    
    if(valueRank < UA_VALUERANK_SCALAR_OR_ONE_DIMENSION)
        return false;

    
    if(!value->data)
        return true;

    size_t arrayDims = value->arrayDimensionsSize;
    if(arrayDims == 0 && !UA_Variant_isScalar(value))
        arrayDims = 1; 

    switch(valueRank) {
        return (arrayDims <= 1);
        return true;
    case UA_VALUERANK_SCALAR: 
        return (arrayDims == 0);
    case UA_VALUERANK_ONE_OR_MORE_DIMENSIONS:
        return (arrayDims >= 1);
    default:
        break;
    }

    UA_assert(valueRank >= UA_VALUERANK_ONE_OR_MORE_DIMENSIONS);

    
    return (arrayDims == (UA_UInt32)valueRank);
}

UA_Boolean
compatibleArrayDimensions(size_t constraintArrayDimensionsSize,
                          const UA_UInt32 *constraintArrayDimensions,
                          size_t testArrayDimensionsSize,
                          const UA_UInt32 *testArrayDimensions) {
    
    if(constraintArrayDimensionsSize == 0)
        return true;

    
    if(testArrayDimensionsSize != constraintArrayDimensionsSize)
        return false;

    for(size_t i = 0; i < constraintArrayDimensionsSize; ++i) {
        if(constraintArrayDimensions[i] < testArrayDimensions[i] &&
           constraintArrayDimensions[i] != 0)
            return false;
    }
    return true;
}

UA_Boolean
compatibleValueArrayDimensions(const UA_Variant *value, size_t targetArrayDimensionsSize,
                               const UA_UInt32 *targetArrayDimensions) {
    size_t valueArrayDimensionsSize = value->arrayDimensionsSize;
    UA_UInt32 const *valueArrayDimensions = value->arrayDimensions;
    UA_UInt32 tempArrayDimensions;
    if(!valueArrayDimensions && !UA_Variant_isScalar(value)) {
        if(value->arrayLength == 0)
            return true;

        
        valueArrayDimensionsSize = 1;
        tempArrayDimensions = (UA_UInt32)value->arrayLength;
        valueArrayDimensions = &tempArrayDimensions;
    }
    UA_assert(valueArrayDimensionsSize == 0 || valueArrayDimensions != NULL);
    return compatibleArrayDimensions(targetArrayDimensionsSize, targetArrayDimensions,
                                     valueArrayDimensionsSize, valueArrayDimensions);
}

const char *reason_EmptyType = "Empty value only allowed for BaseDataType";
const char *reason_ValueDataType = "DataType of the value is incompatible";
const char *reason_ValueArrayDimensions = "ArrayDimensions of the value are incompatible";
const char *reason_ValueValueRank = "ValueRank of the value is incompatible";

UA_Boolean
compatibleValue(UA_Server *server, UA_Session *session, const UA_NodeId *targetDataTypeId,
                UA_Int32 targetValueRank, size_t targetArrayDimensionsSize,
                const UA_UInt32 *targetArrayDimensions, const UA_Variant *value,
                const UA_NumericRange *range, const char **reason) {
    
    if(UA_Variant_isEmpty(value)) {
        
        if(UA_NodeId_equal(targetDataTypeId, &UA_TYPES[UA_TYPES_VARIANT].typeId) ||
           UA_NodeId_equal(targetDataTypeId, &UA_NODEID_NULL))
            return true;

        
        if(server->bootstrapNS0 ||
           server->config.allowEmptyVariables == UA_RULEHANDLING_ACCEPT)
            return true;

        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "Only Variables with data type BaseDataType "
                            "can contain an empty value");

        
        if(server->config.allowEmptyVariables == UA_RULEHANDLING_WARN)
            return true;

        
        *reason = reason_EmptyType;
        return false;
    }

    
    if(UA_Variant_hasArrayType(value, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) &&
       value->arrayLength == 0) {
        return true;        
    }

    
    if(!compatibleValueDataType(server, value->type, targetDataTypeId)) {
        *reason = reason_ValueDataType;
        return false;
    }

    
    if(range)
        return true;

    
    if(!compatibleValueArrayDimensions(value, targetArrayDimensionsSize,
                                       targetArrayDimensions)) {
        *reason = reason_ValueArrayDimensions;
        return false;
    }

    
    if(!compatibleValueRankValue(targetValueRank, value)) {
        *reason = reason_ValueValueRank;
        return false;
    }

    return true;
}





static void
freeWrapperArray(void *app, void *context) {
    UA_free(context);
}

static void
unwrapEOArray(UA_Server *server, UA_Variant *value) {
    
    if(!UA_Variant_hasArrayType(value, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]) ||
       value->arrayLength == 0)
        return;

    
    UA_ExtensionObject *eo = (UA_ExtensionObject*)value->data;
    const UA_DataType *innerType = eo[0].content.decoded.type;
    for(size_t i = 0; i < value->arrayLength; i++) {
        if(eo[i].encoding != UA_EXTENSIONOBJECT_DECODED &&
           eo[i].encoding != UA_EXTENSIONOBJECT_DECODED_NODELETE)
            return;
        if(eo[i].content.decoded.type != innerType)
            return;
    }

    UA_DelayedCallback *dc = (UA_DelayedCallback*)
        UA_malloc(sizeof(UA_DelayedCallback) + (value->arrayLength * innerType->memSize));
    if(!dc)
        return;

    
    uintptr_t pos = ((uintptr_t)dc) + sizeof(UA_DelayedCallback);
    void *unwrappedArray = (void*)pos;
    for(size_t i = 0; i < value->arrayLength; i++) {
        memcpy((void*)pos, eo[i].content.decoded.data, innerType->memSize);
        pos += innerType->memSize;
    }

    
    value->type = innerType;
    value->data = unwrappedArray;

    
    dc->callback = freeWrapperArray;
    dc->application = NULL;
    dc->context = dc;
    UA_EventLoop *el = server->config.eventLoop;
    el->addDelayedCallback(el, dc);
}

void
adjustValueType(UA_Server *server, UA_Variant *value,
                const UA_NodeId *targetDataTypeId) {
    
    const UA_DataType *type = value->type;
    if(!type)
        return;

    
    if(UA_NodeId_equal(&type->typeId, targetDataTypeId))
        return;

    
    unwrapEOArray(server, value);

    
    const UA_DataType *targetType =
        UA_findDataTypeWithCustom(targetDataTypeId, server->config.customDataTypes);
    if(!targetType)
        return;

    
    adjustType(value, targetType);
}

static UA_StatusCode
writeArrayDimensionsAttribute(UA_Server *server, UA_Session *session,
                              UA_VariableNode *node, const UA_VariableTypeNode *type,
                              size_t arrayDimensionsSize, UA_UInt32 *arrayDimensions) {
    UA_assert(node != NULL);
    UA_assert(type != NULL);

    if(node->head.nodeClass == UA_NODECLASS_VARIABLETYPE &&
       UA_Node_hasSubTypeOrInstances(&node->head)) {
        UA_LOG_INFO(server->config.logging, UA_LOGCATEGORY_SERVER,
                    "Cannot change a variable type with existing instances");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    
    if(!compatibleValueRankArrayDimensions(server, session, node->valueRank,
                                           arrayDimensionsSize)) {
        UA_LOG_DEBUG(server->config.logging, UA_LOGCATEGORY_SERVER,
                     "Cannot write the ArrayDimensions. The ValueRank does not match.");
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    if(type->arrayDimensions &&
       !compatibleArrayDimensions(type->arrayDimensionsSize, type->arrayDimensions,
                                  arrayDimensionsSize, arrayDimensions)) {
       UA_LOG_DEBUG(server->config.logging, UA_LOGCATEGORY_SERVER,
                    "Array dimensions in the variable type do not match");
       return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    
    UA_DataValue value;
    UA_DataValue_init(&value);
    UA_StatusCode retval = readValueAttribute(server, session, node, &value);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    if(value.hasValue) {
        if(!compatibleValueArrayDimensions(&value.value, arrayDimensionsSize,
                                           arrayDimensions))
            retval = UA_STATUSCODE_BADTYPEMISMATCH;
        UA_DataValue_clear(&value);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_DEBUG(server->config.logging, UA_LOGCATEGORY_SERVER,
                         "Array dimensions in the current value do not match");
            return retval;
        }
    }

    
    UA_UInt32 *oldArrayDimensions = node->arrayDimensions;
    size_t oldArrayDimensionsSize = node->arrayDimensionsSize;
    retval = UA_Array_copy(arrayDimensions, arrayDimensionsSize,
                           (void**)&node->arrayDimensions,
                           &UA_TYPES[UA_TYPES_UINT32]);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    UA_Array_delete(oldArrayDimensions, oldArrayDimensionsSize, &UA_TYPES[UA_TYPES_UINT32]);
    node->arrayDimensionsSize = arrayDimensionsSize;
    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode
writeValueRank(UA_Server *server, UA_Session *session,
               UA_VariableNode *node, const UA_VariableTypeNode *type,
               UA_Int32 valueRank) {
    UA_assert(node != NULL);
    UA_assert(type != NULL);

    UA_Int32 constraintValueRank = type->valueRank;

    if(node->head.nodeClass == UA_NODECLASS_VARIABLETYPE &&
       UA_Node_hasSubTypeOrInstances(&node->head))
        return UA_STATUSCODE_BADINTERNALERROR;

    
    if(!compatibleValueRanks(valueRank, constraintValueRank))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    size_t arrayDims = node->arrayDimensionsSize;
    if(arrayDims == 0) {
        UA_DataValue value;
        UA_DataValue_init(&value);
        UA_StatusCode retval = readValueAttribute(server, session, node, &value);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        if(!value.hasValue || !value.value.type) {
            
            node->valueRank = valueRank;
            return UA_STATUSCODE_GOOD;
        }
        if(!UA_Variant_isScalar(&value.value))
            arrayDims = 1;
        UA_DataValue_clear(&value);
    }
    if(!compatibleValueRankArrayDimensions(server, session, valueRank, arrayDims))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    
    node->valueRank = valueRank;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeDataTypeAttribute(UA_Server *server, UA_Session *session,
                       UA_VariableNode *node, const UA_VariableTypeNode *type,
                       const UA_NodeId *dataType) {
    UA_assert(node != NULL);
    UA_assert(type != NULL);

    if(node->head.nodeClass == UA_NODECLASS_VARIABLETYPE &&
       UA_Node_hasSubTypeOrInstances(&node->head))
        return UA_STATUSCODE_BADINTERNALERROR;

    
    if(!compatibleDataTypes(server, dataType, &type->dataType))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    
    UA_DataValue value;
    UA_DataValue_init(&value);
    UA_StatusCode retval = readValueAttribute(server, session, node, &value);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    if(value.hasValue) {
        const char *reason; 
        if(!compatibleValue(server, session, dataType, node->valueRank,
                            node->arrayDimensionsSize, node->arrayDimensions,
                            &value.value, NULL, &reason))
            retval = UA_STATUSCODE_BADTYPEMISMATCH;
        UA_DataValue_clear(&value);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_DEBUG(server->config.logging, UA_LOGCATEGORY_SERVER,
                         "The current value does not match the new data type");
            return retval;
        }
    }

    
    UA_NodeId dtCopy = node->dataType;
    retval = UA_NodeId_copy(dataType, &node->dataType);
    if(retval != UA_STATUSCODE_GOOD) {
        node->dataType = dtCopy;
        return retval;
    }
    UA_NodeId_clear(&dtCopy);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeValueAttributeWithoutRange(UA_VariableNode *node, const UA_DataValue *value) {
    UA_DataValue *oldValue = &node->value.data.value;
    UA_DataValue tmpValue = *value;

    if(oldValue->hasValue && oldValue->value.type && oldValue->value.type->pointerFree &&
       value->hasValue && value->value.type && value->value.type->pointerFree &&
       oldValue->value.type->memSize == value->value.type->memSize) {
        size_t oSize = 1;
        size_t vSize = 1;
        if(!UA_Variant_isScalar(&oldValue->value))
            oSize = oldValue->value.arrayLength;
        if(!UA_Variant_isScalar(&value->value))
            vSize = value->value.arrayLength;

        if(oSize == vSize &&
           oldValue->value.arrayDimensionsSize == value->value.arrayDimensionsSize) {
            
            tmpValue.value = oldValue->value;
            tmpValue.value.type = value->value.type;
            tmpValue.value.arrayLength = value->value.arrayLength;

            
            memcpy(tmpValue.value.data, value->value.data,
                   oSize * oldValue->value.type->memSize);
            if(oldValue->value.arrayDimensionsSize > 0) 
                memcpy(tmpValue.value.arrayDimensions, value->value.arrayDimensions,
                       sizeof(UA_UInt32) * oldValue->value.arrayDimensionsSize);

            
            node->value.data.value = tmpValue;
            return UA_STATUSCODE_GOOD;
        }
    }

    
    UA_StatusCode retval = UA_Variant_copy(&value->value, &tmpValue.value);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    UA_DataValue_clear(&node->value.data.value);
    node->value.data.value = tmpValue;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeValueAttributeWithRange(UA_VariableNode *node, const UA_DataValue *value,
                             const UA_NumericRange *rangeptr) {
    
    if(value->status != node->value.data.value.status ||
       !value->hasValue || !node->value.data.value.hasValue)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;

    
    UA_Variant editableValue;
    const UA_Variant *v = &value->value;
    if(UA_Variant_isScalar(&value->value)) {
        editableValue = value->value;
        editableValue.arrayLength = 1;
        v = &editableValue;
    }

    
    if(!node->value.data.value.value.type || !v->type ||
       !UA_NodeId_equal(&node->value.data.value.value.type->typeId,
                        &v->type->typeId))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    
    UA_StatusCode retval =
        UA_Variant_setRangeCopy(&node->value.data.value.value,
                                v->data, v->arrayLength, *rangeptr);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    
    node->value.data.value.hasStatus = value->hasStatus;
    node->value.data.value.status = value->status;
    node->value.data.value.hasSourceTimestamp = value->hasSourceTimestamp;
    node->value.data.value.sourceTimestamp = value->sourceTimestamp;
    node->value.data.value.hasSourcePicoseconds = value->hasSourcePicoseconds;
    node->value.data.value.sourcePicoseconds = value->sourcePicoseconds;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeNodeValueAttribute(UA_Server *server, UA_Session *session,
                        UA_VariableNode *node, const UA_DataValue *value,
                        const UA_String *indexRange) {
    UA_assert(node != NULL);
    UA_assert(session != NULL);
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    
    UA_NumericRange range;
    range.dimensions = NULL;
    UA_NumericRange *rangeptr = NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(indexRange && indexRange->length > 0) {
        retval = UA_NumericRange_parse(&range, *indexRange);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        rangeptr = &range;
    }

    UA_DataValue adjustedValue = *value;

    
    const char *reason;
    if(value->hasValue && value->value.type) {
        
        adjustValueType(server, &adjustedValue.value, &node->dataType);

        
        if(!compatibleValue(server, session, &node->dataType, node->valueRank,
                            node->arrayDimensionsSize, node->arrayDimensions,
                            &adjustedValue.value, rangeptr, &reason)) {
            if(session == &server->adminSession) {
                
                UA_LOG_WARNING_SESSION(server->config.logging, session,
                               "Writing the value of Node %N failed with the "
                               "following reason: %s", node->head.nodeId, reason);
            } else {
                
                UA_LOG_DEBUG_SESSION(server->config.logging, session,
                                     "Writing the value of Node %N failed with the "
                                     "following reason: %s", node->head.nodeId, reason);
            }
            if(rangeptr && rangeptr->dimensions != NULL)
                UA_free(rangeptr->dimensions);
            return UA_STATUSCODE_BADTYPEMISMATCH;
        }
    }

    if(node->head.nodeClass == UA_NODECLASS_VARIABLE && !node->isDynamic) {
        adjustedValue.hasSourceTimestamp = false;
        adjustedValue.hasSourcePicoseconds = false;
    }

    retval = UA_STATUSCODE_BADWRITENOTSUPPORTED; 
    switch(node->valueBackend.backendType) {
    case UA_VALUEBACKENDTYPE_NONE:
        if(node->valueSource == UA_VALUESOURCE_DATA) {
            
            if(!rangeptr)
                retval = writeValueAttributeWithoutRange(node, &adjustedValue);
            else
                retval = writeValueAttributeWithRange(node, &adjustedValue, rangeptr);

            
            if(retval == UA_STATUSCODE_GOOD &&
               node->value.data.callback.onWrite) {
                UA_UNLOCK(&server->serviceMutex);
                node->value.data.callback.
                    onWrite(server, &session->sessionId, session->context,
                            &node->head.nodeId, node->head.context,
                            rangeptr, &adjustedValue);
                UA_LOCK(&server->serviceMutex);
            }
        } else if(node->value.dataSource.write) {
            
            UA_UNLOCK(&server->serviceMutex);
            retval = node->value.dataSource.
                write(server, &session->sessionId, session->context,
                      &node->head.nodeId, node->head.context,
                      rangeptr, &adjustedValue);
            UA_LOCK(&server->serviceMutex);
        }
        break;

    case UA_VALUEBACKENDTYPE_EXTERNAL:
        retval = UA_STATUSCODE_GOOD;
        if(node->valueBackend.backend.external.callback.userWrite) {
            retval = node->valueBackend.backend.external.callback.
                userWrite(server, &session->sessionId, session->context,
                          &node->head.nodeId, node->head.context,
                          rangeptr, &adjustedValue);
        } else {
            if(node->valueBackend.backend.external.value) {
                UA_DataValue_clear(*node->valueBackend.backend.external.value);
                retval = UA_DataValue_copy(&adjustedValue,
                                           *node->valueBackend.backend.external.value);
            }
        }
        break;

    case UA_VALUEBACKENDTYPE_INTERNAL:
    case UA_VALUEBACKENDTYPE_DATA_SOURCE_CALLBACK:
    default:
        break;
    }

#ifdef UA_ENABLE_HISTORIZING
    if(retval == UA_STATUSCODE_GOOD &&
       node->head.nodeClass == UA_NODECLASS_VARIABLE &&
       server->config.historyDatabase.setValue) {
        UA_UNLOCK(&server->serviceMutex);
        server->config.historyDatabase.
            setValue(server, server->config.historyDatabase.context,
                     &session->sessionId, session->context,
                     &node->head.nodeId, node->historizing, &adjustedValue);
        UA_LOCK(&server->serviceMutex);
    }
#endif

    
    if(rangeptr && rangeptr->dimensions != NULL)
        UA_free(rangeptr->dimensions);
    return retval;
}

static UA_StatusCode
writeIsAbstract(UA_Node *node, UA_Boolean value) {
    switch(node->head.nodeClass) {
    case UA_NODECLASS_OBJECTTYPE:
        node->objectTypeNode.isAbstract = value;
        break;
    case UA_NODECLASS_REFERENCETYPE:
        node->referenceTypeNode.isAbstract = value;
        break;
    case UA_NODECLASS_VARIABLETYPE:
        node->variableTypeNode.isAbstract = value;
        break;
    case UA_NODECLASS_DATATYPE:
        node->dataTypeNode.isAbstract = value;
        break;
    default:
        return UA_STATUSCODE_BADNODECLASSINVALID;
    }
    return UA_STATUSCODE_GOOD;
}





#define CHECK_DATATYPE_SCALAR(EXP_DT)                                   \
    if(!wvalue->value.hasValue ||                                       \
       &UA_TYPES[UA_TYPES_##EXP_DT] != wvalue->value.value.type ||      \
       !UA_Variant_isScalar(&wvalue->value.value)) {                    \
        retval = UA_STATUSCODE_BADTYPEMISMATCH;                         \
        break;                                                          \
    }

#define CHECK_DATATYPE_ARRAY(EXP_DT)                                    \
    if(!wvalue->value.hasValue ||                                       \
       &UA_TYPES[UA_TYPES_##EXP_DT] != wvalue->value.value.type ||      \
       UA_Variant_isScalar(&wvalue->value.value)) {                     \
        retval = UA_STATUSCODE_BADTYPEMISMATCH;                         \
        break;                                                          \
    }

#define CHECK_NODECLASS_WRITE(CLASS)                                    \
    if((node->head.nodeClass & (CLASS)) == 0) {                         \
        retval = UA_STATUSCODE_BADNODECLASSINVALID;                     \
        break;                                                          \
    }

#define CHECK_USERWRITEMASK(mask)                           \
    if(!(userWriteMask & (mask))) {                         \
        retval = UA_STATUSCODE_BADUSERACCESSDENIED;         \
        break;                                              \
    }

#define GET_NODETYPE                                \
    type = (const UA_VariableTypeNode*)             \
        getNodeType(server, &node->head);           \
    if(!type) {                                     \
        retval = UA_STATUSCODE_BADTYPEMISMATCH;     \
        break;                                      \
    }

static UA_StatusCode
updateLocalizedText(const UA_LocalizedText *source, UA_LocalizedText *target) {
    UA_LocalizedText tmp;
    UA_StatusCode retval = UA_LocalizedText_copy(source, &tmp);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    UA_LocalizedText_clear(target);
    *target = tmp;
    return UA_STATUSCODE_GOOD;
}

#ifdef UA_ENABLE_SUBSCRIPTIONS
static void
triggerImmediateDataChange(UA_Server *server, UA_Session *session,
                           UA_Node *node, const UA_WriteValue *wvalue) {
    UA_MonitoredItem *mon = node->head.monitoredItems;
    for(; mon != NULL; mon = mon->sampling.nodeListNext) {
        if(mon->itemToMonitor.attributeId != wvalue->attributeId)
            continue;
        UA_DataValue value;
        UA_DataValue_init(&value);
        ReadWithNode(node, server, session, mon->timestampsToReturn,
                     &mon->itemToMonitor, &value);
        UA_MonitoredItem_processSampledValue(server, mon, &value);
    }
}
#endif

static UA_StatusCode
copyAttributeIntoNode(UA_Server *server, UA_Session *session,
                      UA_Node *node, const UA_WriteValue *wvalue) {
    UA_assert(session != NULL);
    const void *value = wvalue->value.value.data;
    UA_UInt32 userWriteMask = getUserWriteMask(server, session, &node->head);
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_LOG_TRACE_SESSION(server->config.logging, session,
                         "Write attribute %" PRIi32 " of Node %N",
                         wvalue->attributeId, node->head.nodeId);

    const UA_VariableTypeNode *type;

    switch(wvalue->attributeId) {
    case UA_ATTRIBUTEID_NODEID:
    case UA_ATTRIBUTEID_NODECLASS:
    case UA_ATTRIBUTEID_USERWRITEMASK:
    case UA_ATTRIBUTEID_USERACCESSLEVEL:
    case UA_ATTRIBUTEID_USEREXECUTABLE:
        retval = UA_STATUSCODE_BADWRITENOTSUPPORTED;
        break;
    case UA_ATTRIBUTEID_DISPLAYNAME:
        CHECK_USERWRITEMASK(UA_WRITEMASK_DISPLAYNAME);
        CHECK_DATATYPE_SCALAR(LOCALIZEDTEXT);
        retval = UA_Node_insertOrUpdateDisplayName(&node->head,
                                                   (const UA_LocalizedText *)value);
        break;
    case UA_ATTRIBUTEID_DESCRIPTION:
        CHECK_USERWRITEMASK(UA_WRITEMASK_DESCRIPTION);
        CHECK_DATATYPE_SCALAR(LOCALIZEDTEXT);
        retval = UA_Node_insertOrUpdateDescription(&node->head,
                                                   (const UA_LocalizedText *)value);
        break;
    case UA_ATTRIBUTEID_WRITEMASK:
        CHECK_USERWRITEMASK(UA_WRITEMASK_WRITEMASK);
        CHECK_DATATYPE_SCALAR(UINT32);
        node->head.writeMask = *(const UA_UInt32*)value;
        break;
    case UA_ATTRIBUTEID_ISABSTRACT:
        CHECK_USERWRITEMASK(UA_WRITEMASK_ISABSTRACT);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        retval = writeIsAbstract(node, *(const UA_Boolean*)value);
        break;
    case UA_ATTRIBUTEID_SYMMETRIC:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_REFERENCETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_SYMMETRIC);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        node->referenceTypeNode.symmetric = *(const UA_Boolean*)value;
        break;
    case UA_ATTRIBUTEID_INVERSENAME:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_REFERENCETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_INVERSENAME);
        CHECK_DATATYPE_SCALAR(LOCALIZEDTEXT);
        retval = updateLocalizedText((const UA_LocalizedText *)value,
                                     &node->referenceTypeNode.inverseName);
        break;
    case UA_ATTRIBUTEID_CONTAINSNOLOOPS:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VIEW);
        CHECK_USERWRITEMASK(UA_WRITEMASK_CONTAINSNOLOOPS);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        node->viewNode.containsNoLoops = *(const UA_Boolean*)value;
        break;
    case UA_ATTRIBUTEID_EVENTNOTIFIER:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VIEW | UA_NODECLASS_OBJECT);
        CHECK_USERWRITEMASK(UA_WRITEMASK_EVENTNOTIFIER);
        CHECK_DATATYPE_SCALAR(BYTE);
        if(node->head.nodeClass == UA_NODECLASS_VIEW) {
            node->viewNode.eventNotifier = *(const UA_Byte*)value;
        } else {
            node->objectNode.eventNotifier = *(const UA_Byte*)value;
        }
        break;
    case UA_ATTRIBUTEID_VALUE:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        if(node->head.nodeClass == UA_NODECLASS_VARIABLE) {
            UA_Byte accessLevel = getUserAccessLevel(server, session, &node->variableNode);
            if(!(accessLevel & (UA_ACCESSLEVELMASK_WRITE))) {
                retval = UA_STATUSCODE_BADUSERACCESSDENIED;
                break;
            }
        } else { 
            CHECK_USERWRITEMASK(UA_WRITEMASK_VALUEFORVARIABLETYPE);
        }
        retval = writeNodeValueAttribute(server, session, &node->variableNode,
                                         &wvalue->value, &wvalue->indexRange);
        break;
    case UA_ATTRIBUTEID_DATATYPE:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_DATATYPE);
        CHECK_DATATYPE_SCALAR(NODEID);
        GET_NODETYPE;
        retval = writeDataTypeAttribute(server, session, &node->variableNode,
                                        type, (const UA_NodeId*)value);
        UA_NODESTORE_RELEASE(server, (const UA_Node*)type);
        break;
    case UA_ATTRIBUTEID_VALUERANK:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_VALUERANK);
        CHECK_DATATYPE_SCALAR(INT32);
        GET_NODETYPE;
        retval = writeValueRank(server, session, &node->variableNode,
                                type, *(const UA_Int32*)value);
        UA_NODESTORE_RELEASE(server, (const UA_Node*)type);
        break;
    case UA_ATTRIBUTEID_ARRAYDIMENSIONS:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_ARRRAYDIMENSIONS);
        CHECK_DATATYPE_ARRAY(UINT32);
        GET_NODETYPE;
        retval = writeArrayDimensionsAttribute(server, session, &node->variableNode,
                                               type, wvalue->value.value.arrayLength,
                                               (UA_UInt32 *)wvalue->value.value.data);
        UA_NODESTORE_RELEASE(server, (const UA_Node*)type);
        break;
    case UA_ATTRIBUTEID_ACCESSLEVEL:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_ACCESSLEVEL);
        CHECK_DATATYPE_SCALAR(BYTE);
        node->variableNode.accessLevel = *(const UA_Byte*)value;
        break;
    case UA_ATTRIBUTEID_ACCESSLEVELEX:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_ACCESSLEVELEX);
        CHECK_DATATYPE_SCALAR(UINT32);
        node->variableNode.accessLevel = (UA_Byte)(*(const UA_UInt32*)value & 0xFF);
        break;
    case UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_MINIMUMSAMPLINGINTERVAL);
        CHECK_DATATYPE_SCALAR(DOUBLE);
        node->variableNode.minimumSamplingInterval = *(const UA_Double*)value;
        break;
    case UA_ATTRIBUTEID_HISTORIZING:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_HISTORIZING);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        node->variableNode.historizing = *(const UA_Boolean*)value;
        break;
    case UA_ATTRIBUTEID_EXECUTABLE:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_METHOD);
        CHECK_USERWRITEMASK(UA_WRITEMASK_EXECUTABLE);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        node->methodNode.executable = *(const UA_Boolean*)value;
        break;
    default:
        retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;
        break;
    }

    
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "WriteRequest returned status code %s",
                            UA_StatusCode_name(retval));
        return retval;
    }

    
#ifdef UA_ENABLE_SUBSCRIPTIONS
    triggerImmediateDataChange(server, session, node, wvalue);
#endif

    return UA_STATUSCODE_GOOD;
}

void
Operation_Write(UA_Server *server, UA_Session *session, void *context,
                const UA_WriteValue *wv, UA_StatusCode *result) {
    UA_assert(session != NULL);
    *result = UA_Server_editNode(server, session, &wv->nodeId, wv->attributeId,
                                 UA_REFERENCETYPESET_NONE, UA_BROWSEDIRECTION_INVALID,
                                 (UA_EditNodeCallback)copyAttributeIntoNode,
                                 (void*)(uintptr_t)wv);
}

void
Service_Write(UA_Server *server, UA_Session *session,
              const UA_WriteRequest *request,
              UA_WriteResponse *response) {
    UA_assert(session != NULL);
    UA_LOG_DEBUG_SESSION(server->config.logging, session,
                         "Processing WriteRequest");
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    if(server->config.maxNodesPerWrite != 0 &&
       request->nodesToWriteSize > server->config.maxNodesPerWrite) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    response->responseHeader.serviceResult =
        UA_Server_processServiceOperations(server, session,
                                           (UA_ServiceOperation)Operation_Write, NULL,
                                           &request->nodesToWriteSize,
                                           &UA_TYPES[UA_TYPES_WRITEVALUE],
                                           &response->resultsSize,
                                           &UA_TYPES[UA_TYPES_STATUSCODE]);
}

UA_StatusCode
UA_Server_write(UA_Server *server, const UA_WriteValue *value) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_LOCK(&server->serviceMutex);
    Operation_Write(server, &server->adminSession, NULL, value, &res);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}


UA_StatusCode
__UA_Server_write(UA_Server *server, const UA_NodeId *nodeId,
                  const UA_AttributeId attributeId,
                  const UA_DataType *attr_type, const void *attr) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode res = writeAttribute(server, &server->adminSession,
                                       nodeId, attributeId, attr, attr_type);
    UA_UNLOCK(&server->serviceMutex);
    return res;
}


UA_StatusCode
writeAttribute(UA_Server *server, UA_Session *session,
               const UA_NodeId *nodeId, const UA_AttributeId attributeId,
               const void *attr, const UA_DataType *attr_type) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_WriteValue wvalue;
    UA_WriteValue_init(&wvalue);
    wvalue.nodeId = *nodeId;
    wvalue.attributeId = attributeId;
    wvalue.value.hasValue = true;
    if(attr_type == &UA_TYPES[UA_TYPES_VARIANT]) {
        wvalue.value.value = *(const UA_Variant*)attr;
    } else if(attr_type == &UA_TYPES[UA_TYPES_DATAVALUE]) {
        wvalue.value = *(const UA_DataValue*)attr;
    } else {
        
        UA_Variant_setScalar(&wvalue.value.value,
                             (void*)(uintptr_t)attr, attr_type);
    }

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    Operation_Write(server, session, NULL, &wvalue, &res);
    return res;
}

#ifdef UA_ENABLE_HISTORIZING
typedef void
 (*UA_HistoryDatabase_readFunc)(UA_Server *server, void *hdbContext,
                                const UA_NodeId *sessionId, void *sessionContext,
                                const UA_RequestHeader *requestHeader,
                                const void *historyReadDetails,
                                UA_TimestampsToReturn timestampsToReturn,
                                UA_Boolean releaseContinuationPoints,
                                size_t nodesToReadSize,
                                const UA_HistoryReadValueId *nodesToRead,
                                UA_HistoryReadResponse *response,
                                void * const * const historyData);

void
Service_HistoryRead(UA_Server *server, UA_Session *session,
                    const UA_HistoryReadRequest *request,
                    UA_HistoryReadResponse *response) {
    UA_assert(session != NULL);
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    if(server->config.historyDatabase.context == NULL) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADNOTSUPPORTED;
        return;
    }

    if(request->historyReadDetails.encoding != UA_EXTENSIONOBJECT_DECODED) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADNOTSUPPORTED;
        return;
    }

    const UA_DataType *historyDataType = &UA_TYPES[UA_TYPES_HISTORYDATA];
    UA_HistoryDatabase_readFunc readHistory = NULL;
    if(request->historyReadDetails.content.decoded.type ==
       &UA_TYPES[UA_TYPES_READRAWMODIFIEDDETAILS]) {
        UA_ReadRawModifiedDetails *details = (UA_ReadRawModifiedDetails*)
            request->historyReadDetails.content.decoded.data;
        if(!details->isReadModified) {
            readHistory = (UA_HistoryDatabase_readFunc)
                server->config.historyDatabase.readRaw;
        } else {
            historyDataType = &UA_TYPES[UA_TYPES_HISTORYMODIFIEDDATA];
            readHistory = (UA_HistoryDatabase_readFunc)
                server->config.historyDatabase.readModified;
        }
    } else if(request->historyReadDetails.content.decoded.type ==
              &UA_TYPES[UA_TYPES_READEVENTDETAILS]) {
        historyDataType = &UA_TYPES[UA_TYPES_HISTORYEVENT];
        readHistory = (UA_HistoryDatabase_readFunc)
            server->config.historyDatabase.readEvent;
    } else if(request->historyReadDetails.content.decoded.type ==
              &UA_TYPES[UA_TYPES_READPROCESSEDDETAILS]) {
        readHistory = (UA_HistoryDatabase_readFunc)
            server->config.historyDatabase.readProcessed;
    } else if(request->historyReadDetails.content.decoded.type ==
              &UA_TYPES[UA_TYPES_READATTIMEDETAILS]) {
        readHistory = (UA_HistoryDatabase_readFunc)
            server->config.historyDatabase.readAtTime;
    } else {
        
        response->responseHeader.serviceResult = UA_STATUSCODE_BADHISTORYOPERATIONUNSUPPORTED;
        return;
    }

    
    if(!readHistory) {
        UA_LOG_INFO_SESSION(server->config.logging, session,
                            "The configured HistoryBackend does not support the selected history-type");
        response->responseHeader.serviceResult = UA_STATUSCODE_BADNOTSUPPORTED;
        return;
    }

    
    if(request->nodesToReadSize == 0) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADNOTHINGTODO;
        return;
    }

    
    if(server->config.maxNodesPerRead != 0 &&
       request->nodesToReadSize > server->config.maxNodesPerRead) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTOOMANYOPERATIONS;
        return;
    }

    void **historyData = (void **)
        UA_calloc(request->nodesToReadSize, sizeof(void*));
    if(!historyData) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }

    
    response->results = (UA_HistoryReadResult*)
        UA_Array_new(request->nodesToReadSize, &UA_TYPES[UA_TYPES_HISTORYREADRESULT]);
    if(!response->results) {
        UA_free(historyData);
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }
    response->resultsSize = request->nodesToReadSize;

    for(size_t i = 0; i < response->resultsSize; ++i) {
        void * data = UA_new(historyDataType);
        UA_ExtensionObject_setValue(&response->results[i].historyData,
                                    data, historyDataType);
        historyData[i] = data;
    }
    UA_UNLOCK(&server->serviceMutex);
    readHistory(server, server->config.historyDatabase.context,
                &session->sessionId, session->context,
                &request->requestHeader,
                request->historyReadDetails.content.decoded.data,
                request->timestampsToReturn,
                request->releaseContinuationPoints,
                request->nodesToReadSize, request->nodesToRead,
                response, historyData);
    UA_LOCK(&server->serviceMutex);
    UA_free(historyData);
}

void
Service_HistoryUpdate(UA_Server *server, UA_Session *session,
                    const UA_HistoryUpdateRequest *request,
                    UA_HistoryUpdateResponse *response) {
    UA_assert(session != NULL);
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    response->resultsSize = request->historyUpdateDetailsSize;
    response->results = (UA_HistoryUpdateResult*)
        UA_Array_new(response->resultsSize, &UA_TYPES[UA_TYPES_HISTORYUPDATERESULT]);
    if(!response->results) {
        response->resultsSize = 0;
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }

    for(size_t i = 0; i < request->historyUpdateDetailsSize; ++i) {
        UA_HistoryUpdateResult_init(&response->results[i]);
        if(request->historyUpdateDetails[i].encoding != UA_EXTENSIONOBJECT_DECODED) {
            response->results[i].statusCode = UA_STATUSCODE_BADNOTSUPPORTED;
            continue;
        }

        const UA_DataType *updateDetailsType =
            request->historyUpdateDetails[i].content.decoded.type;
        void *updateDetailsData = request->historyUpdateDetails[i].content.decoded.data;

        if(updateDetailsType == &UA_TYPES[UA_TYPES_UPDATEDATADETAILS]) {
            if(!server->config.historyDatabase.updateData) {
                response->results[i].statusCode = UA_STATUSCODE_BADNOTSUPPORTED;
                continue;
            }
            UA_UNLOCK(&server->serviceMutex);
            server->config.historyDatabase.
                updateData(server, server->config.historyDatabase.context,
                           &session->sessionId, session->context,
                           &request->requestHeader,
                           (UA_UpdateDataDetails*)updateDetailsData,
                           &response->results[i]);
            UA_LOCK(&server->serviceMutex);
            continue;
        }

        if(updateDetailsType == &UA_TYPES[UA_TYPES_DELETERAWMODIFIEDDETAILS]) {
            if(!server->config.historyDatabase.deleteRawModified) {
                response->results[i].statusCode = UA_STATUSCODE_BADNOTSUPPORTED;
                continue;
            }
            UA_UNLOCK(&server->serviceMutex);
            server->config.historyDatabase.
                deleteRawModified(server, server->config.historyDatabase.context,
                                  &session->sessionId, session->context,
                                  &request->requestHeader,
                                  (UA_DeleteRawModifiedDetails*)updateDetailsData,
                                  &response->results[i]);
            UA_LOCK(&server->serviceMutex);
            continue;
        }

        response->results[i].statusCode = UA_STATUSCODE_BADNOTSUPPORTED;
    }
}

#endif

UA_StatusCode
UA_Server_writeObjectProperty(UA_Server *server, const UA_NodeId objectId,
                              const UA_QualifiedName propertyName,
                              const UA_Variant value) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retVal = writeObjectProperty(server, objectId, propertyName, value);
    UA_UNLOCK(&server->serviceMutex);
    return retVal;
}

UA_StatusCode
writeObjectProperty(UA_Server *server, const UA_NodeId objectId,
                    const UA_QualifiedName propertyName,
                    const UA_Variant value) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_RelativePathElement rpe;
    UA_RelativePathElement_init(&rpe);
    rpe.referenceTypeId = UA_NS0ID(HASPROPERTY);
    rpe.isInverse = false;
    rpe.includeSubtypes = false;
    rpe.targetName = propertyName;

    UA_BrowsePath bp;
    UA_BrowsePath_init(&bp);
    bp.startingNode = objectId;
    bp.relativePath.elementsSize = 1;
    bp.relativePath.elements = &rpe;

    UA_StatusCode retval;
    UA_BrowsePathResult bpr = translateBrowsePathToNodeIds(server, &bp);
    if(bpr.statusCode != UA_STATUSCODE_GOOD || bpr.targetsSize < 1) {
        retval = bpr.statusCode;
        UA_BrowsePathResult_clear(&bpr);
        return retval;
    }

    retval = writeValueAttribute(server, bpr.targets[0].targetId.nodeId, &value);

    UA_BrowsePathResult_clear(&bpr);
    return retval;
}

UA_StatusCode
writeObjectProperty_scalar(UA_Server *server, const UA_NodeId objectId,
                                     const UA_QualifiedName propertyName,
                                     const void *value, const UA_DataType *type) {
    UA_Variant var;
    UA_Variant_init(&var);
    UA_Variant_setScalar(&var, (void*)(uintptr_t)value, type);
    return writeObjectProperty(server, objectId, propertyName, var);
}

UA_StatusCode UA_EXPORT
UA_Server_writeObjectProperty_scalar(UA_Server *server, const UA_NodeId objectId,
                                     const UA_QualifiedName propertyName,
                                     const void *value, const UA_DataType *type) {
    UA_LOCK(&server->serviceMutex);
    UA_StatusCode retval = 
        writeObjectProperty_scalar(server, objectId, propertyName, value, type);
    UA_UNLOCK(&server->serviceMutex);
    return retval;
}

static UA_LocalizedText
getLocalizedForSession(const UA_Session *session,
                       const UA_LocalizedTextListEntry *root) {
    const UA_LocalizedTextListEntry *lt;
    UA_LocalizedText result;
    UA_LocalizedText_init(&result);

    
    if(!session)
        goto not_found;

    
    for(size_t i = 0; i < session->localeIdsSize; ++i) {
        for(lt = root; lt != NULL; lt = lt->next) {
            if(UA_String_equal(&session->localeIds[i], &lt->localizedText.locale))
                return lt->localizedText;
        }
    }

    
    for(size_t i = 0; i < session->localeIdsSize; ++i) {
        if(session->localeIds[i].length < 2 ||
           (session->localeIdsSize > 2 &&
            session->localeIds[i].data[2] != '-'))
            continue;

        UA_String requestedPrefix;
        requestedPrefix.data = session->localeIds[i].data;
        requestedPrefix.length = 2;

        for(lt = root; lt != NULL; lt = lt->next) {
            if(lt->localizedText.locale.length < 2 ||
               (lt->localizedText.locale.length > 2 &&
                lt->localizedText.locale.data[2] != '-'))
                continue;

            UA_String currentPrefix;
            currentPrefix.data = lt->localizedText.locale.data;
            currentPrefix.length = 2;

            if(UA_String_equal(&requestedPrefix, &currentPrefix))
                return lt->localizedText;
        }
    }

 not_found:
    if(!root)
        return result;
    while(root->next)
        root = root->next;
    return root->localizedText;
}

UA_LocalizedText
UA_Session_getNodeDisplayName(const UA_Session *session,
                              const UA_NodeHead *head) {
    return getLocalizedForSession(session, head->displayName);
}

UA_LocalizedText
UA_Session_getNodeDescription(const UA_Session *session,
                              const UA_NodeHead *head) {
    return getLocalizedForSession(session, head->description);
}
