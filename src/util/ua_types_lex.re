
#include <opcua/types.h>
#include <opcua/util.h>
#include <opcua/nodeids.h>
#include "base64.h"
#include "ua_util_internal.h"


#define YYCURSOR pos
#define YYMARKER context.marker
#define YYSKIP() ++YYCURSOR;
#define YYBACKUP() YYMARKER = YYCURSOR
#define YYRESTORE() YYCURSOR = YYMARKER
#define YYSTAGP(t) t = YYCURSOR
#define YYSTAGN(t) t = NULL
#define YYSHIFTSTAG(t, shift) t += shift

typedef struct {
    const char *marker;
    
} LexContext;


static UA_StatusCode
parse_guid(UA_Guid *guid, const UA_Byte *s, const UA_Byte *e) {
    size_t len = (size_t)(e - s);
    if(len != 36 || s[8] != '-' || s[13] != '-' || s[23] != '-')
        return UA_STATUSCODE_BADDECODINGERROR;

    UA_UInt32 tmp;
    if(UA_readNumberWithBase(s, 8, &tmp, 16) != 8)
        return UA_STATUSCODE_BADDECODINGERROR;
    guid->data1 = tmp;

    if(UA_readNumberWithBase(&s[9], 4, &tmp, 16) != 4)
        return UA_STATUSCODE_BADDECODINGERROR;
    guid->data2 = (UA_UInt16)tmp;

    if(UA_readNumberWithBase(&s[14], 4, &tmp, 16) != 4)
        return UA_STATUSCODE_BADDECODINGERROR;
    guid->data3 = (UA_UInt16)tmp;

    if(UA_readNumberWithBase(&s[19], 2, &tmp, 16) != 2)
        return UA_STATUSCODE_BADDECODINGERROR;
    guid->data4[0] = (UA_Byte)tmp;

    if(UA_readNumberWithBase(&s[21], 2, &tmp, 16) != 2)
        return UA_STATUSCODE_BADDECODINGERROR;
    guid->data4[1] = (UA_Byte)tmp;

    for(size_t pos = 2, spos = 24; pos < 8; pos++, spos += 2) {
        if(UA_readNumberWithBase(&s[spos], 2, &tmp, 16) != 2)
            return UA_STATUSCODE_BADDECODINGERROR;
        guid->data4[pos] = (UA_Byte)tmp;
    }

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Guid_parse(UA_Guid *guid, const UA_String str) {
    UA_StatusCode res = parse_guid(guid, str.data, str.data + str.length);
    if(res != UA_STATUSCODE_GOOD)
        *guid = UA_GUID_NULL;
    return res;
}

static UA_StatusCode
parse_nodeid_body(UA_NodeId *id, const char *body, const char *end) {
    size_t len = (size_t)(end - (body+2));
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    switch(*body) {
    case 'i': {
        if(UA_readNumber((const UA_Byte*)body+2, len, &id->identifier.numeric) != len)
            return UA_STATUSCODE_BADDECODINGERROR;
        id->identifierType = UA_NODEIDTYPE_NUMERIC;
        break;
    }
    case 's': {
        UA_String tmpstr;
        tmpstr.data = (UA_Byte*)(uintptr_t)body+2;
        tmpstr.length = len;
        res = UA_String_copy(&tmpstr, &id->identifier.string);
        if(res != UA_STATUSCODE_GOOD)
            break;
        id->identifierType = UA_NODEIDTYPE_STRING;
        break;
    }
    case 'g':
        res = parse_guid(&id->identifier.guid, (const UA_Byte*)body+2, (const UA_Byte*)end);
        if(res == UA_STATUSCODE_GOOD)
            id->identifierType = UA_NODEIDTYPE_GUID;
        break;
    case 'b':
        id->identifier.byteString.data =
            UA_unbase64((const unsigned char*)body+2, len,
                        &id->identifier.byteString.length);
        if(!id->identifier.byteString.data && len > 0)
            return UA_STATUSCODE_BADDECODINGERROR;
        id->identifierType = UA_NODEIDTYPE_BYTESTRING;
        break;
    default:
        return UA_STATUSCODE_BADDECODINGERROR;
    }
    return res;
}

static UA_StatusCode
parse_nodeid(UA_NodeId *id, const char *pos, const char *end) {
    *id = UA_NODEID_NULL; 
    LexContext context;
    memset(&context, 0, sizeof(LexContext));
    const char *ns = NULL, *nse= NULL;

}

UA_StatusCode
UA_NodeId_parse(UA_NodeId *id, const UA_String str) {
    UA_StatusCode res =
        parse_nodeid(id, (const char*)str.data, (const char*)str.data+str.length);
    if(res != UA_STATUSCODE_GOOD)
        UA_NodeId_clear(id);
    return res;
}

static UA_StatusCode
parse_expandednodeid(UA_ExpandedNodeId *id, const char *pos, const char *end) {
    *id = UA_EXPANDEDNODEID_NULL; 
    LexContext context;
    memset(&context, 0, sizeof(LexContext));
    const char *svr = NULL, *svre = NULL, *nsu = NULL, *ns = NULL, *body = NULL;

}

UA_StatusCode
UA_ExpandedNodeId_parse(UA_ExpandedNodeId *id, const UA_String str) {
    UA_StatusCode res =
        parse_expandednodeid(id, (const char*)str.data, (const char*)str.data+str.length);
    if(res != UA_STATUSCODE_GOOD)
        UA_ExpandedNodeId_clear(id);
    return res;
}

static UA_StatusCode
relativepath_addelem(UA_RelativePath *rp, UA_RelativePathElement *el) {
    
    UA_RelativePathElement *newArray = (UA_RelativePathElement*)
        UA_realloc(rp->elements, sizeof(UA_RelativePathElement) * (rp->elementsSize + 1));
    if(!newArray)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    rp->elements = newArray;

    
    rp->elements[rp->elementsSize] = *el;
    rp->elementsSize++;
    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode
parse_refpath_qn_name(UA_QualifiedName *qn, const char **pos, const char *end) {
    
    size_t maxlen = (size_t)(end - *pos);
    if(maxlen == 0) {
        qn->name.data = (UA_Byte*)UA_EMPTY_ARRAY_SENTINEL;
        return UA_STATUSCODE_GOOD;
    }
    char *name = (char*)UA_malloc(maxlen);
    if(!name)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    size_t index = 0;
    for(; *pos < end; (*pos)++) {
        char c = **pos;
        
        if(c == '/' || c == '.' || c == '<' || c == '>' ||
           c == ':' || c == '#' || c == '!')
            break;

        
        if(c == '&') {
            (*pos)++;
            if(*pos >= end ||
               (**pos != '/' && **pos != '.' && **pos != '<' && **pos != '>' &&
                **pos != ':' && **pos != '#' && **pos != '!' && **pos != '&')) {
                UA_free(name);
                return UA_STATUSCODE_BADDECODINGERROR;
            }
            c = **pos;
        }

        
        name[index] = c;
        index++;
    }

    if(index > 0) {
        qn->name.data = (UA_Byte*)name;
        qn->name.length = index;
    } else {
        qn->name.data = (UA_Byte*)UA_EMPTY_ARRAY_SENTINEL;
        UA_free(name);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
parse_refpath_qn(UA_QualifiedName *qn, const char *pos, const char *end) {
    LexContext context;
    memset(&context, 0, sizeof(LexContext));
    const char *ns = NULL, *nse = NULL;
    UA_QualifiedName_init(qn);


 parse_qn_name:
    return parse_refpath_qn_name(qn, &pos, end);
}

static UA_StatusCode
parse_relativepath(UA_Server *server, UA_RelativePath *rp, const UA_String str) {
    const char *pos = (const char*)str.data;
    const char *end = (const char*)(str.data + str.length);

    LexContext context;
    memset(&context, 0, sizeof(LexContext));
    const char *begin = NULL, *finish = NULL;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_RelativePath_init(rp); 

    
    UA_RelativePathElement current;
 loop:
    UA_RelativePathElement_init(&current);
    current.includeSubtypes = true; 

    

    
 reftype_target:
    if(res != UA_STATUSCODE_GOOD)
        return res;


    
 add_element:
    res |= relativepath_addelem(rp, &current);
    if(res != UA_STATUSCODE_GOOD) {
        UA_RelativePathElement_clear(&current);
        return res;
    }
    goto loop;
}

UA_StatusCode
UA_RelativePath_parse(UA_RelativePath *rp, const UA_String str) {
    UA_StatusCode res = parse_relativepath(NULL, rp, str);
    if(res != UA_STATUSCODE_GOOD)
        UA_RelativePath_clear(rp);
    return res;
}

UA_StatusCode
UA_RelativePath_parseWithServer(UA_Server *server, UA_RelativePath *rp,
                                const UA_String str) {
    UA_StatusCode res = parse_relativepath(server, rp, str);
    if(res != UA_STATUSCODE_GOOD)
        UA_RelativePath_clear(rp);
    return res;
}

UA_StatusCode
UA_SimpleAttributeOperand_parse(UA_SimpleAttributeOperand *sao,
                                const UA_String str) {
    
    UA_SimpleAttributeOperand_init(sao);

    
    UA_String edit_str;
    UA_StatusCode res = UA_String_copy(&str, &edit_str);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    char *pos = (char*)edit_str.data;
    char *end = (char*)(edit_str.data + edit_str.length);

    
    if(pos < end && *pos != '/' && *pos != '#' && *pos != '[') {
        char *typedef_pos = pos;
        pos = find_unescaped(pos, end, true);
        UA_String typeString = {(size_t)(pos - typedef_pos), (UA_Byte*)typedef_pos};
        UA_String_unescape(&typeString, true);
        res = UA_NodeId_parse(&sao->typeDefinitionId, typeString);
        if(res != UA_STATUSCODE_GOOD)
            goto cleanup;
    } else {
        
        sao->typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
    }

    
    while(pos < end && *pos == '/') {
        UA_QualifiedName browseName;
        UA_QualifiedName_init(&browseName);
        char *browsename_pos = ++pos;

        
        char *browsename_name_pos = pos;
        if(pos < end && *pos >= '0' && *pos <= '9') {
 check_colon:
            pos++;
            if(pos < end) {
                if(*pos >= '0' && *pos <= '9')
                    goto check_colon;
                if(*pos ==':')
                    browsename_name_pos = ++pos;
            }
        }

        
        pos = find_unescaped(browsename_name_pos, end, true);

        
        UA_String bnString = {(size_t)(pos - browsename_name_pos), (UA_Byte*)browsename_name_pos};
        UA_String_unescape(&bnString, true);

        
        res = parse_refpath_qn(&browseName, browsename_pos, (char*)bnString.data + bnString.length);
        if(res != UA_STATUSCODE_GOOD)
            goto cleanup;

        
        res = UA_Array_append((void**)&sao->browsePath, &sao->browsePathSize,
                              &browseName, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
        if(res != UA_STATUSCODE_GOOD) {
            UA_QualifiedName_clear(&browseName);
            goto cleanup;
        }
    }

    
    if(pos < end && *pos == '#') {
        
        char *attr_pos = ++pos;
        while(pos < end && ((*pos >= 'a' && *pos <= 'z') ||
                            (*pos >= 'A' && *pos <= 'Z'))) {
            pos++;
        }
        
        UA_String attrString = {(size_t)(pos - attr_pos), (UA_Byte*)attr_pos};
        sao->attributeId = UA_AttributeId_fromName(attrString);
        if(sao->attributeId == UA_ATTRIBUTEID_INVALID) {
            res = UA_STATUSCODE_BADDECODINGERROR;
            goto cleanup;
        }
    } else {
        
        sao->attributeId = UA_ATTRIBUTEID_VALUE;
    }

    if(pos < end && *pos == '[') {
        
        char *range_pos = ++pos;
        while(pos < end && *pos != ']') {
            pos++;
        }
        if(pos == end) {
            res = UA_STATUSCODE_BADDECODINGERROR;
            goto cleanup;
        }
        UA_String rangeString = {(size_t)(pos - range_pos), (UA_Byte*)range_pos};
        UA_NumericRange nr;
        memset(&nr, 0, sizeof(UA_NumericRange));
        res = UA_NumericRange_parse(&nr, rangeString);
        if(res != UA_STATUSCODE_GOOD)
            goto cleanup;
        res = UA_String_copy(&rangeString, &sao->indexRange);
        if(nr.dimensionsSize > 0)
            UA_free(nr.dimensions);
        pos++;
    }

    
    if(pos != end)
        res = UA_STATUSCODE_BADDECODINGERROR;

 cleanup:
    UA_String_clear(&edit_str);
    if(res != UA_STATUSCODE_GOOD)
        UA_SimpleAttributeOperand_clear(sao);
    return res;
}
