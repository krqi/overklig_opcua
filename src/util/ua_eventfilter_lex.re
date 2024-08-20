
#include <opcua/util.h>
#include "ua_eventfilter_parser.h"



#undef YYPEEK
#undef YYSKIP
#undef YYBACKUP
#undef YYRESTORE
#undef YYSHIFT
#undef YYSTAGP
#undef YYSTAGN
#undef YYSHIFTSTAG
#undef YYRESTORETAG
#define YYPEEK() (pos < end) ? *pos: 0
#define YYSKIP() ++pos;
#define YYBACKUP() m = pos;
#define YYRESTORE() pos = m;
#define YYSHIFT(shift) pos += shift
#define YYSTAGP(t) t = pos
#define YYSTAGN(t) t = NULL
#define YYSHIFTSTAG(t, shift) t += shift
#define YYRESTORETAG(t) pos = t;


UA_StatusCode
UA_EventFilter_skip(const UA_ByteString content, size_t *offset,
                    EFParseContext *ctx) {
    const char *pos = (const char*)&content.data[*offset];
    const char *end = (const char*)&content.data[content.length];

  begin:
    *offset = (uintptr_t)(pos - (const char*)content.data);
    size_t initial = *offset;

}

int
UA_EventFilter_lex(const UA_ByteString content, size_t *offset,
                   EFParseContext *ctx, Operand **token) {
    const char *pos = (const char*)&content.data[*offset];
    const char *end = (const char*)&content.data[content.length];
    const char *m, *b; 
    
    const UA_DataType *lt; 
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_ByteString match;
    UA_FilterOperator f;

    int tokenId = 0;
    while(true) {
        
        b = pos;

    }

unary_op:
    tokenId = EF_TOK_UNARY_OP;
    goto make_op;

binary_op:
    tokenId = EF_TOK_BINARY_OP;
    goto make_op;

make_op:
    *token = create_operand(ctx, OT_OPERATOR);
    (*token)->operand.op.filter = f;
    goto finish;

namedoperand:
    *token = create_operand(ctx, OT_REF);
    size_t nameSize = (uintptr_t)(pos - b);
    (*token)->operand.ref = (char*)UA_malloc(nameSize+1);
    memcpy((*token)->operand.ref, b, nameSize);
    (*token)->operand.ref[nameSize] = 0;
    tokenId = EF_TOK_NAMEDOPERAND;
    goto finish;

json:
    
    match.length = (uintptr_t)(end-b);
    match.data = (UA_Byte*)(uintptr_t)b;
    *token = create_operand(ctx, OT_LITERAL);
    UA_DecodeJsonOptions options;
    memset(&options, 0, sizeof(UA_DecodeJsonOptions));
    size_t jsonOffset = 0;
    options.decodedLength = &jsonOffset;
    res = UA_decodeJson(&match, &(*token)->operand.literal,
                        &UA_TYPES[UA_TYPES_VARIANT], &options);
    tokenId = (res == UA_STATUSCODE_GOOD) ? EF_TOK_LITERAL : 0;
    pos = b + jsonOffset;
    goto finish;

lit:
    
    match.length = (uintptr_t)(pos-b);
    match.data = (UA_Byte*)(uintptr_t)b;
    *token = create_operand(ctx, OT_LITERAL);
    (*token)->operand.literal.data = UA_new(lt);
    (*token)->operand.literal.type = lt;
    if(lt == &UA_TYPES[UA_TYPES_NODEID]) {
        res = UA_NodeId_parse((UA_NodeId*)(*token)->operand.literal.data, match);
    } else if(lt == &UA_TYPES[UA_TYPES_EXPANDEDNODEID]) {
        res = UA_ExpandedNodeId_parse((UA_ExpandedNodeId*)(*token)->operand.literal.data, match);
    } else if(lt == &UA_TYPES[UA_TYPES_GUID]) {
        res = UA_Guid_parse((UA_Guid*)(*token)->operand.literal.data, match);
    } else {
        res = UA_decodeJson(&match, (*token)->operand.literal.data, lt, NULL);
    }
    tokenId = (res == UA_STATUSCODE_GOOD) ? EF_TOK_LITERAL : 0;
    goto finish;

sao:
    
    match.length = (uintptr_t)(pos-b);
    match.data = (UA_Byte*)(uintptr_t)b;
    *token = create_operand(ctx, OT_SAO);
    res = UA_SimpleAttributeOperand_parse(&(*token)->operand.sao, match);
    tokenId = (res == UA_STATUSCODE_GOOD) ? EF_TOK_SAO : 0;

finish:
    if(pos > end)
        pos = end;

    
    if(tokenId != 0)
        *offset = (uintptr_t)(pos - (const char*)content.data);

    return tokenId;
}
