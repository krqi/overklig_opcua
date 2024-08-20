
#include "ua_eventfilter_parser.h"

void
pos2lines(const UA_ByteString content, size_t pos,
          unsigned *outLine, unsigned *outCol) {
    unsigned line = 1, col = 1;
    for(size_t i = 0; i < pos; i++) {
        if(content.data[i] == '\n') {
            line++;
            col = 1;
        } else {
            col++;
        }
    }
    *outLine = line;
    *outCol = col;
}

static Operand *
newOperand(EFParseContext *ctx) {
    Operand *op = (Operand*)UA_calloc(1, sizeof(Operand));
    LIST_INSERT_HEAD(&ctx->operands, op, entries);
    ctx->operandsSize++;
    return op;
}

static Operand *
findOperand(EFParseContext *ctx, char *ref) {
    Operand *temp, *found = NULL;
    LIST_FOREACH(temp, &ctx->operands, entries) {
        if(!temp->ref || strcmp(temp->ref, ref) != 0)
            continue;
        if(found) {
            UA_LOG_ERROR(ctx->logger, UA_LOGCATEGORY_USERLAND,
                         "Duplicate definition of operand reference %s", ref);
            return NULL;
        }
        found = temp;
    }
    if(!found) {
        UA_LOG_ERROR(ctx->logger, UA_LOGCATEGORY_USERLAND,
                     "Failed to find the operand reference %s", ref);
    }
    return found;
}

static Operand *
resolveOperandRef(EFParseContext *ctx, Operand *op, size_t depth) {
    if(depth > ctx->operandsSize)
        return NULL; 
    if(!op)
        return NULL;
    if(op->type != OT_REF)
        return op;
    return resolveOperandRef(ctx, findOperand(ctx, op->operand.ref), depth+1);
}

static void
deleteOperand(Operand *on) {
    UA_free(on->ref);
    if(on->type == OT_OPERATOR) {
        UA_free(on->operand.op.children);
    } else if(on->type == OT_REF) {
        UA_free(on->operand.ref);
    } else if(on->type == OT_SAO) {
        UA_SimpleAttributeOperand_clear(&on->operand.sao);
    } else if(on->type == OT_LITERAL) {
        UA_Variant_clear(&on->operand.literal);
    }
    UA_free(on);
}

void
EFParseContext_clear(EFParseContext *ctx) {
    Operand *temp, *temp1;
    LIST_FOREACH_SAFE(temp, &ctx->operands, entries, temp1) {
        LIST_REMOVE(temp, entries);
        deleteOperand(temp);
    }
}

void append_select(EFParseContext *ctx, Operand *on) {
    TAILQ_INSERT_TAIL(&ctx->select_operands, on, select_entries);
}

char *
save_string(char *str) {
    char *local_str = (char*) UA_calloc(strlen(str)+1, sizeof(char));
    strcpy(local_str, str);
    return local_str;
}

Operand *
create_operand(EFParseContext *ctx, OperandType ot) {
    Operand *on = newOperand(ctx);
    on->type = ot;
    return on;
}

Operand *
create_operator(EFParseContext *ctx, UA_FilterOperator fo) {
    Operand *on = create_operand(ctx, OT_OPERATOR);
    on->operand.op.filter = fo;
    return on;
}

void
append_operand(Operand *op, Operand *on) {
    Operator *optr = &op->operand.op;
    optr->children = (Operand**)
        UA_realloc(optr->children, (optr->childrenSize + 1) * sizeof(Operand*));
    optr->children[optr->childrenSize] = on;
    optr->childrenSize++;
}

static size_t
markPrinted(EFParseContext *ctx, Operand *top, UA_StatusCode *res) {
    top = resolveOperandRef(ctx, top, 0);
    if(!top) {
        *res |= UA_STATUSCODE_BADINTERNALERROR;
        return 0;
    }
    if(top->type != OT_OPERATOR)
        return 0; 
    if(top->operand.op.required)
        return 0; 
    top->operand.op.required = true;
    size_t count = 1;
    for(size_t i = 0; i < top->operand.op.childrenSize; i++)
        count += markPrinted(ctx, top->operand.op.children[i], res);
    return count;
}

static Operator *
getPrintable(EFParseContext *ctx) {
    Operand *on;
    LIST_FOREACH(on, &ctx->operands, entries) {
        if(on->type != OT_OPERATOR)
            continue;

        Operator *op = &on->operand.op;
        if(!op->required || op->elementIndex > 0)
            continue; 

        
        size_t i = 0;
        for(; i < op->childrenSize; i++) {
            Operand *op_i = resolveOperandRef(ctx, op->children[i], 0);
            if(op_i->type == OT_OPERATOR && op_i->operand.op.elementIndex == 0)
                break;
        }
        if(i == op->childrenSize)
            return op; 
    }
    return NULL;
}

static UA_StatusCode
printOperator(EFParseContext *ctx, UA_ContentFilterElement *elm, Operator *op) {
    UA_ContentFilterElement_init(elm);
    elm->filterOperandsSize = op->childrenSize;
    elm->filterOperands = (UA_ExtensionObject*)
        UA_calloc(op->childrenSize, sizeof(UA_ExtensionObject));
    elm->filterOperator = op->filter;
    for(size_t i = 0; i < op->childrenSize; i++) {
        Operand *op_i = resolveOperandRef(ctx, op->children[i], 0);
        if(op_i->type == OT_OPERATOR) {
            UA_ElementOperand *elmo = UA_ElementOperand_new();
            elmo->index = (UA_UInt32)op_i->operand.op.elementIndex;
            UA_ExtensionObject_setValue(&elm->filterOperands[i], elmo,
                                        &UA_TYPES[UA_TYPES_ELEMENTOPERAND]);
        } else if(op_i->type == OT_SAO) {
            UA_SimpleAttributeOperand *sao = UA_SimpleAttributeOperand_new();
            UA_SimpleAttributeOperand_copy(&op_i->operand.sao, sao);
            UA_ExtensionObject_setValue(&elm->filterOperands[i], sao,
                                        &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
        } else if(op_i->type == OT_LITERAL) {
            UA_LiteralOperand *lit = UA_LiteralOperand_new();
            UA_Variant_copy(&op_i->operand.literal, &lit->value);
            UA_ExtensionObject_setValue(&elm->filterOperands[i], lit,
                                        &UA_TYPES[UA_TYPES_LITERALOPERAND]);
        }
    }
    return UA_STATUSCODE_GOOD;
}

// #define UA_EVENTFILTERPARSER_DEBUG 1

#ifdef UA_EVENTFILTERPARSER_DEBUG
#include <stdio.h>
static void
debug_element(Operand *on) {
    if(on->ref)
        printf("%s: ", on->ref);
    if(on->type == OT_REF) {
        printf("-> %s\n", on->operand.ref);
    } else if(on->type == OT_OPERATOR) {
        printf("Operator %i\n", (int)on->operand.op.filter);
    } else if(on->type == OT_SAO) {
        printf("SAO\n");
    } else if(on->type == OT_LITERAL) {
        printf("Literal\n");
    }
}
#endif

UA_StatusCode
create_filter(EFParseContext *ctx, UA_EventFilter *filter) {
#ifdef UA_EVENTFILTERPARSER_DEBUG
    Operand *temp;
    LIST_FOREACH(temp, &ctx->operands, entries) {
        debug_element(temp);
    }
#endif

    
    Operand *sao;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    TAILQ_FOREACH(sao, &ctx->select_operands, select_entries) {
        sao = resolveOperandRef(ctx, sao, 0);
        if(!sao)
            return UA_STATUSCODE_BADINTERNALERROR;
        if(sao->type != OT_SAO) {
            UA_LOG_ERROR(ctx->logger, UA_LOGCATEGORY_USERLAND,
                         "The select clause must only contain SimpleAttributeOperands");
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        res = UA_Array_append((void **)&filter->selectClauses,
                              &filter->selectClausesSize, &sao->operand.sao,
                              &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    
    if(!ctx->top)
        return UA_STATUSCODE_GOOD; 

    Operand *top = resolveOperandRef(ctx, ctx->top, 0);
    if(!top || top->type != OT_OPERATOR) {
        UA_LOG_ERROR(ctx->logger, UA_LOGCATEGORY_USERLAND,
                     "The where clause has no top-level operator");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    size_t count = markPrinted(ctx, top, &res); 
    if(res != UA_STATUSCODE_GOOD)
        return res;

    
    filter->whereClause.elements = (UA_ContentFilterElement*)
        UA_Array_new(count, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENT]);
    filter->whereClause.elementsSize = count;

    
    Operator *printable;
    while(count > 0 && (printable = getPrintable(ctx))) {
        count--;
        res |= printOperator(ctx, &filter->whereClause.elements[count], printable);
        printable->elementIndex = count;
    }

    if(count > 0) {
        UA_LOG_ERROR(ctx->logger, UA_LOGCATEGORY_USERLAND,
                     "Cyclic operand references detected");
        res |= UA_STATUSCODE_BADINTERNALERROR;
    }

    return res;
}
