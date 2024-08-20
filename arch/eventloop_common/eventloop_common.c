
#include "eventloop_common.h"

UA_StatusCode
UA_KeyValueRestriction_validate(const UA_Logger *logger, const char *logprefix,
                                const UA_KeyValueRestriction *restrictions,
                                size_t restrictionsSize,
                                const UA_KeyValueMap *map) {
    for(size_t i = 0; i < restrictionsSize; i++) {
        const UA_KeyValueRestriction *r = &restrictions[i];
        const UA_Variant *val = UA_KeyValueMap_get(map, r->name);

        
        if(!val) {
            if(r->required) {
                UA_LOG_WARNING(logger, UA_LOGCATEGORY_USERLAND,
                               "%s\t| Parameter %.*s required but not defined",
                               logprefix, (int)r->name.name.length, (char*)r->name.name.data);
                return UA_STATUSCODE_BADINTERNALERROR;
            }
            continue;
        }

        
        if(val->type != r->type) {
            UA_LOG_WARNING(logger, UA_LOGCATEGORY_USERLAND,
                           "%s\t| Parameter %.*s has the wrong type",
                           logprefix, (int)r->name.name.length, (char*)r->name.name.data);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        
        UA_Boolean scalar = UA_Variant_isScalar(val);
        if(scalar && !r->scalar) {
            UA_LOG_WARNING(logger, UA_LOGCATEGORY_USERLAND,
                           "%s\t| Parameter %.*s must not be scalar",
                           logprefix, (int)r->name.name.length, (char*)r->name.name.data);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        if(!scalar && !r->array) {
            UA_LOG_WARNING(logger, UA_LOGCATEGORY_USERLAND,
                           "%s\t| Parameter %.*s must not be an array",
                           logprefix, (int)r->name.name.length, (char*)r->name.name.data);
            return UA_STATUSCODE_BADCONNECTIONREJECTED;
        }
    }

    return UA_STATUSCODE_GOOD;
}
