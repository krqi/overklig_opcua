
#ifndef ITOA_H
#define ITOA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <opcua/types.h>

UA_UInt16 itoaUnsigned(UA_UInt64 value, char* buffer, UA_Byte base);
UA_UInt16 itoaSigned(UA_Int64 value, char* buffer);

#ifdef __cplusplus
}
#endif

#endif 

