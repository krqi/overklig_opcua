
#ifndef UA_HISTORYDATABACKEND_MEMORY_H_
#define UA_HISTORYDATABACKEND_MEMORY_H_

#include "history_data_backend.h"

_UA_BEGIN_DECLS

#define INITIAL_MEMORY_STORE_SIZE 1000

UA_HistoryDataBackend UA_EXPORT
UA_HistoryDataBackend_Memory(size_t initialNodeIdStoreSize, size_t initialDataStoreSize);

UA_HistoryDataBackend UA_EXPORT
UA_HistoryDataBackend_Memory_Circular(size_t initialNodeIdStoreSize, size_t initialDataStoreSize);

void UA_EXPORT
UA_HistoryDataBackend_Memory_clear(UA_HistoryDataBackend *backend);

_UA_END_DECLS

#endif 
