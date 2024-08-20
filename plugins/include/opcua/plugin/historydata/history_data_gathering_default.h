
#ifndef UA_HISTORYDATAGATHERING_DEFAULT_H_
#define UA_HISTORYDATAGATHERING_DEFAULT_H_

#include "history_data_gathering.h"

_UA_BEGIN_DECLS

UA_HistoryDataGathering UA_EXPORT
UA_HistoryDataGathering_Default(size_t initialNodeIdStoreSize);

UA_HistoryDataGathering UA_EXPORT
UA_HistoryDataGathering_Circular(size_t initialNodeIdStoreSize);

_UA_END_DECLS

#endif 
