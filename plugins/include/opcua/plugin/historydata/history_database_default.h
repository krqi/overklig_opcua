
#ifndef UA_HISTORYDATASERVICE_DEFAULT_H_
#define UA_HISTORYDATASERVICE_DEFAULT_H_

#include <opcua/plugin/historydatabase.h>

#include "history_data_gathering.h"

_UA_BEGIN_DECLS

UA_HistoryDatabase UA_EXPORT
UA_HistoryDatabase_default(UA_HistoryDataGathering gathering);

_UA_END_DECLS

#endif 
