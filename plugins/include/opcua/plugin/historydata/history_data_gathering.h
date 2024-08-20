
#ifndef UA_PLUGIN_HISTORY_DATA_GATHERING_H_
#define UA_PLUGIN_HISTORY_DATA_GATHERING_H_

#include "history_data_backend.h"

_UA_BEGIN_DECLS

typedef enum {
} UA_HistorizingUpdateStrategy;

typedef struct {
    UA_HistoryDataBackend historizingBackend; 
    size_t pollingInterval; 
    void *userContext; 
} UA_HistorizingNodeIdSettings;

typedef struct UA_HistoryDataGathering UA_HistoryDataGathering;
struct UA_HistoryDataGathering {
    void *context;

    void
    (*deleteMembers)(UA_HistoryDataGathering *gathering);

    UA_StatusCode
    (*registerNodeId)(UA_Server *server,
                      void *hdgContext,
                      const UA_NodeId *nodeId,
                      const UA_HistorizingNodeIdSettings setting);

    UA_StatusCode
    (*stopPoll)(UA_Server *server,
                void *hdgContext,
                const UA_NodeId *nodeId);

    UA_StatusCode
    (*startPoll)(UA_Server *server,
                 void *hdgContext,
                 const UA_NodeId *nodeId);

    UA_Boolean
    (*updateNodeIdSetting)(UA_Server *server,
                           void *hdgContext,
                           const UA_NodeId *nodeId,
                           const UA_HistorizingNodeIdSettings setting);

    const UA_HistorizingNodeIdSettings*
    (*getHistorizingSetting)(UA_Server *server,
                             void *hdgContext,
                             const UA_NodeId *nodeId);

    void
    (*setValue)(UA_Server *server,
                void *hdgContext,
                const UA_NodeId *sessionId,
                void *sessionContext,
                const UA_NodeId *nodeId,
                UA_Boolean historizing,
                const UA_DataValue *value);
};

_UA_END_DECLS

#endif 
