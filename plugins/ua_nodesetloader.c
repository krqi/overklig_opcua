
#include <opcua/plugin/nodesetloader.h>
#include <NodesetLoader/backendopcua.h>
#include <NodesetLoader/dataTypes.h>
#include <opcua/server.h>

UA_StatusCode
UA_Server_loadNodeset(UA_Server *server, const char *nodeset2XmlFilePath,
                      UA_NodeSetLoaderOptions *options) {
    if(!NodesetLoader_loadFile(server,
                               nodeset2XmlFilePath,
                               (NodesetLoader_ExtensionInterface*)options)) {
        return UA_STATUSCODE_BAD;
    }

    return UA_STATUSCODE_GOOD;
}
