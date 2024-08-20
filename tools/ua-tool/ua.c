

#if !defined(_XOPEN_SOURCE)
# define _XOPEN_SOURCE 600
#endif
#ifndef _DEFAULT_SOURCE
# define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
# define _BSD_SOURCE
#endif

#include <stdio.h>
#include <ctype.h>
#include <opcua/client.h>
#include <opcua/client_config_default.h>

static UA_Client *client = NULL;
static UA_NodeId nodeidval = {0};
static char *url = NULL;
static char *service = NULL;
static char *nodeid = NULL;
static char *value = NULL;
#ifdef UA_ENABLE_JSON_ENCODING
static UA_Boolean json = false;
#endif

static void
usage(void) {
    printf("Usage: ua <server-url> <service> [--json] [--help]\n"
           " <server-url>: opc.tcp://domain[:port]\n"
           " <service> -> getendpoints: Log the endpoint descriptions of the server\n"
           " <service> -> read <nodeid>: Read an attribute of the node\n"
           "   --attr <attribute-id | attribute-name>: Attribute to read from the node. "
           "[default: value]\n"
           //" <service> -> browse <nodeid>: Browse the Node\n"
           //" <service> -> call <method-id> <object-id> <arguments>: Call the method \n"
           //" <service> -> write <nodeid> <value>: Write an attribute of the node\n"
#ifdef UA_ENABLE_JSON_ENCODING
           " --json: Format output as JSON\n"
#endif
           " --help: Print this message\n");
}

static void
printType(void *p, const UA_DataType *type) {
    UA_ByteString out = UA_BYTESTRING_NULL;
#ifdef UA_ENABLE_JSON_ENCODING
    if(!json) {
        UA_print(p, type, &out);
    } else {
        UA_StatusCode res = UA_encodeJson(p, type, &out, NULL);
        (void)res;
    }
#else
    UA_print(p, type, &out);
#endif
    printf("%.*s\n", (int)out.length, out.data);
    UA_ByteString_clear(&out);
}

static void
abortWithStatus(UA_StatusCode res) {
    printf("Aborting with status code %s\n", UA_StatusCode_name(res));
}

static int
getEndpoints(int argc, char **argv) {
    client = UA_Client_new();
    if(!client)
        return -1;
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    
    size_t endpointDescriptionsSize = 0;
    UA_EndpointDescription* endpointDescriptions = NULL;
    UA_StatusCode res = UA_Client_getEndpoints(client, url,
                                               &endpointDescriptionsSize,
                                               &endpointDescriptions);
    UA_Client_delete(client);
    if(res != UA_STATUSCODE_GOOD) {
        abortWithStatus(res);
        return -1;
    }

    
    UA_Variant var;
    UA_Variant_setArray(&var, endpointDescriptions, endpointDescriptionsSize,
                        &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    printType(&var, &UA_TYPES[UA_TYPES_VARIANT]);

    UA_Variant_clear(&var); 
    return 0;
}

static int
parseNodeId(void) {
    UA_StatusCode res = UA_NodeId_parse(&nodeidval, UA_STRING(nodeid));
    if(res != UA_STATUSCODE_GOOD) {
        printf("Could not parse the NodeId\n");
        return -1;
    }
    return 0;
}

static int
connectClient(void) {
    client = UA_Client_new();
    if(!client)
        return -1;
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    UA_StatusCode res = UA_Client_connect(client, url);
    if(res != UA_STATUSCODE_GOOD) {
        abortWithStatus(res);
        return -1;
    }
    return 0;
}

static const char *attributeIds[27] = {
    "nodeid", "nodeclass", "browsename", "displayname", "description",
    "writemask", "userwritemask", "isabstract", "symmetric", "inversename",
    "containsnoloops", "eventnotifier", "value", "datatype", "valuerank",
    "arraydimensions", "accesslevel", "useraccesslevel",
    "minimumsamplinginterval", "historizing", "executable", "userexecutable",
    "datatypedefinition", "rolepermissions", "userrolepermissions",
    "accessrestrictions", "accesslevelex"
};

static int
readAttr(int argc, char **argv) {
    
    UA_UInt32 attr = UA_ATTRIBUTEID_VALUE;
    for(int argpos = 1; argpos < argc; argpos++) {
        if(argv[argpos] == NULL)
            continue;
        if(strcmp(argv[argpos], "--attr") == 0) {
            argpos++;
            if(argpos == argc) {
                usage();
                return -1;
            }

            
            attr = (UA_UInt32)atoi(argv[argpos]);
            if(attr != 0)
                continue;

            
            for(char *w = argv[argpos]; *w; w++)
                *w = (char)tolower(*w);
            for(UA_UInt32 i = 0; i < 26; i++) {
                if(strcmp(argv[argpos], attributeIds[i]) == 0) {
                    attr = i+1;
                    break;
                }
            }
            if(attr != 0)
                continue;
            usage();
            return -1;
        }

        
        usage();
        return -1;
    }

    int ret = parseNodeId();
    if(ret != 0)
        return ret;

    ret = connectClient();
    if(ret != 0) {
        UA_NodeId_clear(&nodeidval);
        return ret;
    }

    
    UA_ReadValueId rvid;
    UA_ReadValueId_init(&rvid);
    rvid.nodeId = nodeidval;
    rvid.attributeId = attr;

    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;
    req.nodesToReadSize = 1;
    req.nodesToRead = &rvid;

    UA_ReadResponse resp = UA_Client_Service_read(client, req);
    UA_Client_delete(client);

    
    if(resp.responseHeader.serviceResult == UA_STATUSCODE_GOOD &&
       resp.resultsSize != 1)
        resp.responseHeader.serviceResult = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(resp.responseHeader.serviceResult == UA_STATUSCODE_GOOD)
        printType(&resp.results[0], &UA_TYPES[UA_TYPES_DATAVALUE]);
    else
        abortWithStatus(resp.responseHeader.serviceResult);

    UA_ReadResponse_clear(&resp);
    UA_NodeId_clear(&nodeidval);
    return 0;
}

int
main(int argc, char **argv) {
    if(argc < 3) {
        usage();
        return 0;
    }

    
    if(strstr(argv[1], "--") == argv[1]) {
        usage();
        return -1;
    }
    url = argv[1];
    argv[1] = NULL;

    
    service = argv[2];
    argv[2] = NULL;

    
    int argpos = 3;
    if(argc > argpos && strstr(argv[argpos], "--") != argv[argpos]) {
        nodeid = argv[argpos];
        argv[argpos] = NULL;
        argpos++;

        
        if(argc > argpos && strstr(argv[argpos], "--") != argv[argpos]) {
            value = argv[argpos];
            argv[argpos] = NULL;
            argpos++;
        }
    }

    
    for(; argpos < argc; argpos++) {
        if(strcmp(argv[argpos], "--help") == 0) {
            usage();
            return 0;
        }

#ifdef UA_ENABLE_JSON_ENCODING
        if(strcmp(argv[argpos], "--json") == 0) {
            json = true;
            argv[argpos] = NULL;
            continue;
        }
#endif
    }

    
    if(strcmp(service, "getendpoints") == 0) {
        if(!nodeid && !value)
            return getEndpoints(argc, argv);
    } else if(strcmp(service, "read") == 0) {
        if(nodeid && !value)
            return readAttr(argc, argv);
    }
    //else if(strcmp(service, "browse") == 0) {
    //    if(nodeid && !value)
    //        return browse(argc, argv);
    //}
    //else if(strcmp(argv[1], "write") == 0) {
    //    if(nodeid && value)
    //        return writeAttr(argc-argpos, &argv[argpos]);
    //}

    
    usage();
    return -1;
}
