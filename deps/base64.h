#ifndef UA_BASE64_H_
#define UA_BASE64_H_

#include <opcua/config.h>

_UA_BEGIN_DECLS

#include <stddef.h>

unsigned char *
UA_base64(const unsigned char *src, size_t len, size_t *out_len);

size_t
UA_base64_buf(const unsigned char *src, size_t len, unsigned char *out);

unsigned char *
UA_unbase64(const unsigned char *src, size_t len, size_t *out_len);

_UA_END_DECLS

#endif 
