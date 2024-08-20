
#ifndef MP_PRINTF_H
#define MP_PRINTF_H

#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int  mp_snprintf(char* s, size_t count, const char* format, ...);
int mp_vsnprintf(char* s, size_t count, const char* format, va_list arg);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // MP_PRINTF_H
