#ifndef ATOI_H
#define ATOI_H

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_MSC_VER) || _MSC_VER >= 1800
# include <stddef.h>
# include <stdint.h>
# include <stdbool.h> 
#else
# include "ms_stdint.h"
# if !defined(__bool_true_false_are_defined)
#  define bool unsigned char
#  define true 1
#  define false 0
#  define __bool_true_false_are_defined
# endif
#endif


size_t parseUInt64(const char *str, size_t size, uint64_t *result);
size_t parseInt64(const char *str, size_t size, int64_t *result);
size_t parseDouble(const char *str, size_t size, double *result);
    
#ifdef __cplusplus
}
#endif

#endif 

