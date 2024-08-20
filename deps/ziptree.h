
#ifndef	ZIPTREE_H_
#define	ZIPTREE_H_

#include <stddef.h>

#ifdef _MSC_VER
# define ZIP_INLINE __inline
#else
# define ZIP_INLINE inline
#endif

#if defined(__GNUC__) || defined(__clang__)
# define ZIP_UNUSED __attribute__((unused))
#else
# define ZIP_UNUSED
#endif

#ifdef __cplusplus
extern "C" {
#endif


#define ZIP_HEAD(name, type)                    \
struct name {                                   \
    struct type *root;                          \
}

#define ZIP_ENTRY(type)                         \
struct {                                        \
    struct type *left;                          \
    struct type *right;                         \
}

enum ZIP_CMP {
    ZIP_CMP_LESS = -1,
    ZIP_CMP_EQ = 0,
    ZIP_CMP_MORE = 1
};

typedef enum ZIP_CMP (*zip_cmp_cb)(const void *key1, const void *key2);

#define ZIP_INIT(head) do { (head)->root = NULL; } while (0)
#define ZIP_ROOT(head) (head)->root
#define ZIP_LEFT(elm, field) (elm)->field.left
#define ZIP_RIGHT(elm, field) (elm)->field.right
#define ZIP_INSERT(name, head, elm) name##_ZIP_INSERT(head, elm)
#define ZIP_FIND(name, head, key) name##_ZIP_FIND(head, key)
#define ZIP_MIN(name, head) name##_ZIP_MIN(head)
#define ZIP_MAX(name, head) name##_ZIP_MAX(head)


#define ZIP_REMOVE(name, head, elm) name##_ZIP_REMOVE(head, elm)

#define ZIP_ZIP(name, left, right) name##_ZIP_ZIP(left, right)
#define ZIP_UNZIP(name, head, key, left, right) \
    name##_ZIP_UNZIP(head, key, left, right)

typedef void * (*zip_iter_cb)(void *context, void *elm);
#define ZIP_ITER(name, head, cb, ctx) name##_ZIP_ITER(head, cb, ctx)


#define ZIP_ITER_KEY(name, head, key, cb, ctx) name##_ZIP_ITER_KEY(head, key, cb, ctx)


#define ZIP_FUNCTIONS(name, type, field, keytype, keyfield, cmp)        \
                                                                        \
ZIP_UNUSED static ZIP_INLINE void                                       \
name##_ZIP_INSERT(struct name *head, struct type *el) {                 \
    __ZIP_INSERT(head, (zip_cmp_cb)cmp, offsetof(struct type, field),   \
                 offsetof(struct type, keyfield), el);                  \
}                                                                       \
                                                                        \
ZIP_UNUSED static ZIP_INLINE struct type *                              \
name##_ZIP_REMOVE(struct name *head, struct type *elm) {                \
    return (struct type*)                                               \
        __ZIP_REMOVE(head, (zip_cmp_cb)cmp,                             \
                     offsetof(struct type, field),                      \
                     offsetof(struct type, keyfield), elm);             \
}                                                                       \
                                                                        \
ZIP_UNUSED static ZIP_INLINE struct type *                              \
name##_ZIP_FIND(struct name *head, const keytype *key) {                \
    struct type *cur = ZIP_ROOT(head);                                  \
    while(cur) {                                                        \
        enum ZIP_CMP eq = cmp(key, &cur->keyfield);                     \
        if(eq == ZIP_CMP_EQ)                                            \
            break;                                                      \
        if(eq == ZIP_CMP_LESS)                                          \
            cur = ZIP_LEFT(cur, field);                                 \
        else                                                            \
            cur = ZIP_RIGHT(cur, field);                                \
    }                                                                   \
    return cur;                                                         \
}                                                                       \
                                                                        \
ZIP_UNUSED static ZIP_INLINE struct type *                              \
name##_ZIP_MIN(struct name *head) {                                     \
    struct type *cur = ZIP_ROOT(head);                                  \
    if(!cur)                                                            \
        return NULL;                                                    \
    while(ZIP_LEFT(cur, field)) {                                       \
        cur = ZIP_LEFT(cur, field);                                     \
    }                                                                   \
    return cur;                                                         \
}                                                                       \
                                                                        \
ZIP_UNUSED static ZIP_INLINE struct type *                              \
name##_ZIP_MAX(struct name *head) {                                     \
    struct type *cur = ZIP_ROOT(head);                                  \
    if(!cur)                                                            \
        return NULL;                                                    \
    while(ZIP_RIGHT(cur, field)) {                                      \
        cur = ZIP_RIGHT(cur, field);                                    \
    }                                                                   \
    return cur;                                                         \
}                                                                       \
                                                                        \
typedef void * (*name##_cb)(void *context, struct type *elm);           \
                                                                        \
ZIP_UNUSED static ZIP_INLINE void *                                     \
name##_ZIP_ITER(struct name *head, name##_cb cb, void *context) {       \
    return __ZIP_ITER(offsetof(struct type, field), (zip_iter_cb)cb,    \
                      context, ZIP_ROOT(head));                         \
}                                                                       \
                                                                        \
ZIP_UNUSED static ZIP_INLINE void *                                     \
name##_ZIP_ITER_KEY(struct name *head, const keytype *key,              \
                    name##_cb cb, void *context) {                      \
    return __ZIP_ITER_KEY((zip_cmp_cb)cmp, offsetof(struct type, field), \
                          offsetof(struct type, keyfield), key,         \
                          (zip_iter_cb)cb, context, ZIP_ROOT(head));    \
}                                                                       \
                                                                        \
ZIP_UNUSED static ZIP_INLINE struct type *                              \
name##_ZIP_ZIP(struct type *left, struct type *right) {                 \
    return (struct type*)                                               \
        __ZIP_ZIP(offsetof(struct type, field), left, right);           \
}                                                                       \
                                                                        \
ZIP_UNUSED static ZIP_INLINE void                                       \
name##_ZIP_UNZIP(struct name *head, const keytype *key,                 \
                 struct name *left, struct name *right) {               \
    __ZIP_UNZIP((zip_cmp_cb)cmp, offsetof(struct type, field),          \
                offsetof(struct type, keyfield), key,                   \
                head, left, right);                                     \
}



void
__ZIP_INSERT(void *h, zip_cmp_cb cmp, unsigned short fieldoffset,
             unsigned short keyoffset, void *elm);

void *
__ZIP_REMOVE(void *h, zip_cmp_cb cmp, unsigned short fieldoffset,
             unsigned short keyoffset, void *elm);

void *
__ZIP_ITER(unsigned short fieldoffset, zip_iter_cb cb,
           void *context, void *elm);

void *
__ZIP_ITER_KEY(zip_cmp_cb cmp, unsigned short fieldoffset,
               unsigned short keyoffset, const void *key,
               zip_iter_cb cb, void *context, void *elm);

void *
__ZIP_ZIP(unsigned short fieldoffset, void *left, void *right);

void
__ZIP_UNZIP(zip_cmp_cb cmp, unsigned short fieldoffset,
            unsigned short keyoffset, const void *key,
            void *h, void *l, void *r);

#ifdef __cplusplus
} 
#endif

#endif 
