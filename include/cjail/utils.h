#ifndef CJAIL_UTILS_H
#define CJAIL_UTILS_H

typedef struct _int_table {
    char *name;
    long value;
} table_int32;
long table_to_int(const table_int32 *table, const char *str);
const char *table_to_str(const table_int32 *table, long value);

typedef struct _uint_table {
    char *name;
    unsigned long value;
} table_uint32;
unsigned long utable_to_uint(const table_uint32 *table, const char *str);
const char *utable_to_str(const table_uint32 *table, unsigned long value);

#endif
