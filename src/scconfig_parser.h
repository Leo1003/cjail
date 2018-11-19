/**
 * @internal
 * @file scconfig_parser.h
 * @brief parsing seccomp config file library header
 */
#ifndef SCCONFIG_PARSER_H
#define SCCONFIG_PARSER_H

#include <stdio.h>
#include "simple_seccomp.h"
#include "utils.h"

#define SCOPT_IGN_NOSYS     0x00000001
#define SCOPT_IGN_NORULE    0x00000002

#define CMD_MAX_LENGTH  16
#define VAL_MAX_LENGTH  64

//Default naming defines
#define PARSER_CMD_TYPE     "TYPE"
#define PARSER_CMD_ACTION   "ACTION"
#define PARSER_CMD_ALLOW    "ALLOW"
#define PARSER_CMD_DENY     "DENY"

#define PARSER_TYPE_WHITE   "WHITELIST"
#define PARSER_TYPE_BLACK   "BLACKLIST"

#define PARSER_ACT_KILL     "KILL"
#define PARSER_ACT_TRAP     "TRAP"
#define PARSER_ACT_ERRNO    "ERROR"
#define PARSER_ACT_TRACE_E  "TRACE_ERROR"
#define PARSER_ACT_TRACE_K  "TRACE_KILL"

#define PARSER_OP_EQ        "=="
#define PARSER_OP_NE        "!="
#define PARSER_OP_GT        ">"
#define PARSER_OP_GE        ">="
#define PARSER_OP_LT        "<"
#define PARSER_OP_LE        "<="
#define PARSER_OP_MASK      "&"

const table_int32 cmd_table[] = {
    { PARSER_CMD_TYPE,      1 },
    { PARSER_CMD_ACTION,    2 },
    { PARSER_CMD_ALLOW,     3 },
    { PARSER_CMD_DENY,      4 },
    { NULL,                 0 }
};

const table_int32 type_table[] = {
    { PARSER_TYPE_WHITE,    CFG_WHITELIST },
    { PARSER_TYPE_BLACK,    CFG_BLACKLIST },
    //Alias strings
    { "WHITE",              CFG_WHITELIST },
    { "BLACK",              CFG_WHITELIST },
    { NULL,                 -1 }
};

const table_int32 action_table[] = {
    { PARSER_ACT_KILL,      DENY_KILL },
    { PARSER_ACT_TRAP,      DENY_TRAP },
    { PARSER_ACT_ERRNO,     DENY_ERRNO },
    { PARSER_ACT_TRACE_E,   DENY_TRACE },
    { PARSER_ACT_TRACE_K,   DENY_TRACE_KILL },
    //Alias strings
    { "SIGNAL",             DENY_TRAP },
    { "ERRNO",              DENY_ERRNO },
    { "TRACE",              DENY_TRACE },
    { "TRACE_ERRNO",        DENY_TRACE },
    { NULL,                 -1 }
};

const table_int32 op_table[] = {
    { PARSER_OP_EQ,         CMP_EQ },
    { PARSER_OP_NE,         CMP_NE },
    { PARSER_OP_GT,         CMP_GT },
    { PARSER_OP_GE,         CMP_GE },
    { PARSER_OP_LT,         CMP_LT },
    { PARSER_OP_LE,         CMP_LE },
    { PARSER_OP_MASK,       CMP_MASK },
    { NULL,                 -1 }
};

#ifndef _DOXYGEN
enum parser_err_type {
    ErrNone = 0,
    ErrFileNotFound,
    ErrNotFile,
    ErrMemory,
    ErrPermission,
    ErrIO,
    ErrSyntax,
    ErrUnknownCmd,
    ErrDupOption,
    ErrUnknownValue,
    ErrNoSyscall,
    ErrNoRule,
    ErrArgCount,
};
#endif

struct parser_error {
    enum parser_err_type type;
    int line;
};

typedef struct parser_error parser_error_t;

parser_error_t parser_get_err();
const char * parser_errstr(enum parser_err_type type);
struct seccomp_config * scconfig_parse_path(const char *path, unsigned int options);
struct seccomp_config * scconfig_parse_file(FILE *stream, unsigned int options);
struct seccomp_config * scconfig_parse_string(const char *str, unsigned int options);

#define skip_spaces(fp) fscanf(fp, "%*[ \t]")

#endif
