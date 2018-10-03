/**
 * @internal
 * @file scconfig_parser.h
 * @brief parsing seccomp config file library header
 */
#ifndef SCCONFIG_PARSER_H
#define SCCONFIG_PARSER_H

#include <stdio.h>
#include "simple_seccomp.h"

#define SCOPT_IGN_NOSYS     0x00000001
#define SCOPT_IGN_NORULE    0x00000002

#define PARSER_CMD_TYPE "TYPE"
#define PARSER_CMD_ACTION "ACTION"
#define PARSER_CMD_ALLOW "ALLOW"
#define PARSER_CMD_DENY "DENY"

enum parser_err_type {
    ErrNone = 0,
    ErrFileNotFound,
    ErrNotFile,
    ErrMemory,
    ErrPermission,
    ErrIO,
    ErrSyntax,
    ErrUnknownOption,
    ErrDupOption,
    ErrUnknownValue,
    ErrNoSyscall,
    ErrNoRule,
    ErrArgCount,
};

struct parser_error {
    enum parser_err_type type;
    int line;
};

typedef struct parser_error parser_error_t;

parser_error_t parser_get_err();
struct seccomp_config * scconfig_parse_path(const char *path, unsigned int options);
struct seccomp_config * scconfig_parse_file(FILE *stream, unsigned int options);
struct seccomp_config * scconfig_parse_string(const char *str, unsigned int options);

#endif
