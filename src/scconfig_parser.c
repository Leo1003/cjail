/**
 * @internal
 * @file scconfig_parser.c
 * @brief parsing seccomp config file library source
 */
#include "scconfig_parser.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int _scconfig_parse(struct seccomp_config **cfg, FILE *stream, unsigned int options);

struct seccomp_config * scconfig_parse_path(const char* path, unsigned int options)
{
    struct stat st;
    if (stat(path, &st)) {
        return NULL;
    }
    if (S_ISDIR(st.st_mode)) {
        errno = EISDIR;
        return NULL;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    struct seccomp_config *cfg;
}

struct seccomp_config * scconfig_parse_file(FILE *stream, unsigned int options)
{
    struct seccomp_config *cfg;
}

struct seccomp_config * scconfig_parse_string(const char *str, unsigned int options)
{
    FILE *fp = fmemopen(NULL, sizeof(char) * (strlen(str) + 10), "r+");
    if (!fp) {
        return NULL;
    }
    fprintf(fp, "%s", str);
    struct seccomp_config *cfg;
}
