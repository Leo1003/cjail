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

#include <seccomp.h>

static parser_error_t _par_err = { 0 };

static int _scconfig_parse(struct seccomp_config **cfg, FILE *stream, unsigned int options);

inline static void set_par_err(enum parser_err_type type, int line)
{
    _par_err.type = type;
    _par_err.line = line;
}

struct seccomp_config * scconfig_parse_path(const char* path, unsigned int options)
{
    struct seccomp_config *cfg = NULL;
    struct stat st;
    if (stat(path, &st)) {
        switch (errno) {
            case ENOENT:
            case ENOTDIR:
                set_par_err(ErrFileNotFound, 0);
                break;
            case EACCES:
                set_par_err(ErrPermission, 0);
                break;
            case ENOMEM:
                set_par_err(ErrMemory, 0);
                break;
            default:
                set_par_err(ErrIO, 0);
                break;
        }
        return NULL;
    }
    if (S_ISDIR(st.st_mode)) {
        errno = EISDIR;
        set_par_err(ErrNotFile, 0);
        return NULL;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        set_par_err(ErrIO, 0);
        return NULL;
    }
    if(_scconfig_parse(&cfg, fp, options)) {
        errno = EINVAL;
        return NULL;
    }
    return cfg;
}

struct seccomp_config * scconfig_parse_file(FILE *stream, unsigned int options)
{
    struct seccomp_config *cfg = NULL;
    if(_scconfig_parse(&cfg, stream, options)) {
        errno = EINVAL;
        return NULL;
    }
    return cfg;
}

struct seccomp_config * scconfig_parse_string(const char *str, unsigned int options)
{
    struct seccomp_config *cfg = NULL;
    FILE *fp = fmemopen(NULL, sizeof(char) * (strlen(str) + 10), "r+");
    if (!fp) {
        set_par_err(ErrMemory, 0);
        return NULL;
    }
    if (fprintf(fp, "%s", str) < 0) {
        set_par_err(ErrIO, 0);
        goto out;
    }
    if (fflush(fp)) {
        set_par_err(ErrIO, 0);
        goto out;
    }
    if(_scconfig_parse(&cfg, fp, options)) {
        errno = EINVAL;
        return NULL;
    }

out:
    fclose(fp);
    return cfg;
}

static enum parser_err_type _parse_line(const char *str, struct seccomp_config *cfg, unsigned int options)
{
    //TODO: Uncomplete
}

static int _scconfig_parse(struct seccomp_config **cfg, FILE *stream, unsigned int options)
{
    char *linestr = NULL;
    size_t linestr_s = 0;
    int line = 0;

    *cfg = scconfig_init();

    while (getline(&linestr, &linestr_s, stream) != EOF) {
        line++;
        enum parser_err_type err = ErrNone;

        //Detect comment, truncate string by '#'
        char *c = strchr(linestr, '#');
        if (c) {
            *c = '\0';
        }

        //ignore empty or comment only line
        if (strlen(linestr) == 0) {
            continue;
        }

        if ((err = _parse_line(linestr, *cfg, options))) {
            set_par_err(err, line);
            break;
        }
    }

    if (!(options & SCOPT_IGN_NORULE) && scconfig_len(*cfg) == 0) {
        set_par_err(ErrNoRule, 0);
    }

    if (_par_err.type) {
        scconfig_free(*cfg);
        return -1;
    }
    return 0;
}
