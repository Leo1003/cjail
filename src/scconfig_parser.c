/**
 * @internal
 * @file scconfig_parser.c
 * @brief parsing seccomp config file library source
 */
#include "logger.h"
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
    //Convert string into C stream
    FILE *fp = fmemopen((void *)str, sizeof(char) * (strlen(str) + 1), "r");
    if (!fp) {
        set_par_err(ErrMemory, 0);
        return NULL;
    }
    if(_scconfig_parse(&cfg, fp, options)) {
        errno = EINVAL;
        cfg = NULL;
        goto out;
    }

out:
    fclose(fp);
    return cfg;
}

parser_error_t parser_get_err()
{
    return _par_err;
}

static enum parser_err_type _parse_syscall(FILE *f, struct seccomp_rule *rule)
{
    char buf[VAL_MAX_LENGTH + 1];
    int argnum = 0;
    //Zero the rule
    memset(rule, 0, sizeof(struct seccomp_rule));
    //Read syscall name
    if (fscanf(f, "%64[A-Za-z0-9_]s", buf) != 1) {
        devf("Syntax Error\n");
        return ErrSyntax;
    }
    rule->syscall  = seccomp_syscall_resolve_name(buf);
    skip_spaces(f);
    //FIXME: feof() may not work
    if (feof(f)) {
        //No parameter given, stop parsing
        return ErrNone;
    }
    //Expecting only one "("
    if (fscanf(f, "%64[(]s", buf) != 1 || strcmp(buf, "(")) {
        devf("Syntax Error\n");
        return ErrSyntax;
    }
    skip_spaces(f);
    //Parsing parameters
    while (1) {
        //Arguments count should not excess 6
        if (argnum >= 6) {
            return ErrArgCount;
        }
        //Parsing operators
        int op;
        if (fscanf(f, "%64[&>=<)]s", buf) != 1) {
            devf("Syntax Error\n");
            return ErrSyntax;
        }
        //Allow only appear "()"
        if (!strcmp(buf, ")") && argnum == 0) {
            break;
        }

        if ((op = table_to_int(op_table, buf)) < 0) {
            return ErrUnknownValue;
        }
        skip_spaces(f);

        unsigned long long val;
        unsigned long long mask;
        if (op == CMP_MASK) {
            //parsing mask
            if (fscanf(f, "%lli", &mask) != 1) {
                devf("Syntax Error\n");
                return ErrSyntax;
            }
            skip_spaces(f);
            //Expecting "=="
            if (fscanf(f, "%64[=]s", buf) != 1 || strcmp(buf, "==")) {
                devf("Syntax Error\n");
                return ErrSyntax;
            }
            skip_spaces(f);
            //parsing number
            if (fscanf(f, "%lli", &val) != 1) {
                devf("Syntax Error\n");
                return ErrSyntax;
            }
            skip_spaces(f);
        } else {
            //parsing number
            if (fscanf(f, "%lli", &val) != 1) {
                devf("Syntax Error\n");
                return ErrSyntax;
            }
            skip_spaces(f);
        }

        rule->args[argnum].cmp = op;
        rule->args[argnum].value = val;
        rule->args[argnum].mask = (op == CMP_MASK) ? mask : 0;

        //Expecting "," or ")"
        if (fscanf(f, "%64[,)]s", buf) != 1) {
            devf("Syntax Error\n");
            return ErrSyntax;
        }
        if (!strcmp(buf, ",")) {
            skip_spaces(f);
        } else if (!strcmp(buf, ")")) {
            break;
        } else {
            devf("Syntax Error\n");
            return ErrSyntax;
        }
        argnum++;
    }

    //Check nosyscall here to avoid there are data unread
    if (rule->syscall < 0) {
        return ErrNoSyscall;
    }
    return ErrNone;
}

static enum parser_err_type _parse_line(const char *str, struct seccomp_config *cfg, unsigned int options)
{
    enum parser_err_type ret = ErrNone;
    char cmd[CMD_MAX_LENGTH + 1], strval[VAL_MAX_LENGTH + 1];
    int val;
    struct seccomp_rule rule;

    //Convert string into C stream
    FILE *mf = fmemopen((void *)str, sizeof(char) * (strlen(str) + 1), "r");
    if (!mf) {
        return ErrMemory;
    }
    skip_spaces(mf);
    if (feof(mf)) {
        //Nothing else except spaces, ignore this line
        goto out;
    }
    if (fscanf(mf, "%16[A-Za-z0-9_]s", cmd) != 1) {
        ret = ErrSyntax;
        goto out;
    }
    //To uppercase
    strupr(cmd);

    skip_spaces(mf);
    switch (table_to_int(cmd_table, cmd)) {
        case 1:      //PARSER_CMD_TYPE
            devf("PARSER_CMD_TYPE\n");
            if (fscanf(mf, "%64[A-Za-z0-9_]s", strval) != 1) {
                ret = ErrSyntax;
                goto out;
            }
            //To uppercase
            strupr(strval);
            if ((val = table_to_int(type_table, strval)) < 0) {
                ret = ErrUnknownValue;
                goto out;
            }
            scconfig_set_type(cfg, val);
            break;
        case 2:      //PARSER_CMD_ACTION
            devf("PARSER_CMD_ACTION\n");
            if (fscanf(mf, "%64[A-Za-z0-9_]s", strval) != 1) {
                ret = ErrSyntax;
                goto out;
            }
            //To uppercase
            strupr(strval);
            if ((val = table_to_int(action_table, strval)) < 0) {
                ret = ErrUnknownValue;
                goto out;
            }
            scconfig_set_deny(cfg, val);
            break;
        case 3:      //PARSER_CMD_ALLOW
            devf("PARSER_CMD_ALLOW\n");
            if ((ret = _parse_syscall(mf, &rule))) {
                if (ret == ErrNoSyscall && options & SCOPT_IGN_NOSYS) {
                    ret = ErrNone;
                }
                goto out;
            }
            rule.type = RULE_ALLOW;
            if (scconfig_add(cfg, &rule, 1)) {
                ret = ErrMemory;
            }
            break;
        case 4:      //PARSER_CMD_DENY
            devf("PARSER_CMD_DENY\n");
            if ((ret = _parse_syscall(mf, &rule))) {
                if (ret == ErrNoSyscall && options & SCOPT_IGN_NOSYS) {
                    ret = ErrNone;
                }
                goto out;
            }
            rule.type = RULE_DENY;
            if (scconfig_add(cfg, &rule, 1)) {
                ret = ErrMemory;
            }
            break;
        default:
            ret = ErrUnknownCmd;
            goto out;
    }

    //Parsing complete, nothing except spaces should appear
    skip_spaces(mf);
    if (fgetc(mf) > 0) {
        devf("nothing except spaces should appear\n");
        ret = ErrSyntax;
        goto out;
    }

out:
    fclose(mf);
    return ret;
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

        //Detect newline charactor
        char *c = strchr(linestr, '\n');
        if (c) {
            *c = '\0';
        }

        //Debug message
        devf("getline: %s\n", linestr);

        //Detect comment, truncate string by '#'
        c = strchr(linestr, '#');
        if (c) {
            *c = '\0';
        }

        //Debug message
        devf("Parsing Line %d: %s\n", line, linestr);

        //ignore empty or comment only line
        if (strlen(linestr) == 0) {
            continue;
        }

        if ((err = _parse_line(linestr, *cfg, options))) {
            set_par_err(err, line);
            break;
        }
    }

    if (_par_err.type == ErrNone && !(options & SCOPT_IGN_NORULE) && scconfig_len(*cfg) == 0) {
        set_par_err(ErrNoRule, 0);
    }

    //Free string allocated by getline
    free(linestr);

    if (_par_err.type) {
        scconfig_free(*cfg);
        return -1;
    }
    return 0;
}
