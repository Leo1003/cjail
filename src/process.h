/**
 * @internal
 * @file process.h
 * @brief child process initilizing header
 */
#ifndef PROCESS_H
#define PROCESS_H

#include "cjail.h"

_Noreturn void child_process(struct exec_para ep);

#endif
