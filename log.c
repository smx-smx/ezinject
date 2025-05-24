/*
 * Copyright (C) 2025 Stefano Moioli <smxdev4@gmail.com>
 * This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *  1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <stdarg.h>
#include "ezinject_common.h"
#include "log.h"

static log_config_t log;

void log_init(log_config_t *cfg){
    log = *cfg;
}

enum verbosity_level log_get_verbosity(){
    return log.verbosity;
}

void log_set_verbosity(int verbosity){
    log.verbosity = verbosity;
}

void log_fini(){
    if(log.log_output && (!log.log_leave_open || log.log_output != stdout)){
        fclose(log.log_output);
    }
}

void log_puts(const char *str){
    if(!log.log_output) return;
    fputs(str, log.log_output);
}

static inline void log_vprintf(const char *format, va_list ap){
    vfprintf(log.log_output, format, ap);
}

void log_printf(const char *format, ...){
    if(!log.log_output) return;

    va_list ap;
    va_start(ap, format);
    log_vprintf(format, ap);
    va_end(ap);
}

void log_logf(enum verbosity_level verbosity, const char *format, ...){
    if(verbosity > log.verbosity) return;
    va_list ap;
    va_start(ap, format);
    log_vprintf(format, ap);
    va_end(ap);
}

void log_putchar(int ch){
    if(!log.log_output) return;
    fputc(ch, log.log_output);
}
