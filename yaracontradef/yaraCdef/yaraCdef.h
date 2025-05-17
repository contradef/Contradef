#pragma once
// YARA_CDEF.h
#ifndef YARA_CDEF_H
#define YARA_CDEF_H

//#define _UNICODE

#include <stdint.h>
#include <stdbool.h>
#include "pch.h"
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yara.h>

#include "common.h"
#include "unicode.h"

// Define your structures
typedef struct _STRING_MATCH {
    uint64_t offset;
    int length;
    char* identifier;
    char* data;
    struct _STRING_MATCH* next;
} STRING_MATCH;

typedef struct _RULE_MATCH {
    char* rnamespace;
    char* identifier;
    char* tags;
    char* meta;
    STRING_MATCH* string_matches;
    struct _RULE_MATCH* next;
} RULE_MATCH;

typedef struct _EXECUTION_ERROR {
    int error_code;
    char* message;
    char* rule_identifier;
    char* string_identifier;
    struct _EXECUTION_ERROR* next;
} EXECUTION_ERROR;

typedef struct _MODULE_DATA
{
    const char* module_name;
    YR_MAPPED_FILE mapped_file;
    struct _MODULE_DATA* next;

} MODULE_DATA;

typedef struct _ERROR_MESSAGE {
    int error_level;
    char* file_name;
    int line_number;
    char* rule_identifier;
    char* message;
    struct _ERROR_MESSAGE* next;
} ERROR_MESSAGE;

typedef struct _COMPILER_RESULTS {
    int errors;
    int warnings;
    ERROR_MESSAGE* error_list;
} COMPILER_RESULTS;

typedef struct _YARA_STATS {
    int ac_tables_size;
    double ac_average_match_list_length;
    int num_rules;
    int num_strings;
    int ac_matches;
    int ac_root_match_list_length;
    int top_ac_match_list_lengths_count;
    int* top_ac_match_list_lengths;
    int ac_match_list_length_pctls[101]; // Índices de 0 a 100
} YARA_STATS;

typedef struct SCAN_OPTIONS
{
    bool follow_symlinks;
    bool recursive_search;
    time_t deadline;

} SCAN_OPTIONS;

typedef struct _YARA_OUTPUT {
    const char_t* file_path;
    int match_count;
    RULE_MATCH* rule_matches;
    COMPILER_RESULTS compiler_results;
    EXECUTION_ERROR* execution_errors;
    YARA_STATS stats;
} YARA_OUTPUT;

typedef struct _CALLBACK_ARGS {
    const char_t* file_path;
    int current_count;
    YARA_OUTPUT* output;
} CALLBACK_ARGS;

#ifdef _WIN32
#define YARA_CALL __stdcall
#else
#define YARA_CALL
#endif

#ifdef _WIN32
#ifdef YARA_CDEF_EXPORTS
#define YARA_CDEF __declspec(dllexport)
#else
#define YARA_CDEF __declspec(dllimport)
#endif
#else
#define YARA_CDEF
#endif

#ifdef __cplusplus
extern "C" {
#endif

    // Declaração das funções
    YARA_CDEF int YARA_CALL run_yara(const char_t* filerules, const char_t* file, YARA_OUTPUT* output);
    YARA_CDEF void YARA_CALL free_yara_output(YARA_OUTPUT* output);

#ifdef __cplusplus
}
#endif


#endif // YARA_CDEF_H