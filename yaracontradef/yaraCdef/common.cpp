/*
Copyright (c) 2017-2021. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#if defined(_WIN32)
#include <io.h>

// In Visual C++ use _taccess_s, in MinGW use _access_s.
#if defined(_MSC_VER)
#define access _taccess_s
#else
#define access _access_s
#endif

#else  // not _WIN32
#include <unistd.h>
#endif

#include <stdbool.h>
#include <yara.h>

#include "common.h"
#include "unicode.h"

char* unicode_to_ansi(const char_t* str)
{
    if (str == NULL)
        return NULL;

    int str_len = WideCharToMultiByte(
        CP_ACP, WC_NO_BEST_FIT_CHARS, str, -1, NULL, 0, NULL, NULL);

    char* str_utf8 = (char*)malloc(str_len);

    WideCharToMultiByte(
        CP_ACP, WC_NO_BEST_FIT_CHARS, str, -1, str_utf8, str_len, NULL, NULL);

    return str_utf8;
}

int define_external_variables(
    char** ext_vars,
    YR_RULES* rules,
    YR_COMPILER* compiler)
{
    int result = ERROR_SUCCESS;

    for (int i = 0; ext_vars[i] != NULL; i++)
    {
        char* equal_sign = strchr(ext_vars[i], '=');

        if (!equal_sign)
        {
            fprintf(stderr, "error: wrong syntax for `-d` option.\n");
            return ERROR_SUCCESS;
        }

        // Replace the equal sign with null character to split the external
        // variable definition (i.e: myvar=somevalue) in two strings: identifier
        // and value.

        *equal_sign = '\0';

        char* value = equal_sign + 1;
        char* identifier = ext_vars[i];

        if (is_float(value))
        {
            if (rules != NULL)
                result = yr_rules_define_float_variable(rules, identifier, atof(value));

            if (compiler != NULL)
                result = yr_compiler_define_float_variable(
                    compiler, identifier, atof(value));
        }
        else if (is_integer(value))
        {
            if (rules != NULL)
                result = yr_rules_define_integer_variable(
                    rules, identifier, atoi(value));

            if (compiler != NULL)
                result = yr_compiler_define_integer_variable(
                    compiler, identifier, atoi(value));
        }
        else if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0)
        {
            if (rules != NULL)
                result = yr_rules_define_boolean_variable(
                    rules, identifier, strcmp(value, "true") == 0);

            if (compiler != NULL)
                result = yr_compiler_define_boolean_variable(
                    compiler, identifier, strcmp(value, "true") == 0);
        }
        else
        {
            if (rules != NULL)
                result = yr_rules_define_string_variable(rules, identifier, value);

            if (compiler != NULL)
                result = yr_compiler_define_string_variable(
                    compiler, identifier, value);
        }
    }

    return result;
}

bool is_integer(const char* str)
{
    if (*str == '-')
        str++;

    if (*str == '\0')
        return false;

    while (*str)
    {
        if (!isdigit(*str))
            return false;
        str++;
    }

    return true;
}

bool is_float(const char* str)
{
    bool has_dot = false;

    if (*str == '-')  // skip the minus sign if present
        str++;

    if (*str == '.')  // float can't start with a dot
        return false;

    while (*str)
    {
        if (*str == '.')
        {
            if (has_dot)  // two dots, not a float
                return false;

            has_dot = true;
        }
        else if (!isdigit(*str))
        {
            return false;
        }

        str++;
    }

    return has_dot;  // to be float must contain a dot
}
