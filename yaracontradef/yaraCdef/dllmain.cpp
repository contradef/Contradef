// dllmain.cpp : Define o ponto de entrada para o aplicativo DLL.
#include "yaracdef.h"

#define exit_with_code(code) \
  {                          \
    result = code;           \
    goto _exit;              \
  }


MODULE_DATA* modules_data_list = NULL;

static char* tags[33];
static char* identifiers[33];
static char* ext_vars[33];
static char* modules_data[33];

static bool follow_symlinks = false;
static bool recursive_search = false;
static bool scan_list_search = false;
static bool show_module_data = true;
static bool show_tags = true;
static bool show_stats = true;
static bool show_strings = true;
static bool show_string_length = true;
static bool show_xor_key = true;
static bool show_meta = true;
static bool show_module_names = true;
static bool show_namespace = true;
static bool show_version = true;
static bool show_help = false;
static bool ignore_warnings = false;
static bool fast_scan = false;
static bool negate = false;
static bool print_count_only = false;
static bool strict_escape = false;
static bool fail_on_warnings = false;
static bool rules_are_compiled = false;
static bool disable_console_logs = false;
static long total_count = 0;
static long limit = 0;
static long timeout = 1000000;
static long stack_size = DEFAULT_STACK_SIZE;
static long threads = YR_MAX_THREADS;
static long max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;
static long max_process_memory_chunk = DEFAULT_MAX_PROCESS_MEMORY_CHUNK;
static long long skip_larger = 0;

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}


static int load_modules_data()
{
    for (int i = 0; modules_data[i] != NULL; i++)
    {
        char* equal_sign = strchr(modules_data[i], '=');

        if (!equal_sign)
        {
            fprintf(stderr, "error: wrong syntax for `-x` option.\n");
            return false;
        }

        *equal_sign = '\0';

        MODULE_DATA* module_data = (MODULE_DATA*)malloc(sizeof(MODULE_DATA));

        if (module_data != NULL)
        {
            module_data->module_name = modules_data[i];

            int result = yr_filemap_map(equal_sign + 1, &module_data->mapped_file);

            if (result != ERROR_SUCCESS)
            {
                free(module_data);

                fprintf(stderr, "error: could not open file \"%s\".\n", equal_sign + 1);

                return false;
            }

            module_data->next = modules_data_list;
            modules_data_list = module_data;
        }
    }

    return true;
}

static void unload_modules_data()
{
    MODULE_DATA* module_data = modules_data_list;

    while (module_data != NULL)
    {
        MODULE_DATA* next_module_data = module_data->next;

        yr_filemap_unmap(&module_data->mapped_file);
        free(module_data);

        module_data = next_module_data;
    }

    modules_data_list = NULL;
}

static int scan_file(YR_SCANNER* scanner, const char_t* filename)
{
    YR_FILE_DESCRIPTOR fd = CreateFile(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (fd == INVALID_HANDLE_VALUE)
        return ERROR_COULD_NOT_OPEN_FILE;

    int result = yr_scanner_scan_fd(scanner, fd);

    CloseHandle(fd);

    return result;
}
bool compile_files(YR_COMPILER* compiler, const char_t** filesrules, void* user_data)
{
    size_t count = 0;
    // Calcula o número de elementos em filesrules
    while (filesrules[count] != NULL)
        count++;

    for (size_t i = 0; i < count; i++)
    {
        FILE* rule_file = NULL;
        const char_t* ns = NULL;
        const char_t* file_name = NULL;
        char_t* colon = NULL;
        int errors = 0;

        if (_taccess(filesrules[i], 0) != 0)
        {
            // Tenta encontrar o ':' que separa o namespace do nome do arquivo
            colon = (char_t*)_tcschr(filesrules[i], ':');
        }

        // O delimitador de namespace deve ser um ':' não seguido por uma barra invertida
        if (colon && *(colon + 1) != '\\')
        {
            file_name = colon + 1;
            *colon = '\0';
            ns = filesrules[i];
        }
        else
        {
            file_name = filesrules[i];
            ns = NULL;
        }

        if (_tcscmp(file_name, _T("-")) == 0)
        {
            rule_file = stdin;
        }
        else
        {
            errno_t err = _wfopen_s(&rule_file, file_name, L"r");
            if (err != 0 || rule_file == NULL)
            {
                // Em vez de imprimir no stderr, armazene o erro
                COMPILER_RESULTS* compiler_results = (COMPILER_RESULTS*)user_data;
                compiler_results->errors++;

                ERROR_MESSAGE* error_msg = (ERROR_MESSAGE*)malloc(sizeof(ERROR_MESSAGE));
                if (error_msg == NULL)
                {
                    // Trate a falha de alocação de memória
                    return false;
                }

                error_msg->error_level = YARA_ERROR_LEVEL_ERROR;
                error_msg->file_name = _tcsdup(file_name);
                error_msg->line_number = 0;
                error_msg->rule_identifier = NULL;
                error_msg->message = _strdup("could not open file");
                error_msg->next = NULL;

                // Adiciona a mensagem de erro à lista
                if (compiler_results->error_list == NULL)
                {
                    compiler_results->error_list = error_msg;
                }
                else
                {
                    ERROR_MESSAGE* last = compiler_results->error_list;
                    while (last->next != NULL)
                    {
                        last = last->next;
                    }
                    last->next = error_msg;
                }

                return false;
            }
        }

#if defined(_UNICODE)
        char* file_name_mb = unicode_to_ansi(file_name);
        char* ns_mb = unicode_to_ansi(ns);

        errors = yr_compiler_add_file(compiler, rule_file, ns_mb, file_name_mb);

        free(file_name_mb);
        free(ns_mb);
#else
        errors = yr_compiler_add_file(compiler, rule_file, ns, file_name);
#endif

        if (rule_file != stdin)
            fclose(rule_file);

        if (errors > 0)
            return false;
    }

    return true;
}

static char* get_error_message(int error)
{
    switch (error)
    {
    case ERROR_SUCCESS:
        return _strdup("Success");
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
        return _strdup("Cannot attach to process (try running as root)");
    case ERROR_INSUFFICIENT_MEMORY:
        return _strdup("Not enough memory");
    case ERROR_COULD_NOT_OPEN_FILE:
        return _strdup("Could not open file");
    case ERROR_COULD_NOT_MAP_FILE:
        return _strdup("Could not map file into memory");
    case ERROR_INVALID_FILE:
        return _strdup("Invalid file");
    case ERROR_CORRUPT_FILE:
        return _strdup("Corrupt file");
    case ERROR_UNSUPPORTED_FILE_VERSION:
        return _strdup("Unsupported file version");
    case ERROR_INVALID_REGULAR_EXPRESSION:
        return _strdup("Invalid regular expression");
    case ERROR_INVALID_HEX_STRING:
        return _strdup("Invalid hex string");
    case ERROR_SYNTAX_ERROR:
        return _strdup("Syntax error");
    case ERROR_LOOP_NESTING_LIMIT_EXCEEDED:
        return _strdup("Loop nesting limit exceeded");
    case ERROR_DUPLICATED_LOOP_IDENTIFIER:
        return _strdup("Duplicated loop identifier");
    case ERROR_DUPLICATED_IDENTIFIER:
        return _strdup("Duplicated identifier");
    case ERROR_DUPLICATED_TAG_IDENTIFIER:
        return _strdup("Duplicated tag identifier");
    case ERROR_DUPLICATED_META_IDENTIFIER:
        return _strdup("Duplicated meta identifier");
    case ERROR_DUPLICATED_STRING_IDENTIFIER:
        return _strdup("Duplicated string identifier");
    case ERROR_UNREFERENCED_STRING:
        return _strdup("Unreferenced string");
    case ERROR_UNDEFINED_STRING:
        return _strdup("Undefined string");
    case ERROR_UNDEFINED_IDENTIFIER:
        return _strdup("Undefined identifier");
    case ERROR_MISPLACED_ANONYMOUS_STRING:
        return _strdup("Misplaced anonymous string");
    case ERROR_INCLUDES_CIRCULAR_REFERENCE:
        return _strdup("Includes circular reference");
    case ERROR_INCLUDE_DEPTH_EXCEEDED:
        return _strdup("Include depth exceeded");
    case ERROR_WRONG_TYPE:
        return _strdup("Wrong type");
    case ERROR_EXEC_STACK_OVERFLOW:
        return _strdup("Stack overflow while evaluating condition (see --stack-size argument)");
    case ERROR_SCAN_TIMEOUT:
        return _strdup("Scanning timed out");
    case ERROR_TOO_MANY_SCAN_THREADS:
        return _strdup("Too many scan threads (legacy code compatibility)");
    case ERROR_CALLBACK_ERROR:
        return _strdup("Callback error");
    case ERROR_INVALID_ARGUMENT:
        return _strdup("Invalid argument");
    case ERROR_TOO_MANY_MATCHES:
        return _strdup("Too many matches");
    case ERROR_INTERNAL_FATAL_ERROR:
        return _strdup("Internal fatal error");
    case ERROR_NESTED_FOR_OF_LOOP:
        return _strdup("Nested for-of loop");
    case ERROR_INVALID_FIELD_NAME:
        return _strdup("Invalid field name");
    case ERROR_UNKNOWN_MODULE:
        return _strdup("Unknown module");
    case ERROR_NOT_A_STRUCTURE:
        return _strdup("Not a structure");
    case ERROR_NOT_INDEXABLE:
        return _strdup("Not indexable");
    case ERROR_NOT_A_FUNCTION:
        return _strdup("Not a function");
    case ERROR_INVALID_FORMAT:
        return _strdup("Invalid format");
    case ERROR_TOO_MANY_ARGUMENTS:
        return _strdup("Too many arguments");
    case ERROR_WRONG_ARGUMENTS:
        return _strdup("Wrong arguments");
    case ERROR_WRONG_RETURN_TYPE:
        return _strdup("Wrong return type");
    case ERROR_DUPLICATED_STRUCTURE_MEMBER:
        return _strdup("Duplicated structure member");
    case ERROR_EMPTY_STRING:
        return _strdup("Empty string");
    case ERROR_DIVISION_BY_ZERO:
        return _strdup("Division by zero");
    case ERROR_REGULAR_EXPRESSION_TOO_LARGE:
        return _strdup("Regular expression too large");
    case ERROR_TOO_MANY_RE_FIBERS:
        return _strdup("Too many RE fibers");
    case ERROR_COULD_NOT_READ_PROCESS_MEMORY:
        return _strdup("Could not read process memory");
    case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
        return _strdup("Invalid type for external variable");
    case ERROR_REGULAR_EXPRESSION_TOO_COMPLEX:
        return _strdup("Regular expression too complex");
    case ERROR_INVALID_MODULE_NAME:
        return _strdup("Invalid module name");
    case ERROR_TOO_MANY_STRINGS:
        return _strdup("Too many strings");
    case ERROR_INTEGER_OVERFLOW:
        return _strdup("Integer overflow");
    case ERROR_CALLBACK_REQUIRED:
        return _strdup("Callback required");
    case ERROR_INVALID_OPERAND:
        return _strdup("Invalid operand");
    case ERROR_COULD_NOT_READ_FILE:
        return _strdup("Could not read file");
    case ERROR_DUPLICATED_EXTERNAL_VARIABLE:
        return _strdup("Duplicated external variable");
    case ERROR_INVALID_MODULE_DATA:
        return _strdup("Invalid module data");
    case ERROR_WRITING_FILE:
        return _strdup("Error writing file");
    case ERROR_INVALID_MODIFIER:
        return _strdup("Invalid modifier");
    case ERROR_DUPLICATED_MODIFIER:
        return _strdup("Duplicated modifier");
    case ERROR_BLOCK_NOT_READY:
        return _strdup("Block not ready");
    case ERROR_INVALID_PERCENTAGE:
        return _strdup("Invalid percentage");
    case ERROR_IDENTIFIER_MATCHES_WILDCARD:
        return _strdup("Identifier matches wildcard");
    case ERROR_INVALID_VALUE:
        return _strdup("Invalid value");
    case ERROR_TOO_SLOW_SCANNING:
        return _strdup("Scanning too slow");
    case ERROR_UNKNOWN_ESCAPE_SEQUENCE:
        return _strdup("Unknown escape sequence");
    default:
    {
        char buffer[64];
        sprintf_s(buffer, sizeof(buffer), "Unknown error code: %d", error);
        return _strdup(buffer);
    }
    }
}

static void add_execution_error(YARA_OUTPUT* output, int error_code, const char* error_message)
{
    char* error_msg = _strdup(error_message);
    if (error_msg != NULL)
    {
        EXECUTION_ERROR* exec_error = (EXECUTION_ERROR*)malloc(sizeof(EXECUTION_ERROR));
        if (exec_error != NULL)
        {
            exec_error->error_code = error_code;
            exec_error->message = error_msg;
            exec_error->rule_identifier = NULL;
            exec_error->string_identifier = NULL;
            exec_error->next = NULL;

            // Adicionar ao final da lista de erros
            if (output->execution_errors == NULL)
            {
                output->execution_errors = exec_error;
            }
            else
            {
                EXECUTION_ERROR* last = output->execution_errors;
                while (last->next != NULL)
                {
                    last = last->next;
                }
                last->next = exec_error;
            }
        }
        else
        {
            // Trate a falha de alocação de memória
            free(error_msg);
        }
    }
}

static void collect_scanner_error(YR_SCANNER* scanner, int error, YARA_OUTPUT* output)
{
    YR_RULE* rule = yr_scanner_last_error_rule(scanner);
    YR_STRING* string = yr_scanner_last_error_string(scanner);

    // Cria uma nova mensagem de erro
    EXECUTION_ERROR* exec_error = (EXECUTION_ERROR*)malloc(sizeof(EXECUTION_ERROR));

    if (exec_error == NULL)
    {
        add_execution_error(output, ERROR_INSUFFICIENT_MEMORY, "Failed to allocate memory for execution error");
        return;
    }

    memset(exec_error, 0, sizeof(EXECUTION_ERROR));

    exec_error->error_code = error;
    exec_error->message = get_error_message(error);
    exec_error->rule_identifier = rule ? _strdup(rule->identifier) : NULL;
    exec_error->string_identifier = string ? _strdup(string->identifier) : NULL;
    exec_error->next = NULL;

    // Adiciona a mensagem de erro à lista
    if (output->execution_errors == NULL)
    {
        output->execution_errors = exec_error;
    }
    else
    {
        EXECUTION_ERROR* last = output->execution_errors;
        while (last->next != NULL)
        {
            last = last->next;
        }
        last->next = exec_error;
    }
}


static void collect_compiler_error(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
    COMPILER_RESULTS* compiler_results = (COMPILER_RESULTS*)user_data;

    // Incrementa o contador de erros ou avisos
    if (error_level == YARA_ERROR_LEVEL_ERROR)
    {
        compiler_results->errors++;
    }
    else if (!ignore_warnings)
    {
        compiler_results->warnings++;
    }
    else
    {
        return;
    }

    // Cria uma nova mensagem de erro
    ERROR_MESSAGE* error_msg = (ERROR_MESSAGE*)malloc(sizeof(ERROR_MESSAGE));
    if (error_msg == NULL)
    {
        // Trate a falha de alocação de memória
        return;
    }

    error_msg->error_level = error_level;
    error_msg->file_name = _strdup(file_name);
    error_msg->line_number = line_number;
    error_msg->rule_identifier = rule ? _strdup(rule->identifier) : NULL;
    error_msg->message = _strdup(message);
    error_msg->next = NULL;

    // Adiciona a mensagem de erro à lista
    if (compiler_results->error_list == NULL)
    {
        compiler_results->error_list = error_msg;
    }
    else
    {
        ERROR_MESSAGE* last = compiler_results->error_list;
        while (last->next != NULL)
        {
            last = last->next;
        }
        last->next = error_msg;
    }
}

static int collect_rules_stats(YR_RULES* rules, YARA_STATS* yara_stats)
{
    YR_RULES_STATS stats;
    int result = yr_rules_get_stats(rules, &stats);

    if (result != ERROR_SUCCESS)
    {
        // Retorne o código de erro para que o chamador possa tratá-lo
        return result;
    }

    // Preencha a estrutura YARA_STATS
    yara_stats->ac_tables_size = stats.ac_tables_size;
    yara_stats->ac_average_match_list_length = stats.ac_average_match_list_length;
    yara_stats->num_rules = stats.num_rules;
    yara_stats->num_strings = stats.num_strings;
    yara_stats->ac_matches = stats.ac_matches;
    yara_stats->ac_root_match_list_length = stats.ac_root_match_list_length;

    // Copie o array top_ac_match_list_lengths
    int t = sizeof(stats.top_ac_match_list_lengths) / sizeof(stats.top_ac_match_list_lengths[0]);
    yara_stats->top_ac_match_list_lengths_count = t;
    yara_stats->top_ac_match_list_lengths = (int*)malloc(t * sizeof(int));
    if (yara_stats->top_ac_match_list_lengths == NULL)
    {
        // Trate a falha de alocação de memória
        return ERROR_INSUFFICIENT_MEMORY;
    }
    memcpy(yara_stats->top_ac_match_list_lengths, stats.top_ac_match_list_lengths, t * sizeof(int));

    // Copie o array ac_match_list_length_pctls
    memcpy(yara_stats->ac_match_list_length_pctls, stats.ac_match_list_length_pctls, sizeof(stats.ac_match_list_length_pctls));

    return ERROR_SUCCESS;
}


static int handle_message(
    YR_SCAN_CONTEXT* context,
    int message,
    YR_RULE* rule,
    void* data)
{
    CALLBACK_ARGS* args = (CALLBACK_ARGS*)data;
    YARA_OUTPUT* output = args->output;
    bool is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

    if (is_matching)
    {
        // Aloca e inicializa RULE_MATCH
        RULE_MATCH* rule_match = (RULE_MATCH*)malloc(sizeof(RULE_MATCH));
        if (rule_match == NULL)
        {
            // Trate a falha de alocação
            return CALLBACK_ERROR;
        }
        memset(rule_match, 0, sizeof(RULE_MATCH));

        // Preenche as informações da regra
        if (show_namespace)
            rule_match->rnamespace = _strdup(rule->ns->name);
        else
            rule_match->rnamespace = NULL;

        rule_match->identifier = _strdup(rule->identifier);

        // Obtém as tags
        if (show_tags)
        {
            const char* tag;
            size_t tags_length = 1; // Inicia com 1 para o terminador nulo

            yr_rule_tags_foreach(rule, tag)
            {
                tags_length += strlen(tag) + 1; // +1 para a vírgula ou terminador
            }

            if (tags_length > 1)
            {
                rule_match->tags = (char*)malloc(tags_length * sizeof(char));
                if (rule_match->tags == NULL)
                {
                    // Trate a falha de alocação
                    free(rule_match->identifier);
                    free(rule_match);
                    return CALLBACK_ERROR;
                }
                rule_match->tags[0] = '\0';

                bool first_tag = true;
                yr_rule_tags_foreach(rule, tag)
                {
                    errno_t err;
                    if (!first_tag)
                    {
                        err = strcat_s(rule_match->tags, tags_length, ",");
                        if (err != 0)
                        {
                            // Trate o erro
                            free(rule_match->tags);
                            free(rule_match->identifier);
                            free(rule_match);
                            return CALLBACK_ERROR;
                        }
                    }
                    else
                    {
                        first_tag = false;
                    }

                    err = strcat_s(rule_match->tags, tags_length, tag);
                    if (err != 0)
                    {
                        // Trate o erro
                        free(rule_match->tags);
                        free(rule_match->identifier);
                        free(rule_match);
                        return CALLBACK_ERROR;
                    }
                }
            }
            else
            {
                rule_match->tags = NULL;
            }
        }

        // Obtém os meta-dados (se necessário)
        if (show_meta)
        {
            YR_META* meta;
            size_t meta_length = 1; // Inicia com 1 para o terminador nulo

            yr_rule_metas_foreach(rule, meta)
            {
                // Estima o tamanho necessário para cada meta
                meta_length += strlen(meta->identifier) + 32; // Ajuste conforme necessário
            }

            if (meta_length > 1)
            {
                rule_match->meta = (char*)malloc(meta_length * sizeof(char));
                if (rule_match->meta == NULL)
                {
                    // Trate a falha de alocação
                    if (rule_match->tags) free(rule_match->tags);
                    free(rule_match->identifier);
                    free(rule_match);
                    return CALLBACK_ERROR;
                }
                rule_match->meta[0] = '\0';

                bool first_meta = true;
                yr_rule_metas_foreach(rule, meta)
                {
                    errno_t err;
                    if (!first_meta)
                    {
                        err = strcat_s(rule_match->meta, meta_length, ",");
                        if (err != 0)
                        {
                            // Trate o erro
                            free(rule_match->meta);
                            if (rule_match->tags) free(rule_match->tags);
                            free(rule_match->identifier);
                            free(rule_match);
                            return CALLBACK_ERROR;
                        }
                    }
                    else
                    {
                        first_meta = false;
                    }

                    char buffer[256];
                    if (meta->type == META_TYPE_INTEGER)
                    {
                        sprintf_s(buffer, sizeof(buffer), "%s=%" PRId64, meta->identifier, meta->integer);
                    }
                    else if (meta->type == META_TYPE_BOOLEAN)
                    {
                        sprintf_s(buffer, sizeof(buffer), "%s=%s", meta->identifier, meta->integer ? "true" : "false");
                    }
                    else
                    {
                        // Escape da string se necessário
                        sprintf_s(buffer, sizeof(buffer), "%s=\"%s\"", meta->identifier, meta->string);
                    }

                    err = strcat_s(rule_match->meta, meta_length, buffer);
                    if (err != 0)
                    {
                        // Trate o erro
                        free(rule_match->meta);
                        if (rule_match->tags) free(rule_match->tags);
                        free(rule_match->identifier);
                        free(rule_match);
                        return CALLBACK_ERROR;
                    }
                }
            }
            else
            {
                rule_match->meta = NULL;
            }
        }

        // Obtém as strings correspondentes
        if (show_strings || show_string_length || show_xor_key)
        {
            YR_STRING* string;
            STRING_MATCH* last_string_match = NULL;

            yr_rule_strings_foreach(rule, string)
            {
                YR_MATCH* match;

                yr_string_matches_foreach(context, string, match)
                {
                    STRING_MATCH* string_match = (STRING_MATCH*)malloc(sizeof(STRING_MATCH));
                    if (string_match == NULL)
                    {
                        // Trate a falha de alocação
                        // Libere recursos alocados previamente
                        if (rule_match->meta) free(rule_match->meta);
                        if (rule_match->tags) free(rule_match->tags);
                        free(rule_match->identifier);
                        free(rule_match);
                        return CALLBACK_ERROR;
                    }
                    memset(string_match, 0, sizeof(STRING_MATCH));

                    string_match->offset = match->base + match->offset;
                    string_match->length = match->data_length;
                    string_match->identifier = _strdup(string->identifier);
                    if (string_match->identifier == NULL)
                    {
                        // Trate a falha de alocação
                        free(string_match);
                        if (rule_match->meta) free(rule_match->meta);
                        if (rule_match->tags) free(rule_match->tags);
                        free(rule_match->identifier);
                        free(rule_match);
                        return CALLBACK_ERROR;
                    }

                    // Copia os dados correspondentes
                    string_match->data = (char*)malloc(match->data_length + 1);
                    if (string_match->data == NULL)
                    {
                        // Trate a falha de alocação
                        free(string_match->identifier);
                        free(string_match);
                        if (rule_match->meta) free(rule_match->meta);
                        if (rule_match->tags) free(rule_match->tags);
                        free(rule_match->identifier);
                        free(rule_match);
                        return CALLBACK_ERROR;
                    }
                    memcpy(string_match->data, match->data, match->data_length);
                    string_match->data[match->data_length] = '\0';

                    // Adiciona à lista
                    if (last_string_match == NULL)
                        rule_match->string_matches = string_match;
                    else
                        last_string_match->next = string_match;

                    last_string_match = string_match;
                }
            }
        }

        // Adiciona rule_match à lista de saída
        rule_match->next = output->rule_matches;
        output->rule_matches = rule_match;

        args->current_count++;
        output->match_count++;
        total_count++;
    }

    if (limit != 0 && total_count >= limit)
        return CALLBACK_ABORT;

    return CALLBACK_CONTINUE;
}


static int callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    switch (message)
    {
    case CALLBACK_MSG_RULE_MATCHING:
    case CALLBACK_MSG_RULE_NOT_MATCHING:
        return handle_message(context, message, (YR_RULE*)message_data, user_data);

    case CALLBACK_MSG_IMPORT_MODULE:
    {
        YR_MODULE_IMPORT* mi = (YR_MODULE_IMPORT*)message_data;
        MODULE_DATA* module_data = modules_data_list;

        while (module_data != NULL)
        {
            if (strcmp(module_data->module_name, mi->module_name) == 0)
            {
                mi->module_data = (void*)module_data->mapped_file.data;
                mi->module_data_size = module_data->mapped_file.size;
                break;
            }

            module_data = module_data->next;
        }

        return CALLBACK_CONTINUE;
    }

    case CALLBACK_MSG_MODULE_IMPORTED:
    {
        if (show_module_data)
        {
            YR_OBJECT* object = (YR_OBJECT*)message_data;

            // Se necessário, processe o objeto do módulo aqui

            // Por exemplo, você pode armazenar informações adicionais na estrutura de saída
        }

        return CALLBACK_CONTINUE;
    }

    case CALLBACK_MSG_TOO_SLOW_SCANNING:
    {
        if (ignore_warnings)
            return CALLBACK_CONTINUE;

        YR_STRING* string = (YR_STRING*)message_data;
        YR_RULE* rule = &context->rules->rules_table[string->rule_idx];

        // Você pode armazenar o aviso na estrutura de saída ou simplesmente continuar

        if (fail_on_warnings)
            return CALLBACK_ERROR;

        return CALLBACK_CONTINUE;
    }

    case CALLBACK_MSG_TOO_MANY_MATCHES:
    {
        if (ignore_warnings)
            return CALLBACK_CONTINUE;

        YR_STRING* string = (YR_STRING*)message_data;
        YR_RULE* rule = &context->rules->rules_table[string->rule_idx];

        // Novamente, você pode optar por armazenar o aviso ou ignorá-lo

        if (fail_on_warnings)
            return CALLBACK_ERROR;

        return CALLBACK_CONTINUE;
    }

    case CALLBACK_MSG_CONSOLE_LOG:
    {
        if (!disable_console_logs)
        {
            // Se desejar, armazene logs ou ignore
        }
        return CALLBACK_CONTINUE;
    }

    default:
        return CALLBACK_ERROR;
    }
}


//
//EXPORT int run_yara(const char_t* filerules, const char_t* file, YARA_OUTPUT* output);
YARA_CDEF int YARA_CALL run_yara(const char_t* filerules, const char_t* file, YARA_OUTPUT* output)
{
    COMPILER_RESULTS cr;
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    YR_SCANNER* scanner = NULL;
    SCAN_OPTIONS scan_opts;
    int flags = 0;
    int result = ERROR_SUCCESS;

    // Inicializa o output
    memset(output, 0, sizeof(YARA_OUTPUT));
    output->file_path = file;

    scan_opts.follow_symlinks = follow_symlinks;
    scan_opts.recursive_search = recursive_search;

    if (!load_modules_data())
    {
        result = ERROR_INTERNAL_FATAL_ERROR;
        goto cleanup;
    }

    result = yr_initialize();
    if (result != ERROR_SUCCESS)
    {
        add_execution_error(output, result, get_error_message(result));
        goto cleanup;
    }

    yr_set_configuration_uint32(YR_CONFIG_STACK_SIZE, stack_size);
    yr_set_configuration_uint32(YR_CONFIG_MAX_STRINGS_PER_RULE, max_strings_per_rule);
    yr_set_configuration_uint64(YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK, max_process_memory_chunk);

    if (rules_are_compiled)
    {
        // Código para carregar regras compiladas
        // ...
    }
    else
    {
        result = yr_compiler_create(&compiler);
        if (result != ERROR_SUCCESS)
        {
            add_execution_error(output, result, get_error_message(result));
            goto cleanup;
        }

        result = define_external_variables(ext_vars, NULL, compiler);
        if (result != ERROR_SUCCESS)
        {
            add_execution_error(output, result, get_error_message(result));
            goto cleanup;
        }

        cr.errors = 0;
        cr.warnings = 0;
        cr.error_list = NULL;

        yr_compiler_set_callback(compiler, collect_compiler_error, &cr);
        compiler->strict_escape = strict_escape;

        const char_t* filesrules[] = { filerules, NULL };

        if (!compile_files(compiler, filesrules, &cr))
        {
            result = ERROR_SYNTAX_ERROR;
            goto cleanup;
        }

        if (cr.errors > 0)
        {
            // Transfere os erros do compilador (do YARA) para o output
            output->compiler_results = cr;
            result = ERROR_SYNTAX_ERROR;
            goto cleanup;
        }

        if (fail_on_warnings && cr.warnings > 0)
        {
            output->compiler_results = cr;
            result = ERROR_SYNTAX_ERROR;
            goto cleanup;
        }

        result = yr_compiler_get_rules(compiler, &rules);
        if (result != ERROR_SUCCESS)
        {
            add_execution_error(output, result, get_error_message(result));
            goto cleanup;
        }
    }

    if (show_stats)
    {
        result = collect_rules_stats(rules, &output->stats);
        if (result != ERROR_SUCCESS)
        {
            add_execution_error(output, result, get_error_message(result));
            goto cleanup;
        }
    }

    if (fast_scan)
        flags |= SCAN_FLAGS_FAST_MODE;

    scan_opts.deadline = time(NULL) + timeout;

    CALLBACK_ARGS user_data = { file, 0, output };

    result = yr_scanner_create(rules, &scanner);
    if (result != ERROR_SUCCESS)
    {
        add_execution_error(output, result, get_error_message(result));
        goto cleanup;
    }

    yr_scanner_set_callback(scanner, callback, &user_data);
    yr_scanner_set_flags(scanner, flags);
    yr_scanner_set_timeout(scanner, timeout);

    result = scan_file(scanner, file);
    if (result == ERROR_COULD_NOT_OPEN_FILE)
    {
        // Tenta interpretar 'file' como um PID
        char_t* endptr = NULL;
        long pid = _tcstol(file, &endptr, 10);

        if (pid > 0 && file != NULL && *endptr == '\x00')
            result = yr_scanner_scan_proc(scanner, (int)pid);
    }

    if (result != ERROR_SUCCESS)
    {
        collect_scanner_error(scanner, result, output);
        goto cleanup;
    }


cleanup:
    unload_modules_data();

    if (scanner != NULL)
        yr_scanner_destroy(scanner);

    if (compiler != NULL)
        yr_compiler_destroy(compiler);

    if (rules != NULL)
        yr_rules_destroy(rules);

    yr_finalize();

    return result;
}


void free_execution_errors(EXECUTION_ERROR* error_list)
{
    while (error_list != NULL)
    {
        EXECUTION_ERROR* next = error_list->next;
        if (error_list->message) free(error_list->message);
        if (error_list->rule_identifier) free(error_list->rule_identifier);
        if (error_list->string_identifier) free(error_list->string_identifier);
        free(error_list);
        error_list = next;
    }
}

void free_error_messages(ERROR_MESSAGE* error_list)
{
    while (error_list != NULL)
    {
        ERROR_MESSAGE* next = error_list->next;
        if (error_list->file_name) free(error_list->file_name);
        if (error_list->rule_identifier) free(error_list->rule_identifier);
        if (error_list->message) free(error_list->message);
        free(error_list);
        error_list = next;
    }
}

void free_yara_stats(YARA_STATS* stats)
{
    if (stats->top_ac_match_list_lengths != NULL)
    {
        free(stats->top_ac_match_list_lengths);
        stats->top_ac_match_list_lengths = NULL;
    }
}

YARA_CDEF void YARA_CALL free_yara_output(YARA_OUTPUT* output)
{
    free_execution_errors(output->execution_errors);
    free_error_messages(output->compiler_results.error_list);
    free_yara_stats(&output->stats);

    RULE_MATCH* rule_match = output->rule_matches;
    while (rule_match)
    {
        RULE_MATCH* next_rule = rule_match->next;

        // Free strings
        if (rule_match->rnamespace)
            free(rule_match->rnamespace);
        if (rule_match->identifier)
            free(rule_match->identifier);
        if (rule_match->tags)
            free(rule_match->tags);
        if (rule_match->meta)
            free(rule_match->meta);

        // Free string matches
        STRING_MATCH* string_match = rule_match->string_matches;
        while (string_match)
        {
            STRING_MATCH* next_string = string_match->next;
            if (string_match->identifier)
                free(string_match->identifier);
            if (string_match->data)
                free(string_match->data);
            free(string_match);
            string_match = next_string;
        }

        free(rule_match);
        rule_match = next_rule;
    }
}