#include "YaraContradef.h"
int RunYara(std::string _rules_file, std::string _target_file, std::ofstream& OutFile, std::vector<std::string>& matched)
{
    // Carregando a API do YARA de forma dinâmica para evitar erros ou conflitos da biblioteca windows.h com pin.h
    using namespace YaraAPI;

    // Converter as strings para wchar_t*
    const wchar_t* rules_file = StringToWString(_rules_file);
    const wchar_t* target_file = StringToWString(_target_file);

    // LoadLibrary e obter ponteiros para funções do YARA
    HMODULE hYaraLib = LoadLibrary(L"yaraCdef64.dll");
    if (hYaraLib == NULL) {
        std::cout << "Erro ao carregar a API do YARA." << std::endl;
        delete[] rules_file;
        delete[] target_file;
        return 1;
    }

    typedef int (*RunYaraFunc)(const wchar_t*, const wchar_t*, YARA_OUTPUT*);
    RunYaraFunc dynamic_run_yara = (RunYaraFunc)GetProcAddress(hYaraLib, "run_yara");
    if (dynamic_run_yara == NULL) {
        std::cout << "Erro ao carregar a função run_yara da API do YARA." << std::endl;
        if (hYaraLib)
            FreeLibrary(hYaraLib);
        delete[] rules_file;
        delete[] target_file;
        return 1;
    }

    typedef void (*FreeYaraOutputFunc)(YARA_OUTPUT* output);
    FreeYaraOutputFunc dynamic_free_yara_output = (FreeYaraOutputFunc)GetProcAddress(hYaraLib, "free_yara_output");
    if (dynamic_free_yara_output == NULL) {
        std::cout << "Erro ao carregar a função free_yara_output da API do YARA." << std::endl;
        if (hYaraLib)
            FreeLibrary(hYaraLib);
        delete[] rules_file;
        delete[] target_file;
        return 1;
    }

    YARA_OUTPUT output;
    int result = dynamic_run_yara(rules_file, target_file, &output);

    if (result == ERROR_SUCCESS)
    {
        OutFile << std::endl << "[+] Regras YARA..." << std::endl;
        OutFile << "    Correspondências encontradas: " << output.match_count << std::endl;
        OutFile << "    Regras correspondidas: " << std::endl;

        // Itera sobre as correspondências de regras
        RULE_MATCH* rule = output.rule_matches;
        while (rule)
        {
            std::string ruleid = rule->identifier;
            if (ruleid.find("Obsidium") != std::string::npos) {
                matched.push_back("Obsidium");
            }
            
            OutFile << "        " << rule->identifier << std::endl;
            STRING_MATCH* sm = rule->string_matches;
            OutFile << std::hex << std::uppercase;
            while (sm)
            {
                OutFile << "            String: " << sm->identifier << " no offset 0x" << sm->offset << std::endl;
                sm = sm->next;
            }
            OutFile << std::dec << std::nouppercase;
            rule = rule->next;
        }
        OutFile << "[*] Concluído" << std::endl << std::endl;

        // Libera a memória alocada pela API
        dynamic_free_yara_output(&output);
    }
    else
    {
        std::cerr << "Erro ao executar a varredura do YARA: " << result << std::endl;

        // Lida com erros de compilação
        ERROR_MESSAGE* error_msg = output.compiler_results.error_list;
        while (error_msg)
        {
            std::cerr << "Erro do compilador no arquivo " << error_msg->file_name << " na linha " << error_msg->line_number << L": " << error_msg->message << std::endl;
            error_msg = error_msg->next;
        }

        // Lida com erros de execução
        EXECUTION_ERROR* exec_error = output.execution_errors;
        while (exec_error)
        {
            std::cerr << "Erro de execução: " << exec_error->message << std::endl;
            exec_error = exec_error->next;
        }

        // Libera a memória alocada pela API
        dynamic_free_yara_output(&output);
    }

    if (hYaraLib)
        FreeLibrary(hYaraLib);

    // Libera a memória dos wide strings
    delete[] rules_file;
    delete[] target_file;

    return 0;
}
