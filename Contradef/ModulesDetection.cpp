#include "ModulesDetection.h"

// Definição dos módulos evasivos conhecidos
const char* EvasiveModules[] = {
    "SbieDll.dll",    // Sandboxie DLL
    "cmdvrt32.dll",   // Comodo virtualized environment
    "dbghelp.dll",    // Debugging helpers
    "api_log.dll",    // API monitoring tools
    "dir_watch.dll",  // Directory monitoring
    "vmcheck.dll",    // Virtual machine detection tools
    "wpespy.dll",     // Winsock packet editor (network sniffing)
    // Adicione outros módulos relevantes aqui
};
const size_t EvasiveModulesSize = sizeof(EvasiveModules) / sizeof(EvasiveModules[0]);

// Função para verificar se o nome de um módulo faz parte da lista de módulos evasivos
bool isModulePartInList(const std::string& moduleName) {
    for (size_t i = 0; i < EvasiveModulesSize; ++i) {
        if (moduleName.find(EvasiveModules[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}
