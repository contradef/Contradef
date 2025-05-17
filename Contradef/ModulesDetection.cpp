#include "ModulesDetection.h"

// Defini��o dos m�dulos evasivos conhecidos
const char* EvasiveModules[] = {
    "SbieDll.dll",    // Sandboxie DLL
    "cmdvrt32.dll",   // Comodo virtualized environment
    "dbghelp.dll",    // Debugging helpers
    "api_log.dll",    // API monitoring tools
    "dir_watch.dll",  // Directory monitoring
    "vmcheck.dll",    // Virtual machine detection tools
    "wpespy.dll",     // Winsock packet editor (network sniffing)
    // Adicione outros m�dulos relevantes aqui
};
const size_t EvasiveModulesSize = sizeof(EvasiveModules) / sizeof(EvasiveModules[0]);

// Fun��o para verificar se o nome de um m�dulo faz parte da lista de m�dulos evasivos
bool isModulePartInList(const std::string& moduleName) {
    for (size_t i = 0; i < EvasiveModulesSize; ++i) {
        if (moduleName.find(EvasiveModules[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}
