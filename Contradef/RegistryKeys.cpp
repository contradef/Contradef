#include "RegistryKeys.h"

// Definição das variáveis no arquivo .cpp

// Detecção de Máquinas Virtuais
const char* VMwareKeys[] = {
    "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\vmci",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\vmhgfs",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\vmvss",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\vmx86"
};
const size_t VMwareKeysSize = sizeof(VMwareKeys) / sizeof(VMwareKeys[0]);

const char* VirtualBoxKeys[] = {
    "HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__",
    "HKLM\\HARDWARE\\ACPI\\FADT\\VBOX__",
    "HKLM\\HARDWARE\\ACPI\\RSDT\\VBOX__",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxGuest",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxMouse",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxService",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxSF",
    "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxVideo"
};
const size_t VirtualBoxKeysSize = sizeof(VirtualBoxKeys) / sizeof(VirtualBoxKeys[0]);

const char* UnknownVMKeys[] = {
    "HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000",
    "HKLM\\Hardware\\description\\System"
};
const size_t UnknownVMKeysSize = sizeof(UnknownVMKeys) / sizeof(UnknownVMKeys[0]);

// Detecção de Antivírus
const char* AntivirusKeys[] = {
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", // procurar por produtos de antivírus instalados
    "HKLM\\SOFTWARE\\Microsoft\\Security Center", // para versões mais antigas do Windows
    "HKLM\\SOFTWARE\\Microsoft\\Windows Defender",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows Defender"
};
const size_t AntivirusKeysSize = sizeof(AntivirusKeys) / sizeof(AntivirusKeys[0]);

// Detecção de Sandboxes
const char* SandboxieKeys[] = {
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sandboxie.exe",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SbieDrv",
    "HKCU\\Software\\Sandboxie",
    "HKLM\\SOFTWARE\\Classes\\CLSID\\{7988B573-EC89-11cf-9C00-00AA00A14F56}"
};
const size_t SandboxieKeysSize = sizeof(SandboxieKeys) / sizeof(SandboxieKeys[0]);

// Detecção de Instrumentadores e Depuradores
const char* DebuggerKeys[] = {
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ollydbg.exe",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\x64dbg.exe",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\windbg.exe",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ida.exe",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ida64.exe"
};
const size_t DebuggerKeysSize = sizeof(DebuggerKeys) / sizeof(DebuggerKeys[0]);

// Detecção de Ferramentas de Análise e Monitoramento
const char* AnalysisToolsKeys[] = {
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Wireshark",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Procmon",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Process Explorer",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Fiddler"
};
const size_t AnalysisToolsKeysSize = sizeof(AnalysisToolsKeys) / sizeof(AnalysisToolsKeys[0]);

// Detecção de Outros Ambientes e Ferramentas
const char* OtherToolsKeys[] = {
    "HKLM\\SOFTWARE\\CuckooSandbox",
    "HKLM\\SOFTWARE\\Comodo\\Firewall Pro",
    "HKLM\\SOFTWARE\\KasperskyLab",
    "HKLM\\SOFTWARE\\Emsisoft\\Anti-Malware",
    "HKLM\\SOFTWARE\\Symantec\\Symantec Endpoint Protection",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
};
const size_t OtherToolsKeysSize = sizeof(OtherToolsKeys) / sizeof(OtherToolsKeys[0]);

bool isRegistryKeyPartInList(const std::string& key) {
    auto checkKeyInList = [&](const char* keys[], size_t size) {
        for (size_t i = 0; i < size; ++i) {
            if (std::string(keys[i]).find(key) != std::string::npos) {
                return true;
            }
        }
        return false;
    };

    if (checkKeyInList(VMwareKeys, VMwareKeysSize)) return true;
    if (checkKeyInList(VirtualBoxKeys, VirtualBoxKeysSize)) return true;
    if (checkKeyInList(AntivirusKeys, AntivirusKeysSize)) return true;
    if (checkKeyInList(UnknownVMKeys, UnknownVMKeysSize)) return true;
    if (checkKeyInList(SandboxieKeys, SandboxieKeysSize)) return true;
    if (checkKeyInList(DebuggerKeys, DebuggerKeysSize)) return true;
    if (checkKeyInList(AnalysisToolsKeys, AnalysisToolsKeysSize)) return true;
    if (checkKeyInList(OtherToolsKeys, OtherToolsKeysSize)) return true;

    return false;
}