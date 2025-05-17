
#include "DllFunctionMapper.h"

std::vector<ModuleRange> moduleRanges;

FunctionData GetFunctionFromAddress(unsigned long long address, unsigned int pid) {
    void* pAddress = reinterpret_cast<void*>(address);
    WindowsAPI::HANDLE process = WindowsAPI::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    char moduleName[MAX_PATH];
    std::string sModuleName;
    if (WindowsAPI::GetMappedFileNameA(process, pAddress, moduleName, MAX_PATH)) {
        sModuleName = std::string(moduleName);
    }
    else {
        // Se falhar, verificar a lista de módulos registrados
        for (const auto& mod : moduleRanges) {
            if (address >= mod.start && address < mod.end) {
                sModuleName = mod.name;
                break;
            }
        }
    }

    WindowsAPI::HMODULE hModule = WindowsAPI::LoadLibraryA(getFileName(sModuleName).c_str());

    if (!hModule) {
        WindowsAPI::FreeLibrary(hModule);
        return { "Invalid Module", "", "Invalid Function" };
    }

    // Obter cabeçalho PE
    WindowsAPI::IMAGE_DOS_HEADER* dosHeader = (WindowsAPI::IMAGE_DOS_HEADER*)hModule;
    WindowsAPI::IMAGE_NT_HEADERS* ntHeaders = (WindowsAPI::IMAGE_NT_HEADERS*)((WindowsAPI::BYTE*)hModule + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        WindowsAPI::FreeLibrary(hModule);
        return { "No Export Directory", "", "Unknown Function" };
    }

    WindowsAPI::IMAGE_EXPORT_DIRECTORY* exportDir = (WindowsAPI::IMAGE_EXPORT_DIRECTORY*)((WindowsAPI::BYTE*)hModule + exportDirRVA);
    DWORD* addressOfFunctions = (DWORD*)((WindowsAPI::BYTE*)hModule + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((WindowsAPI::BYTE*)hModule + exportDir->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((WindowsAPI::BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD numberOfFunctions = exportDir->NumberOfFunctions;

    // Coletar e ordenar endereços de funções
    std::vector<std::pair<WindowsAPI::DWORD64, std::string>> functionAddresses;
    for (DWORD i = 0; i < numberOfFunctions; i++) {
        DWORD functionRVA = addressOfFunctions[i];
        WindowsAPI::DWORD64 functionAddress = (WindowsAPI::DWORD64)hModule + functionRVA;

        std::string functionName = "Unnamed Function";
        for (DWORD j = 0; j < exportDir->NumberOfNames; j++) {
            if (addressOfNameOrdinals[j] == i) {
                const char* name = (const char*)((WindowsAPI::BYTE*)hModule + addressOfNames[j]);
                functionName = name;
                break;
            }
        }

        functionAddresses.push_back(std::make_pair(functionAddress, functionName));
    }

    // Ordenar endereços
    std::sort(functionAddresses.begin(), functionAddresses.end(),
        [](const std::pair<WindowsAPI::DWORD64, std::string>& a, const std::pair<WindowsAPI::DWORD64, std::string>& b) {
            return a.first < b.first;
        });

    // Construir intervalos de funções
    std::vector<FunctionRange> functionRanges;
    for (size_t i = 0; i < functionAddresses.size(); i++) {
        FunctionRange range;
        range.start = functionAddresses[i].first;
        range.name = functionAddresses[i].second;
        range.end = (i + 1 < functionAddresses.size()) ? functionAddresses[i + 1].first : -1;
        functionRanges.push_back(range);
    }

    // Procurar endereço no intervalo
    for (const auto& range : functionRanges) {
        if (address >= range.start && (range.end == -1 || address < range.end)) {
            WindowsAPI::FreeLibrary(hModule);
            return { sModuleName, getFileName(sModuleName), range.name.empty() ? "Unnamed Function" : range.name };
        }
    }

    WindowsAPI::FreeLibrary(hModule);
    return { sModuleName, getFileName(sModuleName), "Function Not Found" };
}


FunctionData GetFunctionFromAddressManualPE(unsigned long long address, unsigned int pid) {
    using namespace WindowsAPI;
    FunctionData result = { "Unknown Module", "Unknown Module", "Unknown Function" };

    // Abrir o processo
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!process) {
        std::cerr << "Failed to open process." << std::endl;
        return result;
    }

    // Obter o nome completo do módulo
    char moduleName[MAX_PATH];
    if (!GetMappedFileNameA(process, reinterpret_cast<void*>(address), moduleName, MAX_PATH)) {
        CloseHandle(process);
        return { "Unknown Module", "Unknown Module", "Unknown Function" };
    }

    result.fullModuleName = moduleName;
    result.moduleName = getFileName(moduleName);

    // Carregar o módulo
    HMODULE hModule = LoadLibraryA(result.moduleName.c_str());
    if (!hModule) {
        CloseHandle(process);
        return { "Invalid Module", result.moduleName, "Unknown Function" };
    }

    // Parsing do PE
    WindowsAPI::IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<WindowsAPI::IMAGE_DOS_HEADER*>(hModule);
    WindowsAPI::IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<WindowsAPI::IMAGE_NT_HEADERS*>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        FreeLibrary(hModule);
        CloseHandle(process);
        return { "No Export Directory", result.moduleName, "Unknown Function" };
    }

    IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<BYTE*>(hModule) + exportDirRVA);

    DWORD* addressOfFunctions = reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(hModule) + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(hModule) + exportDir->AddressOfNames);
    WORD* addressOfNameOrdinals = reinterpret_cast<WORD*>(
        reinterpret_cast<BYTE*>(hModule) + exportDir->AddressOfNameOrdinals);

    // Coletar e ordenar as funções
    std::vector<FunctionRange> functionRanges;
    for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++) {
        DWORD functionRVA = addressOfFunctions[i];
        DWORD64 functionStart = reinterpret_cast<DWORD64>(hModule) + functionRVA;
        DWORD64 functionEnd = (i + 1 < exportDir->NumberOfFunctions) ?
            (reinterpret_cast<DWORD64>(hModule) + addressOfFunctions[i + 1]) : -1;

        std::string functionName = "Unnamed Function";
        for (DWORD j = 0; j < exportDir->NumberOfNames; j++) {
            if (addressOfNameOrdinals[j] == i) {
                functionName = reinterpret_cast<char*>(
                    reinterpret_cast<BYTE*>(hModule) + addressOfNames[j]);
                break;
            }
        }

        functionRanges.push_back({ functionStart, functionEnd, functionName });
    }

    // Procurar o endereço na lista de intervalos
    for (const auto& range : functionRanges) {
        if (address >= range.start && (range.end == -1 || address < range.end)) {
            FreeLibrary(hModule);
            CloseHandle(process);
            return { result.fullModuleName, result.moduleName, range.name };
        }
    }

    FreeLibrary(hModule);
    CloseHandle(process);
    return result;
}