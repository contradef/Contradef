// utils.cpp
#include "utils.h"


bool IsPointer(ADDRINT value) {
    // Verifica se o valor é um ponteiro acessível
    return PIN_CheckReadAccess(reinterpret_cast<void*>(value));
}


std::string GetNumericValue(ADDRINT ea, UINT32 size) {
    if (size == 0) {
        return "0"; // Retorna "0" para tamanho inválido
    }

    std::stringstream ss;

    switch (size) {
    case 1:
    {
        UINT8 value = static_cast<UINT8>(ea);
        ss << std::dec << static_cast<unsigned int>(value);
    }
    break;

    case 2:
    {
        UINT16 value = static_cast<UINT16>(ea);
        ss << std::dec << value;
    }
    break;

    case 4:
    {
        UINT32 value = static_cast<UINT32>(ea);
        ss << std::dec << value;
    }
    break;

    case 8:
    {
        UINT64 value = static_cast<UINT64>(ea);
        ss << std::dec << value;
    }
    break;

    default:
        // Trata outros casos como um ponteiro de 64 bits
        ss << std::dec << static_cast<UINT64>(ea);
        break;
    }

    return ss.str();
}

std::string GetNumericHexValue(ADDRINT ea, UINT32 size) {
    if (size == 0) {
        return "0"; // Retorna "0" para tamanho inválido
    }

    std::stringstream ss;
    ss << "0x"; // Prefixo hexadecimal para maior clareza

    switch (size) {
    case 1:
    {
        UINT8 value = static_cast<UINT8>(ea);
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(value);
    }
    break;

    case 2:
    {
        UINT16 value = static_cast<UINT16>(ea);
        ss << std::setfill('0') << std::setw(4) << std::hex << value;
    }
    break;

    case 4:
    {
        UINT32 value = static_cast<UINT32>(ea);
        ss << std::setfill('0') << std::setw(8) << std::hex << value;
    }
    break;

    case 8:
    {
        UINT64 value = static_cast<UINT64>(ea);
        ss << std::setfill('0') << std::setw(16) << std::hex << value;
    }
    break;

    default:
        // Trata outros casos como um ponteiro de 64 bits
        ss << std::hex << static_cast<UINT64>(ea);
        break;
    }

    return ss.str();
}

std::string GetNumericValueFromRef(VOID* ea, UINT32 size) {
    if (!IsPointer(reinterpret_cast<ADDRINT>(ea))) {
        return ""; // Retorna um valor padrão se o ponteiro for inválido
    }

    std::stringstream ss;
    ss << "0x"; // Prefixo hexadecimal para maior clareza

    switch (size) {
    case 0:
        return ""; // Tamanho inválido
        break;

    case 1:
    {
        UINT8 x;
        PIN_SafeCopy(&x, static_cast<UINT8*>(ea), 1);
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int>(x) << " (" << std::dec << static_cast<unsigned int>(x) << ")"; // Converte UINT8 para string
    }
    break;

    case 2:
    {
        UINT16 x;
        PIN_SafeCopy(&x, static_cast<UINT16*>(ea), 2);
        ss << std::setfill('0') << std::setw(4) << std::hex << x << " (" << std::dec << x << ")"; // Converte UINT16 para string
    }
    break;

    case 4:
    {
        UINT32 x;
        PIN_SafeCopy(&x, static_cast<UINT32*>(ea), 4);
        ss << std::setfill('0') << std::setw(8) << std::hex << x << " (" << std::dec << x << ")"; // Converte UINT32 para string
    }
    break;

    case 8:
    {
        UINT64 x;
        PIN_SafeCopy(&x, static_cast<UINT64*>(ea), 8);
        ss << std::setfill('0') << std::setw(16) << std::hex << x << " (" << std::dec << x << ")"; // Converte UINT64 para string
    }
    break;

    default:
        // Converte o ponteiro em string hexadecimal
        ss << "0x" << std::hex << reinterpret_cast<uintptr_t>(ea);
        break;
    }

    return ss.str();
}

bool IsStringPointer(UINT64 addr) {
    if (!IsPointer(addr)) {
        return false; // Ponteiro inválido
    }

    char* str = reinterpret_cast<char*>(addr);
    for (int i = 0; i < 256; ++i) { // Limite para evitar leitura fora do contexto
        if (!PIN_CheckReadAccess(&str[i])) {
            return false; // Parte da string não é acessível
        }
        if (str[i] == '\0') {
            return true; // Encontrou o final da string
        }
        if (str[i] < 0x20 || str[i] > 0x7E) {
            return false; // Não é um caractere imprimível
        }
    }
    return false; // Não encontrou um final de string válido
}


bool IsValidWideString(const std::wstring& str) {
    // Verifique primeiro o tamanho mínimo
    if (str.size() < 3) {
        return false;
    }

    for (wchar_t ch : str) {
        // Permitir apenas caracteres ASCII alfanuméricos e os permitidos extras
        if (!((ch >= L'0' && ch <= L'9') || // Números
            (ch >= L'A' && ch <= L'Z') || // Letras maiúsculas
            (ch >= L'a' && ch <= L'z') || // Letras minúsculas
            ch == L'.' || ch == L'-' || ch == L'_' ||
            ch == L':' || ch == L'\\' || ch == L'/')) {
            return false; // Caractere inválido encontrado
        }
    }

    return true; // Todos os caracteres são válidos
}


bool IsValidString(const std::string& str) {
    // Verifique primeiro o tamanho mínimo
    if (str.size() < 3) {
        return false;
    }

    for (char ch : str) {
        // Permitir apenas caracteres ASCII alfanuméricos e os extras permitidos
        if (!((ch >= '0' && ch <= '9') || // Números
            (ch >= 'A' && ch <= 'Z') || // Letras maiúsculas
            (ch >= 'a' && ch <= 'z') || // Letras minúsculas
            ch == '.' || ch == '-' || ch == '_' ||
            ch == ':' || ch == '\\' || ch == '/')) {
            return false; // Caractere inválido encontrado
        }
    }

    return true; // Todos os caracteres são válidos
}

std::string InterpretAddrIntAsASCII(ADDRINT value) {
    std::string result;
    for (std::size_t i = 0; i < sizeof(ADDRINT); ++i) {
        char c = static_cast<char>((value >> (i * 8)) & 0xFF);
        if (std::isprint(static_cast<unsigned char>(c)) || c == '\0') {
            result += c;
        }
        else {
            break; // interrompe no primeiro caractere não imprimível
        }
    }
    return result;
}

std::wstring CopyLPCWSTR(ADDRINT addr) {
    const size_t MAX_STRING_LENGTH = 800; // Defina o tamanho máximo da string
    wchar_t buffer[MAX_STRING_LENGTH];    // Buffer para armazenar a string copiada
    memset(buffer, 0, sizeof(buffer));    // Inicializa o buffer com zeros

    size_t copied = 0;                    // Contador de caracteres copiados

    for (size_t i = 0; i < MAX_STRING_LENGTH - 1; i++) {
        // Use PIN_SafeCopy para copiar um único caractere wide por vez (2 bytes em UTF-16/UCS-2)
        size_t result = PIN_SafeCopy(&buffer[i], reinterpret_cast<const void*>(addr + i * sizeof(wchar_t)), sizeof(wchar_t));

        // Se a cópia falhar ou encontrar o terminador nulo, finalize
        if (result != sizeof(wchar_t) || buffer[i] == L'\0') {
            break;
        }

        copied++;
    }

    // Verifica se o tamanho máximo foi excedido
    if (copied == MAX_STRING_LENGTH - 1) {
        //std::wcerr << L"Warning: Wide string copy reached the maximum limit." << std::endl;
    }

    return std::wstring(buffer); // Retorna a string wide copiada como um std::wstring
}

std::string CopyLPCSTR(ADDRINT addr) {
    const size_t MAX_STRING_LENGTH = 800; // Defina o tamanho máximo da string
    char buffer[MAX_STRING_LENGTH];       // Buffer para armazenar a string copiada
    memset(buffer, 0, sizeof(buffer));    // Inicializa o buffer com zeros

    size_t copied = 0;                    // Contador de bytes copiados

    for (size_t i = 0; i < MAX_STRING_LENGTH - 1; i++) {
        // Use PIN_SafeCopy para copiar um único caractere por vez
        size_t result = PIN_SafeCopy(&buffer[i], reinterpret_cast<const void*>(addr + i), 1);

        // Se a cópia falhar ou encontrar o terminador nulo, finalize
        if (result == 0 || buffer[i] == '\0') {
            break;
        }

        copied++;
    }

    // Verifica se o tamanho máximo foi excedido
    if (copied == MAX_STRING_LENGTH - 1) {
        //std::cerr << "Warning: String copy reached the maximum limit." << std::endl;
    }

    return std::string(buffer); // Retorna a string copiada como um std::string
}

std::string GetStringValueFromRegister(UINT64 value, UINT32 size) {
    std::ostringstream result;

    // Caso de um único caractere (1 byte)
    if (size == 1) {
        char c = static_cast<char>(value & 0xFF); // Apenas o byte menos significativo
        if (c >= 0x20 && c <= 0x7E) { // Verifica se é imprimível
            result << "'" << c << "'";
        }
        else {
            result << "";
        }
        return result.str();
    }

    // Caso de sequência de caracteres (até 8 bytes)
    const char* str = reinterpret_cast<const char*>(&value);
    bool isString = true;
    for (UINT32 i = 0; i < size && i < 8; ++i) { // Limite do registrador é 8 bytes
        if (str[i] == '\0') { // Terminação de string
            break;
        }
        if (str[i] < 0x20 || str[i] > 0x7E) { // Não imprimível
            isString = false;
            break;
        }
    }

    if (isString) {
        result << std::string(str, size).c_str(); // Converte para string
    }
    else {
        result << "";
    }

    return result.str();
}

size_t GetSafeWStringLength(ADDRINT addr, size_t maxLen) {
    size_t length = 0;
    wchar_t ch = 0;

    for (; length < maxLen; ++length) {
        // Copia apenas 1 wchar_t por vez de forma segura
        if (PIN_SafeCopy(&ch, reinterpret_cast<void*>(addr + length * sizeof(wchar_t)), sizeof(wchar_t)) != sizeof(wchar_t)) {
            break; // Falha ao acessar a memória -> parar
        }

        if (ch == L'\0') {
            break; // Fim da string
        }
    }

    return length;
}

std::wstring ConvertAddrToWideStringSafe(ADDRINT addr, size_t maxLen) {
    std::wstring result;

    size_t length = GetSafeWStringLength(addr, maxLen);
    if (length == 0) return result;

    // Buffer temporário com terminador adicional
    std::vector<wchar_t> buffer(length + 1, L'\0');

    // Use &buffer[0] no lugar de buffer.data() — compatível com C++11
    size_t copied = PIN_SafeCopy(&buffer[0], reinterpret_cast<void*>(addr), (length + 1) * sizeof(wchar_t));
    if (copied >= length * sizeof(wchar_t)) {
        result = std::wstring(&buffer[0]);
    }

    return result;
}


std::wstring ConvertAddrToWideString(ADDRINT addr) {
    if (addr != 0) {
        wchar_t* wideCharStr = reinterpret_cast<wchar_t*>(addr);
        return std::wstring(wideCharStr);
    }
    else {
        return std::wstring();  // Retorna uma string vazia se o endereço for nulo
    }
}

std::string ConvertAddrToAnsiString(ADDRINT addr) {
    if (addr != 0) {
        const char* charStr = reinterpret_cast<const char*>(addr);
        return std::string(charStr);
    }
    else {
        return std::string();  // Retorna uma string vazia se o endereço for nulo
    }
}

std::string WStringToString(const std::wstring& wstr)
{
    if (wstr.empty())
    {
        return std::string();
    }

    // Obtém o tamanho necessário do buffer para a string convertida (em UTF-8)
    int sizeNeeded = WindowsAPI::WideCharToMultiByte(
        CP_UTF8,          // Código de página para UTF-8
        0,                // Nenhum flag extra
        wstr.data(),      // Ponteiro para a string wide char
        static_cast<int>(wstr.size()), // Comprimento da string wide char
        nullptr,          // Sem buffer de saída por enquanto (queremos saber o tamanho necessário)
        0,
        nullptr,          // Sem uso de caractere de substituição
        nullptr           // Sem retorno de caractere substituto usado
    );

    if (sizeNeeded <= 0)
    {
        return std::string();
    }

    // Cria um buffer de tamanho adequado para a string resultante
    std::string result(sizeNeeded, 0);

    // Converte de wide char para string em UTF-8
    WindowsAPI::WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.data(),
        static_cast<int>(wstr.size()),
        &result[0],
        sizeNeeded,
        nullptr,
        nullptr
    );

    return result;
}

// Função para converter std::string para const wchar_t*
const wchar_t* StringToWString(const std::string& str)
{
    using namespace WindowsAPI;
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    wchar_t* wideStr = new wchar_t[size_needed];
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wideStr, size_needed);
    return wideStr;
}

void LogWString(const std::wstring& wstr) {
    std::string str = WStringToString(wstr);
    LOG("Converted String: %s\n", str.c_str());
}

std::string ExtractModuleName(const std::string& fullPath) {
    size_t lastSlashPos = fullPath.find_last_of("\\/");
    if (lastSlashPos != std::string::npos) {
        return fullPath.substr(lastSlashPos + 1);
    }
    else {
        return fullPath; // Retorna o fullPath original se não houver separador de diretório
    }
}

std::string toUpperCase(const std::string& str) {
    std::string upperCaseStr = str; // Cria uma cópia da string original
    for (char& c : upperCaseStr) {
        c = std::toupper(static_cast<unsigned char>(c));
    }
    return upperCaseStr;
}

VOID PrintTrace(std::deque<std::string>& threadTraces) {
    std::cout << "Routine Trace:" << std::endl;
    for (const auto& name : threadTraces) {
        std::cout << "  " << name << std::endl;
    }
}


void PrintCallContextMap(std::map<CallContextKey, CallContext*>& callContextMap) {

    for (const auto& pair : callContextMap) {
        const CallContextKey& key = pair.first;
        const CallContext* context = pair.second;

        std::cout << "CallContextKey: (callCtxId: " << key.callId
            << ", tid: " << key.threadId << ")" << std::endl;

        std::cout << "  CallContext: " << std::endl;
        std::cout << "    callCtxId: " << context->callId << std::endl;
        std::cout << "    tid: " << context->threadId << std::endl;
        std::cout << "    rtnAddress: " << std::hex << context->rtnAddress << std::dec << std::endl;
        std::cout << "    stringStream: " << context->stringStream.str() << std::endl;
    }
}


void GetParentProcessName() {
    using namespace WindowsAPI;
    DWORD currentProcessId = GetCurrentProcessId();
    DWORD parentProcessId = 0;

    // Tirar um snapshot de todos os processos
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Erro ao criar snapshot.\n";
        return;
    }

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == currentProcessId) {
                parentProcessId = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (parentProcessId != 0) {
        // Tirar outro snapshot para procurar o processo pai
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "Erro ao criar snapshot.\n";
            return;
        }

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == parentProcessId) {
                    std::wcout << L"Nome do processo pai: " << pe32.szExeFile << L"\n";
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }
    else {
        std::cerr << "Processo pai não encontrado.\n";
    }
}

DWORD GetProcessIdByName(std::string processName) {
    using namespace WindowsAPI;
    DWORD processId = 0;

    // Cria um snapshot de todos os processos
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Erro ao criar snapshot.\n";
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Percorre os processos no snapshot
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Compara o nome do executável
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
            std::string pName = WStringToString(pe32.szExeFile);
            std::transform(pName.begin(), pName.end(), pName.begin(), ::tolower);
            if (processName == pName) {
                processId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    else {
        std::cerr << "Erro ao percorrer os processos.\n";
    }

    CloseHandle(hSnapshot);
    return processId;
}

std::string getFileName(const std::string& filePath) {
    // Encontra a última ocorrência de '\' ou '/'
    size_t pos = filePath.find_last_of("\\/");

    if (pos != std::string::npos) {
        return filePath.substr(pos + 1);
    }

    return filePath;
}