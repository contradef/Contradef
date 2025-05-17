#include "InstGetVolumePathNameW.h"

// Inicialização das variáveis estáticas
std::map<CallContextKey, CallContext*> InstGetVolumePathNameW::callContextMap;
UINT32 InstGetVolumePathNameW::imgCallId = 0;
UINT32 InstGetVolumePathNameW::fcnCallId = 0;
Notifier* InstGetVolumePathNameW::globalNotifierPtr;

// Callback executado antes da chamada da função GetVolumePathNameW
VOID InstGetVolumePathNameW::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpszFileName, ADDRINT lpszVolumePathName, ADDRINT cchBufferLength) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Estrutura para armazenar os argumentos
    GetVolumePathNameWArgs args;
    args.lpszFileName = lpszFileName;
    args.lpszVolumePathName = lpszVolumePathName;
    args.cchBufferLength = cchBufferLength;

    // Criação de um ID único para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;

    // Criação e armazenamento do contexto da chamada
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Construção da mensagem de log
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetVolumePathNameW..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;

    // Tenta ler e exibir a string de entrada, se possível
    if (args.lpszFileName != 0 && args.cchBufferLength > 0) {
        std::wstring fileName;
        fileName.resize(args.cchBufferLength);
        SIZE_T charsRead = PIN_SafeCopy(&fileName[0], reinterpret_cast<wchar_t*>(args.lpszFileName), sizeof(wchar_t) * args.cchBufferLength) / sizeof(wchar_t);
        if (charsRead > 0) {
            fileName.resize(charsRead);
            stringStream << "        lpszFileName: " << WStringToString(fileName.c_str()) << std::endl;
        }
        else {
            stringStream << "        lpszFileName: <não pôde ser lido>" << std::endl;
        }
    }
    else {
        stringStream << "        lpszFileName: NULL ou cchBufferLength inválido." << std::endl;
    }

    stringStream << "        lpszVolumePathName: 0x" << std::hex << args.lpszVolumePathName << std::dec << std::endl;
    stringStream << "        cchBufferLength: " << args.cchBufferLength << " caracteres" << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada GetVolumePathNameW" << std::endl;

}

// Callback executado após a chamada da função GetVolumePathNameW
VOID InstGetVolumePathNameW::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT lpszFileName, ADDRINT lpszVolumePathName, ADDRINT cchBufferLength) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Criação do ID único para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };

    // Busca do contexto da chamada no mapa
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient(); // Proteção para acesso seguro ao contexto

        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        // Conversão do valor de retorno para BOOL
        BOOL result = static_cast<BOOL>(retValAddr);
        stringStream << "    Retorno GetVolumePathNameW: " << (result ? "TRUE" : "FALSE") << std::endl;

        if (result != 0) {
            // Sucesso: tenta ler o valor retornado em lpszVolumePathName
            if (lpszVolumePathName != 0 && cchBufferLength > 0) {
                std::wstring volumePath;
                volumePath.resize(cchBufferLength);
                SIZE_T charsRead = PIN_SafeCopy(&volumePath[0], reinterpret_cast<wchar_t*>(lpszVolumePathName), sizeof(wchar_t) * cchBufferLength) / sizeof(wchar_t);
                if (charsRead > 0) {
                    volumePath.resize(charsRead);
                    stringStream << "    Volume Path Name: " << WStringToString(volumePath.c_str()) << std::endl;
                }
                else {
                    stringStream << "    Volume Path Name: <não pôde ser lido>" << std::endl;
                }
            }
            else {
                stringStream << "    lpszVolumePathName: NULL ou cchBufferLength inválido. Não foi possível ler o Volume Path Name." << std::endl;
            }
            stringStream << "    Operação concluída com sucesso." << std::endl;
        }
        else {
            // Falha: obtém o código de erro
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao obter o Volume Path Name. Código de erro: " << error << std::endl;
        }

        // Finalização das mensagens de log
        stringStream << "  [-] Chamada GetVolumePathNameW concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        // Notificação aos observadores após capturar o resultado
        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        // Limpeza: remove e deleta o contexto da chamada
        delete callContext;
        callContextMap.erase(it);

        PIN_UnlockClient(); // Desprotege o contexto
    }
}


// Método responsável por inserir os callbacks na função GetVolumePathNameW
VOID InstGetVolumePathNameW::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetVolumePathNameW") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // BOOL GetVolumePathNameW(
        //   LPCWSTR lpszFileName,
        //   LPWSTR  lpszVolumePathName,
        //   DWORD   cchBufferLength
        // );

        // Inserção do CallbackBefore antes da chamada da função
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpszFileName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpszVolumePathName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // cchBufferLength
            IARG_END);

        // Inserção do CallbackAfter após a chamada da função
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // valor de retorno (BOOL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpszFileName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpszVolumePathName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // cchBufferLength
            IARG_END);

        RTN_Close(rtn);
    }
}