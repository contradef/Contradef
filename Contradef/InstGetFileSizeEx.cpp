#include "InstGetFileSizeEx.h"

// Inicializa��o das vari�veis est�ticas
std::map<CallContextKey, CallContext*> InstGetFileSizeEx::callContextMap;
UINT32 InstGetFileSizeEx::imgCallId = 0;
UINT32 InstGetFileSizeEx::fcnCallId = 0;
Notifier* InstGetFileSizeEx::globalNotifierPtr;

// Callback executado antes da chamada da fun��o GetFileSizeEx
VOID InstGetFileSizeEx::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hFile, ADDRINT lpFileSize) {

    // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Estrutura para armazenar os argumentos
    GetFileSizeExArgs args;
    args.hFile = hFile;
    args.lpFileSize = lpFileSize;

    // Cria��o de um ID �nico para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;

    // Cria��o e armazenamento do contexto da chamada
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Constru��o da mensagem de log
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetFileSizeEx..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endere�o da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Par�metros: " << std::endl;
    stringStream << "        hFile: 0x" << std::hex << hFile << std::dec << std::endl;
    stringStream << "        lpFileSize: 0x" << std::hex << lpFileSize << std::dec << std::endl;
    stringStream << "    Endere�o da fun��o chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] In�cio da chamada GetFileSizeEx" << std::endl;

}

// Callback executado ap�s a chamada da fun��o GetFileSizeEx
VOID InstGetFileSizeEx::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT hFile, ADDRINT lpFileSize) {

    // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Cria��o do ID �nico para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };

    // Busca do contexto da chamada no mapa
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient(); // Prote��o para acesso seguro ao contexto

        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        // Convers�o do valor de retorno para BOOL
        BOOL result = static_cast<BOOL>(retValAddr);
        stringStream << "    Retorno GetFileSizeEx: " << result << std::endl;

        if (result != 0) {
            // Sucesso: tenta ler o valor retornado em lpFileSize
            using namespace WindowsAPI;
            LARGE_INTEGER fileSize;
            if (lpFileSize != 0) {
                PIN_SafeCopy(&fileSize, reinterpret_cast<LARGE_INTEGER*>(lpFileSize), sizeof(LARGE_INTEGER));
                stringStream << "    Tamanho do arquivo: " << fileSize.QuadPart << " bytes" << std::endl;
            }
            else {
                stringStream << "    lpFileSize � NULL. N�o foi poss�vel ler o tamanho do arquivo." << std::endl;
            }
            stringStream << "    Opera��o conclu�da com sucesso." << std::endl;
        }
        else {
            // Falha: obt�m o c�digo de erro
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao obter o tamanho do arquivo. C�digo de erro: " << error << std::endl;
        }

        // Finaliza��o das mensagens de log
        stringStream << "  [-] Chamada GetFileSizeEx conclu�da" << std::endl;
        stringStream << "[*] Conclu�do" << std::endl << std::endl;

        // Notifica��o aos observadores ap�s capturar o resultado
        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        // Limpeza: remove e deleta o contexto da chamada
        delete callContext;
        callContextMap.erase(it);

        PIN_UnlockClient(); // Desprotege o contexto
    }

    // Incrementa o ID da chamada
    fcnCallId++;
}

// M�todo respons�vel por inserir os callbacks na fun��o GetFileSizeEx
VOID InstGetFileSizeEx::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetFileSizeEx") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // BOOL GetFileSizeEx(
        //   HANDLE         hFile,
        //   PLARGE_INTEGER lpFileSize
        // );

        // Inser��o do CallbackBefore antes da chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpFileSize
            IARG_END);

        // Inser��o do CallbackAfter ap�s a chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (BOOL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpFileSize
            IARG_END);

        RTN_Close(rtn);
    }
}
