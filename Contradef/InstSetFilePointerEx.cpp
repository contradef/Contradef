#include "InstSetFilePointerEx.h"

// Inicializa��o das vari�veis est�ticas
std::map<CallContextKey, CallContext*> InstSetFilePointerEx::callContextMap;
UINT32 InstSetFilePointerEx::imgCallId = 0;
UINT32 InstSetFilePointerEx::fcnCallId = 0;
Notifier* InstSetFilePointerEx::globalNotifierPtr;

// Callback executado antes da chamada da fun��o SetFilePointerEx
VOID InstSetFilePointerEx::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hFile, ADDRINT liDistanceToMovePtr, ADDRINT lpNewFilePointer, ADDRINT dwMoveMethod) {

    // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }


    // Estrutura para armazenar os argumentos
    SetFilePointer::SetFilePointerExArgs args;
    args.hFile = hFile;
    // Tenta copiar a estrutura LARGE_INTEGER apontada por liDistanceToMovePtr
    if (liDistanceToMovePtr != 0) {
        PIN_SafeCopy(&args.liDistanceToMove, reinterpret_cast<SetFilePointer::LARGE_INTEGER*>(liDistanceToMovePtr), sizeof(SetFilePointer::LARGE_INTEGER));
    }
    else {
        // Se o ponteiro for NULL, inicializa com zero
        args.liDistanceToMove.QuadPart = 0;
    }
    args.lpNewFilePointer = lpNewFilePointer;
    args.dwMoveMethod = dwMoveMethod;

    // Cria��o de um ID �nico para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;

    // Cria��o e armazenamento do contexto da chamada
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Constru��o da mensagem de log
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] SetFilePointerEx..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endere�o da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Par�metros: " << std::endl;
    stringStream << "        hFile: 0x" << std::hex << hFile << std::dec << std::endl;
    stringStream << "        liDistanceToMove: " << args.liDistanceToMove.QuadPart << " bytes" << std::endl;
    stringStream << "        lpNewFilePointer: 0x" << std::hex << lpNewFilePointer << std::dec << std::endl;
    stringStream << "        dwMoveMethod: " << dwMoveMethod << std::endl;
    stringStream << "    Endere�o da fun��o chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] In�cio da chamada SetFilePointerEx" << std::endl;

}

// Callback executado ap�s a chamada da fun��o SetFilePointerEx
VOID InstSetFilePointerEx::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT hFile, ADDRINT liDistanceToMovePtr, ADDRINT lpNewFilePointer, ADDRINT dwMoveMethod) {

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
        stringStream << "    Retorno SetFilePointerEx: " << result << std::endl;

        if (result != 0) {
            // Sucesso: tenta ler o valor retornado em lpNewFilePointer
            if (lpNewFilePointer != 0) {
                SetFilePointer::LARGE_INTEGER newFilePointer;
                PIN_SafeCopy(&newFilePointer, reinterpret_cast<SetFilePointer::LARGE_INTEGER*>(lpNewFilePointer), sizeof(SetFilePointer::LARGE_INTEGER));
                stringStream << "    Novo ponteiro do arquivo: " << newFilePointer.QuadPart << " bytes" << std::endl;
            }
            else {
                stringStream << "    lpNewFilePointer � NULL. N�o foi poss�vel ler o novo ponteiro do arquivo." << std::endl;
            }
            stringStream << "    Opera��o conclu�da com sucesso." << std::endl;
        }
        else {
            // Falha: obt�m o c�digo de erro
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao mover o ponteiro do arquivo. C�digo de erro: " << error << std::endl;
        }

        // Finaliza��o das mensagens de log
        stringStream << "  [-] Chamada SetFilePointerEx conclu�da" << std::endl;
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

// M�todo respons�vel por inserir os callbacks na fun��o SetFilePointerEx
VOID InstSetFilePointerEx::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "SetFilePointerEx") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // BOOL SetFilePointerEx(
        //   HANDLE         hFile,
        //   LARGE_INTEGER  liDistanceToMove,
        //   PLARGE_INTEGER lpNewFilePointer,
        //   DWORD          dwMoveMethod
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // liDistanceToMove (pointer)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpNewFilePointer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // dwMoveMethod
            IARG_END);

        // Inser��o do CallbackAfter ap�s a chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // valor de retorno (BOOL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // liDistanceToMove (pointer)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpNewFilePointer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // dwMoveMethod
            IARG_END);

        RTN_Close(rtn);
    }
}
