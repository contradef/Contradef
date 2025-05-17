#include "InstBasepConstructSxsCreateProcessMessage.h"

// Inicializa��o das vari�veis est�ticas
std::map<CallContextKey, CallContext*> InstBasepConstructSxsCreateProcessMessage::callContextMap;
UINT32 InstBasepConstructSxsCreateProcessMessage::imgCallId = 0;
UINT32 InstBasepConstructSxsCreateProcessMessage::fcnCallId = 0;
Notifier* InstBasepConstructSxsCreateProcessMessage::globalNotifierPtr;

// Callback executado antes da chamada da fun��o BasepConstructSxsCreateProcessMessage
VOID InstBasepConstructSxsCreateProcessMessage::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT param1, ADDRINT param2, ADDRINT param3) {

    // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Estrutura para armazenar os argumentos
    BasepConstructSxsCreateProcessMessageArgs args;
    args.param1 = param1;
    args.param2 = param2;
    args.param3 = param3;
    // Inicialize mais par�metros conforme necess�rio

    // Cria��o de um ID �nico para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;

    // Cria��o e armazenamento do contexto da chamada
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Constru��o da mensagem de log
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] BasepConstructSxsCreateProcessMessage..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endere�o da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Par�metros: " << std::endl;
    stringStream << "        param1: 0x" << std::hex << param1 << std::dec << std::endl;
    stringStream << "        param2: 0x" << std::hex << param2 << std::dec << std::endl;
    stringStream << "        param3: 0x" << std::hex << param3 << std::dec << std::endl;
    // Adicione mais par�metros conforme necess�rio
    stringStream << "    Endere�o da fun��o chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] In�cio da chamada BasepConstructSxsCreateProcessMessage" << std::endl;

}

// Callback executado ap�s a chamada da fun��o BasepConstructSxsCreateProcessMessage
VOID InstBasepConstructSxsCreateProcessMessage::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT param1, ADDRINT param2, ADDRINT param3) {

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

        // Convers�o do valor de retorno para o tipo adequado
        // Substitua 'DWORD' pelo tipo real de retorno se necess�rio
        DWORD result = static_cast<DWORD>(retValAddr);
        stringStream << "    Retorno BasepConstructSxsCreateProcessMessage: " << result << std::endl;

        if (result != 0) {
            // Sucesso: adicione detalhes espec�ficos se dispon�veis
            stringStream << "    Opera��o conclu�da com sucesso." << std::endl;
        }
        else {
            // Falha: obt�m o c�digo de erro
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha na opera��o. C�digo de erro: " << error << std::endl;
        }

        // Finaliza��o das mensagens de log
        stringStream << "  [-] Chamada BasepConstructSxsCreateProcessMessage conclu�da" << std::endl;
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

// M�todo respons�vel por inserir os callbacks na fun��o BasepConstructSxsCreateProcessMessage
VOID InstBasepConstructSxsCreateProcessMessage::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "BasepConstructSxsCreateProcessMessage") { // Verifique o nome exato da fun��o
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura assumida:
        // DWORD BasepConstructSxsCreateProcessMessage(
        //   DWORD param1,
        //   DWORD param2,
        //   DWORD param3
        // );
        // Substitua os tipos e par�metros conforme a assinatura real

        // Inser��o do CallbackBefore antes da chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // param1
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // param2
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // param3
            IARG_END);

        // Inser��o do CallbackAfter ap�s a chamada da fun��o
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // valor de retorno (DWORD)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // param1
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // param2
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // param3
            IARG_END);

        RTN_Close(rtn);
    }
}
