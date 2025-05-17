#include "InstBasepConstructSxsCreateProcessMessage.h"

// Inicialização das variáveis estáticas
std::map<CallContextKey, CallContext*> InstBasepConstructSxsCreateProcessMessage::callContextMap;
UINT32 InstBasepConstructSxsCreateProcessMessage::imgCallId = 0;
UINT32 InstBasepConstructSxsCreateProcessMessage::fcnCallId = 0;
Notifier* InstBasepConstructSxsCreateProcessMessage::globalNotifierPtr;

// Callback executado antes da chamada da função BasepConstructSxsCreateProcessMessage
VOID InstBasepConstructSxsCreateProcessMessage::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT param1, ADDRINT param2, ADDRINT param3) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Estrutura para armazenar os argumentos
    BasepConstructSxsCreateProcessMessageArgs args;
    args.param1 = param1;
    args.param2 = param2;
    args.param3 = param3;
    // Inicialize mais parâmetros conforme necessário

    // Criação de um ID único para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;

    // Criação e armazenamento do contexto da chamada
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Construção da mensagem de log
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] BasepConstructSxsCreateProcessMessage..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        param1: 0x" << std::hex << param1 << std::dec << std::endl;
    stringStream << "        param2: 0x" << std::hex << param2 << std::dec << std::endl;
    stringStream << "        param3: 0x" << std::hex << param3 << std::dec << std::endl;
    // Adicione mais parâmetros conforme necessário
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada BasepConstructSxsCreateProcessMessage" << std::endl;

}

// Callback executado após a chamada da função BasepConstructSxsCreateProcessMessage
VOID InstBasepConstructSxsCreateProcessMessage::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT param1, ADDRINT param2, ADDRINT param3) {

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

        // Conversão do valor de retorno para o tipo adequado
        // Substitua 'DWORD' pelo tipo real de retorno se necessário
        DWORD result = static_cast<DWORD>(retValAddr);
        stringStream << "    Retorno BasepConstructSxsCreateProcessMessage: " << result << std::endl;

        if (result != 0) {
            // Sucesso: adicione detalhes específicos se disponíveis
            stringStream << "    Operação concluída com sucesso." << std::endl;
        }
        else {
            // Falha: obtém o código de erro
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha na operação. Código de erro: " << error << std::endl;
        }

        // Finalização das mensagens de log
        stringStream << "  [-] Chamada BasepConstructSxsCreateProcessMessage concluída" << std::endl;
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

    // Incrementa o ID da chamada
    fcnCallId++;
}

// Método responsável por inserir os callbacks na função BasepConstructSxsCreateProcessMessage
VOID InstBasepConstructSxsCreateProcessMessage::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "BasepConstructSxsCreateProcessMessage") { // Verifique o nome exato da função
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura assumida:
        // DWORD BasepConstructSxsCreateProcessMessage(
        //   DWORD param1,
        //   DWORD param2,
        //   DWORD param3
        // );
        // Substitua os tipos e parâmetros conforme a assinatura real

        // Inserção do CallbackBefore antes da chamada da função
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

        // Inserção do CallbackAfter após a chamada da função
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
