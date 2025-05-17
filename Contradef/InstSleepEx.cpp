#include "InstSleepEx.h"

std::map<CallContextKey, CallContext*> InstSleepEx::callContextMap;
UINT32 InstSleepEx::imgCallId = 0;
UINT32 InstSleepEx::fcnCallId = 0;
Notifier* InstSleepEx::globalNotifierPtr;

VOID InstSleepEx::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT dwMilliseconds, ADDRINT bAlertable) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    SleepExArgs args;
    args.dwMilliseconds = dwMilliseconds;
    args.bAlertable = bAlertable;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] SleepEx..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        dwMilliseconds: " << dwMilliseconds << std::endl;
    stringStream << "        bAlertable: " << (bAlertable ? "TRUE" : "FALSE") << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada SleepEx" << std::endl;

}

VOID InstSleepEx::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT dwMilliseconds, ADDRINT bAlertable) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        DWORD result = static_cast<DWORD>(retValAddr);
        stringStream << "    Retorno SleepEx: " << result << std::endl;

        // SleepEx retorna:
        // 0 se o tempo expirou,
        // WAIT_IO_COMPLETION (0x000000C0) se a função retornou devido a uma chamada APC.
        // Não há "erro" tradicional aqui, mas podemos interpretar o resultado.
        if (result == 0) {
            stringStream << "    O tempo expirou e a função retornou normalmente." << std::endl;
        }
        else if (result == 0xC0) { // WAIT_IO_COMPLETION
            stringStream << "    Acordou devido à chamada de uma função APC." << std::endl;
        }
        else {
            // Caso algum outro valor seja retornado, pode-se interpretar como erro ou situação não esperada.
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Valor de retorno inesperado (0x" << std::hex << result << std::dec << "). Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada SleepEx concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        callContextMap.erase(it);
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstSleepEx::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "SleepEx") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura SleepEx:
        // DWORD SleepEx(
        //   DWORD dwMilliseconds,
        //   BOOL bAlertable
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // dwMilliseconds
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // bAlertable
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (DWORD)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // dwMilliseconds
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // bAlertable
            IARG_END);

        RTN_Close(rtn);
    }
}
