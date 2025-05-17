#include "InstRaiseException.h"

std::map<CallContextKey, CallContext*> InstRaiseException::callContextMap;
UINT32 InstRaiseException::imgCallId = 0;
UINT32 InstRaiseException::fcnCallId = 0;
Notifier* InstRaiseException::globalNotifierPtr;

VOID InstRaiseException::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT dwExceptionCode, ADDRINT dwExceptionFlags, ADDRINT nNumberOfArguments, ADDRINT lpArguments) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    RaiseExceptionArgs args;
    args.dwExceptionCode = dwExceptionCode;
    args.dwExceptionFlags = dwExceptionFlags;
    args.nNumberOfArguments = nNumberOfArguments;
    args.lpArguments = lpArguments;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] RaiseException..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        dwExceptionCode: 0x" << std::hex << dwExceptionCode << std::dec << std::endl;
    stringStream << "        dwExceptionFlags: 0x" << std::hex << dwExceptionFlags << std::dec << std::endl;
    stringStream << "        nNumberOfArguments: " << nNumberOfArguments << std::endl;
    stringStream << "        lpArguments: 0x" << std::hex << lpArguments << std::dec << std::endl;

    // Opcional: se nNumberOfArguments > 0, podemos tentar imprimir os argumentos
    if (nNumberOfArguments > 0 && lpArguments != 0) {
        ULONG_PTR argsArray[16]; // assumindo no máx. 16 arg. Ajuste conforme necessário.
        size_t count = (nNumberOfArguments > 16) ? 16 : static_cast<size_t>(nNumberOfArguments);
        PIN_SafeCopy(argsArray, reinterpret_cast<ULONG_PTR*>(lpArguments), count * sizeof(ULONG_PTR));

        for (size_t i = 0; i < count; i++) {
            stringStream << "        Argumento[" << i << "]: 0x" << std::hex << argsArray[i] << std::dec << std::endl;
            if (argsArray[i] != 0) {
                if (PIN_CheckReadAccess(reinterpret_cast<VOID*>(argsArray[i])))
                {
                    //wprintf(L" ** RETURN WStringX --> %ls <-\n", ConvertAddrToWideString(argsArray[i]));
                }
            }
        }
    }

    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada RaiseException" << std::endl;

}

VOID InstRaiseException::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT dwExceptionCode, ADDRINT dwExceptionFlags, ADDRINT nNumberOfArguments, ADDRINT lpArguments) {

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

        // RaiseException não retorna valor significativo, é VOID.
        // Mas iremos imprimir algo coerente com o padrão.
        // retValAddr aqui deve ser ignorado ou tratado como VOID.
        // Vamos simplesmente indicar que a função não retorna valor.

        stringStream << "    Retorno RaiseException: (VOID)" << std::endl;
        stringStream << "    Exceção foi levantada." << std::endl;

        stringStream << "  [-] Chamada RaiseException concluída" << std::endl;
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

VOID InstRaiseException::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "RaiseException") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // VOID RaiseException(
        //   DWORD dwExceptionCode,
        //   DWORD dwExceptionFlags,
        //   DWORD nNumberOfArguments,
        //   const ULONG_PTR* lpArguments
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // dwExceptionCode
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwExceptionFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nNumberOfArguments
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpArguments
            IARG_END);

        // RaiseException é VOID, mas usaremos After para manter o padrão.
        // O valor de retorno (FUNCRET_EXITPOINT_VALUE) será ignorado.
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (void) - ignoraremos
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // dwExceptionCode
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwExceptionFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nNumberOfArguments
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpArguments
            IARG_END);

        RTN_Close(rtn);
    }
}
