#include "InstNtQueryKey.h"

std::map<CallContextKey, CallContext*> InstNtQueryKey::callContextMap;
UINT32 InstNtQueryKey::imgCallId = 0;
UINT32 InstNtQueryKey::fcnCallId = 0;
Notifier* InstNtQueryKey::globalNotifierPtr;


VOID InstNtQueryKey::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT KeyHandle, ADDRINT KeyInformationClass, ADDRINT KeyInformation, ADDRINT Length, ADDRINT ResultLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstNtQueryKeyArgs args;
    args.KeyHandle = KeyHandle;
    args.KeyInformationClass = KeyInformationClass;
    args.KeyInformation = KeyInformation;
    args.Length = Length;
    args.ResultLength = ResultLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstNtQueryKey::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT KeyHandle, ADDRINT KeyInformationClass, ADDRINT KeyInformation, ADDRINT Length, ADDRINT ResultLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar fun��o
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar Parámetros
        const InstNtQueryKeyArgs* args = reinterpret_cast<InstNtQueryKeyArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << " Detected..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        KeyHandle: " << args->KeyHandle << std::endl;
        stringStream << "        KeyInformationClass: " << args->KeyInformationClass << std::endl;
        stringStream << "        KeyInformation: " << args->KeyInformation << std::endl;
        stringStream << "        Length: " << args->Length << std::endl;
        stringStream << "        ResultLength: " << args->ResultLength << std::endl;
        stringStream << "    Valor de retorno: " << *retValAddr << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        // Cria evento
        ExecutionEventData executionEvent(executionCompletedInfo);
        // Notifica os observers
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstNtQueryKey::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtQueryKey" || rtnName == "ZwQueryKey") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // KeyHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // KeyInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // KeyInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // Length
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // ResultLength
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // KeyHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // KeyInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // KeyInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // Length
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // ResultLength
            IARG_END);

        RTN_Close(rtn);
    }
}
