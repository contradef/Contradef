#include "InstRegQueryValueW.h"

std::map<CallContextKey, CallContext*> InstRegQueryValueW::callContextMap;
UINT32 InstRegQueryValueW::imgCallId = 0;
UINT32 InstRegQueryValueW::fcnCallId = 0;
Notifier* InstRegQueryValueW::globalNotifierPtr;


VOID InstRegQueryValueW::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT hKey, ADDRINT lpSubKey, ADDRINT lpValue, ADDRINT lpcbValue) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    RegQueryValueWArgs args;
    args.hKey = hKey;
    args.lpSubKey = lpSubKey;
    args.lpValue = lpValue;
    args.lpcbValue = lpcbValue;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstRegQueryValueW::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT hKey, ADDRINT lpSubKey, ADDRINT lpValue, ADDRINT lpcbValue) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar fun�ao
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar Parámetros
        const RegQueryValueWArgs* args = reinterpret_cast<RegQueryValueWArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        std::wstring ansiStringlpSubKey = ConvertAddrToWideString(args->lpSubKey);
        std::wstring ansiStringlpValue = ConvertAddrToWideString(args->lpValue);
        std::wstring ansiStringlpcbValue = ConvertAddrToWideString(args->lpcbValue);         // Obter a RTN da instru��o atual
        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        hKey: " << args->hKey << std::endl;
        stringStream << "        lpSubKey: " << WStringToString(ansiStringlpSubKey) << std::endl;
        stringStream << "        lpValue: " << WStringToString(ansiStringlpValue) << std::endl;
        stringStream << "        lpcbValue: " << WStringToString(ansiStringlpcbValue) << std::endl;
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

VOID InstRegQueryValueW::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (RTN_Name(rtn) == "RegQueryValueW") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(CallbackBefore),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hKey
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpSubKey
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpValue
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpcbValue
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hKey
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpSubKey
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpValue
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpcbValue
            IARG_END);

        RTN_Close(rtn);
    }
}
