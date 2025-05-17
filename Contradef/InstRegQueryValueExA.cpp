#include "InstRegQueryValueExA.h"

std::map<CallContextKey, CallContext*> InstRegQueryValueExA::callContextMap;
UINT32 InstRegQueryValueExA::imgCallId = 0;
UINT32 InstRegQueryValueExA::fcnCallId = 0;
Notifier* InstRegQueryValueExA::globalNotifierPtr;


VOID InstRegQueryValueExA::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT hKey, ADDRINT lpValueName, ADDRINT lpReserved, ADDRINT lpType, ADDRINT lpData, ADDRINT lpcbData) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstRegQueryValueExAArgs args;
    args.hKey = hKey;
    args.lpValueName = lpValueName;
    args.lpReserved = lpReserved;
    args.lpType = lpType;
    args.lpData = lpData;
    args.lpcbData = lpcbData;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstRegQueryValueExA::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT hKey, ADDRINT lpValueName, ADDRINT lpReserved, ADDRINT lpType, ADDRINT lpData, ADDRINT lpcbData) {
   
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
        const InstRegQueryValueExAArgs* args = reinterpret_cast<InstRegQueryValueExAArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        std::string ansiStringlpValueName = ConvertAddrToAnsiString(args->lpValueName);
        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        hKey: " << args->hKey << std::endl;
        stringStream << "        lpValueName: " << ansiStringlpValueName << std::endl;
        stringStream << "        lpReserved: " << args->lpReserved << std::endl;
        stringStream << "        lpType: " << args->lpType << std::endl;
        stringStream << "        lpData: " << args->lpData << std::endl;
        stringStream << "        lpcbData: " << args->lpcbData << std::endl;
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

VOID InstRegQueryValueExA::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    SEC sec = RTN_Sec(rtn);
    IMG img = SEC_Img(sec);
    if (IMG_Valid(img)) {
        std::string imageName = IMG_Name(img);
        std::string moduleName = ExtractModuleName(IMG_Name(img));
        if (toUpperCase(moduleName) != "KERNELBASE.DLL") {
            return;
        }
    }
    else {
        return;
    }

   std::string rtnName = RTN_Name(rtn);
    if (RTN_Name(rtn) == "RegQueryValueExA") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpValueName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpReserved
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpData
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // lpcbData
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpValueName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpReserved
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpData
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // lpcbData
            IARG_END);

        RTN_Close(rtn);
    }
}