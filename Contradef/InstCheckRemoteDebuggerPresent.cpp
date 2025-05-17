#include "InstCheckRemoteDebuggerPresent.h"
#include <iostream>

// Inicializações estáticas
std::map<CallContextKey, CallContext*> InstCheckRemoteDebuggerPresent::callContextMap;
UINT32 InstCheckRemoteDebuggerPresent::imgCallId = 0;
UINT32 InstCheckRemoteDebuggerPresent::fcnCallId = 0;
Notifier* InstCheckRemoteDebuggerPresent::globalNotifierPtr;

VOID InstCheckRemoteDebuggerPresent::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT hProcess, PBOOL   pbDebuggerPresent) {
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstCheckRemoteDebuggerPresentArgs args;
    args.hProcess = hProcess;
    args.pbDebuggerPresent = pbDebuggerPresent;

    UINT32 callCtxId = callId * 100 + fcnCallId;
    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

}

VOID InstCheckRemoteDebuggerPresent::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT hProcess, PBOOL pbDebuggerPresent) {
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        const InstCheckRemoteDebuggerPresentArgs* args = reinterpret_cast<const InstCheckRemoteDebuggerPresentArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parâmetros: " << std::endl;
        stringStream << "        hProcess: " << args->hProcess << std::endl;

        std::string dp = "NULL";
        
        BOOL* ppbDebuggerPresent = reinterpret_cast<BOOL*>(args->pbDebuggerPresent);

        if (ppbDebuggerPresent == nullptr) {
            dp = "FALSE";
        }
        else
        {
            dp = (*ppbDebuggerPresent ? "TRUE" : "FALSE");
            // CONTRAMEDIDA
            //std::cout << "ppbDebuggerPresent -> " << *ppbDebuggerPresent << std::endl;

            if (*ppbDebuggerPresent) {
                //std::cout << "Aplicando contramedida\n";
                *ppbDebuggerPresent = 0;
            }
        }

        
        stringStream << "        pbDebuggerPresent: " << dp << std::endl;
        stringStream << "    Valor de retorno: " << *retValAddr << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstCheckRemoteDebuggerPresent::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
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
    if (rtnName == "CheckRemoteDebuggerPresent") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(CallbackBefore),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hProcess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // pbDebuggerPresent
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hProcess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // pbDebuggerPresent
            IARG_END);
        RTN_Close(rtn);
    }
}
