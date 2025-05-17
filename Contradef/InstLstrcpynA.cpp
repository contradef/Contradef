#include "InstLstrcpynA.h"

std::map<CallContextKey, CallContext*> InstLstrcpynA::callContextMap;
UINT32 InstLstrcpynA::imgCallId = 0;
UINT32 InstLstrcpynA::fcnCallId = 0;
Notifier* InstLstrcpynA::globalNotifierPtr;

VOID InstLstrcpynA::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT lpString1, ADDRINT lpString2, ADDRINT iMaxLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    LstrcpynAArgs args;
    args.lpString1 = lpString1;
    args.lpString2 = lpString2;
    args.iMaxLength = iMaxLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;
}

VOID InstLstrcpynA::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT lpString1, ADDRINT lpString2, ADDRINT iMaxLength) {

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
        const LstrcpynAArgs* args = reinterpret_cast<LstrcpynAArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        std::string sString1 = StringFromAddrint(args->lpString1);
        std::string sString2 = StringFromAddrint(args->lpString2);
        RTN rtnCurrent = RTN_FindByAddress(instAddress);

        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parâmetros: " << std::endl;
        stringStream << "        lpString1: " << sString1 << std::endl;
        stringStream << "        lpString2: " << sString2 << std::endl;
        stringStream << "        iMaxLength: " << args->iMaxLength << std::endl;
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

VOID InstLstrcpynA::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "lstrcpynA") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpString1
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpString2
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // iMaxLength
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpString1
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpString2
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // iMaxLength
            IARG_END);

        RTN_Close(rtn);
    }
}
