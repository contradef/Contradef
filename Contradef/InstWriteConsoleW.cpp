#include "InstWriteConsoleW.h"

std::map<CallContextKey, CallContext*> InstWriteConsoleW::callContextMap;
UINT32 InstWriteConsoleW::imgCallId = 0;
UINT32 InstWriteConsoleW::fcnCallId = 0;
Notifier* InstWriteConsoleW::globalNotifierPtr;

VOID InstWriteConsoleW::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT hConsoleOutput, ADDRINT lpBuffer, ADDRINT nNumberOfCharsToWrite, ADDRINT lpNumberOfCharsWritten, ADDRINT lpReserved) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    WriteConsoleWArgs args;
    args.hConsoleOutput = hConsoleOutput;
    args.lpBuffer = lpBuffer;
    args.nNumberOfCharsToWrite = nNumberOfCharsToWrite;
    args.lpNumberOfCharsWritten = lpNumberOfCharsWritten;
    args.lpReserved = lpReserved;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;
}

VOID InstWriteConsoleW::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT hConsoleOutput, ADDRINT lpBuffer, ADDRINT nNumberOfCharsToWrite) {

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
        const WriteConsoleWArgs* args = reinterpret_cast<WriteConsoleWArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        std::wstring wsBuffer = ConvertAddrToWideString(args->lpBuffer);
        RTN rtnCurrent = RTN_FindByAddress(instAddress);

        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parâmetros: " << std::endl;
        stringStream << "        hConsoleOutput: " << args->hConsoleOutput << std::endl;
        stringStream << "        lpBuffer: " << WStringToString(wsBuffer) << std::endl;
        stringStream << "        nNumberOfCharsToWrite: " << args->nNumberOfCharsToWrite << std::endl;
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

VOID InstWriteConsoleW::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "WriteConsoleW") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hConsoleOutput
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nNumberOfCharsToWrite
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpNumberOfCharsWritten
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpReserved
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hConsoleOutput
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nNumberOfCharsToWrite
            IARG_END);

        RTN_Close(rtn);
    }
}
