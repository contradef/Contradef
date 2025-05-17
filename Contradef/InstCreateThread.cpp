#include "InstCreateThread.h"
#include "NtStructures.h"

std::map<CallContextKey, CallContext*> InstCreateThread::callContextMap;
UINT32 InstCreateThread::imgCallId = 0;
UINT32 InstCreateThread::fcnCallId = 0;
Notifier* InstCreateThread::globalNotifierPtr;

VOID InstCreateThread::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpThreadAttributes, ADDRINT dwStackSize, ADDRINT lpStartAddress, ADDRINT lpParameter,
    ADDRINT dwCreationFlags, ADDRINT lpThreadId) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    CreateThreadArgs args;
    args.lpThreadAttributes = lpThreadAttributes;
    args.dwStackSize = dwStackSize;
    args.lpStartAddress = lpStartAddress;
    args.lpParameter = lpParameter;
    args.dwCreationFlags = dwCreationFlags;
    args.lpThreadId = lpThreadId;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] CreateThread..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        lpThreadAttributes: " << std::hex << lpThreadAttributes << std::dec << std::endl;
    stringStream << "        dwStackSize: " << dwStackSize << std::endl;
    stringStream << "        lpStartAddress: " << std::hex << lpStartAddress << std::dec << std::endl;
    stringStream << "        lpParameter: " << std::hex << lpParameter << std::dec << std::endl;
    stringStream << "        dwCreationFlags: " << dwCreationFlags << std::endl;
    stringStream << "        lpThreadId: " << std::hex << lpThreadId << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada CreateThread" << std::endl;

}

VOID InstCreateThread::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {

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

        // Se lpThreadId não for NULL, podemos ler o valor do Thread ID criado
        DWORD threadId = 0;
        CreateThreadArgs* args = static_cast<CreateThreadArgs*>(callContext->functionArgs);
        if (args->lpThreadId != 0) {
            PIN_SafeCopy(&threadId, reinterpret_cast<DWORD*>(args->lpThreadId), sizeof(DWORD));
        }

        stringStream << "    Handle da thread criada: " << std::hex << retVal << std::dec << std::endl;
        if (args->lpThreadId != 0) {
            stringStream << "    Thread ID: " << threadId << std::endl;
        }
        stringStream << "  [-] Chamada CreateThread concluída" << std::endl;
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

VOID InstCreateThread::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "CreateThread") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // lpThreadAttributes
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // dwStackSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // lpStartAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // lpParameter
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,      // dwCreationFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,      // lpThreadId
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCRET_EXITPOINT_VALUE,          // Valor de retorno (HANDLE)
            IARG_END);

        RTN_Close(rtn);
    }
}
