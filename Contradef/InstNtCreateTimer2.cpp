#include "InstNtCreateTimer2.h"

std::map<CallContextKey, CallContext*> InstNtCreateTimer2::callContextMap;
UINT32 InstNtCreateTimer2::imgCallId = 0;
UINT32 InstNtCreateTimer2::fcnCallId = 0;
Notifier* InstNtCreateTimer2::globalNotifierPtr;


VOID InstNtCreateTimer2::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT TimerHandle, ADDRINT DesiredAccess, ADDRINT ObjectAttributes, ADDRINT TimerType,
    ADDRINT TimerAttributes, ADDRINT Anonymous1, ADDRINT Anonymous2, ADDRINT Anonymous3) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstNtCreateTimer2Args args;
    args.TimerHandle = TimerHandle;
    args.DesiredAccess = DesiredAccess;
    args.ObjectAttributes = ObjectAttributes;
    args.TimerType = TimerType;
    args.TimerAttributes = TimerAttributes;
    args.Anonymous1 = Anonymous1;
    args.Anonymous2 = Anonymous2;
    args.Anonymous3 = Anonymous3;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstNtCreateTimer2::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT TimerHandle, ADDRINT DesiredAccess, ADDRINT ObjectAttributes, ADDRINT TimerType,
    ADDRINT TimerAttributes, ADDRINT Anonymous1, ADDRINT Anonymous2, ADDRINT Anonymous3) {

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
        const InstNtCreateTimer2Args* args = reinterpret_cast<InstNtCreateTimer2Args*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        // Obter a RTN da instruc�o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        TimerHandle: " << args->TimerHandle << std::endl;
        stringStream << "        DesiredAccess: " << args->DesiredAccess << std::endl;
        stringStream << "        ObjectAttributes: " << args->ObjectAttributes << std::endl;
        stringStream << "        TimerType: " << args->TimerType << std::endl;
        stringStream << "        TimerAttributes: " << args->TimerAttributes << std::endl;
        stringStream << "        Anonymous1: " << args->Anonymous1 << std::endl;
        stringStream << "        Anonymous2: " << args->Anonymous2 << std::endl;
        stringStream << "        Anonymous3: " << args->Anonymous3 << std::endl;
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

VOID InstNtCreateTimer2::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtCreateTimer2" || rtnName == "ZwCreateTimer2") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // TimerHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // DesiredAccess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // ObjectAttributes
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // TimerType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // TimerAttributes
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // Anonymous1
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // Anonymous2
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, // Anonymous3
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // TimerHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // DesiredAccess
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // ObjectAttributes
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // TimerType
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // TimerAttributes
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // Anonymous1
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // Anonymous2
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, // Anonymous3
            IARG_END);

        RTN_Close(rtn);
    }
}
