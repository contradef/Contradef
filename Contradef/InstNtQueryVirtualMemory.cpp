#include "InstNtQueryVirtualMemory.h"

std::map<CallContextKey, CallContext*> InstNtQueryVirtualMemory::callContextMap;
UINT32 InstNtQueryVirtualMemory::imgCallId = 0;
UINT32 InstNtQueryVirtualMemory::fcnCallId = 0;
Notifier* InstNtQueryVirtualMemory::globalNotifierPtr;


VOID InstNtQueryVirtualMemory::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT ProcessHandle, ADDRINT BaseAddress, ADDRINT MemoryInformationClass, ADDRINT MemoryInformation,
    ADDRINT MemoryInformationLength, ADDRINT ReturnLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstNtQueryVirtualMemoryArgs args;
    args.ProcessHandle = ProcessHandle;
    args.BaseAddress = BaseAddress;
    args.MemoryInformationClass = MemoryInformationClass;
    args.MemoryInformation = MemoryInformation;
    args.MemoryInformationLength = MemoryInformationLength;
    args.ReturnLength = ReturnLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstNtQueryVirtualMemory::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT ProcessHandle, ADDRINT BaseAddress, ADDRINT MemoryInformationClass, ADDRINT MemoryInformation,
    ADDRINT MemoryInformationLength, ADDRINT ReturnLength) {

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
        const InstNtQueryVirtualMemoryArgs* args = reinterpret_cast<InstNtQueryVirtualMemoryArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;
        stringStream << "        ProcessHandle: " << args->ProcessHandle << std::endl;
        stringStream << "        BaseAddress: " << args->BaseAddress << std::endl;
        stringStream << "        MemoryInformationClass: " << args->MemoryInformationClass << std::endl;
        stringStream << "        MemoryInformation: " << args->MemoryInformation << std::endl;
        stringStream << "        MemoryInformationLength: " << args->MemoryInformationLength << std::endl;
        stringStream << "        ReturnLength: " << args->ReturnLength << std::endl;
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

VOID InstNtQueryVirtualMemory::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtQueryVirtualMemory" || rtnName == "ZwQueryVirtualMemory") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ProcessHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // BaseAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // MemoryInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // MemoryInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // MemoryInformationLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // ReturnLength
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ProcessHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // BaseAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // MemoryInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // MemoryInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // MemoryInformationLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // ReturnLength
            IARG_END);

        RTN_Close(rtn);
    }
}