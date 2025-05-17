#include "InstVirtualQuery.h"

std::map<CallContextKey, CallContext*> InstVirtualQuery::callContextMap;
UINT32 InstVirtualQuery::imgCallId = 0;
UINT32 InstVirtualQuery::fcnCallId = 0;
Notifier* InstVirtualQuery::globalNotifierPtr;

// Baseado em https://stackoverflow.com/questions/65897402/c-winapi-virtualqueryex-function-gives-me-000000
unsigned long InstVirtualQuery::show_module(MEMORY_BASIC_INFORMATION info, std::stringstream& stringStream) {
    unsigned long usage = 0;

    stringStream << "    Informação do bloco de memória: " << info.BaseAddress << "(" << info.RegionSize / 1024 << ")\t";

    switch (info.State) {
    case MEM_COMMIT:
        stringStream << "Committed";
        break;
    case MEM_RESERVE:
        stringStream << "Reserved";
        break;
    case MEM_FREE:
        stringStream << "Free";
        break;
    }
    stringStream << "\t";
    switch (info.Type) {
    case MEM_IMAGE:
        stringStream << "Code Module";
        break;
    case MEM_MAPPED:
        stringStream << "Mapped     ";
        break;
    case MEM_PRIVATE:
        stringStream << "Private    ";
    }
    stringStream << "\t";

    int guard = 0, nocache = 0;

    if (info.AllocationProtect & PAGE_NOCACHE)
        nocache = 1;
    if (info.AllocationProtect & PAGE_GUARD)
        guard = 1;

    info.AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE);

    if ((info.State == MEM_COMMIT) && (info.AllocationProtect == PAGE_READWRITE || info.AllocationProtect == PAGE_READONLY))
        usage += info.RegionSize;

    switch (info.AllocationProtect) {
    case PAGE_READONLY:
        stringStream << "Read Only";
        break;
    case PAGE_READWRITE:
        stringStream << "Read/Write";
        break;
    case PAGE_WRITECOPY:
        stringStream << "Copy on Write";
        break;
    case PAGE_EXECUTE:
        stringStream << "Execute only";
        break;
    case PAGE_EXECUTE_READ:
        stringStream << "Execute/Read";
        break;
    case PAGE_EXECUTE_READWRITE:
        stringStream << "Execute/Read/Write";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        stringStream << "COW Executable";
        break;
    }

    if (guard)
        stringStream << "\tguard page";
    if (nocache)
        stringStream << "\tnon-cacheable";
    stringStream << "\n";
    return usage;
}

VOID InstVirtualQuery::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpAddress, ADDRINT lpBuffer, ADDRINT dwLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    InstVirtualQueryArgs args;
    args.lpAddress = lpAddress;
    args.lpBuffer = lpBuffer;
    args.dwLength = dwLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;
}

VOID InstVirtualQuery::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress,
    ADDRINT lpAddress, ADDRINT lpBuffer, ADDRINT dwLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar função
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar parâmetros
        const InstVirtualQueryArgs* args = reinterpret_cast<InstVirtualQueryArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;

        // Obter a RTN da instrução atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parâmetros: " << std::endl;
        stringStream << "        lpAddress: " << args->lpAddress << std::endl;
        stringStream << "        lpBuffer: " << args->lpBuffer << std::endl;
        stringStream << "        dwLength: " << args->dwLength << std::endl;
        stringStream << "    Valor de retorno: " << *retValAddr << std::endl;
        MEMORY_BASIC_INFORMATION* info = reinterpret_cast<MEMORY_BASIC_INFORMATION*>(args->lpBuffer);
        show_module(*info, stringStream);
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

VOID InstVirtualQuery::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "VirtualQuery") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwLength
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // dwLength
            IARG_END);

        RTN_Close(rtn);
    }
}