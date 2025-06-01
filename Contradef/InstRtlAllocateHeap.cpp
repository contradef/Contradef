#include "InstRtlAllocateHeap.h"

std::map<CallContextKey, CallContext*> InstRtlAllocateHeap::callContextMap;
UINT32 InstRtlAllocateHeap::imgCallId = 0;
UINT32 InstRtlAllocateHeap::fcnCallId = 0;
Notifier* InstRtlAllocateHeap::globalNotifierPtr = nullptr;

VOID InstRtlAllocateHeap::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT inst, ADDRINT rtn, CONTEXT*, ADDRINT retIP, ADDRINT HeapHandle, ADDRINT Flags, ADDRINT Size)
{
    if (instrumentOnlyMain && !IsMainExecutable(retIP)) return;

    RtlAllocateHeapArgs args{ HeapHandle, Flags, Size };

    UINT32 ctxId = callId * 100 + fcnCallId;
    auto* cc = new CallContext(ctxId, tid, inst, &args);
    callContextMap[{ctxId, tid}] = cc;

    std::stringstream& ss = cc->stringStream;
    ss << "\n[+] RtlAllocateHeap...\n"
        << "    Thread: " << tid << '\n'
        << "    Id de chamada: " << fcnCallId << '\n'
        << "    Endereço da rotina: 0x" << std::hex << cc->rtnAddress << std::dec << '\n'
        << "    Parâmetros:\n"
        << "        HeapHandle: 0x" << std::hex << HeapHandle << std::dec << '\n'
        << "        Flags: 0x" << std::hex << Flags << std::dec << '\n'
        << "        Size: " << Size << " bytes\n"
        << "    Endereço da função chamante: 0x" << std::hex << retIP << std::dec << '\n'
        << "  [-] Início da chamada RtlAllocateHeap\n";

}

VOID InstRtlAllocateHeap::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT inst, ADDRINT rtn, CONTEXT*,
    ADDRINT retIP,
    ADDRINT retValAddr,
    ADDRINT HeapHandle, ADDRINT Flags, ADDRINT Size)
{
    if (instrumentOnlyMain && !IsMainExecutable(retIP)) return;

    UINT32 ctxId = callId * 100 + fcnCallId;
    auto it = callContextMap.find({ ctxId, tid });
    if (it != callContextMap.end()) {
        PIN_LockClient();
        CallContext* cc = it->second;
        std::stringstream& ss = cc->stringStream;

        ss << "    Ponteiro retornado (endereço alocado): 0x"
            << std::hex << retValAddr << std::dec << '\n';

        if (retValAddr != 0)
            ss << "    Alocação realizada com sucesso.\n";
        else {
            using namespace WindowsAPI;
            DWORD err = GetLastError();
            ss << "    Falha na alocação. GetLastError = " << err << '\n';
        }

        ss << "  [-] Chamada RtlAllocateHeap concluída\n"
            << "[*] Concluído\n\n";

        globalNotifierPtr->NotifyAll(new ExecutionEventData({ ss.str() }));

        delete cc;
        callContextMap.erase(it);
        PIN_UnlockClient();
    }
    fcnCallId++;
}

VOID InstRtlAllocateHeap::InstrumentFunction(RTN rtn, Notifier& globalNotifier)
{
    if (RTN_Name(rtn) != "RtlAllocateHeap") return;

    imgCallId++;
    globalNotifierPtr = &globalNotifier;
    RTN_Open(rtn);

    // NTAPI
    // PVOID RtlAllocateHeap(
    //      PVOID  HeapHandle,
    //      ULONG  Flags,
    //      SIZE_T Size );

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
        IARG_THREAD_ID,
        IARG_UINT32, imgCallId,
        IARG_INST_PTR,
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_CONTEXT,
        IARG_RETURN_IP,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // HeapHandle
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Flags
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // Size
        IARG_END);

    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
        IARG_THREAD_ID,
        IARG_UINT32, imgCallId,
        IARG_INST_PTR,
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_CONTEXT,
        IARG_RETURN_IP,
        IARG_FUNCRET_EXITPOINT_VALUE,     // ponteiro retornado
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // HeapHandle
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Flags
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // Size
        IARG_END);

    RTN_Close(rtn);
}
