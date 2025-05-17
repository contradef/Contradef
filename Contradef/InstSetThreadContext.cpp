#include "InstSetThreadContext.h"
#include "NtStructures.h"

std::map<CallContextKey, CallContext*> InstSetThreadContext::callContextMap;
UINT32 InstSetThreadContext::imgCallId = 0;
UINT32 InstSetThreadContext::fcnCallId = 0;
Notifier* InstSetThreadContext::globalNotifierPtr;

VOID InstSetThreadContext::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hThread, ADDRINT lpContext) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    SetThreadContextArgs args;
    args.hThread = hThread;
    args.lpContext = lpContext;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Registrando os parâmetros e o endereço da função chamante
    std::stringstream stringStream;
    stringStream << std::endl << "[+] SetThreadContext..." << std::endl;
    stringStream << "    Thread ID: " << tid << std::endl;
    stringStream << "    ID de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << rtn << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        hThread: " << std::hex << hThread << std::dec << std::endl;
    stringStream << "        lpContext: " << std::hex << lpContext << std::dec << std::endl;

    if (lpContext != 0) {
        ::WindowsAPI::CONTEXT ctxData;
        PIN_SafeCopy(&ctxData, reinterpret_cast<void*>(lpContext), sizeof(::WindowsAPI::CONTEXT));

        stringStream << "    Contexto da Thread para Configuração:" << std::endl;
        stringStream << "        P1Home: " << std::hex << ctxData.P1Home << std::dec << std::endl;
        stringStream << "        P2Home: " << std::hex << ctxData.P2Home << std::dec << std::endl;
        stringStream << "        P3Home: " << std::hex << ctxData.P3Home << std::dec << std::endl;
        stringStream << "        P4Home: " << std::hex << ctxData.P4Home << std::dec << std::endl;
        stringStream << "        P5Home: " << std::hex << ctxData.P5Home << std::dec << std::endl;
        stringStream << "        P6Home: " << std::hex << ctxData.P6Home << std::dec << std::endl;
        stringStream << "        ContextFlags: " << std::hex << ctxData.ContextFlags << std::dec << std::endl;
        stringStream << "        MxCsr: " << std::hex << ctxData.MxCsr << std::dec << std::endl;
        stringStream << "        SegCs: " << std::hex << ctxData.SegCs << std::dec << std::endl;
        stringStream << "        SegDs: " << std::hex << ctxData.SegDs << std::dec << std::endl;
        stringStream << "        SegEs: " << std::hex << ctxData.SegEs << std::dec << std::endl;
        stringStream << "        SegFs: " << std::hex << ctxData.SegFs << std::dec << std::endl;
        stringStream << "        SegGs: " << std::hex << ctxData.SegGs << std::dec << std::endl;
        stringStream << "        SegSs: " << std::hex << ctxData.SegSs << std::dec << std::endl;
        stringStream << "        EFlags: " << std::hex << ctxData.EFlags << std::dec << std::endl;
        stringStream << "        Dr0: " << std::hex << ctxData.Dr0 << std::dec << std::endl;
        stringStream << "        Dr1: " << std::hex << ctxData.Dr1 << std::dec << std::endl;
        stringStream << "        Dr2: " << std::hex << ctxData.Dr2 << std::dec << std::endl;
        stringStream << "        Dr3: " << std::hex << ctxData.Dr3 << std::dec << std::endl;
        stringStream << "        Dr6: " << std::hex << ctxData.Dr6 << std::dec << std::endl;
        stringStream << "        Dr7: " << std::hex << ctxData.Dr7 << std::dec << std::endl;
        stringStream << "        Rax: " << std::hex << ctxData.Rax << std::dec << std::endl;
        stringStream << "        Rcx: " << std::hex << ctxData.Rcx << std::dec << std::endl;
        stringStream << "        Rdx: " << std::hex << ctxData.Rdx << std::dec << std::endl;
        stringStream << "        Rbx: " << std::hex << ctxData.Rbx << std::dec << std::endl;
        stringStream << "        Rsp: " << std::hex << ctxData.Rsp << std::dec << std::endl;
        stringStream << "        Rbp: " << std::hex << ctxData.Rbp << std::dec << std::endl;
        stringStream << "        Rsi: " << std::hex << ctxData.Rsi << std::dec << std::endl;
        stringStream << "        Rdi: " << std::hex << ctxData.Rdi << std::dec << std::endl;
        stringStream << "        R8: " << std::hex << ctxData.R8 << std::dec << std::endl;
        stringStream << "        R9: " << std::hex << ctxData.R9 << std::dec << std::endl;
        stringStream << "        R10: " << std::hex << ctxData.R10 << std::dec << std::endl;
        stringStream << "        R11: " << std::hex << ctxData.R11 << std::dec << std::endl;
        stringStream << "        R12: " << std::hex << ctxData.R12 << std::dec << std::endl;
        stringStream << "        R13: " << std::hex << ctxData.R13 << std::dec << std::endl;
        stringStream << "        R14: " << std::hex << ctxData.R14 << std::dec << std::endl;
        stringStream << "        R15: " << std::hex << ctxData.R15 << std::dec << std::endl;
        stringStream << "        Rip: " << std::hex << ctxData.Rip << std::dec << std::endl;
        stringStream << "        Header: " << std::hex << ctxData.Header << std::dec << std::endl;
        stringStream << "        Legacy: " << std::hex << ctxData.Legacy << std::dec << std::endl;
        stringStream << "        Xmm0: " << std::hex << ctxData.Xmm0.High << std::dec << std::endl;
        stringStream << "        Xmm1: " << std::hex << ctxData.Xmm1.High << std::dec << std::endl;
        stringStream << "        Xmm2: " << std::hex << ctxData.Xmm2.High << std::dec << std::endl;
        stringStream << "        Xmm3: " << std::hex << ctxData.Xmm3.High << std::dec << std::endl;
        stringStream << "        Xmm4: " << std::hex << ctxData.Xmm4.High << std::dec << std::endl;
        stringStream << "        Xmm5: " << std::hex << ctxData.Xmm5.High << std::dec << std::endl;
        stringStream << "        Xmm6: " << std::hex << ctxData.Xmm6.High << std::dec << std::endl;
        stringStream << "        Xmm7: " << std::hex << ctxData.Xmm7.High << std::dec << std::endl;
        stringStream << "        Xmm8: " << std::hex << ctxData.Xmm8.High << std::dec << std::endl;
        stringStream << "        Xmm9: " << std::hex << ctxData.Xmm9.High << std::dec << std::endl;
        stringStream << "        Xmm10: " << std::hex << ctxData.Xmm10.High << std::dec << std::endl;
        stringStream << "        Xmm11: " << std::hex << ctxData.Xmm11.High << std::dec << std::endl;
        stringStream << "        Xmm12: " << std::hex << ctxData.Xmm12.High << std::dec << std::endl;
        stringStream << "        Xmm13: " << std::hex << ctxData.Xmm13.High << std::dec << std::endl;
        stringStream << "        Xmm14: " << std::hex << ctxData.Xmm14.High << std::dec << std::endl;
        stringStream << "        Xmm15: " << std::hex << ctxData.Xmm15.High << std::dec << std::endl;
        // Outros registros podem ser adicionados aqui
    }

    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada SetThreadContext" << std::endl;

}

VOID InstSetThreadContext::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retVal) {

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

        stringStream << "    Valor de retorno: " << retVal << std::endl;

        if (retVal != 0) {
            stringStream << "    Configuração do contexto da thread bem-sucedida." << std::endl;
        }
        else {
            stringStream << "    Falha ao configurar o contexto da thread." << std::endl;
        }

        stringStream << "  [-] Chamada SetThreadContext concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        callContextMap.erase(it);
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstSetThreadContext::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "SetThreadContext") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // hThread
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // lpContext
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCRET_EXITPOINT_VALUE,          // Valor de retorno
            IARG_END);

        RTN_Close(rtn);
    }
}
