#include "InstNtdllDefWindowProc_W.h"

std::map<CallContextKey, CallContext*> InstNtdllDefWindowProc_W::callContextMap;
UINT32 InstNtdllDefWindowProc_W::imgCallId = 0;
UINT32 InstNtdllDefWindowProc_W::fcnCallId = 0;
Notifier* InstNtdllDefWindowProc_W::globalNotifierPtr;

VOID InstNtdllDefWindowProc_W::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hWnd, ADDRINT Msg, ADDRINT wParam, ADDRINT lParam) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    NtdllDefWindowProc_WArgs args;
    args.hWnd = hWnd;
    args.Msg = Msg;
    args.wParam = wParam;
    args.lParam = lParam;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] NtdllDefWindowProc_W..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        hWnd: 0x" << std::hex << hWnd << std::dec << std::endl;
    stringStream << "        Msg: 0x" << std::hex << Msg << std::dec << " (" << Msg << ")" << std::endl;
    stringStream << "        wParam: 0x" << std::hex << wParam << std::dec << std::endl;
    stringStream << "        lParam: 0x" << std::hex << lParam << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada NtdllDefWindowProc_W" << std::endl;

}

VOID InstNtdllDefWindowProc_W::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT hWnd, ADDRINT Msg, ADDRINT wParam, ADDRINT lParam) {

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

        
        using namespace WindowsAPI;
        LRESULT result = static_cast<LRESULT>(retValAddr);
        stringStream << "    Retorno NtdllDefWindowProc_W: 0x" << std::hex << retValAddr << std::dec << std::endl;
        
        // Em geral, DefWindowProc retorna um valor interpretado pelo sistema.
        // Não há "erro" tradicional aqui, mas se quisermos, podemos usar GetLastError().
        // Se não for esperado erro, apenas indicaremos o valor retornado.
        // Vamos apenas considerar que não há falha específica.

        stringStream << "    Chamado DefWindowProc interno (ou Ntdll) retornou valor de processamento: 0x" << std::hex << result << std::dec << std::endl;

        stringStream << "  [-] Chamada NtdllDefWindowProc_W concluída" << std::endl;
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

VOID InstNtdllDefWindowProc_W::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtdllDefWindowProc_W") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura assumida:
        // LRESULT NtdllDefWindowProc_W(
        //   HWND hWnd,
        //   UINT Msg,
        //   WPARAM wParam,
        //   LPARAM lParam
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hWnd
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Msg
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // wParam
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lParam
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (LRESULT)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hWnd
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Msg
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // wParam
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lParam
            IARG_END);

        RTN_Close(rtn);
    }
}
