#include "InstRtlQueryPerformanceCounter.h"

std::map<CallContextKey, CallContext*> InstRtlQueryPerformanceCounter::callContextMap;
UINT32 InstRtlQueryPerformanceCounter::imgCallId = 0;
UINT32 InstRtlQueryPerformanceCounter::fcnCallId = 0;
Notifier* InstRtlQueryPerformanceCounter::globalNotifierPtr;

VOID InstRtlQueryPerformanceCounter::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    RtlQueryPerformanceCounterArgs args;
    args.PerformanceCounter = PerformanceCounter;
    args.PerformanceFrequency = PerformanceFrequency;

    UINT32 callCtxId = callId * 100 + fcnCallId;
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] RtlQueryPerformanceCounter..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        PerformanceCounter: 0x" << std::hex << PerformanceCounter << std::dec << std::endl;

    if (PerformanceFrequency != 0) {
        stringStream << "        PerformanceFrequency: 0x" << std::hex << PerformanceFrequency << std::dec << std::endl;
    }
    else {
        stringStream << "        PerformanceFrequency: NULL (opcional)" << std::endl;
    }

    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada RtlQueryPerformanceCounter" << std::endl;

}

VOID InstRtlQueryPerformanceCounter::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT PerformanceCounter, ADDRINT PerformanceFrequency) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
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

        // RtlQueryPerformanceCounter é VOID, então não há valor de retorno a exibir diretamente.
        // Podemos, no entanto, tentar ler o valor retornado em PerformanceCounter e PerformanceFrequency.

        if (PerformanceCounter != 0) {
            WindowsAPI::LARGE_INTEGER counterValue = { 0 };
            PIN_SafeCopy(&counterValue, reinterpret_cast<WindowsAPI::LARGE_INTEGER*>(PerformanceCounter), sizeof(WindowsAPI::LARGE_INTEGER));
            stringStream << "    Valor de PerformanceCounter: " << counterValue.QuadPart << std::endl;
        }
        else {
            stringStream << "    PerformanceCounter é NULL, não foi possível ler o valor." << std::endl;
        }

        if (PerformanceFrequency != 0) {
            WindowsAPI::LARGE_INTEGER freqValue = { 0 };
            PIN_SafeCopy(&freqValue, reinterpret_cast<WindowsAPI::LARGE_INTEGER*>(PerformanceFrequency), sizeof(WindowsAPI::LARGE_INTEGER));
            stringStream << "    Valor de PerformanceFrequency: " << freqValue.QuadPart << std::endl;
        }
        else {
            stringStream << "    PerformanceFrequency era NULL, não há frequência a exibir." << std::endl;
        }

        // A função não retorna BOOL ou valor indicativo de falha, mas podemos supor que se ocorreu algum erro
        // o código apareceria em GetLastError(). Caso não faça sentido para esta função, você pode omitir.
        // Aqui apenas mostraremos a execução concluída.

        stringStream << "    Operação concluída." << std::endl;
        stringStream << "  [-] Chamada RtlQueryPerformanceCounter concluída" << std::endl;
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

VOID InstRtlQueryPerformanceCounter::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "RtlQueryPerformanceCounter") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura presumida:
        // VOID RtlQueryPerformanceCounter(
        //   PLARGE_INTEGER PerformanceCounter,
        //   PLARGE_INTEGER PerformanceFrequency OPTIONAL
        // );
        //
        // A função não retorna valor (VOID).

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // PerformanceCounter
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // PerformanceFrequency (opcional)
            IARG_END);

        // Para funções VOID, ainda podemos usar IPOINT_AFTER para registrar a finalização da chamada.
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            // Não há valor de retorno, mas ainda chamamos para registrar o final da execução
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // PerformanceCounter
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // PerformanceFrequency
            IARG_END);

        RTN_Close(rtn);
    }
}
