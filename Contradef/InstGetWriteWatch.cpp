#include "InstGetWriteWatch.h"

std::map<CallContextKey, CallContext*> InstGetWriteWatch::callContextMap;
UINT32 InstGetWriteWatch::imgCallId = 0;
UINT32 InstGetWriteWatch::fcnCallId = 0;
Notifier* InstGetWriteWatch::globalNotifierPtr;

VOID InstGetWriteWatch::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT dwFlags, ADDRINT lpBaseAddress, ADDRINT dwRegionSize, ADDRINT lpAddresses, ADDRINT lpdwCount, ADDRINT lpdwGranularity) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    GetWriteWatchArgs args;
    args.dwFlags = dwFlags;
    args.lpBaseAddress = lpBaseAddress;
    args.dwRegionSize = dwRegionSize;
    args.lpAddresses = lpAddresses;
    args.lpdwCount = lpdwCount;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;

    stringStream << std::endl << "[+] GetWriteWatch..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: " << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        dwFlags: " << dwFlags << std::endl;
    stringStream << "        lpBaseAddress: " << std::hex << lpBaseAddress << std::dec << std::endl;
    stringStream << "        dwRegionSize: " << dwRegionSize << " bytes" << std::endl;
    stringStream << "        lpAddresses (Endereço de Escritas): " << std::hex << lpAddresses << std::dec << std::endl;
    stringStream << "        lpdwCount (Contagem de Páginas): " << std::hex << lpdwCount << std::dec << std::endl;
   
}

VOID InstGetWriteWatch::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT dwFlags, ADDRINT lpBaseAddress, ADDRINT dwRegionSize, ADDRINT lpAddresses, ADDRINT lpdwCount, ADDRINT lpdwGranularity) {

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

        stringStream << "    Valor de retorno original: " << *retValAddr << std::endl;
        stringStream << "  [-] Monitoramento de páginas escritas concluído" << std::endl << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        //CONTRAMEDIDA
        // Alterar o valor de retorno:
        // interceptar a função GetWriteWatch e configurar um valor fixo para o retorno(como 0 ou um conjunto específico de endereços), simulando uma situação em que não há escrita adicional ou que as escritas seguem um padrão “esperado”.
        //    Esse método cria uma resposta previsível para GetWriteWatch, independentemente das escritas reais, reduzindo a probabilidade de que o software evasivo identifique o ambiente de análise.
        // Modifica o retorno para um conjunto vazio ou controle específico de páginas
        ULONG_PTR* lpdwCountMod = reinterpret_cast<ULONG_PTR*>(lpdwCount);
        //*lpdwCountMod = 0; // Define zero endereços como "escritos"
        DWORD* lpdwGranularityMod = reinterpret_cast<DWORD*>(lpdwGranularity);
        //*lpdwGranularityMod = PAGE_SIZE; // Define a granularidade
        
        // Alterar o valor de retorno como sucesso = 
        //*retValAddr = 0;

        delete callContext;
        PIN_UnlockClient();
    }

    fcnCallId++;
}

VOID InstGetWriteWatch::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetWriteWatch") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // dwFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // lpBaseAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // dwRegionSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // lpAddresses
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,      // lpdwCount
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,      // lpdwCount
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,           // Valor de retorno da função
            IARG_RETURN_IP,                        // Endereço da função chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,      // dwFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,      // lpBaseAddress
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,      // dwRegionSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3,      // lpAddresses
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4,      // lpdwCount
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5,      // lpdwCount
            IARG_END);

        RTN_Close(rtn);
    }
}
