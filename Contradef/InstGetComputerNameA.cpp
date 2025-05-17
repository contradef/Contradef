#include "InstGetComputerNameA.h"

std::map<CallContextKey, CallContext*> InstGetComputerNameA::callContextMap;
UINT32 InstGetComputerNameA::imgCallId = 0;
UINT32 InstGetComputerNameA::fcnCallId = 0;
Notifier* InstGetComputerNameA::globalNotifierPtr;

VOID InstGetComputerNameA::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpBuffer, ADDRINT nSize) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    GetComputerNameAArgs args;
    args.lpBuffer = lpBuffer;
    args.nSize = nSize;

    UINT32 callCtxId = callId * 100 + fcnCallId;
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] GetComputerNameA..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        lpBuffer: 0x" << std::hex << lpBuffer << std::dec << std::endl;
    stringStream << "        nSize (LPDWORD): 0x" << std::hex << nSize << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada GetComputerNameA" << std::endl;

}

VOID InstGetComputerNameA::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT lpBuffer, ADDRINT nSize) {

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

        BOOL result = static_cast<BOOL>(retValAddr);
        stringStream << "    Retorno GetComputerNameA: " << (result ? "TRUE" : "FALSE") << std::endl;

        if (result != 0) {
            // Sucesso: tenta ler o nome do computador
            if (lpBuffer != 0 && nSize != 0) {
                DWORD bufferSize = 0;
                PIN_SafeCopy(&bufferSize, reinterpret_cast<DWORD*>(nSize), sizeof(DWORD));
                if (bufferSize > 0) {
                    // Limita a leitura a um tamanho razoável
                    DWORD bytesToRead = (bufferSize < 256) ? bufferSize : 256;
                    std::vector<char> compName(bytesToRead, '\0');
                    SIZE_T charsRead = PIN_SafeCopy(compName.begin(), reinterpret_cast<char*>(lpBuffer), bytesToRead - 1);
                    compName[charsRead] = '\0';

                    stringStream << "    Nome do computador: " << compName.begin() << std::endl;
                }
                else {
                    stringStream << "    nSize aponta para zero ou não pôde ser lido." << std::endl;
                }
            }
            else {
                stringStream << "    lpBuffer NULL ou nSize inválido. Não foi possível ler o nome do computador." << std::endl;
            }
            stringStream << "    Operação concluída com sucesso." << std::endl;
        }
        else {
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha ao obter o nome do computador. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada GetComputerNameA concluída" << std::endl;
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

VOID InstGetComputerNameA::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "GetComputerNameA") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // BOOL GetComputerNameA(
        //   LPSTR  lpBuffer,
        //   LPDWORD nSize
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // nSize
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // valor de retorno (BOOL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // nSize
            IARG_END);

        RTN_Close(rtn);
    }
}
