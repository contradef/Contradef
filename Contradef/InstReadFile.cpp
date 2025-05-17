#include "InstReadFile.h"

std::map<CallContextKey, CallContext*> InstReadFile::callContextMap;
UINT32 InstReadFile::imgCallId = 0;
UINT32 InstReadFile::fcnCallId = 0;
Notifier* InstReadFile::globalNotifierPtr;

VOID InstReadFile::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hFile, ADDRINT lpBuffer, ADDRINT nNumberOfBytesToRead, ADDRINT lpNumberOfBytesRead, ADDRINT lpOverlapped) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ReadFileArgs args;
    args.hFile = hFile;
    args.lpBuffer = lpBuffer;
    args.nNumberOfBytesToRead = nNumberOfBytesToRead;
    args.lpNumberOfBytesRead = lpNumberOfBytesRead;
    args.lpOverlapped = lpOverlapped;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);

    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] ReadFile..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        hFile: 0x" << std::hex << hFile << std::dec << std::endl;
    stringStream << "        lpBuffer: 0x" << std::hex << lpBuffer << std::dec << std::endl;
    stringStream << "        nNumberOfBytesToRead: " << nNumberOfBytesToRead << std::endl;
    stringStream << "        lpNumberOfBytesRead: 0x" << std::hex << lpNumberOfBytesRead << std::dec << std::endl;
    stringStream << "        lpOverlapped: 0x" << std::hex << lpOverlapped << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada ReadFile" << std::endl;

}

VOID InstReadFile::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT retValAddr,
    ADDRINT hFile, ADDRINT lpBuffer, ADDRINT nNumberOfBytesToRead, ADDRINT lpNumberOfBytesRead, ADDRINT lpOverlapped) {

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
        stringStream << "    Retorno ReadFile: " << result << std::endl;

        if (result != 0) {
            // Sucesso
            DWORD bytesRead = 0;
            if (lpNumberOfBytesRead != 0) {
                PIN_SafeCopy(&bytesRead, reinterpret_cast<DWORD*>(lpNumberOfBytesRead), sizeof(DWORD));
            }
            stringStream << "    Leitura bem-sucedida." << std::endl;
            stringStream << "    Bytes lidos: " << bytesRead << std::endl;
        }
        else {
            // Falha
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha na leitura. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada ReadFile concluída" << std::endl;
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

VOID InstReadFile::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "ReadFile") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nNumberOfBytesToRead
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpNumberOfBytesRead
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpOverlapped
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,     // valor de retorno (BOOL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hFile
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // lpBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nNumberOfBytesToRead
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // lpNumberOfBytesRead
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpOverlapped
            IARG_END);

        RTN_Close(rtn);
    }
}
