#include "InstLCMapStringEx.h"

std::map<CallContextKey, CallContext*> InstLCMapStringEx::callContextMap;
UINT32 InstLCMapStringEx::imgCallId = 0;
UINT32 InstLCMapStringEx::fcnCallId = 0;
Notifier* InstLCMapStringEx::globalNotifierPtr;

VOID InstLCMapStringEx::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT lpLocaleName, ADDRINT dwMapFlags, ADDRINT lpSrcStr, ADDRINT cchSrc,
    ADDRINT lpDestStr, ADDRINT cchDest, ADDRINT lpVersionInformation,
    ADDRINT lpReserved, ADDRINT lParam) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    LCMapStringExArgs args;
    args.lpLocaleName = lpLocaleName;
    args.dwMapFlags = dwMapFlags;
    args.lpSrcStr = lpSrcStr;
    args.cchSrc = (int)cchSrc;
    args.lpDestStr = lpDestStr;
    args.cchDest = (int)cchDest;
    args.lpVersionInformation = lpVersionInformation;
    args.lpReserved = lpReserved;
    args.lParam = lParam;

    UINT32 callCtxId = callId * 100 + fcnCallId;
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] LCMapStringEx..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;

    // Tenta ler a lpLocaleName (LPCWSTR)
    if (lpLocaleName != 0) {
        std::wstring localeName;
        localeName.resize(256);
        SIZE_T charsRead = PIN_SafeCopy(&localeName[0], reinterpret_cast<wchar_t*>(lpLocaleName), 255 * sizeof(wchar_t)) / sizeof(wchar_t);
        localeName[charsRead] = L'\0';
        stringStream << "        lpLocaleName: " << WStringToString(localeName) << std::endl;
    }
    else {
        stringStream << "        lpLocaleName: NULL" << std::endl;
    }

    stringStream << "        dwMapFlags: 0x" << std::hex << dwMapFlags << std::dec << std::endl;

    // Tenta ler a string de entrada (lpSrcStr) se cchSrc > 0
    if (lpSrcStr != 0 && cchSrc > 0) {
        int charsToRead = (cchSrc < 256) ? cchSrc : 256;
        std::wstring srcStr;
        srcStr.resize(charsToRead);
        SIZE_T charsRead = PIN_SafeCopy(&srcStr[0], reinterpret_cast<wchar_t*>(lpSrcStr), (charsToRead - 1) * sizeof(wchar_t)) / sizeof(wchar_t);
        srcStr[charsRead] = L'\0';
        stringStream << "        lpSrcStr: " << WStringToString(srcStr) << " (cchSrc: " << cchSrc << ")" << std::endl;
    }
    else if (lpSrcStr != 0 && cchSrc == -1) {
        // String null-terminated
        std::wstring srcStr;
        srcStr.resize(256);
        SIZE_T charsRead = PIN_SafeCopy(&srcStr[0], reinterpret_cast<wchar_t*>(lpSrcStr), 255 * sizeof(wchar_t)) / sizeof(wchar_t);
        srcStr[charsRead] = L'\0';
        stringStream << "        lpSrcStr: " << WStringToString(srcStr) << " (cchSrc: -1, null-terminated)" << std::endl;
    }
    else {
        stringStream << "        lpSrcStr: NULL ou cchSrc inválido" << std::endl;
    }

    stringStream << "        lpDestStr: 0x" << std::hex << lpDestStr << std::dec << ", cchDest: " << cchDest << std::endl;
    stringStream << "        lpVersionInformation: 0x" << std::hex << lpVersionInformation << std::dec << std::endl;
    stringStream << "        lpReserved: 0x" << std::hex << lpReserved << std::dec << std::endl;
    stringStream << "        lParam: 0x" << std::hex << lParam << std::dec << std::endl;

    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada LCMapStringEx" << std::endl;

}

VOID InstLCMapStringEx::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT lpLocaleName, ADDRINT dwMapFlags, ADDRINT lpSrcStr, ADDRINT cchSrc,
    ADDRINT lpDestStr, ADDRINT cchDest, ADDRINT lpVersionInformation, ADDRINT lpReserved, ADDRINT lParam) {

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

        int result = static_cast<int>(retValAddr);
        stringStream << "    Retorno LCMapStringEx: " << result << std::endl;

        if (result > 0) {
            // Sucesso: tenta ler a string de saída
            if (lpDestStr != 0 && cchDest > 0) {
                int charsToRead = (cchDest < 256) ? cchDest : 256;
                std::wstring destStr;
                destStr.resize(charsToRead);
                SIZE_T charsRead = PIN_SafeCopy(&destStr[0], reinterpret_cast<wchar_t*>(lpDestStr), (charsToRead - 1) * sizeof(wchar_t)) / sizeof(wchar_t);
                destStr[charsRead] = L'\0';

                stringStream << "    String resultante (lpDestStr): " << WStringToString(destStr) << std::endl;
            }
            else {
                stringStream << "    lpDestStr NULL ou cchDest inválido. Não foi possível ler a string resultante." << std::endl;
            }
            stringStream << "    Operação concluída com sucesso." << std::endl;
        }
        else {
            // Falha
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha na operação. Código de erro: " << error << std::endl;
        }

        stringStream << "  [-] Chamada LCMapStringEx concluída" << std::endl;
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

VOID InstLCMapStringEx::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "LCMapStringEx") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // int LCMapStringEx(
        //   LPCWSTR          lpLocaleName,
        //   DWORD            dwMapFlags,
        //   LPCWSTR          lpSrcStr,
        //   int              cchSrc,
        //   LPWSTR           lpDestStr,
        //   int              cchDest,
        //   LPNLSVERSIONINFO lpVersionInformation,
        //   LPVOID           lpReserved,
        //   LPARAM           lParam
        // );

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpLocaleName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwMapFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpSrcStr
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // cchSrc
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpDestStr
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // cchDest
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // lpVersionInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, // lpReserved
            IARG_FUNCARG_ENTRYPOINT_VALUE, 8, // lParam
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // int retorno
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // lpLocaleName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwMapFlags
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpSrcStr
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // cchSrc
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpDestStr
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // cchDest
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // lpVersionInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, // lpReserved
            IARG_FUNCARG_ENTRYPOINT_VALUE, 8, // lParam
            IARG_END);

        RTN_Close(rtn);
    }
}
