#include "InstNtQueryValueKey.h"
#include "utils.h"
#include "NtStructures.h"

#ifndef REG_NONE
#define REG_NONE 0
#endif

#ifndef REG_SZ
#define REG_SZ 1
#endif

#ifndef REG_EXPAND_SZ
#define REG_EXPAND_SZ 2
#endif

#ifndef REG_BINARY
#define REG_BINARY 3
#endif

#ifndef REG_DWORD
#define REG_DWORD 4
#endif

#ifndef REG_MULTI_SZ
#define REG_MULTI_SZ 7
#endif

#ifndef REG_QWORD
#define REG_QWORD 11
#endif


std::map<CallContextKey, CallContext*> InstNtQueryValueKey::callContextMap;
UINT32 InstNtQueryValueKey::imgCallId = 0;
UINT32 InstNtQueryValueKey::fcnCallId = 0;
Notifier* InstNtQueryValueKey::globalNotifierPtr;


VOID InstNtQueryValueKey::InterpretKeyValueInformationFull(BYTE* keyValueInformation, std::stringstream& stringStream) {
    using namespace QueryValueKey;
    //KEY_VALUE_PARTIAL_INFORMATION* info;
    //info = (KEY_VALUE_PARTIAL_INFORMATION*)keyValueInformation;

    auto info = reinterpret_cast<KEY_VALUE_FULL_INFORMATION*>(keyValueInformation);

    stringStream << "            Tipo do valor: " << info->Type << std::endl;
    stringStream << "            Tamanho do dado: " << std::dec << info->DataLength << " bytes" << std::endl;

    BYTE* data = keyValueInformation + info->DataOffset;

    switch (info->Type) {
    case REG_NONE: {
        stringStream << "            Valor (REG_NONE): ";
        if (info->DataLength > 100000) {
            stringStream << "            Tamanho excede o limite";
        }
        else {
            for (ULONG i = 0; i < info->DataLength; ++i) {
                stringStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(data[i]) << " ";
            }
        }
        stringStream << "            (dados bin�rios brutos)" << std::endl;
        break;
    }
    case REG_SZ: {
        std::wstring stringValue(reinterpret_cast<WCHAR*>(data), info->DataLength / sizeof(WCHAR));
        stringStream << "            Valor (string): " << WStringToString(stringValue) << std::endl;
        break;
    }
    case REG_EXPAND_SZ: {
        std::wstring stringValue(reinterpret_cast<WCHAR*>(data), info->DataLength / sizeof(WCHAR));
        stringStream << "            Valor (string): " << WStringToString(stringValue) << std::endl;
        break;
    }
    case REG_DWORD: {
        if (info->DataLength >= sizeof(DWORD)) {
            DWORD dwordValue = *reinterpret_cast<DWORD*>(data);
            stringStream << "            Valor (DWORD): " << dwordValue << std::endl;
        }
        break;
    }
    case REG_BINARY: {
        stringStream << "            Valor (bin�rio): ";
        for (ULONG i = 0; i < info->DataLength; ++i) {
            stringStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(data[i]) << " ";
        }
        stringStream << std::endl;
        break;
    }
    case REG_MULTI_SZ: {
        const WCHAR* multiSz = reinterpret_cast<const WCHAR*>(data);
        stringStream << "            Valor (multi-string): ";

        while (*multiSz) {
            std::wstring str(multiSz);
            stringStream << "            " << WStringToString(str) << " | ";
            multiSz += str.size() + 1;
        }
        stringStream << std::endl;
        break;
    }
    case REG_QWORD: {
        if (info->DataLength >= sizeof(ULONGLONG)) {
            ULONGLONG qwordValue = *reinterpret_cast<ULONGLONG*>(data);
            stringStream << "            Valor (QWORD): " << qwordValue << std::endl;
        }
        break;
    }
    default:
        stringStream << "            Tipo de dado n�o reconhecido ou n�o suportado." << std::endl;
    }
}

VOID InstNtQueryValueKey::InterpretKeyValueInformationPartial(BYTE* keyValueInformation, std::stringstream& stringStream) {
    using namespace QueryValueKey;
    auto info = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION*>(keyValueInformation);

    stringStream << "            Tipo do valor: " << info->Type << std::endl;
    stringStream << "            Tamanho do dado: " << std::dec << info->DataLength << " bytes" << std::endl;

    // O dado � armazenado diretamente na estrutura ap�s os campos iniciais
    BYTE* data = info->Data;

    // Exemplo de interpreta��o de dados, dependendo do tipo
    switch (info->Type) {
    case REG_NONE: {
        stringStream << "            Valor (REG_NONE): ";
        if (info->DataLength > 100000) {
            stringStream << "            Tamanho excede o limite";
        }
        else {
            for (ULONG i = 0; i < info->DataLength; ++i) {
                stringStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(data[i]) << " ";
            }
        }
        stringStream << "            (dados bin�rios brutos)" << std::endl;
        break;
    }
    case REG_SZ: {
        std::wstring stringValue(reinterpret_cast<WCHAR*>(data), info->DataLength / sizeof(WCHAR));
        stringStream << "            Valor (string): " << WStringToString(stringValue) << std::endl;
        break;
    }
    case REG_EXPAND_SZ: {
        std::wstring stringValue(reinterpret_cast<WCHAR*>(data), info->DataLength / sizeof(WCHAR));
        stringStream << "            Valor (string): " << WStringToString(stringValue) << std::endl;
        break;
    }
    case REG_DWORD: {
        if (info->DataLength >= sizeof(DWORD)) {
            DWORD dwordValue = *reinterpret_cast<DWORD*>(data);
            stringStream << "            Valor (DWORD): " << dwordValue << std::endl;
        }
        break;
    }
    case REG_BINARY: {
        stringStream << "            Valor (bin�rio): ";
        for (ULONG i = 0; i < info->DataLength; ++i) {
            stringStream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(data[i]) << " ";
        }
        std::cout << std::endl;
        break;
    }
    case REG_MULTI_SZ: {
        const WCHAR* multiSz = reinterpret_cast<const WCHAR*>(data);
        stringStream << "            Valor (multi-string): ";

        while (*multiSz) {
            std::wstring str(multiSz);
            stringStream << "            " << WStringToString(str) << " | ";
            multiSz += str.size() + 1;
        }
        stringStream << std::endl;
        break;
    }
    case REG_QWORD: {
        if (info->DataLength >= sizeof(ULONGLONG)) {
            ULONGLONG qwordValue = *reinterpret_cast<ULONGLONG*>(data);
            stringStream << "            Valor (QWORD): " << qwordValue << std::endl;
        }
        break;
    }
    default:
        stringStream << "            Tipo de dado n�o reconhecido ou n�o suportado." << std::endl;
    }
}


VOID InstNtQueryValueKey::InterpretKeyValueInformationBasic(BYTE* keyValueInformation, std::stringstream& stringStream) {
    using namespace QueryValueKey;
    auto info = reinterpret_cast<KEY_VALUE_BASIC_INFORMATION*>(keyValueInformation);

    stringStream << "            Tipo do valor: " << info->Type << std::endl;
    stringStream << "            Comprimento do nome do valor: " << std::dec << info->NameLength << " bytes" << std::endl;

    // O nome do valor � armazenado diretamente na estrutura ap�s os campos iniciais
    std::wstring valueName(info->Name, info->NameLength / sizeof(WCHAR));
    stringStream << "            Nome do valor: " << WStringToString(valueName) << std::endl;

}

VOID InstNtQueryValueKey::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT KeyHandle, ADDRINT ValueName, USHORT KeyValueInformationClass, ADDRINT KeyValueInformation, UINT Length, UINT ResultLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    NtQueryValueKeyArgs args;
    args.KeyHandle = KeyHandle;
    args.ValueName = ValueName;
    args.KeyValueInformationClass = KeyValueInformationClass;
    args.KeyValueInformation = KeyValueInformation;
    args.Length = Length;
    args.ResultLength = ResultLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);

    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    }

VOID InstNtQueryValueKey::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT KeyHandle, ADDRINT ValueName, USHORT KeyValueInformationClass, ADDRINT KeyValueInformation, UINT Length, UINT ResultLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar fun�ao
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(instAddress);
        CallContext* callContext = it->second;
        // Registrar Parámetros
        const NtQueryValueKeyArgs* args = reinterpret_cast<NtQueryValueKeyArgs*>(callContext->functionArgs);
        std::stringstream& stringStream = callContext->stringStream;
        // Obter a RTN da instru��o atual
        RTN rtnCurrent = RTN_FindByAddress(instAddress);
        stringStream << std::endl << "[+] " << RTN_Name(rtnCurrent) << "..." << std::endl;
        stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Id de chamada: " << fcnCallId << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << callContext->rtnAddress << std::dec << std::endl;
        stringStream << "    Parámetros: " << std::endl;

        UNICODE_STRING* unicodeString = reinterpret_cast<UNICODE_STRING*>(args->ValueName);
        if (unicodeString && unicodeString->Buffer) {
            WCHAR* wideCharStr = reinterpret_cast<WCHAR*>(unicodeString->Buffer);
            std::wstring valueNameStr = std::wstring(wideCharStr);
            stringStream << "        ValueName: " << WStringToString(valueNameStr) << std::endl;
        }

        BYTE* KeyValueInformationBuffer = reinterpret_cast<BYTE*>(args->KeyValueInformation);
        if (args->KeyValueInformationClass == 0) {
            InterpretKeyValueInformationBasic(KeyValueInformationBuffer, stringStream);
        }
        else if (args->KeyValueInformationClass == 1) {
            InterpretKeyValueInformationFull(KeyValueInformationBuffer, stringStream);
        }
        else if (args->KeyValueInformationClass == 2) {
            InterpretKeyValueInformationPartial(KeyValueInformationBuffer, stringStream);
        }

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

VOID InstNtQueryValueKey::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {
    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtQueryValueKey" || rtnName == "ZwQueryValueKey") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(CallbackBefore),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // KeyHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // ValueName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // KeyValueInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // KeyValueInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // Length
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // ResultLength
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // KeyHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // ValueName
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // KeyValueInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // KeyValueInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // Length
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // ResultLength
            IARG_END);

        RTN_Close(rtn);
    }

}