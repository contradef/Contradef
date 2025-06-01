#include "InstEnumSystemFirmwareTables.h"

std::map<CallContextKey, CallContext*> InstEnumSystemFirmwareTables::callContextMap;
UINT32 InstEnumSystemFirmwareTables::imgCallId = 0;
UINT32 InstEnumSystemFirmwareTables::fcnCallId = 0;
Notifier* InstEnumSystemFirmwareTables::globalNotifierPtr = nullptr;

VOID InstEnumSystemFirmwareTables::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT*,
    ADDRINT returnAddress,
    ADDRINT FirmwareTableProviderSignature,
    ADDRINT pFirmwareTableEnumBuffer,
    ADDRINT BufferSize)
{
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) return;

    EnumSystemFirmwareTablesArgs args{
        FirmwareTableProviderSignature,
        pFirmwareTableEnumBuffer,
        BufferSize
    };

    UINT32 callCtxId = callId * 100 + fcnCallId;
    auto* ctx = new CallContext(callCtxId, tid, instAddress, &args);
    callContextMap[{callCtxId, tid}] = ctx;

    std::stringstream& s = ctx->stringStream;
    s << "\n[+] EnumSystemFirmwareTables...\n"
        << "    Thread: " << tid << '\n'
        << "    Id de chamada: " << fcnCallId << '\n'
        << "    Endereço da rotina: 0x" << std::hex << ctx->rtnAddress << std::dec << '\n'
        << "    Parâmetros:\n"
        << "        FirmwareTableProviderSignature: 0x" << std::hex << FirmwareTableProviderSignature << std::dec << '\n'
        << "        pFirmwareTableEnumBuffer: 0x" << std::hex << pFirmwareTableEnumBuffer << std::dec << '\n'
        << "        BufferSize: " << BufferSize << " bytes\n"
        << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << '\n'
        << "  [-] Início da chamada EnumSystemFirmwareTables\n";

}

VOID InstEnumSystemFirmwareTables::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT*,
    ADDRINT returnAddress,
    ADDRINT retValAddr,
    ADDRINT FirmwareTableProviderSignature,
    ADDRINT pFirmwareTableEnumBuffer,
    ADDRINT BufferSize)
{
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) return;

    UINT32 callCtxId = callId * 100 + fcnCallId;
    auto it = callContextMap.find({ callCtxId, tid });
    if (it != callContextMap.end()) {
        PIN_LockClient();
        CallContext* ctx = it->second;
        std::stringstream& s = ctx->stringStream;

        DWORD bytesReturned = static_cast<DWORD>(retValAddr);
        s << "    Retorno EnumSystemFirmwareTables (bytes necessários/retornados): "
            << bytesReturned << '\n';

        if (bytesReturned && pFirmwareTableEnumBuffer && BufferSize) {
            DWORD toShow = (bytesReturned < 128 ? bytesReturned : 128);
            std::vector<BYTE> data(toShow);
            SIZE_T copied = PIN_SafeCopy(data.begin(),
                reinterpret_cast<BYTE*>(pFirmwareTableEnumBuffer),
                toShow);
            s << "    Primeiros " << copied << " bytes do buffer: ";
            for (SIZE_T i = 0; i < copied; ++i) s << std::hex << (int)data[i] << ' ';
            s << std::dec << '\n';
        }

        s << "  [-] Chamada EnumSystemFirmwareTables concluída\n"
            << "[*] Concluído\n\n";

        globalNotifierPtr->NotifyAll(new ExecutionEventData({ s.str() }));

        delete ctx;
        callContextMap.erase(it);
        PIN_UnlockClient();
    }
    fcnCallId++;
}

VOID InstEnumSystemFirmwareTables::InstrumentFunction(RTN rtn, Notifier& globalNotifier)
{
    if (RTN_Name(rtn) != "EnumSystemFirmwareTables") return;

    imgCallId++;
    globalNotifierPtr = &globalNotifier;
    RTN_Open(rtn);

    // Assinatura:
    // UINT EnumSystemFirmwareTables(
    //      DWORD  FirmwareTableProviderSignature,
    //      PVOID  pFirmwareTableEnumBuffer,
    //      DWORD  BufferSize);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
        IARG_THREAD_ID,
        IARG_UINT32, imgCallId,
        IARG_INST_PTR,
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_CONTEXT,
        IARG_RETURN_IP,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // FirmwareTableProviderSignature
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // pFirmwareTableEnumBuffer
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // BufferSize
        IARG_END);

    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
        IARG_THREAD_ID,
        IARG_UINT32, imgCallId,
        IARG_INST_PTR,
        IARG_ADDRINT, RTN_Address(rtn),
        IARG_CONTEXT,
        IARG_RETURN_IP,
        IARG_FUNCRET_EXITPOINT_VALUE,      // DWORD retornado
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // FirmwareTableProviderSignature
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // pFirmwareTableEnumBuffer
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // BufferSize
        IARG_END);

    RTN_Close(rtn);
}
