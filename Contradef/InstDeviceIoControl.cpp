#include "InstDeviceIoControl.h"

// Inicialização das variáveis estáticas
std::map<CallContextKey, CallContext*> InstDeviceIoControl::callContextMap;
UINT32 InstDeviceIoControl::imgCallId = 0;
UINT32 InstDeviceIoControl::fcnCallId = 0;
Notifier* InstDeviceIoControl::globalNotifierPtr;

// Callback executado antes da chamada da função DeviceIoControl
VOID InstDeviceIoControl::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT hDevice, ADDRINT dwIoControlCode, ADDRINT lpInBuffer, ADDRINT nInBufferSize,
    ADDRINT lpOutBuffer, ADDRINT nOutBufferSize, ADDRINT lpBytesReturned, ADDRINT lpOverlapped) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Estrutura para armazenar os argumentos
    DeviceIoControlArgs args;
    args.hDevice = hDevice;
    args.dwIoControlCode = dwIoControlCode;
    args.lpInBuffer = lpInBuffer;
    args.nInBufferSize = nInBufferSize;
    args.lpOutBuffer = lpOutBuffer;
    args.nOutBufferSize = nOutBufferSize;
    args.lpBytesReturned = lpBytesReturned;
    args.lpOverlapped = lpOverlapped;

    // Criação de um ID único para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;

    // Criação e armazenamento do contexto da chamada
    auto* callContext = new CallContext(callCtxId, tid, instAddress, &args);
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    // Construção da mensagem de log
    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] DeviceIoControl..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        hDevice: 0x" << std::hex << hDevice << std::dec << std::endl;
    stringStream << "        dwIoControlCode: 0x" << std::hex << dwIoControlCode << std::dec << std::endl;

    // Tenta ler e exibir o buffer de entrada, se possível
    if (args.lpInBuffer != 0 && args.nInBufferSize > 0) {
        // Para evitar logs excessivos, limitamos a quantidade de bytes a serem exibidos
        DWORD bytesToDisplay = (args.nInBufferSize < 64) ? args.nInBufferSize : 64;
        std::vector<BYTE> inBufferData(bytesToDisplay);
        PIN_SafeCopy(inBufferData.begin(), reinterpret_cast<BYTE*>(args.lpInBuffer), bytesToDisplay);

        stringStream << "        lpInBuffer: 0x" << std::hex << args.lpInBuffer << std::dec << std::endl;
        stringStream << "            Dados (até " << bytesToDisplay << " bytes): ";
        for (DWORD i = 0; i < bytesToDisplay; ++i) {
            stringStream << std::hex << static_cast<int>(inBufferData[i]) << " ";
        }
        stringStream << std::dec << std::endl;
    }
    else {
        stringStream << "        lpInBuffer: NULL ou nInBufferSize inválido." << std::endl;
    }

    // Tenta ler e exibir o buffer de saída, se possível
    if (args.lpOutBuffer != 0 && args.nOutBufferSize > 0) {
        // Para evitar logs excessivos, limitamos a quantidade de bytes a serem exibidos
        DWORD bytesToDisplay = (args.nOutBufferSize < 64) ? args.nOutBufferSize : 64;
        std::vector<BYTE> outBufferData(bytesToDisplay);
        PIN_SafeCopy(outBufferData.begin(), reinterpret_cast<BYTE*>(args.lpOutBuffer), bytesToDisplay);

        stringStream << "        lpOutBuffer: 0x" << std::hex << args.lpOutBuffer << std::dec << std::endl;
        stringStream << "            Dados (até " << bytesToDisplay << " bytes): ";
        for (DWORD i = 0; i < bytesToDisplay; ++i) {
            stringStream << std::hex << static_cast<int>(outBufferData[i]) << " ";
        }
        stringStream << std::dec << std::endl;
    }
    else {
        stringStream << "        lpOutBuffer: NULL ou nOutBufferSize inválido." << std::endl;
    }

    //stringStream << "        cchBufferLength: " << args.cchBufferLength << " bytes" << std::endl;
    stringStream << "        lpBytesReturned: 0x" << std::hex << args.lpBytesReturned << std::dec << std::endl;
    stringStream << "        lpOverlapped: 0x" << std::hex << args.lpOverlapped << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada DeviceIoControl" << std::endl;

}

// Callback executado após a chamada da função DeviceIoControl
VOID InstDeviceIoControl::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT rtn, CONTEXT* ctx, ADDRINT returnAddress,
    ADDRINT retValAddr, ADDRINT hDevice, ADDRINT dwIoControlCode, ADDRINT lpInBuffer, ADDRINT nInBufferSize,
    ADDRINT lpOutBuffer, ADDRINT nOutBufferSize, ADDRINT lpBytesReturned, ADDRINT lpOverlapped) {

    // Verificação para instrumentar apenas o executável principal, se aplicável
    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Criação do ID único para o contexto da chamada
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };

    // Busca do contexto da chamada no mapa
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient(); // Proteção para acesso seguro ao contexto

        CallContext* callContext = it->second;
        std::stringstream& stringStream = callContext->stringStream;

        // Conversão do valor de retorno para BOOL
        BOOL result = static_cast<BOOL>(retValAddr);
        stringStream << "    Retorno DeviceIoControl: " << (result ? "TRUE" : "FALSE") << std::endl;

        if (result != 0) {
            // Sucesso: lê o número de bytes retornados, se aplicável
            if (lpBytesReturned != 0) {
                DWORD bytesReturned = 0;
                PIN_SafeCopy(&bytesReturned, reinterpret_cast<DWORD*>(lpBytesReturned), sizeof(DWORD));
                stringStream << "    Bytes Retornados: " << bytesReturned << " bytes" << std::endl;
            }
            else {
                stringStream << "    lpBytesReturned: NULL. Não foi possível ler o número de bytes retornados." << std::endl;
            }

            // Indica sucesso
            stringStream << "    Operação concluída com sucesso." << std::endl;
        }
        else {
            // Falha: obtém o código de erro
            using namespace WindowsAPI;
            DWORD error = GetLastError();
            stringStream << "    Falha na operação. Código de erro: " << error << std::endl;
        }

        // Finalização das mensagens de log
        stringStream << "  [-] Chamada DeviceIoControl concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        // Notificação aos observadores após capturar o resultado
        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        // Limpeza: remove e deleta o contexto da chamada
        delete callContext;
        callContextMap.erase(it);

        PIN_UnlockClient(); // Desprotege o contexto
    }

    // Incrementa o ID da chamada
    fcnCallId++;
}

// Método responsável por inserir os callbacks na função DeviceIoControl
VOID InstDeviceIoControl::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

    std::string rtnName = RTN_Name(rtn);
    if (rtnName == "DeviceIoControl") {
        imgCallId++;
        globalNotifierPtr = &globalNotifier;

        RTN_Open(rtn);

        // Assinatura:
        // BOOL DeviceIoControl(
        //   HANDLE       hDevice,
        //   DWORD        dwIoControlCode,
        //   LPVOID       lpInBuffer,
        //   DWORD        nInBufferSize,
        //   LPVOID       lpOutBuffer,
        //   DWORD        nOutBufferSize,
        //   LPDWORD      lpBytesReturned,
        //   LPOVERLAPPED lpOverlapped
        // );

        // Inserção do CallbackBefore antes da chamada da função
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallbackBefore,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hDevice
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwIoControlCode
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpInBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // nInBufferSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpOutBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // nOutBufferSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // lpBytesReturned
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, // lpOverlapped
            IARG_END);

        // Inserção do CallbackAfter após a chamada da função
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CallbackAfter,
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_RETURN_IP,
            IARG_FUNCRET_EXITPOINT_VALUE,    // valor de retorno (BOOL)
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // hDevice
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // dwIoControlCode
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // lpInBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // nInBufferSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // lpOutBuffer
            IARG_FUNCARG_ENTRYPOINT_VALUE, 5, // nOutBufferSize
            IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // lpBytesReturned
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, // lpOverlapped
            IARG_END);

        RTN_Close(rtn);
    }
}
