#include "InstNtQueryInformationProcess.h"

/*
A fun��o NtQueryInformationProcess � uma chamada de sistema do Windows, e a instrumenta��o para ela pode ser mais complexa do que para fun��es de API padr�o.

Info sobre a fun��o:
https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FNtQueryInformationProcess.html
https://pubhtml5.com/dtiq/ufpk/Windows_Kernel_Programming/274
https://forums.codeguru.com/showthread.php?371338-debugger-check-via-PEB
https://copyprogramming.com/howto/ntqueryinformationprocess-function-winternl-h
https://anti-debug.checkpoint.com/techniques/debug-flags.html
https://www.youtube.com/watch?v=WlE8abc8V-4
https://community.osr.com/discussion/228192

Verificar se pode ser utilizado para obter os argumentos de execu��o do processo e ver se est� sendo debugado:
https://www.bordergate.co.uk/argument-spoofing/

*/


// Defini��o do PROCESSINFOCLASS e ProcessBasicInformation
// Mais informa��o sobre classes de comportamento evasivo -> https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
/*
Value	Meaning
ProcessBasicInformation
0
Retrieves a pointer to a PEB structure that can be used to determine whether the specified process is being debugged, and a unique value used by the system to identify the specified process.
Use the CheckRemoteDebuggerPresent and GetProcessId functions to obtain this information.

ProcessDebugPort
7
Retrieves a DWORD_PTR value that is the port number of the debugger for the process. A nonzero value indicates that the process is being run under the control of a ring 3 debugger.
Use the CheckRemoteDebuggerPresent or IsDebuggerPresent function.

ProcessWow64Information
26
Determines whether the process is running in the WOW64 environment (WOW64 is the x86 emulator that allows Win32-based applications to run on 64-bit Windows).
Use the IsWow64Process2 function to obtain this information.

ProcessImageFileName
27
Retrieves a UNICODE_STRING value containing the name of the image file for the process.
Use the QueryFullProcessImageName or GetProcessImageFileName function to obtain this information.

ProcessBreakOnTermination
29
Retrieves a ULONG value indicating whether the process is considered critical.
Note  This value can be used starting in Windows XP with SP3. Starting in Windows 8.1, IsProcessCritical should be used instead.

ProcessTelemetryIdInformation
64
Retrieves a PROCESS_TELEMETRY_ID_INFORMATION_TYPE value that contains metadata about a process.

ProcessSubsystemInformation
75
Retrieves a SUBSYSTEM_INFORMATION_TYPE value indicating the subsystem type of the process. The buffer pointed to by the ProcessInformation parameter should be large enough to hold a single SUBSYSTEM_INFORMATION_TYPE enumeration.


Extra�do de:
https://github.com/winsiderss/systeminformer/blob/ae0cdac96f9c752c881a801af03f5b74deb51fa9/phnt/include/ntpsapi.h#L110
https://ntdoc.m417z.com/processinfoclass

Outras estruturas: https://www.cin.ufpe.br/~frsn/arquivos/GnuWin32/include/ddk/ntapi.h
*/

LONG InstNtQueryInformationProcess::retVal;
ADDRINT InstNtQueryInformationProcess::TARGET_MEMORY_ADDRESS;
DWORD InstNtQueryInformationProcess::NtGlobalFlag = -1;
std::map<CallContextKey, CallContext*> InstNtQueryInformationProcess::callContextMap;
UINT32 InstNtQueryInformationProcess::imgCallId = 0;
UINT32 InstNtQueryInformationProcess::fcnCallId = 0;
Notifier* InstNtQueryInformationProcess::globalNotifierPtr;


VOID InstNtQueryInformationProcess::CallbackBefore(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT returnAddress, ADDRINT ProcessHandle, ADDRINT ProcessInformationClass, ADDRINT ProcessInformation, ADDRINT ProcessInformationLength, ADDRINT ReturnLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    ADDRINT rtnAddress = GetRtnAddr(instAddress);

    NtQueryInformationProcessArgs args;
    args.ProcessHandle = ProcessHandle;
    args.ProcessInformationClass = ProcessInformationClass;
    args.ProcessInformation = ProcessInformation;
    args.ProcessInformationLength = ProcessInformationLength;
    args.ReturnLength = ReturnLength;

    UINT32 callCtxId = callId * 100 + fcnCallId;

    auto* callContext = new CallContext(callCtxId, tid, rtnAddress, &args);
    
    CallContextKey key = { callCtxId, tid };
    callContextMap[key] = callContext;

    std::stringstream& stringStream = callContext->stringStream;
    stringStream << std::endl << "[+] NtQueryInformationProcess..." << std::endl;
    stringStream << "    Thread: " << tid << std::endl;
    stringStream << "    Id de chamada: " << fcnCallId << std::endl;
    stringStream << "    Endereço da rotina: 0x" << std::hex << callContext->rtnAddress << std::dec << std::endl;
    stringStream << "    Parâmetros: " << std::endl;
    stringStream << "        ProcessHandle: 0x" << std::hex << ProcessHandle << std::dec << std::endl;
    stringStream << "        ProcessInformationClass: " << ProcessInformationClass << std::endl;
    stringStream << "        ProcessInformation: 0x" << std::hex << ProcessInformation << std::dec << std::endl;
    stringStream << "        ProcessInformationLength: " << ProcessInformationLength << std::endl;
    stringStream << "        ReturnLength: 0x" << std::hex << ReturnLength << std::dec << std::endl;
    stringStream << "    Endereço da função chamante: 0x" << std::hex << returnAddress << std::dec << std::endl;
    stringStream << "  [-] Início da chamada NtQueryInformationProcess" << std::endl;
    
}

VOID InstNtQueryInformationProcess::CallbackAfter(THREADID tid, UINT32 callId, ADDRINT instAddress, ADDRINT  rtn, CONTEXT* ctx, ADDRINT* retValAddr, ADDRINT returnAddress, ADDRINT ProcessHandle, ADDRINT ProcessInformationClass, ADDRINT ProcessInformation, ADDRINT ProcessInformationLength, ADDRINT ReturnLength) {

    if (instrumentOnlyMain && !IsMainExecutable(returnAddress)) {
        return;
    }

    // Instrumentar fun�ao
    UINT32 callCtxId = callId * 100 + fcnCallId;
    CallContextKey key = { callCtxId, tid };
    auto it = callContextMap.find(key);
    if (it != callContextMap.end()) {
        PIN_LockClient();

        CallContext* callContext = it->second;
        
        std::stringstream& stringStream = callContext->stringStream;

        // O retorno é NTSTATUS (LONG)
        LONG status = *retValAddr;
        stringStream << "    Retorno NtQueryInformationProcess (NTSTATUS): 0x"
            << std::hex << status << std::dec << std::endl;

        if (status == 0) { // STATUS_SUCCESS (0)
            stringStream << "    Operação bem-sucedida (STATUS_SUCCESS)." << std::endl;

            // Se fizer sentido, podemos tentar ler parte do 'ProcessInformation'
            // dependendo do 'ProcessInformationClass' e do tamanho do buffer,
            // mas este exemplo apenas ilustra a leitura:
            if (ProcessInformation != 0 && ProcessInformationLength > 0) {
                ULONG bytesToRead = (ProcessInformationLength < 256) ? ProcessInformationLength : 256;
                std::vector<BYTE> infoData(bytesToRead);
                SIZE_T bytesCopied = PIN_SafeCopy(infoData.begin(), reinterpret_cast<BYTE*>(ProcessInformation), bytesToRead);
                stringStream << "    (Leu " << bytesCopied << " bytes de ProcessInformation, exibindo em hexa): ";
                for (SIZE_T i = 0; i < bytesCopied; i++) {
                    stringStream << std::hex << (int)infoData[i] << " ";
                }
                stringStream << std::dec << std::endl;
            }
        }
        else {
            // Em caso de falha, podemos exibir mais detalhes, se necessários.
            stringStream << "    Falha na operação (NTSTATUS != 0). Código: 0x"
                << std::hex << status << std::dec << std::endl;
        }

        stringStream << "  [-] Chamada NtQueryInformationProcess concluída" << std::endl;
        stringStream << "[*] Concluído" << std::endl << std::endl;

        ExecutionInformation executionCompletedInfo = { stringStream.str() };
        ExecutionEventData executionEvent(executionCompletedInfo);
        globalNotifierPtr->NotifyAll(&executionEvent);

        delete callContext;
        callContextMap.erase(it);



        
        
        

        // Outro Processamento
        const NtQueryInformationProcessArgs* args = reinterpret_cast<NtQueryInformationProcessArgs*>(callContext->functionArgs);

        //CONTRAMEDIDAS
        if (args->ProcessInformationClass == ProcessDebugPort) {
            DWORD* debugPort = reinterpret_cast<DWORD*>(args->ProcessInformation);
            if (*debugPort != 0) {
                //std::cout << "debugPort\n";
                //*debugPort = 0;
            }
        }

        if (args->ProcessInformationClass == ProcessDebugObjectHandle) {
            HANDLE* debugHandle = reinterpret_cast<HANDLE*>(args->ProcessInformation);

            if (*debugHandle != 0) {
                //std::cout << "debugHandle "<< *debugHandle;
                //*debugHandle = 0;
            }
        }

        if (args->ProcessInformationClass == ProcessDebugFlags) {
            DWORD* debugFlags = reinterpret_cast<DWORD*>(args->ProcessInformation);
            if (*debugFlags == 0) {
                //std::cout << "debugFlags\n";
                //*debugFlags = -1;
            }
        }



        if (false && ProcessInformationClass == ProcessBasicInformation) { // desativado
            // Verifica se ProcessInformation � um ponteiro v�lido
            if (args->ProcessInformation != NULL) {
                PROCESS_BASIC_INFORMATION* pbi = reinterpret_cast<PROCESS_BASIC_INFORMATION*>(args->ProcessInformation);

                // 32 bits
                // DWORD ptr = (DWORD)pbi->PebBaseAddress;
                // ptr |= 0x68;
                // DWORD* NtGlobalFlagPtr = reinterpret_cast<DWORD*>(ptr);

                // 64 bits
                DWORD_PTR pebBaseAddress = reinterpret_cast<DWORD_PTR>(pbi->PebBaseAddress);
                if (PIN_CheckReadAccess(reinterpret_cast<void*>(pebBaseAddress))) {
                    // Considerando que 0xBC � o offset para NtGlobalFlag no PEB
                    DWORD_PTR NtGlobalFlagPtrAddress = pebBaseAddress + 0xBC;
                    DWORD* NtGlobalFlagPtr = reinterpret_cast<DWORD*>(NtGlobalFlagPtrAddress);

                    if (PIN_CheckReadAccess(reinterpret_cast<void*>(NtGlobalFlagPtr))) {
                        TARGET_MEMORY_ADDRESS = reinterpret_cast<ADDRINT>(NtGlobalFlagPtr);
                        NtGlobalFlag = *NtGlobalFlagPtr; // Salvar o valor de NtGlobalFlag

                        // Criar a fun��o de instrumenta��o apenas uma vez e enviar o ponteiro para o Endereço de memoria dque deve ser verificado. En
                        INS_AddInstrumentFunction(Instruction, callContext);
                    }
                }

            }
        }
        PIN_UnlockClient();
    }
    
    retVal = *retValAddr;

    fcnCallId++;

}


/// transferir fun�oes para o main
// Vari�vel de estado para rastrear o progresso na identifica��o da sequ�ncia




// Lista de registradores permitidos para instrumenta��o
REG init[] = {
    REG_GAX,
    REG_GBX,
    REG_GCX,
    REG_GDX,
    REG_GSI,
    REG_GDI,
    REG_GBP,
    REG_SEG_SS,
    REG_SEG_CS,
    REG_SEG_DS,
    REG_SEG_ES,
    REG_SEG_FS,
    REG_SEG_GS,
    REG_R8,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
    REG_R15,
};
std::set<REG> permittedRegisters(init, init + sizeof(init) / sizeof(init[0]));

// Fun��o para verificar se um registrador est� na lista permitida
bool InstNtQueryInformationProcess::IsRegisterAllowed(const REG& regName) {
    return permittedRegisters.find(regName) != permittedRegisters.end();
}

VOID FetchInsCode(INS ins) {
    
    PIN_LockClient();

    // Obter o Endereço da instru��o
    ADDRINT address = INS_Address(ins);

    // Definir um buffer para armazenar o c�digo bin�rio da instru��o
    std::vector<UINT8> buffer(15); //15 bytes -> x64bits Tamanho m�ximo para uma instru��o x86/64

    EXCEPTION_INFO exceptInfo;

    // Buscar o c�digo bin�rio da instru��o
    if (PIN_FetchCode(reinterpret_cast<UINT8*>(&buffer[0]), (VOID*)address, 15, &exceptInfo)) {
        std::cout << "Instru��o em 0x" << std::hex << address << ": ";
        for (UINT8 byte : buffer) {
            std::cout << std::hex << static_cast<unsigned>(byte);
        }
        std::cout << std::endl;
    }
    //else {
    //    std::cout << "Falha ao buscar o c�digo da instru��o em 0x" << std::hex << address << std::endl;
    //}

    PIN_UnlockClient();

}

// Callback de an�lise para ler um valor de mem�ria
VOID InstNtQueryInformationProcess::ReadMemoryValue(THREADID tid, CallContext* callContext, CONTEXT* ctxt, INS ins, ADDRINT instAddress, ADDRINT memoryAddress, UINT32 readSize) {
    
    if (callContext == nullptr) {
        return;
    }

    const NtQueryInformationProcessArgs* args = reinterpret_cast<NtQueryInformationProcessArgs*>(callContext->functionArgs);
    std::stringstream& stringStream = callContext->stringStream;

    if (InstNtQueryInformationProcess::TARGET_MEMORY_ADDRESS != 0 && InstNtQueryInformationProcess::TARGET_MEMORY_ADDRESS == memoryAddress) {
        if (INS_Opcode(ins) != XED_ICLASS_CMP && INS_Opcode(ins) != XED_ICLASS_CMOVZ && INS_Opcode(ins) != XED_ICLASS_CMOVNZ) {
            //return;
        }
        
        int numOperands = INS_OperandCount(ins);
        for (int i = 0; i < numOperands; ++i) {
            // Verificar se o operando � imediato
            // O valor de mem�ria procurado � dinamico, ent�o n�o pode estar como valor imediato (constante)
            // Porem, o operando a ser comparado com o valor em memoria pode conter o valor 0
            if (INS_OperandIsImmediate(ins, i)) {
                ADDRINT imm = INS_OperandImmediate(ins, i);
                //std::cout << "Valor do operando imediato: " << imm << std::endl;
            }

            // Verificar se o operando � do tipo registrador
            //if (INS_OperandIsReg(ins, i)) {
            //    REG reg = INS_OperandReg(ins, i);
            //    ADDRINT regValue = PIN_GetContextReg(ctxt, reg);

            //    // Imprimir o valor do registrador em hexadecimal
            //    //std::cout << std::hex << std::showbase;  // Configurar o fluxo de sa�da para hexadecimal
            //    std::cout << "Valor do registrador " << REG_StringShort(reg) << ": " << regValue << std::endl;
            //    //std::cout << std::dec;  // Voltar para a formata��o decimal para futuras impress�es
            //}

            // Verificar se o operando � do tipo mem�ria
            if (INS_OperandIsMemory(ins, i)) {
                // Se necess�rio inserir alguma rotina de verifica��o
            }

        }


        // Realizar a leitura do valor em memoria
        int valueAtNtGlobalFlagAddress = *reinterpret_cast<int*>(TARGET_MEMORY_ADDRESS);

        if (valueAtNtGlobalFlagAddress != NtGlobalFlag) {
            return;
        }

        PIN_LockClient();
        
        IMG img = IMG_FindByAddress(instAddress);
        if (IMG_Valid(img)) {
            std::string moduleName = ExtractModuleName(IMG_Name(img));
            if (toUpperCase(moduleName) == "NTDLL.DLL") {
                // Se a leitura ocorre em ntdll.dll desconsidera. Alguns protetores podem carregar fun��es em modulos diferentes ao principal, se for o caso, desativar o return
                PIN_UnlockClient();
                return;
            }
        }

        // Obter o ponteiro para a pilha atual
        ADDRINT* stackPtr;
        PIN_GetContextRegval(ctxt, REG_STACK_PTR, reinterpret_cast<UINT8*>(&stackPtr));

        // Obter o Endereço de retorno da pilha
        ADDRINT returnAddr = *stackPtr;

        // Obter a disassemblagem da instru��o
        std::string disassembledInstruction = INS_Disassemble(ins);
        
        // Obter a RTN da instru��o atual
        RTN rtn = INS_Rtn(ins);

        ADDRINT rtnAddress = RTN_Address(rtn);
        stringStream << std::endl << "[+] NtQueryInformationProcess..." << std::endl;
        if (IMG_Valid(img)) {
            stringStream << "    Nome do módulo: " << IMG_Name(img) << std::endl;
        }
        stringStream << "    Thread: " << tid << std::endl;
        stringStream << "    Endereço da rotina: " << std::hex << rtnAddress << std::dec << std::endl;
        if (RTN_Valid(rtn)) {
            stringStream << "    Nome da rotina: " + RTN_Name(rtn) << std::endl;
        }
        stringStream << "    Valor de retorno (NtQueryInformationProcess): " << retVal << std::endl;
        stringStream << "    Instru��o: " << disassembledInstruction << std::endl;
        stringStream << "    Endereço da instru��o: " << std::hex << std::showbase << instAddress << std::dec << std::endl;
        stringStream << "    Endereço do valor em mem�ria: " << std::hex << std::showbase << memoryAddress << std::dec << std::endl;
        stringStream << "    Valor da flag NtGlobalFlag: " << valueAtNtGlobalFlagAddress << std::endl;

        PIN_UnlockClient();

        InstNtQueryInformationProcess::TARGET_MEMORY_ADDRESS = 0;
    }
}

// (DESATIVADO) Callback de an�lise para ler um valor de um registrador 
VOID InstNtQueryInformationProcess::RegContentAnalysisRoutine(CONTEXT* ctxt, REG regToInspect) {
    ADDRINT regValue = PIN_GetContextReg(ctxt, regToInspect);
    //std::cout << "Valor do registrador: " << REG_StringShort(regToInspect) << " = " << regValue << std::endl;
    if (InstNtQueryInformationProcess::TARGET_MEMORY_ADDRESS != 0 && InstNtQueryInformationProcess::TARGET_MEMORY_ADDRESS == regValue) {
        std::cout << "-----Endereço de mem�ria para o NtGlobalFlagPtr foi acessado em uma instru��o CMP por meio do registrador " << REG_StringShort(regToInspect) << "com valor " << regValue << std::endl;
    }
}

VOID InstNtQueryInformationProcess::Instruction(INS ins, VOID* v) {
    /*
    Procurar em qual registrador � armazenado o valor NtGlobalFlagPtr e logo se tem um CMP com 0 na sequencia (cmp dword ptr [rbx], 0)
    */
    if (INS_IsMemoryRead(ins) ) { // 
        // CMP identificado

        // Obter a disassemblagem da instru��o
        //std::string disassembledInstruction = INS_Disassemble(ins);
        // Imprimir a disassemblagem
        //std::cout << disassembledInstruction << std::endl;

        // Verificar se tem ao menos dois operandos
        if (INS_OperandCount(ins) > 1) {
            // Obter o n�mero de operandos
            int numOperands = INS_OperandCount(ins);

            for (int i = 0; i < numOperands; ++i) {
                // Verificar se o operando � imediato
                // O valor de mem�ria procurado � dinamico, ent�o n�o pode estar como valor imediato (constante)
                // Porem, o operando a ser comparado com o valor em memoria pode conter o valor 0
                if (INS_OperandIsImmediate(ins, i)) {
                    ADDRINT imm = INS_OperandImmediate(ins, i);
                }

                // Verificar se o operando � do tipo registrador
                if (INS_OperandIsReg(ins, i)) {
                    REG reg = INS_OperandReg(ins, i);
                    if (IsRegisterAllowed(reg)) {
                        // Inserir o callback de an�lise antes da execu��o da instru��o
                        // Habilitar no cado de uma verifica��o mais exaustiva. Pode reduzir a acuracia pois a verifica��o � aplicada sob o Endereço de memoria como valor do registrador
                        /*INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RegContentAnalysisRoutine,
                            IARG_CONTEXT,
                            IARG_UINT32, reg,
                            IARG_END);*/
                    }
                }

                // Verificar se o operando � do tipo mem�ria
                if (INS_OperandIsMemory(ins, i)) {
                    // Inserir um callback de an�lise antes da instru��o

                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMemoryValue,
                        IARG_THREAD_ID,
                        IARG_PTR, v,
                        IARG_CONTEXT,
                        IARG_PTR, ins,
                        IARG_INST_PTR,
                        IARG_MEMORYREAD_EA,
                        IARG_MEMORYREAD_SIZE,
                        IARG_END);
                }
            }
        }
    }
}

// Fin transferir

VOID InstNtQueryInformationProcess::InstrumentFunction(RTN rtn, Notifier& globalNotifier) {

   std::string rtnName = RTN_Name(rtn);
    if (rtnName == "NtQueryInformationProcess" || rtnName == "ZwQueryInformationProcess") {
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
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ProcessHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // ProcessInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // ProcessInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // ProcessInformationLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // ReturnLength
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
            IARG_THREAD_ID,
            IARG_UINT32, imgCallId,
            IARG_INST_PTR,
            IARG_ADDRINT, RTN_Address(rtn),
            IARG_CONTEXT,
            IARG_REG_REFERENCE, REG_GAX,
            IARG_RETURN_IP, // Endereço da fun��o chamante
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ProcessHandle
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // ProcessInformationClass
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // ProcessInformation
            IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // ProcessInformationLength
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // ReturnLength
            IARG_END);

        RTN_Close(rtn);
    }
}
