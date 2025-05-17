#include "InstNtQueryInformationProcess.h"


/*
A função NtQueryInformationProcess é uma chamada de sistema do Windows, e a instrumentação para ela pode ser mais complexa do que para funções de API padrão.

Info sobre a função:
https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FNtQueryInformationProcess.html
https://pubhtml5.com/dtiq/ufpk/Windows_Kernel_Programming/274
https://forums.codeguru.com/showthread.php?371338-debugger-check-via-PEB
https://copyprogramming.com/howto/ntqueryinformationprocess-function-winternl-h
https://anti-debug.checkpoint.com/techniques/debug-flags.html
https://www.youtube.com/watch?v=WlE8abc8V-4
https://community.osr.com/discussion/228192

Verificar se pode ser utilizado para obter os argumentos de execução do processo e ver se está sendo debugado:
https://www.bordergate.co.uk/argument-spoofing/

*/


// Definição do PROCESSINFOCLASS e ProcessBasicInformation
// Mais informação sobre classes de comportamento evasivo -> https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
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


Extraído de:
https://github.com/winsiderss/systeminformer/blob/ae0cdac96f9c752c881a801af03f5b74deb51fa9/phnt/include/ntpsapi.h#L110
https://ntdoc.m417z.com/processinfoclass

Outras estruturas: https://www.cin.ufpe.br/~frsn/arquivos/GnuWin32/include/ddk/ntapi.h
*/

std::map<ADDRINT, NtQueryInformationProcessArgs> InstNtQueryInformationProcess::argsMap;

VOID InstNtQueryInformationProcess::CallbackBefore(ADDRINT instrPtr, ADDRINT ProcessHandle, ADDRINT ProcessInformationClass, ADDRINT ProcessInformation, ADDRINT ProcessInformationLength, ADDRINT ReturnLength) {
    NtQueryInformationProcessArgs args;
    args.ProcessHandle = ProcessHandle;
    args.ProcessInformationClass = ProcessInformationClass;
    args.ProcessInformation = ProcessInformation;
    args.ProcessInformationLength = ProcessInformationLength;
    args.ReturnLength = ReturnLength;

    argsMap[instrPtr] = args;
    /*
    std::cout << "[Contradef] NtQueryInformationProcess será chamada com os seguintes parâmetros:" << std::endl;
    std::cout << "[Contradef] ProcessHandle: " << ProcessHandle << std::endl;
    std::cout << "[Contradef] ProcessInformationClass: " << ProcessInformationClass << std::endl;
    std::cout << "[Contradef] ProcessInformation: " << ProcessInformation << std::endl;
    std::cout << "[Contradef] ProcessInformationLength: " << ProcessInformationLength << std::endl;
    std::cout << "[Contradef] ReturnLength (Endereço): " << ReturnLength << std::endl;
    */

}

VOID InstNtQueryInformationProcess::CallbackAfter(ADDRINT instrPtr, ADDRINT* retValAddr, ADDRINT ProcessHandle, ADDRINT ProcessInformationClass, ADDRINT ProcessInformation, ADDRINT ProcessInformationLength, ADDRINT ReturnLength) {
    auto it = argsMap.find(instrPtr-20);
    if (it != argsMap.end()) {
        const NtQueryInformationProcessArgs& args = it->second;

        // Utilizar os valores armazenados
        //std::cout << "[Contradef] NtQueryInformationProcess foi chamada com ProcessInformationClass: " << args.ProcessInformationClass << std::endl;
        //std::cout << "[Contradef] NtQueryInformationProcess foi chamada com ProcessInformation: " << args.ProcessInformation << std::endl;
        
        // ADDRINT ProcessInformation é alterado no retorno, posivelmente por alguma manipulação do registrador durante a execução da funçaõ.

        if (ProcessInformationClass == ProcessBasicInformation) {
            // Verifica se ProcessInformation é um ponteiro válido
            if (args.ProcessInformation != NULL) {
                PROCESS_BASIC_INFORMATION* pbi = reinterpret_cast<PROCESS_BASIC_INFORMATION*>(args.ProcessInformation);

                // 32 bits
                // DWORD ptr = (DWORD)pbi->PebBaseAddress;
                // ptr |= 0x68;
                // DWORD* NtGlobalFlagPtr = reinterpret_cast<DWORD*>(ptr);

                // 64 bits
                DWORD_PTR ptr = reinterpret_cast<DWORD_PTR>(pbi->PebBaseAddress);
                ptr |= 0xBC; // or no endereço base, o valor de ptr é o ponteiro para NtGlobalFlag
                DWORD* NtGlobalFlagPtr = reinterpret_cast<DWORD*>(ptr); // Cast do valor de ptr para ponteiro em temp

                // Endereço de memoria para intrumentar (verificar leitura em alguma instrução)
                TARGET_MEMORY_ADDRESS = reinterpret_cast<ADDRINT>(NtGlobalFlagPtr);
                std::cout << "[Contradef] NtGlobalFlagPtr (Endereço): " << TARGET_MEMORY_ADDRESS << std::endl;

            }
        }

        // Limpeza após o uso
        argsMap.erase(it);
    }


    std::cout << "[Contradef] Valor de retorno de NtQueryInformationProcess: " << *retValAddr << std::endl;

}


/// transferir funçoes para o main
// Variável de estado para rastrear o progresso na identificação da sequência


ADDRINT InstNtQueryInformationProcess::TARGET_MEMORY_ADDRESS;

VOID InstNtQueryInformationProcess::MemoryAccess(VOID* ip, VOID* address) {
    if ((ADDRINT)address == TARGET_MEMORY_ADDRESS) {
        std::cout << "+++++++++++++++++++Acesso à memória no endereço de interesse por " << ip << std::endl;
    }
}

// Callback de análise para ler um valor de memória
VOID ReadMemoryValue(ADDRINT instAddress, ADDRINT memoryAddress, UINT32 readSize) {
    // Buffer para armazenar o valor lido da memória
    //UINT32 buffer[64];  // Tamanho do buffer deve ser suficiente para o maior tamanho de leitura esperado

    //// Garantir que o buffer não é maior que o tamanho de leitura
    //if (readSize > sizeof(buffer)) {
    //    readSize = sizeof(buffer);
    //}

    //// Ler o valor da memória
    //if (PIN_SafeCopy(&buffer, reinterpret_cast<void*>(memoryAddress), readSize) == readSize) {
    //    // Valor lido com sucesso, agora você pode processar o buffer
    //    std::cout << "Valor lido da memória em " << std::hex << memoryAddress << ": ";
    //    for (UINT32 i = 0; i < readSize; ++i) {
    //        std::cout << static_cast<unsigned int>(buffer[i]) << " ";
    //    }
    //    std::cout << std::endl;
    //}
    //else {
    //    std::cout << "Falha ao ler a memória em " << std::hex << memoryAddress << std::endl;
    //}
    std::cout << "instAddress" << instAddress << std::endl;
    std::cout << "memoryAddress" << memoryAddress << std::endl;
    std::cout << "readSize" << readSize << std::endl;
}

// Lista de registradores permitidos para instrumentação
REG init[] = {
    //REG_INST_PTR,
    REG_GAX,
    REG_GBX,
    REG_GCX,
    REG_GDX,
    REG_GSI,
    REG_GDI,
    REG_GBP,
    //REG_STACK_PTR,
    REG_SEG_SS,
    REG_SEG_CS,
    REG_SEG_DS,
    REG_SEG_ES,
    REG_SEG_FS,
    REG_SEG_GS,
    //REG_GFLAGS,
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

// Função para verificar se um registrador está na lista permitida
bool IsRegisterPermitted(const REG& regName) {
    return permittedRegisters.find(regName) != permittedRegisters.end();
}

VOID MyAnalysisRoutine(CONTEXT* ctxt, REG regToInspect) {
    ADDRINT regValue = PIN_GetContextReg(ctxt, regToInspect);
    std::cout << "Valor do registrador: " << REG_StringShort(regToInspect) << " = " << regValue << std::endl;
}

enum State {
    NONE,
    MOV_FOUND,
    OR_FOUND,
    LEA_1_FOUND,
    LEA_2_FOUND
};

State state = NONE;

VOID InstNtQueryInformationProcess::Instruction(INS ins, VOID* v) {
 /*   if (INS_IsMemoryRead(ins)) {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)MemoryAccess,
            IARG_INST_PTR,
            IARG_MEMORYOP_EA, 0,
            IARG_END);
    }*/

    switch (state) {
        case NONE:
            if (INS_Opcode(ins) == XED_ICLASS_MOV) { //if (INS_Opcode(ins) == XED_ICLASS_MOV && /* Verificar operandos */) {
                state = MOV_FOUND;
            }
            break;

        case MOV_FOUND:
            if (INS_Opcode(ins) == XED_ICLASS_OR) { // idem ao de cima
                state = OR_FOUND;
            }
            else {
                state = NONE;  // Resetar se a sequência não corresponder
            }
            break;

        case OR_FOUND:
            if (INS_Opcode(ins) == XED_ICLASS_LEA) { // idem ao de cima
                state = LEA_1_FOUND;
            }
            else {
                state = NONE;  // Resetar se a sequência não corresponder
            }
            break;
        case LEA_1_FOUND:
            if (INS_Opcode(ins) == XED_ICLASS_LEA) { // idem ao de cima
                state = LEA_2_FOUND;
            }
            else {
                state = NONE;  // Resetar se a sequência não corresponder
            }
            break;
        case LEA_2_FOUND:
            if (INS_Opcode(ins) == XED_ICLASS_CMP) { // idem ao de cima
                // Sequência identificada
                
                // Obter a disassemblagem da instrução
                std::string disassembledInstruction = INS_Disassemble(ins);
                // Imprimir a disassemblagem
                std::cout << disassembledInstruction << std::endl;

                // Verificar se tem ao menos dois operandos
                if (INS_OperandCount(ins) > 1) {
                    // Obter o número de operandos
                    int numOperands = INS_OperandCount(ins);

                    for (int i = 0; i < numOperands; ++i) {
                        // Verificar se o operando é do tipo registrador
                        if (INS_OperandIsReg(ins, i)) {
                            REG reg = INS_OperandReg(ins, i);
                            if (IsRegisterPermitted(reg)) {
                                std::cout << "-Operando " << i << " é um registrador: " << reg << std::endl;
                                std::cout << "Operando " << i << " é um registrador: " << REG_StringShort(reg) << std::endl;
                                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MyAnalysisRoutine, IARG_CONTEXT, IARG_REG_VALUE, reg, IARG_END);
                            }
                            
                        }

                        // Verificar se o operando é do tipo memória
                        if (INS_OperandIsMemory(ins, i)) {
                            std::cout << "Operando " << i << " é um acesso à memória" << std::endl;
                            // Inserir um callback de análise antes da instrução
                            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMemoryValue,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD_EA,
                                IARG_MEMORYREAD_SIZE,
                                IARG_END);
                        }

                        // Verificar se o operando é imediato
                        if (INS_OperandIsImmediate(ins, i)) {
                            ADDRINT imm = INS_OperandImmediate(ins, i);
                            std::cout << "Operando " << i << " é um valor imediato: " << imm << std::endl;
                        }

                        // Outros tipos de operandos podem ser verificados aqui...
                    }
                }
                state = NONE;  // Resetar a sequência
            }
            else {
                state = NONE;  // Resetar se a sequência não corresponder
            }
            break;
    }

    /*
    Procurar em qual registrador é armazenado o valor NtGlobalFlagPtr e logo se tem um CMP com 0 na sequencia (cmp dword ptr [rbx], 0)
    */
}

// Fin transferir

VOID InstNtQueryInformationProcess::InstrumentFunction(RTN rtn) {
    PROTO protoNtQueryInformationProcess = PROTO_Allocate(PIN_PARG(ADDRINT), CALLINGSTD_STDCALL,
        "NtQueryInformationProcess",
        PIN_PARG(ADDRINT),   // ProcessHandle
        PIN_PARG(ADDRINT),   // ProcessInformationClass
        PIN_PARG(ADDRINT),   // ProcessInformation
        PIN_PARG(ADDRINT),   // ProcessInformationLength
        PIN_PARG(ADDRINT),   // ReturnLength
        PIN_PARG_END());

    RTN_Open(rtn);

    RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(CallbackBefore),
        IARG_PROTOTYPE, protoNtQueryInformationProcess,
        IARG_INST_PTR,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ProcessHandle
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // ProcessInformationClass
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // ProcessInformation
        IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // ProcessInformationLength
        IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // ReturnLength
        IARG_END);

    RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfter),
        IARG_PROTOTYPE, protoNtQueryInformationProcess,
        IARG_INST_PTR,
        IARG_REG_REFERENCE, REG_GAX,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // ProcessHandle
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // ProcessInformationClass
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // ProcessInformation
        IARG_FUNCARG_ENTRYPOINT_VALUE, 3, // ProcessInformationLength
        IARG_FUNCARG_ENTRYPOINT_VALUE, 4, // ReturnLength
        IARG_END);

    // Criar a função de instrumentação apenas uma vez e enviar o ponteiro para o endereço de memoria dque deve ser verificado. En
    INS_AddInstrumentFunction(Instruction, 0);

    RTN_Close(rtn);

    PROTO_Free(protoNtQueryInformationProcess);
}
