#include "InstrumentationCallbacks.h"

VOID SequenceMatchCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    std::cout << "\n[CONTRADEF][CALLBACK]\n";

    SetZfToZero(ctxt);
}

VOID SequenceMatchAntiDebugSameTarget(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    InstructionSequenceDetector* disassembly_seq_detector = reinterpret_cast<InstructionSequenceDetector*>(v);
    std::deque<InstrumentedInstruction*> instruction_queue = disassembly_seq_detector->GetDisassembledInstructionQueue();

    InstrumentedInstruction* inst = instruction_queue[instruction_queue.size() - 2];
    InstrumentedInstruction* inst2 = instruction_queue[instruction_queue.size() - 1];

    std::string inststr = inst->instructionStr;
    std::string inststr2 = inst2->instructionStr;

    std::string subinst = inststr.substr(2, 15);
    std::string subinst2 = inststr2.substr(3, 15);

    if (subinst == subinst2 && (inst->instAddr + 2) == inst2->instAddr) {  // 2 = tamanho da instrução jz (SHORT JUMP)
        std::cout << "\n[CONTRADEF][ANTIDEBUG] Instruções de Salto com o Mesmo Alvo:" << std::endl;
        std::cout << "    " << std::hex << inst->instAddr << " | " << inststr << std::dec << std::endl;
        std::cout << "    " << std::hex << inst2->instAddr << " | " << inststr2 << std::dec << std::endl;
    }
}


VOID SequenceMatchAntiDebugConstCondition(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    InstructionSequenceDetector* disassembly_seq_detector = reinterpret_cast<InstructionSequenceDetector*>(v);
    std::deque<InstrumentedInstruction*> instruction_queue = disassembly_seq_detector->GetDisassembledInstructionQueue();

    InstrumentedInstruction* inst = instruction_queue[instruction_queue.size() - 2];
    InstrumentedInstruction* inst2 = instruction_queue[instruction_queue.size() - 1];

    std::string inststr = inst->instructionStr;
    std::string inststr2 = inst2->instructionStr;

    if ((inst->instAddr + 2) == inst2->instAddr) { // 2 = tamanho da instrução xor
        std::cout << "\n[CONTRADEF][ANTIDEBUG] Instruções com Condição Constante:" << std::endl;
        std::cout << "    " << std::hex << inst->instAddr << " | " << inststr << std::dec << std::endl;
        std::cout << "    " << std::hex << inst2->instAddr << " | " << inststr2 << std::dec << std::endl;
    }
}


VOID SequenceMatchPauseCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
    OS_PROCESS_ID pid = PIN_GetPid();
    std::cout << "Sequencia de instrucoes identificada, endereco de instrucao " << std::hex << ip << std::dec << ", corresponde a funcao: " << GetFunctionFromAddress(ip, pid).functionName << std::endl;
    PauseAtAddress(ip);
}
