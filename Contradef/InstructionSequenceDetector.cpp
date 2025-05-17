#include "InstructionSequenceDetector.h"


std::vector<std::string> CreateVectorFromArgs(const char* first, ...) {
    std::vector<std::string> result;

    va_list args;
    va_start(args, first);

    // Adiciona o primeiro argumento
    const char* current = first;
    while (current != NULL) { // Use NULL como delimitador
        result.push_back(std::string(current));
        current = va_arg(args, const char*);
    }

    va_end(args);
    return result;
}

std::string CaptureAndConvertToUpper(const std::string& input) {
    std::string result;

    for (char ch : input) {
        if (ch == ' ') {
            break;
        }
        result += std::toupper(ch);
    }

    return result;
}

void NormalizeInstructionText(std::string& instr)
{
    // Converter para minúsculas
    std::transform(instr.begin(), instr.end(), instr.begin(), ::tolower);

    // Remover espaços e tabulações
    instr.erase(std::remove_if(instr.begin(), instr.end(), ::isspace), instr.end());


    // Substituir endereços hexadecimais por "0xADDR"
    size_t pos = 0;
    while ((pos = instr.find("0x", pos)) != std::string::npos)
    {
        size_t end = pos + 2; // Começar após "0x"

        // Verificar se há pelo menos 6 caracteres hexadecimais após "0x"
        size_t hexCount = 0;
        while (end < instr.size() && std::isxdigit(instr[end]))
        {
            ++end;
            ++hexCount;
        }

        // Verifica se o endereço hexadecimal é suficientemente longo (por exemplo, 6 ou mais dígitos)
        if (hexCount >= 6)
        {
            instr.replace(pos, end - pos, "0xADDR");
            pos += 6; // Avançar após "0xADDR"
        }
        else
        {
            pos = end; // Avançar para a próxima posição
        }
    }
}

BOOL InstMatch(const InstrumentedInstruction& queue_inst, const InstructionToMatch& seq_inst) {
    if (seq_inst.hasWildcard) {
        if (queue_inst.strSize != seq_inst.size) {
            return false; // Tamanho diferente não pode corresponder
        }
        // Comparar caracter a caracter, considerando coringas
        for (size_t x = 0; x < seq_inst.size; ++x) {
            if (seq_inst.normalizedInstructionStr[x] != '?' &&
                queue_inst.normalizedInstructionStr[x] != seq_inst.normalizedInstructionStr[x]) {
                return false; // Encontrou um caractere que não corresponde
            }
        }
        return true; // Todos os caracteres corresponderam
    }

    // Comparação direta quando não há coringas
    return queue_inst.normalizedInstructionStr == seq_inst.normalizedInstructionStr;
}

InstructionSequenceDetector::InstructionSequenceDetector()
    : max_sequence_length(0)
{
    tls_key = PIN_CreateThreadDataKey(NULL);
}

InstructionSequenceDetector::~InstructionSequenceDetector()
{
    // Nada a destruir explicitamente
}

void InstructionSequenceDetector::AddInstructionSequence(const std::vector<std::vector<std::string>>& sequence, SeqMatchCallbackFunc matchCallBack, VOID* v, int matchOcurrenceIndex, int matchOcurrenceIndexEnd)
{
    if (matchOcurrenceIndex >= 0 && matchOcurrenceIndexEnd < 0) {
        matchOcurrenceIndexEnd = matchOcurrenceIndex;
    }
    SequenceInstructions* sequenceInstructions = new SequenceInstructions(sequence, matchCallBack, v, matchOcurrenceIndex, matchOcurrenceIndexEnd);

    instruction_sequences.push_back(sequenceInstructions);

    // Atualizar o tamanho máximo da sequência
    if (sequenceInstructions->instruction_sequences.size() > max_sequence_length)
    {
        max_sequence_length = sequenceInstructions->instruction_sequences.size();
    }
}

VOID InstructionSequenceDetector::Instruction(ADDRINT ip, CONTEXT* ctxt, InstrumentedInstruction* ins_instr)
{
    ThreadData* tdata = GetThreadData();

    // Adicionar a instrução atual à fila (com limite fixo de tamanho)
    ins_instr->instAddr = ip;
    if (tdata->instruction_queue.size() == max_sequence_length) {
        tdata->instruction_queue.pop_front();
    }
    tdata->instruction_queue.push_back(ins_instr);

    // Comparar a fila de instruções com as sequências armazenadas
    for (auto* sequence : instruction_sequences)
    {

        size_t seq_length = sequence->instruction_sequences.size();
        if (tdata->instruction_queue.size() < seq_length) {
            continue; // Não há instruções suficientes na fila para realizar a comparação
        }

        // Comparar a sequência da fila com a sequência armazenada
        auto start_it = tdata->instruction_queue.end() - seq_length;

        bool match = std::equal(start_it, tdata->instruction_queue.end(), sequence->instruction_sequences.begin(),
            [](const InstrumentedInstruction* queue_inst, std::vector<InstructionToMatch*>& seq_inst) {
                bool match = false;
                for (const auto* inst : seq_inst) {
                    if (inst->isAnyInst) {
                        match = true;
                        break;
                    }
                    if (inst->insClass != queue_inst->insClass) {
                        continue; // As instruções devem ser do mesmo tipo
                    }
                    if (InstMatch(*queue_inst, *inst)) {
                        match = true;
                        break;
                    }
                }
                return match;
            });

        if (match) {
            // Sequência encontrada, chamar o callback
            sequence->matchCount++;
            if (sequence->match_callback && (sequence->matchOcurrenceIndex == -1 || (sequence->matchCount >= sequence->matchOcurrenceIndex && sequence->matchCount <= sequence->matchOcurrenceIndexEnd))) {
                sequence->match_callback(PIN_ThreadId(), ip, ctxt, *sequence, sequence->v);
            }
        }
    }
}


VOID InstructionSequenceDetector::DisassembledInstruction(ADDRINT ip, InstrumentedInstruction* ins_instr)
{
    ThreadData* tdata = GetThreadData();

    // Adicionar a instrução atual à fila (com limite fixo de tamanho)
    ins_instr->instAddr = ip;
    if (tdata->disassembled_instruction_queue.size() == max_sequence_length) {
        tdata->disassembled_instruction_queue.pop_front();
    }
    tdata->disassembled_instruction_queue.push_back(ins_instr);

    // Comparar a fila de instruções com as sequências armazenadas
    for (auto* sequence : instruction_sequences)
    {

        size_t seq_length = sequence->instruction_sequences.size();
        if (tdata->disassembled_instruction_queue.size() < seq_length) {
            continue; // Não há instruções suficientes na fila para realizar a comparação
        }

        // Comparar a sequência da fila com a sequência armazenada
        auto start_it = tdata->disassembled_instruction_queue.end() - seq_length;

        bool match = std::equal(start_it, tdata->disassembled_instruction_queue.end(), sequence->instruction_sequences.begin(),
            [](const InstrumentedInstruction* queue_inst, std::vector<InstructionToMatch*>& seq_inst) {
                bool match = false;
                for (const auto* inst : seq_inst) {
                    if (inst->isAnyInst) {
                        match = true;
                        break;
                    }
                    if (inst->insClass != queue_inst->insClass) {
                        continue; // As instruções devem ser do mesmo tipo
                    }
                    if (InstMatch(*queue_inst, *inst)) {
                        match = true;
                        break;
                    }
                }
                return match;
            });

        if (match) {
            // Sequência encontrada, chamar o callback
            sequence->matchCount++;
            if (sequence->match_callback && (sequence->matchOcurrenceIndex == -1 || (sequence->matchCount >= sequence->matchOcurrenceIndex && sequence->matchCount <= sequence->matchOcurrenceIndexEnd))) {
                sequence->match_callback(PIN_ThreadId(), ip, nullptr, *sequence, sequence->v);
            }
        }
    }
}

VOID InstructionSequenceDetector::seqInstCB(ADDRINT ip, CONTEXT* ctxt, InstrumentedInstruction* ins_instr)
{
    Instruction(ip, ctxt, ins_instr);
}

VOID InstructionSequenceDetector::seqInstCBWrapper(ADDRINT ip, CONTEXT* ctxt, InstrumentedInstruction* ins_instr, InstructionSequenceDetector* self)
{
    // Chama o método não estático da classe
    self->seqInstCB(ip, ctxt, ins_instr);
}

VOID InstructionSequenceDetector::InstructionTrace(INS ins, VOID* v, CaptureMode captureMode)
{
    bool add = false;
    OPCODE iOpCode = INS_Opcode(ins);

    ADDRINT address = INS_Address(ins);
    std::string disassembledInstr = INS_Disassemble(ins);

    InstrumentedInstruction* ins_inst = nullptr;

    if (captureMode == onDisassembly) {
        ins_inst = new InstrumentedInstruction(iOpCode, disassembledInstr);
        DisassembledInstruction(address, ins_inst);
        return;
    }

    // Criar a chave para o cache
    InstructionKey key(address, disassembledInstr);

    // Verificar se já está no cache
    auto cachedInstr = instructionCache.find(key);

    if (cachedInstr != instructionCache.end()) {
        // Recuperar do cache
        ins_inst = cachedInstr->second;
        add = true;
    }
    else {
        // Criar uma nova entrada

        // Comparar a fila com as sequências
        for (const auto* sequence : instruction_sequences) {
            for (const auto& instructionArr : sequence->instruction_sequences)
            {
                for (const auto* inst : instructionArr)
                {
                    if (inst->isAnyInst) {
                        add = true;
                        break;
                    }
                    if (inst->insClass != iOpCode) {
                        continue; // As instruções devem ser do mesmo tipo
                    }
                    if (ins_inst == nullptr)
                    {
                        ins_inst = new InstrumentedInstruction(iOpCode, disassembledInstr);
                    }
                    if (InstMatch(*ins_inst, *inst))
                    {
                        add = true;
                        break;
                    }
                }
                if (add) // Interrompe o loop externo se o valor foi achado
                {
                    break;
                }
            }
            if (add) // Interrompe o loop externo se o valor foi achado
            {
                break;
            }
        }
        if (add) {
            instructionCache[key] = ins_inst;
        }
        else {
            delete ins_inst;
        }

    }

    InstructionSequenceDetector* detector = reinterpret_cast<InstructionSequenceDetector*>(v);

    if (add) {
        if (captureMode == onCall) {

            INS_InsertCall(ins,
                IPOINT_BEFORE,
                AFUNPTR(seqInstCBWrapper),
                IARG_INST_PTR,
                IARG_CONTEXT,
                IARG_PTR, ins_inst,
                IARG_PTR, detector,
                IARG_END);
        }
;
    }
}

VOID InstructionSequenceDetector::ThreadStartImpl(THREADID tid, CONTEXT* ctxt, INT32 flags)
{
    ThreadData* tdata = new ThreadData();
    PIN_SetThreadData(tls_key, tdata, tid);
}

VOID InstructionSequenceDetector::ThreadFiniImpl(THREADID tid, const CONTEXT* ctxt, INT32 code)
{
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    delete tdata;
}

VOID InstructionSequenceDetector::ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    InstructionSequenceDetector* detector = reinterpret_cast<InstructionSequenceDetector*>(v);

    if (detector)
    {
        detector->ThreadStartImpl(tid, ctxt, flags);
    }
}

VOID InstructionSequenceDetector::ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    InstructionSequenceDetector* detector = reinterpret_cast<InstructionSequenceDetector*>(v);

    if (detector)
    {
        detector->ThreadFiniImpl(tid, ctxt, code);
    }
}

void InstructionSequenceDetector::Initialize()
{
    // Registrar as funções de callback estáticas
    PIN_AddThreadStartFunction(ThreadStart, this);
    PIN_AddThreadFiniFunction(ThreadFini, this);
}

InstructionSequenceDetector::ThreadData* InstructionSequenceDetector::GetThreadData()
{
    THREADID tid = PIN_ThreadId();
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    return tdata;
}

std::deque<InstrumentedInstruction*> InstructionSequenceDetector::GetInstructionQueue()
{
    ThreadData* tdata = GetThreadData();
    return tdata->instruction_queue;
}

std::deque<InstrumentedInstruction*> InstructionSequenceDetector::GetDisassembledInstructionQueue()
{
    ThreadData* tdata = GetThreadData();
    return tdata->disassembled_instruction_queue;
}