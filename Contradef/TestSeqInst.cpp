#include "TestSeqInst.h"
#include "ContextOperations.h"

void AddTestSequences(InstructionSequenceDetector& seq_detector, InstructionSequenceDetector& disassembly_seq_detector) {
	// Detector de sequência de instruções aplicado à instruções executadas (na ordem da execução)
	// Exemplo de uso
	std::vector<std::vector<std::string>> sequence;
	sequence.push_back(CreateInstVector("jz 0x000000000000"));
	sequence.push_back(CreateInstVector("test word ptr [r?i+0xa], 0x2")); // "?" substitui qualquer valor
	sequence.push_back(CreateInstVector("jmp 0x000000000000", "jnb 0x000000000000", "jb 0x000000000000")); // Qualquer dessas instruções é considerada
	sequence.push_back(CreateInstVector("ja 0x000000000000"));
	sequence.push_back(CreateInstVector("jnz 0x000000000000"));

	//seq_detector.AddInstructionSequence(sequence, SequenceMatchCallback, 34, 34); // O callback será disparado na ocorrência 34 da mesma sequência de instruções
	seq_detector.AddInstructionSequence(sequence, SequenceMatchCallback); // O callback SequenceMatchCallback será disparado em todas as ocorrências 


	// Detector de sequência de instruções aplicado ao código desmontado (na ordem da desmontagem)
	// Tecnica antidesmontagem
	std::vector<std::vector<std::string>> ad_same_target;
	ad_same_target.push_back(CreateInstVector("jz 0x000000000000"));
	ad_same_target.push_back(CreateInstVector("jnz 0x000000000000"));
	disassembly_seq_detector.AddInstructionSequence(ad_same_target, SequenceMatchAntiDebugSameTarget, &disassembly_seq_detector);

	// Tecnica antidesmontagem
	std::vector<std::vector<std::string>> ad_const_condition;
	ad_const_condition.push_back(CreateInstVector("xor eax, eax"));
	ad_const_condition.push_back(CreateInstVector("jz 0x000000000000"));
	disassembly_seq_detector.AddInstructionSequence(ad_const_condition, SequenceMatchAntiDebugConstCondition, &disassembly_seq_detector);

}
