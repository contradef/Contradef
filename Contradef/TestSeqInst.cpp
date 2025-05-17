#include "TestSeqInst.h"
#include "ContextOperations.h"



VOID TestSeqCB(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v)
{
	std::cout << "\n[CONTRADEF][ANTIDEBUG] Sleep" << std::endl;

	SetZfToZero(ctxt);
}


void testSequences(InstructionSequenceDetector& seq_detector, InstructionSequenceDetector& disassembly_seq_detector) {
	// Tecnicas evasivas obsiium 1.8.5 Antidbi
	std::vector<std::vector<std::string>> sequence;
	sequence.push_back(CreateInstVector("jmp 0x7ff6f499d6e1"));
	sequence.push_back(CreateInstVector("test word ptr [r?i+0xa], 0x2"));
	sequence.push_back(CreateInstVector("jmp 0x7ff6f499d6eb", "jnb 0x7ff6f499d6eb", "jno 0x7ff6f499d6eb", "jb 0x7ff7bf17d3eb", "jo 0x7ff6cafbeb87"));
	sequence.push_back(CreateInstVector("jz 0x7ff6f499d2da"));

	//seq_detector.AddInstructionSequence(sequence, SequenceMatchCallback, 34, 34);
	seq_detector.AddInstructionSequence(sequence, SequenceMatchCallback); // TODAS



	// Instrução para ver as funções que será chamadas
	std::vector<std::vector<std::string>> sequence_call_fcn;
	sequence_call_fcn.push_back(CreateInstVector("add rsp, 0x?8"));
	sequence_call_fcn.push_back(CreateInstVector("pop r13"));
	sequence_call_fcn.push_back(CreateInstVector("pop r12"));
	sequence_call_fcn.push_back(CreateInstVector("jmp r10"));
	//seq_detector.AddInstructionSequence(sequence_call_fcn, SequenceMatchCallFcnCallback);


	// Função que escolhe o texto de erro que aparece na tela na tela
	std::vector<std::vector<std::string>> sequence_print_fcn;
	sequence_print_fcn.push_back(CreateInstVector("movzx r10d, word ptr [rax]")); // <- 0x7ff6a5335780
	sequence_print_fcn.push_back(CreateInstVector("test r10d, r10d"));
	sequence_print_fcn.push_back(CreateInstVector("jz 0x7ff6a533579c"));
	sequence_print_fcn.push_back(CreateInstVector("cmp r10b, cl"));
	sequence_print_fcn.push_back(CreateInstVector("jz 0x7ff6a533579e")); // <- se é a string procurada ele salta
	sequence_print_fcn.push_back(CreateInstVector("jnbe 0x7ff6a533579c"));
	sequence_print_fcn.push_back(CreateInstVector("movzx r11d, word ptr [rax+0x2]"));
	sequence_print_fcn.push_back(CreateInstVector("lea rax, ptr [rax+r11*2+0x4]"));
	sequence_print_fcn.push_back(CreateInstVector("jmp 0x7ff6a5335780")); // <- volta para: movzx r10d, word ptr [rax]
	//seq_detector.AddInstructionSequence(sequence_print_fcn, SequenceMatchReadStringForCallback);



	//// Função que varifica o texto para os nomes de funçoes - FUNCIONANDO
	//std::vector<std::vector<std::string>> sequence_read_string_fcn;
	//sequence_read_string_fcn.push_back(CreateInstVector("jz 0x7ff6d6ed3e4b"));
	//sequence_read_string_fcn.push_back(CreateInstVector("xor eax, eax"));
	//sequence_read_string_fcn.push_back(CreateInstVector("xor r8, r8"));
	//sequence_read_string_fcn.push_back(CreateInstVector("dec eax"));
	//sequence_read_string_fcn.push_back(CreateInstVector("mov r8b, byte ptr [rcx]"));
	//seq_detector.AddInstructionSequence(sequence_read_string_fcn, SequenceMatchReadStringFcnCallback);

	// Contem a string "=ExitCode=00000000"
	//std::vector<std::vector<std::string>> sequence_read_string_fcn;
	//sequence_read_string_fcn.push_back(CreateInstVector("jnz 0x7ff6d6eabc9c"));
	//sequence_read_string_fcn.push_back(CreateInstVector("lea rbp, ptr [rbp+rax*2]"));
	//sequence_read_string_fcn.push_back(CreateInstVector("add rbp, 0x2"));
	//sequence_read_string_fcn.push_back(CreateInstVector("cmp word ptr [rbp], si"));
	//sequence_read_string_fcn.push_back(CreateInstVector("jnz 0x7ff6d6eabc98"));
	//sequence_read_string_fcn.push_back(CreateInstVector("or rax, 0xffffffffffffffff"));
	//sequence_read_string_fcn.push_back(CreateInstVector("inc rax"));
	//sequence_read_string_fcn.push_back(CreateInstVector("cmp word ptr [rbp+rax*2], si"));
	//seq_detector.AddInstructionSequence(sequence_read_string_fcn, SequenceMatchReadStringEnvsCallback);






	//Algumas strings, IMPORTNTE, segue a função GetModuleFileNameW, e precede a função openFile e closeHandle
	std::vector<std::vector<std::string>> sequence_read_string_fcn;
	sequence_read_string_fcn.push_back(CreateInstVector("jmp 0x7ff6d6ecf9d6"));
	sequence_read_string_fcn.push_back(CreateInstVector("jmp 0x7ff6d6ecf37b"));
	sequence_read_string_fcn.push_back(CreateInstVector("movzx eax, byte ptr [rcx]"));
	//seq_detector.AddInstructionSequence(sequence_read_string_fcn, SequenceMatchReadStringStrings1Callback);




	std::vector<std::vector<std::string>> read_string_cmp;
	read_string_cmp.push_back(CreateInstVector("or rax, 0xffffffffffffffff"));
	read_string_cmp.push_back(CreateInstVector("inc rax"));
	read_string_cmp.push_back(CreateInstVector("cmp word ptr [rbp+rax*2], si"));
	read_string_cmp.push_back(CreateInstVector("jnz 0x7ff7e1c5bc9c"));
	read_string_cmp.push_back(CreateInstVector("inc rax"));
	read_string_cmp.push_back(CreateInstVector("cmp word ptr [rbp+rax*2], si"));
	//seq_detector.AddInstructionSequence(read_string_cmp, SequenceMatchReadStringCmpCallback);



	std::vector<std::vector<std::string>> read_string_cmp2;
	read_string_cmp2.push_back(CreateInstVector("jnz 0x7ff7e1c5bc9c"));
	read_string_cmp2.push_back(CreateInstVector("lea rbp, ptr [rbp+rax*2]"));
	read_string_cmp2.push_back(CreateInstVector("add rbp, 0x2"));
	read_string_cmp2.push_back(CreateInstVector("cmp word ptr [rbp], si"));
	//seq_detector.AddInstructionSequence(read_string_cmp2, SequenceMatchReadStringCmp2Callback);


	std::vector<std::vector<std::string>> read_string_cmp3;
	read_string_cmp3.push_back(CreateInstVector("mov rdi, rax"));
	read_string_cmp3.push_back(CreateInstVector("test rax, rax"));
	read_string_cmp3.push_back(CreateInstVector("jnz 0x7ff7e1c5bd0c"));
	read_string_cmp3.push_back(CreateInstVector("mov qword ptr [rsp+0x38], rsi"));
	read_string_cmp3.push_back(CreateInstVector("mov r9d, ebp"));
	read_string_cmp3.push_back(CreateInstVector("mov qword ptr [rsp+0x30], rsi"));
	read_string_cmp3.push_back(CreateInstVector("mov r8, rbx"));
	read_string_cmp3.push_back(CreateInstVector("mov dword ptr [rsp+0x28], r14d"));
	read_string_cmp3.push_back(CreateInstVector("xor edx, edx"));
	read_string_cmp3.push_back(CreateInstVector("xor ecx, ecx"));
	read_string_cmp3.push_back(CreateInstVector("mov qword ptr [rsp+0x20], rdi"));
	//seq_detector.AddInstructionSequence(read_string_cmp3, SequenceMatchReadStringCmp3Callback);


	// IMPORTANTE - Contem o nome de alguns depuradores
	std::vector<std::vector<std::string>> read_string_cmp40;
	read_string_cmp40.push_back(CreateInstVector("jmp 0x7ff625001cd1"));
	read_string_cmp40.push_back(CreateInstVector("jmp 0x7ff625001cd6"));
	read_string_cmp40.push_back(CreateInstVector("mov al, byte ptr [r10+rcx*1+0x1]"));
	read_string_cmp40.push_back(CreateInstVector("jmp 0x7ff625001cde"));
	//seq_detector.AddInstructionSequence(read_string_cmp40, SequenceMatchReadStringCmp40Callback);


	// IMPORTANTE - Contem os valores a serem comparados com os nomes de alguns depuradores
	std::vector<std::vector<std::string>> read_string_cmp41;
	read_string_cmp41.push_back(CreateInstVector("mov al, byte ptr [r10+rcx*1+0x1]"));
	read_string_cmp41.push_back(CreateInstVector("jmp 0x7ff625001cde"));
	read_string_cmp41.push_back(CreateInstVector("test al, al"));
	read_string_cmp41.push_back(CreateInstVector("jno 0x7ff625001ce4"));
	read_string_cmp41.push_back(CreateInstVector("jz 0x7ff625001d46"));
	read_string_cmp41.push_back(CreateInstVector("jmp 0x7ff625001ced"));
	read_string_cmp41.push_back(CreateInstVector("cmp ax, word ptr [rbp+rcx*2]"));
	//seq_detector.AddInstructionSequence(read_string_cmp41, SequenceMatchReadStringCmp41Callback);


	// Tecnica antidesmontagem, verificada
	std::vector<std::vector<std::string>> ad_same_target;
	ad_same_target.push_back(CreateInstVector("jz 0x7ff62f10fe35"));
	ad_same_target.push_back(CreateInstVector("jnz 0x7ff62f10fe35"));
	disassembly_seq_detector.AddInstructionSequence(ad_same_target, SequenceMatchAntiDebugSameTarget, &disassembly_seq_detector);


	// Tecnica antidesmontagem, verificada
	std::vector<std::vector<std::string>> ad_const_condition;
	ad_const_condition.push_back(CreateInstVector("xor eax, eax"));
	ad_const_condition.push_back(CreateInstVector("jz 0x7ff62f10fe35"));
	disassembly_seq_detector.AddInstructionSequence(ad_const_condition, SequenceMatchAntiDebugConstCondition, &disassembly_seq_detector);


	// para testes
	//std::vector<std::vector<std::string>> read_string_cmp4;
	//read_string_cmp4.push_back(CreateInstVector("call qword ptr [rip+0x1231f]"));
	//read_string_cmp4.push_back(CreateInstVector("mov r10, rcx"));
	//read_string_cmp4.push_back(CreateInstVector("mov eax, 0x1067"));
	//read_string_cmp4.push_back(CreateInstVector("test byte ptr [0x7ffe0308], 0x1"));
	//read_string_cmp4.push_back(CreateInstVector("jnz 0x7fffb26b21c5"));


	//seq_detector.AddInstructionSequence(read_string_cmp4, TestSeqCB);

}
