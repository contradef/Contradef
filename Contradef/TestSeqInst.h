#pragma once
#ifndef TEST_SEQ_INST_CPP
#define TEST_SEQ_INST_CPP

#include <vector>
#include "InstructionSequenceDetector.h"
#include <string>
#include "InstrumentationCallbacks.h"

void testSequences(InstructionSequenceDetector& seq_detector, InstructionSequenceDetector& disassembly_seq_detector);

#endif // TEST_SEQ_INST_CPP