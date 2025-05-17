#pragma once
#ifndef INSTRUMENTATION_CALLBACKS_H
#define INSTRUMENTATION_CALLBACKS_H

#include "pin.H"
#include <iostream>
#include <string>
#include "DllFunctionMapper.h"
#include "regvalue_utils.h"
#include "Utils.h"
#include "InstructionSequenceDetector.h"
#include "InstrumentationUtils.h"

VOID SequenceMatchCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchCallFcnCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchReadStringFcnCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchReadStringEnvsCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchReadStringForCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchReadStringCmpCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchReadStringCmp2Callback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchReadStringCmp3Callback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchReadStringCmp40Callback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchReadStringCmp41Callback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchAntiDebugSameTarget(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchAntiDebugConstCondition(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);
VOID SequenceMatchPauseCallback(THREADID tid, ADDRINT ip, CONTEXT* ctxt, SequenceInstructions& sequence, VOID* v);

#endif // INSTRUMENTATION_CALLBACKS_H