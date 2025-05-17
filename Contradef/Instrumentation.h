#pragma once

#ifndef INSTRUMENTATION_H
#define INSTRUMENTATION_H

#include "pin.H"

#include <set>
#include <cctype>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <deque>
#include <cwctype> // Para funções de verificação de caracteres wide, como iswalnum
#include <cstdint>

#include "YaraContradef.h"
#include "Notifier.h"
#include "NtStructures.h"
#include "Utils.h"
#include "InstrumentationUtils.h"
#include "regvalue_utils.h"

#include "FunctionInterceptor.h"
#include "InstructionSequenceDetector.h"
#include "CallStackManager.h"
#include "DllFunctionTracker.h"
#include "DllFunctionMapper.h"
#include "TraceInstructions.h"
#include "TraceMemory.h"
#include "TraceFcnCall.h"
#include "TraceDisassembly.h"
#include "TestSeqInst.h"

extern KNOB<bool> KnobDetailLevel; // Assume que KnobDetailLevel está definido em params.h

BOOL IsMainExecutable(ADDRINT address);
ADDRINT GetRtnAddr(ADDRINT instAddress);
std::string getFileName(const std::string& filePath);
VOID GetSectionInfo(IMG img, std::ofstream& OutFile);
VOID PauseAtEntryPoint(ADDRINT entryAddress);
VOID PauseAtAddress(ADDRINT address);
VOID TraceInstSeq(INS ins, VOID* v);
VOID InstrumentFunctionInterceptor(IMG img, VOID* v);
VOID InitPauseAtEntryPoint(IMG img, VOID* v);
VOID configOutput();
VOID HandleExecutionCompletedEvent(const EventData* data, void* context);

int InitInstrumentation();

#endif // INSTRUMENTATION_H