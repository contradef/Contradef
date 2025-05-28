#pragma once
#ifndef INIT_PARAMS_H
#define INIT_PARAMS_H

#include "pin.H"
#include <string>

// Apenas declarações, sem inicialização
extern KNOB<std::string> KnobOutputFile;
extern KNOB<std::string> KnobYaraRulesFile;
extern KNOB<BOOL> KnobAllowAttachDebugger;
extern KNOB<BOOL> KnobFunctionInterceptor;
extern KNOB<BOOL> KnobTraceExternalCallTrace;
extern KNOB<BOOL> KnobTraceMemory;
extern KNOB<BOOL> KnobTraceMemoryOnlyStr;
extern KNOB<BOOL> KnobTraceInstructions;
extern KNOB<THREADID> KnobWatchThread;
extern KNOB<BOOL> KnobFlush;
extern KNOB<BOOL> KnobSymbols;
extern KNOB<BOOL> KnobFullImgName;
extern KNOB<BOOL> KnobLines;
extern KNOB<BOOL> KnobTraceCalls;
extern KNOB<BOOL> KnobTraceOnlyMain;
extern KNOB<BOOL> KnobTraceMemoryInstructions;
extern KNOB<BOOL> KnobSilent;
extern KNOB<BOOL> KnobEarlyOut;
extern KNOB<BOOL> KnobTraceDisassembly;
extern KNOB<BOOL> KnobSeqDetector;

#endif // INIT_PARAMS_H