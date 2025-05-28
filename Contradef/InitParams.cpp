#include "InitParams.h"

// Arquivo de Saída 
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "contradef", "specify file name for output logs ");

// Regra Yara
KNOB<std::string> KnobYaraRulesFile(KNOB_MODE_WRITEONCE, "pintool", "yara", "", "specify file name for YARA rules ");

// Attach debugger
KNOB<BOOL> KnobAllowAttachDebugger(KNOB_MODE_WRITEONCE, "pintool", "ad", "0", "Allow attach debugger ");

// Interceptador de Funções
KNOB<BOOL> KnobFunctionInterceptor(KNOB_MODE_WRITEONCE, "pintool", "intercept_fcn", "0", "Activate function interceptor");

// Trace de funções
KNOB<BOOL> KnobTraceExternalCallTrace(KNOB_MODE_WRITEONCE, "pintool", "trace_exfcn", "0", "Save external call trace file ");

// Trace de memoria
KNOB<BOOL> KnobTraceMemory(KNOB_MODE_WRITEONCE, "pintool", "trace_mem", "0", "Trace memory");
KNOB<BOOL> KnobTraceMemoryOnlyStr(KNOB_MODE_WRITEONCE, "pintool", "memory-only-str", "1", "Trace memory");

// Trace de instruções
KNOB<BOOL> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "trace_instr", "0", "Trace instructions");
KNOB<THREADID> KnobWatchThread(KNOB_MODE_WRITEONCE, "pintool", "watch_thread", "-1", "Thread to watch, -1 for all");
KNOB<BOOL> KnobFlush(KNOB_MODE_WRITEONCE, "pintool", "flush", "0", "Flush output after every instruction");
KNOB<BOOL> KnobSymbols(KNOB_MODE_WRITEONCE, "pintool", "symbols", "1", "Include symbol information");
KNOB<BOOL> KnobFullImgName(KNOB_MODE_WRITEONCE, "pintool", "full_img_name", "0", "Include full image name");
KNOB<BOOL> KnobLines(KNOB_MODE_WRITEONCE, "pintool", "lines", "1", "Include line number information");
KNOB<BOOL> KnobTraceCalls(KNOB_MODE_WRITEONCE, "pintool", "call", "1", "Trace calls");
KNOB<BOOL> KnobTraceOnlyMain(KNOB_MODE_WRITEONCE, "pintool", "only_main", "0", "Trace only main image");
KNOB<BOOL> KnobTraceMemoryInstructions(KNOB_MODE_WRITEONCE, "pintool", "atmemory", "0", "Attach trace memory to trace instrucions");
KNOB<BOOL> KnobSilent(KNOB_MODE_WRITEONCE, "pintool", "silent", "0", "Do everything but write file (for debugging).");
KNOB<BOOL> KnobEarlyOut(KNOB_MODE_WRITEONCE, "pintool", "early_out", "0", "Exit after tracing the first region.");

// Trace disassembly
KNOB<BOOL> KnobTraceDisassembly(KNOB_MODE_WRITEONCE, "pintool", "trace_dasm", "0", "Trace disassembly");

// Ativa o detector de sequencia de instruções
KNOB<BOOL> KnobSeqDetector(KNOB_MODE_WRITEONCE, "pintool", "detect_seq", "0", "Enables the instruction sequence detector");
