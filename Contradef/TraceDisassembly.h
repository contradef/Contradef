#pragma once
#ifndef TRACE_DISASSEMBLY_H
#define TRACE_DISASSEMBLY_H

#include <fstream>
#include <string>
#include "pin.H"

namespace TraceDisassembly {

    extern std::ofstream disassemblyTraceOut;

    VOID TraceInst(INS ins, VOID* v);
    VOID Fini(INT32 code, VOID* v);
    int InitTraceDisassembly(std::string pid, std::string filename);
}

#endif // TRACE_DISASSEMBLY_H