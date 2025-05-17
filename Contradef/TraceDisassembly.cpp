#include "TraceDisassembly.h"
#include "InstrumentationUtils.h"
#include "CallContext.h"

KNOB<BOOL> KnobDisassembly(KNOB_MODE_WRITEONCE, "pintool", "dasm", "1", "Trace disassembly");

namespace TraceDisassembly {

    std::ofstream disassemblyTraceOut;

    VOID TraceInst(INS ins, VOID* v)
    {
        ADDRINT addr = INS_Address(ins);

        // Verifica��o para instrumentar apenas o execut�vel principal, se aplic�vel
        if (instrumentOnlyMain && !IsMainExecutable(addr)) {
            return;
        }

        std::string disassembledInstr = INS_Disassemble(ins);

        if (KnobDisassembly) {
            disassemblyTraceOut << INS_Address(ins) << " | " << disassembledInstr << std::endl;
        }
    }

    VOID Fini(INT32 code, VOID* v)
    {
        if (KnobDisassembly && disassemblyTraceOut.is_open()) {
            disassemblyTraceOut.close();
        }
    }

    int InitTraceDisassembly(std::string pid, std::string filename)
    {
        if (KnobDisassembly) {
            filename += "." + pid + ".disassembly.cdf";
            disassemblyTraceOut.open(filename.c_str());
            disassemblyTraceOut << std::hex << std::right;
            disassemblyTraceOut.setf(std::ios::showbase);
        }

        INS_AddInstrumentFunction(TraceInst, 0);
        PIN_AddFiniFunction(Fini, 0);

        return 0;
    }


}
