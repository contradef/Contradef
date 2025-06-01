#include "Instrumentation.h"
#include "HeapTracker.h"
#include "SectionTracker.h"

PIN_LOCK lock;

Notifier globalNotifier;
static std::ofstream MainOutFile;

FunctionInterceptor fcnInterceptor; // As estratégias já estão adicionadas no Interceptor

InstructionSequenceDetector seq_detector;
InstructionSequenceDetector disassembly_seq_detector;


// Função para aguardar no Entry Point
VOID PauseAtEntryPoint(ADDRINT entryAddress) {
    std::cout << "[CONTRADEF] O Contradef pausou no entry point do processo (" << std::hex << entryAddress << ")" << std::endl;
    std::cout << "[CONTRADEF] Anexe o depurador ao processo agora." << std::endl;
    std::cout << "[CONTRADEF] Pressione Enter para continuar a execucao..." << std::endl;

    std::cin.get(); // Aguarda entrada do usuário para continuar
}


// TODO: Transferir para o detector de seq de inst
VOID InstrumentInstructionSeq(INS ins, VOID* v)
{
    seq_detector.InstructionTrace(ins, &seq_detector, onCall);
    disassembly_seq_detector.InstructionTrace(ins, &disassembly_seq_detector, onDisassembly);
}


VOID InstrumentFunctionInterceptor(IMG img, VOID* v) {
    if (IMG_IsMainExecutable(img))
    {
        std::string execName = IMG_Name(img);
        std::string rules_file = KnobYaraRulesFile.Value();

        std::string yaraRulesPath = KnobYaraRulesFile.Value();
        if (!yaraRulesPath.empty())
        {
            std::vector<std::string> matched;
            RunYara(rules_file, execName, MainOutFile, matched);
            fcnInterceptor.scanScope.assign(matched.begin(), matched.end());
        }

        fcnInterceptor.InitStrategies();
    }

    fcnInterceptor.ExecuteAllStrategies(img, globalNotifier);
}

// Instrumenta o carregamento de imagens
VOID InitPauseAtEntryPoint(IMG img, VOID* v) {
    if (IMG_IsMainExecutable(img)) {
        ADDRINT entryPoint = IMG_EntryAddress(img); // IMG_Entry(img);
        std::cout << "[CONTRADEF] Executavel principal carregado: " << IMG_Name(img) << std::endl;
        //std::cout << "[CONTRADEF] Localizando Entry Point: " << std::hex << entryPoint << std::endl;

        PIN_LockClient();
        // Insere o callback para pausar no entry point
        RTN entryRtn = RTN_FindByAddress(entryPoint);
        if (RTN_Valid(entryRtn)) {
            RTN_Open(entryRtn);
            RTN_InsertCall(entryRtn, IPOINT_BEFORE, (AFUNPTR)PauseAtEntryPoint,
                IARG_ADDRINT, entryPoint, // Endereço do Entry Point
                IARG_END);
            RTN_Close(entryRtn);
        }
        else {
            std::cerr << "Falha ao localizar rotina no Entry Point." << std::endl;
        }
        PIN_UnlockClient();

    }
}


VOID configOutput() {
    using namespace WindowsAPI;
    std::setlocale(LC_ALL, "en_US.UTF-8"); // Definir o local adequado
    SetConsoleOutputCP(CP_UTF8); // Configura o console para UTF-8
    std::wcout.imbue(std::locale("")); // Configura a saída wide para usar a codificação local
    std::cout.imbue(std::locale("")); // Configura a saída wide para usar a codificação local
    MainOutFile.imbue(std::locale(""));
    MainOutFile << "\xEF\xBB\xBF"; // Adiciona BOM para indicar UTF-8
}

VOID HandleExecutionCompletedEvent(const EventData* data, void* context) {
    if (data->type != EventData::ExecutionCompleted) {
        return;
    }

    auto executionEvent = static_cast<const ExecutionEventData*>(data);
    auto executionOutputText = executionEvent->executionInformation.outputText;
    MainOutFile << executionOutputText;
    MainOutFile.flush();  // Esvazia o buffer de saída
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v) {
    std::cerr << "Exceção detectada no thread " << tid << ": "
        << PIN_ExceptionToString(pExceptInfo) << std::endl;
    exit(1);
    return EXCEPT_HANDLING_RESULT::EHR_HANDLED;
    // Pode-se modificar o contexto ou apenas registrar o erro
}

int InitInstrumentation() {

    // Criando observadores dinamicamente com o contexto nulo
    auto* executionCompleted = new Observer(HandleExecutionCompletedEvent, NULL);
    // Anexa os observers ao notificador
    globalNotifier.Attach(executionCompleted);


    // Obter o PID do Processo
    string pid = decstr(WindowsAPI::getpid());
    // Log para o interceptador de funções
    string logsName = KnobOutputFile.Value();


    // Iniciar o PIN e instrumentação
    PIN_InitSymbols();

    HeapTracker::Init();
    SectionTracker::Init(&globalNotifier);
    
    if (KnobFunctionInterceptor) {
        string logfilename = logsName + "." + pid + ".log.cdf";
        MainOutFile.open(logfilename.c_str(), std::ios::binary);
        IMG_AddInstrumentFunction(InstrumentFunctionInterceptor, 0);
    }

    if (KnobSeqDetector) {
        // Iniciar detector de sequencia de instruções
        AddTestSequences(seq_detector, disassembly_seq_detector);
        seq_detector.Initialize();
        disassembly_seq_detector.Initialize();
        INS_AddInstrumentFunction(InstrumentInstructionSeq, 0);
    }

    if (KnobTraceExternalCallTrace) {
        TraceFcnCall::InitFcnCallTrace(pid, logsName);
    }

    if (KnobTraceInstructions) {
        TraceInstructions::InitTrace(pid, logsName);
    }

    if (KnobTraceDisassembly) {
        TraceDisassembly::InitTraceDisassembly(pid, logsName);
    }

    if (KnobTraceMemory) {
        TraceMemory::InitMemoryTrace(pid, logsName);
    }

    if (KnobAllowAttachDebugger) {
        IMG_AddInstrumentFunction(InitPauseAtEntryPoint, nullptr);
    }

    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

    PIN_StartProgram();
    return 0;
}