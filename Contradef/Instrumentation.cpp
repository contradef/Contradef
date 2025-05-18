#include "Instrumentation.h"

PIN_LOCK lock;

Notifier globalNotifier;
static std::ofstream MainOutFile;

FunctionInterceptor fcnInterceptor; // As estrat�gias j� est�o adicionadas no Interceptor

InstructionSequenceDetector seq_detector;
InstructionSequenceDetector disassembly_seq_detector;


// Fun��o para aguardar no Entry Point
VOID PauseAtEntryPoint(ADDRINT entryAddress) {
    std::cout << "[CONTRADEF] O Contradef pausou no entry point do processo (" << std::hex << entryAddress << ")" << std::endl;
    std::cout << "[CONTRADEF] Anexe o depurador ao processo agora." << std::endl;
    std::cout << "[CONTRADEF] Pressione Enter para continuar a execucao..." << std::endl;

    std::cin.get(); // Aguarda entrada do usu�rio para continuar
}


VOID GetSectionInfo(IMG img, std::ofstream& MainOutFile)
{
    MainOutFile << std::endl << "[+] Informa��o de se��es..." << std::endl;
    MainOutFile << "    Nome da imagem: " << std::string(IMG_Name(img)) << std::endl;

    // �ndice da se��o
    int index = 0;

    // Itera sobre as se��es da imagem
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec), ++index)
    {
        std::string secName = SEC_Name(sec);
        secName = secName.empty() ? "[VAZIO]" : secName;
        ADDRINT secAddr = SEC_Address(sec);
        UINT64 secSize = SEC_Size(sec);

        MainOutFile << "    Se��o [" << index << "]" << std::endl;
        MainOutFile << "        Nome da se��o: " << secName << std::endl;
        MainOutFile << "        Endere�o: 0x" << std::hex << static_cast<uint64_t>(secAddr) << std::dec << std::endl;
        MainOutFile << "        Tamanho: " << static_cast<uint64_t>(secSize) << " bytes" << std::endl;

        MainOutFile << "        Caracter�sticas: " << std::endl;
        if (SEC_IsExecutable(sec))
        {
            MainOutFile << "            A se��o � execut�vel." << std::endl;
        }
        if (SEC_IsReadable(sec))
        {
            MainOutFile << "            A se��o � leg�vel." << std::endl;
        }
        if (SEC_IsWriteable(sec))
        {
            MainOutFile << "            A se��o � grav�vel." << std::endl;
        }
    }

    MainOutFile << "[*] Conclu�do" << std::endl << std::endl;

    MainOutFile.flush();  // Esvazia o buffer de sa�da
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
        GetSectionInfo(img, MainOutFile);

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
                IARG_ADDRINT, entryPoint, // Endere�o do Entry Point
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
    std::wcout.imbue(std::locale("")); // Configura a sa�da wide para usar a codifica��o local
    std::cout.imbue(std::locale("")); // Configura a sa�da wide para usar a codifica��o local
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
    MainOutFile.flush();  // Esvazia o buffer de sa�da
}

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v) {
    std::cerr << "Exce��o detectada no thread " << tid << ": "
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


    // Log para o interceptador de fun��es
    string logsName = KnobOutputFile.Value();
    string logfilename = logsName + "." + pid + ".log.cdf";
    MainOutFile.open(logfilename.c_str(), std::ios::binary);


    // Iniciar o PIN e instrumenta��o
    PIN_InitSymbols();

    if (KnobSeqDetector) {
        // Iniciar detector de sequencia de instru��es
        AddTestSequences(seq_detector, disassembly_seq_detector);
        seq_detector.Initialize();
        disassembly_seq_detector.Initialize();
        INS_AddInstrumentFunction(InstrumentInstructionSeq, 0);
    }

    if (KnobSaveExternalCallTrace) {
        TraceFcnCall::InitFcnCallTrace(pid, logsName);
    }

    if (KnobTraceInterceptor) {
        IMG_AddInstrumentFunction(InstrumentFunctionInterceptor, 0);
    }

    if (KnobTraceInstructions) {
        TraceInstructions::InitTrace(pid, logsName);
    }

    if (KnobDisassembly) {
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