#include "Instrumentation.h"

PIN_LOCK lock;

Notifier globalNotifier;
static std::ofstream MainOutFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "contradef", "specify file name for output logs ");
KNOB<string> KnobYaraRulesFile(KNOB_MODE_WRITEONCE, "pintool", "y", "", "specify file name for YARA rules ");
KNOB<BOOL> KnobAllowAttachDebugger(KNOB_MODE_WRITEONCE, "pintool", "ad", "0", "Allow attach debugger ");

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


VOID GetSectionInfo(IMG img, std::ofstream& MainOutFile)
{
    MainOutFile << std::endl << "[+] Informação de seções..." << std::endl;
    MainOutFile << "    Nome da imagem: " << std::string(IMG_Name(img)) << std::endl;

    // Índice da seção
    int index = 0;

    // Itera sobre as seções da imagem
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec), ++index)
    {
        std::string secName = SEC_Name(sec);
        secName = secName.empty() ? "[VAZIO]" : secName;
        ADDRINT secAddr = SEC_Address(sec);
        UINT64 secSize = SEC_Size(sec);

        MainOutFile << "    Seção [" << index << "]" << std::endl;
        MainOutFile << "        Nome da seção: " << secName << std::endl;
        MainOutFile << "        Endereço: 0x" << std::hex << static_cast<uint64_t>(secAddr) << std::dec << std::endl;
        MainOutFile << "        Tamanho: " << static_cast<uint64_t>(secSize) << " bytes" << std::endl;

        MainOutFile << "        Características: " << std::endl;
        if (SEC_IsExecutable(sec))
        {
            MainOutFile << "            A seção é executável." << std::endl;
        }
        if (SEC_IsReadable(sec))
        {
            MainOutFile << "            A seção é legível." << std::endl;
        }
        if (SEC_IsWriteable(sec))
        {
            MainOutFile << "            A seção é gravável." << std::endl;
        }
    }

    MainOutFile << "[*] Concluído" << std::endl << std::endl;

    MainOutFile.flush();  // Esvazia o buffer de saída
}

// TODO: Transferir para o detector de seq de inst
VOID TraceInstSeq(INS ins, VOID* v)
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

int InitInstrumentation()
{
    testSequences(seq_detector, disassembly_seq_detector);

    // Recuperar o valor do caminho do arquivo YARA
    std::string yaraRulesPath = KnobYaraRulesFile.Value();
    if (yaraRulesPath.empty())
    {
        //std::cerr << "Por favor, forneça o caminho para o arquivo de regras YARA usando -y." << std::endl;
        //return 1;
    }


    // Criando observadores dinamicamente com o contexto nulo
    auto* executionCompleted = new Observer(HandleExecutionCompletedEvent, NULL);
    // Anexa os observers ao notificador
    globalNotifier.Attach(executionCompleted);


    // Obter o PID do Processo
    string pid = decstr(WindowsAPI::getpid());


    // Log Principal
    string logsName = KnobOutputFile.Value();
    string logfilename = logsName + "." + pid + ".log.cdf";
    MainOutFile.open(logfilename.c_str(), std::ios::binary);


    // Iniciar detector de sequencia de instruções
    seq_detector.Initialize();
    disassembly_seq_detector.Initialize();


    // Iniciar o PIN e instrumentação
    PIN_InitSymbols();

    IMG_AddInstrumentFunction(InstrumentFunctionInterceptor, 0);

    //INS_AddInstrumentFunction(TraceInstSeq, 0);

    TraceInstructions::InitTrace(pid, logsName);

   // TraceDisassembly::InitTraceDisassembly(pid, logsName);

    //TraceMemory::InitMemoryTrace(pid, logsName);

    TraceFcnCall::InitFcnCallTrace(pid, logsName);


    if (KnobAllowAttachDebugger)
    {
        IMG_AddInstrumentFunction(InitPauseAtEntryPoint, nullptr);
    }

    PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

    PIN_StartProgram();
    return 0;
}