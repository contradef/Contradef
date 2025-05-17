#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>

extern "C" __declspec(dllimport) void __stdcall Sleep(unsigned long dwMilliseconds);


using std::string;
using std::cerr;
using std::cout;
using std::wcout;
using std::wcerr;
using std::endl;
using std::flush;
using std::set;
using std::wstring;

typedef UINT64 HWND;   // HWND é normalmente um ponteiro ou um valor integral
typedef const wchar_t* LPCWSTR;  // Para LPCWSTR, use um ponteiro para wchar_t
typedef unsigned int UINT;   // UINT é um inteiro sem sinal


std::ofstream TraceFile;
set<string> functionsToIntercept;  // Lista de funções a serem interceptadas

string ExtractFileName(const std::string& fullPath) {
    size_t lastSlashPos = fullPath.find_last_of("\\/");
    if (lastSlashPos != std::string::npos) {
        return fullPath.substr(lastSlashPos + 1);
    }
    else {
        return fullPath; // Retorna o fullPath original se não houver separador de diretório
    }
}
const wchar_t* newText = L"Texto da mensage2";




VOID BeforeFunctionCall(ADDRINT* args) {
    // Suponha que você queira modificar o primeiro argumento da função
    ADDRINT* firstArgAddress = &args[3];

    cerr << "MessageBoxW interceptada: " << " - Mensagem original: " << (wchar_t*)*firstArgAddress << endl;
    wchar_t* message = reinterpret_cast<wchar_t*>((wchar_t*)*firstArgAddress); // Cast para wchar_t*
    cerr << "Mensagem interceptada2: " << message << endl;
    wstring wsMessage((wchar_t*)*firstArgAddress); // Converte wchar_t* para wstring
    cerr << " - Mensagem: " << std::string(wsMessage.begin(), wsMessage.end()) << std::endl;
    cerr << "Mensagem substituída: " << newText << endl;

    // Novo valor que você deseja escrever
    ADDRINT newValue = (ADDRINT)newText;

    // Escrevendo o novo valor de forma segura
    //PIN_SafeCopy(firstArgAddress, &newValue, sizeof(ADDRINT));
}


VOID BeforeMessageBoxWCall(ADDRINT hWnd, ADDRINT lpText, ADDRINT lpCaption, UINT uType)
{
    LPCWSTR originalText = reinterpret_cast<LPCWSTR>(lpText);
    LPCWSTR originalCaption = reinterpret_cast<LPCWSTR>(lpCaption);

    wstring wsOriginalText(originalText); 
    cout << "Original Text: " << std::string(wsOriginalText.begin(), wsOriginalText.end()) << std::endl;

    wstring wsOriginalCaption(originalCaption);
    cout << "Original Caption: " << std::string(wsOriginalCaption.begin(), wsOriginalCaption.end()) << std::endl;
}




VOID CallbackAfterMessageBoxW(ADDRINT* retValAddr)
{
    // Modifica o valor de retorno na pilha
    //*retValAddr = 4; // Substitua NovoValorDeRetorno pelo valor desejado
    cerr << "return value " << *retValAddr;

}

VOID CallbackBeforeMessageBoxW1(ADDRINT* lpText)
{
    // Verificar se o ponteiro não é NULL
    if (*lpText != 0) {
        wstring wsMessage((wchar_t*)*lpText);
        cerr << " - Mensagem: " << std::string(wsMessage.begin(), wsMessage.end()) << std::endl;
    }
    else {
        std::cout << "GetModuleHandleA será chamada com lpModuleName: NULL" << std::endl;
    }

}

VOID CallbackAfterRegQueryValueEx(ADDRINT* retValAddr)
{
    cout << "TESTESTES";
    //*retValAddr = 2;
}

VOID CallbackAfterRegOpenKeyExW(ADDRINT* retValAddr)
{
    cout << "RRRRRR";
    *retValAddr = 2;
}

VOID CallbackBeforeGetModuleHandleA(ADDRINT lpModuleName)
{
    // Verificar se o ponteiro não é NULL
    if (lpModuleName != 0) {
        // Converter de ADDRINT para LPCSTR
        const char* moduleNameStr = reinterpret_cast<const char*>(lpModuleName);

        // Acessar a string com segurança
        char moduleNameBuffer[256] = { 0 };
        PIN_SafeCopy(moduleNameBuffer, moduleNameStr, sizeof(moduleNameBuffer));

        std::cout << "GetModuleHandleA será chamada com lpModuleName: " << moduleNameBuffer << std::endl;
    }
    else {
        std::cout << "GetModuleHandleA será chamada com lpModuleName: NULL" << std::endl;
    }
}


VOID CallbackAfterGetModuleHandleA(ADDRINT* returnValue)
{
    //Sleep(5000);
    std::cout << "GetModuleHandleA retornou---: " << *returnValue << std::endl;
    //*returnValue = 0;
}

VOID InstrumentFunction(IMG img, VOID* v) {
    string moduleName = IMG_Name(img);
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
        RTN rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
        if (RTN_Valid(rtn) && RTN_IsSafeForProbedInsertion(rtn)) {
            string funcName = RTN_Name(rtn);
            string fileName = ExtractFileName(moduleName);
            string fullFunctionName = fileName + "::" + funcName;
            if (functionsToIntercept.find(fullFunctionName) != functionsToIntercept.end()) {
                cerr << "Funcao---->" << fullFunctionName << endl;
                if (fullFunctionName == "USER32.dll::MessageBoxW") {
                    cerr << "---->" << fullFunctionName << endl;
                    //RTN_InsertCallProbed(rtn, IPOINT_BEFORE, AFUNPTR(BeforeFunctionCall),
                    //    IARG_ADDRINT, RTN_Address(rtn),
                    //    IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Captura o segundo argumento (texto da mensagem)
                    //    IARG_END);
                    
                    PROTO protoMessageBoxW = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_STDCALL,
                        "MessageBoxW",
                        PIN_PARG(HWND),   // hWnd
                        PIN_PARG(LPCWSTR), // lpText
                        PIN_PARG(LPCWSTR), // lpCaption
                        PIN_PARG(UINT),   // uType
                        PIN_PARG_END());

                    RTN_InsertCallProbed(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfterMessageBoxW),
                        IARG_PROTOTYPE, protoMessageBoxW,
                        IARG_REG_REFERENCE, REG_GAX, // ou outro registrador conforme a convenção de chamada
                        IARG_END);

                    RTN_InsertCallProbed(rtn, IPOINT_BEFORE, AFUNPTR(CallbackBeforeMessageBoxW1),
                        IARG_REG_REFERENCE, REG_GDX, // ou outro registrador conforme a convenção de chamada
                        IARG_END);
                    //
                    //RTN_InsertCallProbed(rtn, IPOINT_BEFORE, AFUNPTR(BeforeMessageBoxWCall),
                    //    IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0, // Passa todos os argumentos
                    //    IARG_END);

                    PROTO_Free(protoMessageBoxW);

                } else if(fullFunctionName == "ADVAPI32.dll::RegQueryValueExW") {
                    cerr << "---->" << fullFunctionName << endl;
                    PROTO protoRegQueryValueEx = PROTO_Allocate(PIN_PARG(ADDRINT), CALLINGSTD_STDCALL,
                        "RegQueryValueExW",
                        PIN_PARG(ADDRINT),   // HKEY é tratado como ADDRINT
                        PIN_PARG(ADDRINT),   // LPCWSTR é tratado como ADDRINT (ponteiro)
                        PIN_PARG(ADDRINT),   // LPDWORD é tratado como ADDRINT (ponteiro)
                        PIN_PARG(ADDRINT),   // LPDWORD é tratado como ADDRINT (ponteiro)
                        PIN_PARG(ADDRINT),   // LPBYTE é tratado como ADDRINT (ponteiro)
                        PIN_PARG(ADDRINT),   // LPDWORD é tratado como ADDRINT (ponteiro)
                        PIN_PARG_END());
                    // Inserir a instrumentação com o protótipo
                    RTN_InsertCallProbed(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfterRegQueryValueEx),
                        IARG_PROTOTYPE, protoRegQueryValueEx,
                        IARG_REG_REFERENCE, REG_GAX, // ou outro registrador conforme a convenção de chamada
                        IARG_END);
                    PROTO_Free(protoRegQueryValueEx);

                } else if(fullFunctionName == "ADVAPI32.dll::RegOpenKeyExW") {
                    cerr << "---->" << fullFunctionName << endl;

                    PROTO protoRegOpenKeyExW = PROTO_Allocate(PIN_PARG(INT32), CALLINGSTD_STDCALL,
                        "RegOpenKeyExW",
                        PIN_PARG(ADDRINT),  // HKEY
                        PIN_PARG(ADDRINT),  // LPCWSTR
                        PIN_PARG(UINT32),   // DWORD
                        PIN_PARG(UINT32),   // REGSAM
                        PIN_PARG(ADDRINT),  // PHKEY
                        PIN_PARG_END());
                   
                    RTN_InsertCallProbed(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfterRegOpenKeyExW),
                        IARG_PROTOTYPE, protoRegOpenKeyExW,
                        IARG_REG_REFERENCE, REG_GAX, // ou outro registrador conforme a convenção de chamada
                        IARG_END);

                    PROTO_Free(protoRegOpenKeyExW);


                }
                else if (fullFunctionName == "KERNEL32.DLL::GetModuleHandleA") {
                    cerr << "---->" << fullFunctionName << endl;

                    PROTO protoGetModuleHandleA = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_STDCALL,
                        "GetModuleHandleA",
                        PIN_PARG(ADDRINT), // LPCSTR como ADDRINT
                        PIN_PARG_END());


                    RTN_InsertCallProbed(rtn, IPOINT_AFTER, AFUNPTR(CallbackAfterGetModuleHandleA),
                        IARG_PROTOTYPE, protoGetModuleHandleA,
                        IARG_REG_REFERENCE, REG_GAX, // ou outro registrador conforme a convenção de chamada
                        IARG_END);


                    PROTO_Free(protoGetModuleHandleA);

                } 
            }
        }

    }
}



VOID Before(UINT32 arg0, UINT32 arg1, UINT32 arg2, UINT32 arg3, UINT32 arg4, UINT32 arg5, UINT32 arg6, UINT32 arg7, UINT32 arg8,
    UINT32 arg9)
{
    cout << "Before: original arguments = ( " << arg0 << ", " << arg1 << ", " << arg2 << ", " << arg3 << ", " << arg4 << ", "
        << arg5 << ", " << arg6 << ", " << arg7 << ", " << arg8 << ", " << arg9 << " )" << endl
        << flush;
}

VOID After(ADDRINT retval) { cout << "After: return value = " << retval << endl << flush; }

/* ===================================================================== */
/* Instrumentation routines  */
/* ===================================================================== */

/* ===================================================================== */
VOID ImageLoad(IMG img, VOID* v) {
    string moduleName = IMG_Name(img);



    RTN rtn = RTN_FindByName(img, ("Bar10"));
    if (RTN_Valid(rtn))
    {
        PROTO proto = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT, "Bar10", PIN_PARG(int), PIN_PARG(int), PIN_PARG(int),
            PIN_PARG(int), PIN_PARG(int), PIN_PARG(int), PIN_PARG(int), PIN_PARG(int), PIN_PARG(int),
            PIN_PARG(int), PIN_PARG_END());

        if (RTN_InsertCallProbed(
            rtn, IPOINT_BEFORE, AFUNPTR(Before), IARG_PROTOTYPE, proto, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 7, IARG_FUNCARG_ENTRYPOINT_VALUE, 8, IARG_FUNCARG_ENTRYPOINT_VALUE, 9, IARG_END) &&
            RTN_InsertCallProbed(rtn, IPOINT_AFTER, AFUNPTR(After), IARG_PROTOTYPE, proto, IARG_REG_VALUE, REG_GAX, IARG_END))
        {
            ASSERTX(RTN_IsSafeForProbedInsertion(rtn));
            cout << "Inserting calls before/after Bar10 in " << IMG_Name(img) << endl;
        }
        else
        {
            cout << "Cannot insert calls around " << RTN_Name(rtn) << "() in " << IMG_Name(img) << endl;
            exit(1);
        }
        PROTO_Free(proto);
    }
}


VOID FillInterceptSet() {
    functionsToIntercept.insert("USER32.dll::MessageBoxW");
    functionsToIntercept.insert("ADVAPI32.dll::RegOpenKeyExW");
    functionsToIntercept.insert("ADVAPI32.dll::RegQueryValueExW");
    functionsToIntercept.insert("KERNEL32.DLL::GetModuleHandleA");
    functionsToIntercept.insert("KERNEL32.DLL::IsDebuggerPresent");
    functionsToIntercept.insert("KERNEL32.DLL::CheckRemoteDebuggerPresent");
    functionsToIntercept.insert("KERNEL32.DLL::OutputDebugString");
    functionsToIntercept.insert("KERNEL32.DLL::QueryPerformanceCounter");
    functionsToIntercept.insert("NTDLL.DLL::NtQueryInformationProcess");
    functionsToIntercept.insert("NTDLL.DLL::NtGlobalFlag");
    functionsToIntercept.insert("USER32.dll::BlockInput");
    functionsToIntercept.insert("USER32.dll::GetAsyncKeyState");
    functionsToIntercept.insert("USER32.dll::GetForegroundWindow");
    functionsToIntercept.insert("KERNEL32.DLL::GetTickCount");
}


int main(int argc, char* argv[]) {
    FillInterceptSet();

    // Inicializa o PIN
    PIN_Init(argc, argv);

    // Abre o arquivo de rastreamento
    TraceFile.open("TraceFile.txt");

    // Adiciona a rotina de instrumentação
    IMG_AddInstrumentFunction(InstrumentFunction, 0);

    // Inicia o programa
    PIN_StartProgramProbed();

    return 0;
}
