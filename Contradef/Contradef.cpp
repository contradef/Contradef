#include "pin.H"
#include <iostream>
#include <string>
#include "YaraContradef.h"
#include "Instrumentation.h"

/// <summary>
/// Caso apresente falhas de compilação, alterar a versão do "Conjunto de Ferramentas da Plataforma" para "Visual Studio 2019 (v142)" nas propiedades do projeto
/// </summary>

INT32 Usage()
{
    cerr << "Esta ferramenta PIN fornece informação sobre possíveis comportamentos evasivos (antianálise) presentes em executáveis\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

int main(int argc, char* argv[]) {
    WindowsAPI::SetConsoleOutputCP(CP_UTF8);

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    InitInstrumentation();

    return 0;
}
