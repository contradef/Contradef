#include "pin.H"
#include <iostream>
#include <string>
#include "YaraContradef.h"
#include "Instrumentation.h"

/// <summary>
/// Caso apresente falhas de compila��o, alterar a vers�o do "Conjunto de Ferramentas da Plataforma" para "Visual Studio 2019 (v142)" nas propiedades do projeto
/// </summary>

INT32 Usage()
{
    cerr << "Esta ferramenta PIN fornece informa��o sobre poss�veis comportamentos evasivos (antian�lise) presentes em execut�veis\n"
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
