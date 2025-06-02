# Contradef – pintool para investigação de executáveis Windows (x64)

Contradef é uma **pintool** construída sobre o Intel Pin com o objetivo principal de analisar _malware_ evasivo em ambiente Windows 64 bits.  
Embora possua contramedidas específicas para técnicas _anti-analysis_ (anti-debug, anti-VM, anti-instrumentation), **também pode ser empregada na análise de qualquer executável legítimo**, sempre que se deseje observar (ou mesmo manipular) o comportamento em tempo de execução com alta granularidade.

---

## 1. Características principais
* **FunctionInterceptor** – _hooking_ seletivo de mais de 100 rotinas sensíveis (ex.: `GetProcAddress`, `VirtualProtect`, `NtQueryInformationProcess`) com registro de parâmetros e valor de retorno.  
* **TraceFcnCall** – dois métodos complementares para registrar chamadas:  
  1. instruções `call` convencionais;  
  2. saltos indiretos usando endereços obtidos em tempo de execução (`GetProcAddress`, `LoadLibrary`, etc.).  
  A combinação é necessária porque _malwares_ protegidos alternam entre os dois esquemas para mascarar APIs críticas.
* **TraceMemory** – log de leituras/escritas (até 16 bytes) com auto-detecção de _strings_ ASCII/Unicode, alerta de transição RW → RX (indício de desempacotamento) e exibição de dados decifrados (URLs C2, chaves, nomes de janelas…).
* **TraceInstructions / TraceDisassembly** – registro sequencial de cada instrução executada, valores de registradores, _flags_ e operandos imediatos; essencial para reconstituir o fluxo em binários ofuscados.
* **Análise estática opcional com YARA** – parâmetro `-yara <regras.yar>` permite apontar um arquivo de regras; detecções prévias servem para **ajustar automaticamente o escopo** dos módulos (ex.: ativar somente _hooks_ de interesse em binários UPX, VMProtect, etc.).

---

## 2. Arquitetura da Ferramenta

<p align="center">
  <img src="docs/Contradef-Arquitetura.png" alt="Arquitetura da Contradef" width="75%">
</p>

A figura acima resume o fluxo interno da **Contradef**:

| Componente (cor) | Função resumida |
|------------------|-----------------|
| **Instrumentation** <br>*(verde)* | Núcleo que injeta *callbacks* em tempo de execução e despacha eventos para os módulos especializados. |
| **TraceMemory / TraceInstructions / TraceFcnCall / TraceDisassembly** <br>*(laranja)* | Módulos de coleta: registram, respectivamente, acessos à memória, instruções executadas, chamadas de função e trechos desassemblados. Todos gravam resultados em **Arquivos Logs**. |
| **FunctionInterceptor** <br>*(laranja, à esquerda)* | Implementa *hooking* seletivo de APIs sensíveis, redirecionando parâmetros/retornos ao respectivo arquivo de log. |
| **Instrumentation Strategy + Strategies** <br>*(cinza)* | Camada de estratégias: regras de instrumentação que podem ser ativadas ou trocadas em tempo de execução (ex.: interceptar apenas `GetWindowTextA`, `GetWriteWatch`, etc.). |
| **Yara Lib** <br>*(cinza)* | Integração opcional para escanear o binário antes da execução; as detecções podem definir quais estratégias ou módulos serão habilitados. |
| **Notifier → Observer** <br>*(cinza)* | Implementa um padrão publicador-assinante (pub/sub), permitindo que qualquer estratégia consiga notificar o registro de um log que será salvo no arquivo. |
| **Arquivos Logs** <br>*(verde-claro)* | Ponto de convergência de todos os traces; cada módulo escreve em seu próprio arquivo para facilitar a correlação posterior. |

Esse desenho evidencia a natureza modular da Contradef: é possível ativar apenas os blocos necessários, sem recompilar o restante da ferramenta.

## 3. Instalação e clonagem do repositório
```console
git clone https://github.com/contradef/Contradef.git
cd <REPO>
```

## 4. Ambiente recomendado para testes
> **IMPORTANTE:** sempre execute amostras reais de _malware_ em ambiente isolado.

1. Crie uma VM no **VirtualBox** (snapshot limpo).  
```text
   • SO convidado: Windows 10/11 x64
   • Disco SSD (recomendado)  
   • Desative: Windows Defender e UAC  
   • Execute o CMD/PowerShell como Administrador
````

2. Copie o diretório do Pin (inclui o `pin.exe`), `contradef.dll` e a amostra para um diretório dentro da VM.
3. Após cada análise, **restaure o snapshot** para evitar contaminação cruzada.

---

## 5. Compilação

Contradef funciona no C++ 11 (compatível com a biblioteca STL Port usada no Pin).

```text
Requisitos:
  • Visual Studio 2019 ou 2022
  • Intel Pin 3.28
  • SDK Windows 10
```

> Mesmo abrindo o projeto no VS 2022, **não atualize** o “Conjunto de Ferramentas da Plataforma” – mantenha **Visual Studio 2019 (v142)** para compatibilidade com o Pin.

1. Abra `Contradef.sln`
2. Selecione **x64 / Debug**
3. Compile (`Ctrl + Shift + B`)
4. O binário resultante `contradef.dll` ficará em `bin\x64\Debug\`.

*Uma release está disponível no diretório* `ContradefDll` 

## 6. Ambiente de Execução Recomendado

Para obter desempenho estável ao instrumentar binários grandes e gerar *traces* volumosos, recomendamos a configuração a seguir (ajuste proporcionalmente caso seu hardware seja mais modesto):

| Camada            | Especificação sugerida |
|-------------------|------------------------|
| **Máquina hospedeira** | • CPU multi-core com suporte a VT-x/AMD-V <br>• **RAM:** ≥ 32 GB <br>• **Storage:** SSD NVMe ≥ 1 TB |
| **Hypervisor**    | Oracle **VirtualBox 7.0**   |
| **Máquina virtual** | • **SO convidado:** Windows 10/11 Pro x64 <br>• **vCPU:** ≥ 4 núcleos dedicados <br>• **RAM:** 6 – 8 GB <br>• **Disco:** 200 – 250 GB fixo, pré-alocado <br>• **Snapshots:** base limpa + checkpoint incremental |
| **Boas-práticas** | • Desative *shared clipboard* e *drag & drop* <br>• Redirecione logs para disco virtual secundário |


## 7. Parâmetros mais comuns

| Parâmetro         | Descrição                           |
| ----------------- | -------------------------------------------------------- |
| `-intercept_fcn`  | Ativa o **FunctionInterceptor** (hooking de APIs)        |
| `-trace_exfcn`    | Ativa o **TraceFcnCall**                                 |
| `-trace_mem`      | Ativa o **TraceMemory**                                  |
| `-trace_instr`    | Ativa o **TraceInstructions**                            |
| `-trace_dasm`     | Ativa o **TraceDisassembly**                             |
| `-yara <arquivo>` | Especifica regras YARA a aplicar antes da instrumentação |

*Para logs superiores a 2 GB recomenda-se abrir com o **EmEditor**.*

---

## 8. Sintaxe de execução

```powershell
<PATH_PIN>\pin.exe ^
  -t <PATH_CONTRADEF>\contradef.dll ^
  -intercept_fcn -trace_exfcn -trace_mem -trace_instr -trace_dasm ^
  -yara C:\regras\malware.yar ^
  -- C:\Samples\alvo.exe
```

*Os arquivos de log são gravados **no diretório atual do terminal**.
Deseja usar outra pasta? Forneça caminhos absolutos tanto para `pin.exe` quanto para `contradef.dll`.*

### Exemplo rápido de execução

```powershell
# Caminhos ilustrativos – ajuste aos seus diretórios
"C:\pin-3.28\pin.exe" ^
  -t "C:\Contradef\bin\x64\Release\contradef.dll" ^
  -intercept_fcn -trace_exfcn -trace_mem -trace_instr -trace_dasm ^
  -yara "C:\Regras\malware.yar" ^
  -- "C:\Samples\alvo.exe"
```
---

## 9. Reproduzindo os experimentos

A seguir encontra-se um roteiro mínimo para repetir os testes descritos no artigo, executado dentro da *guest* Windows 10 ×64 apresentada no tópico **Ambiente de Execução Recomendado**.
Todos os caminhos partem do diretório-raiz `C:\Experimentos` do repositório.

### Organização das pastas

```text
C:\Experimentos
 ├── pin\                   → binários originais do Pin 3.28
 ├── ContradefDll\          → contradef.dll já compilado (toolset v142)
 └── Amostras\              → amostras compactadas (.zip)
     ├── 36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.zip       → amostra 1 (VMProtect)
     └── 0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.zip       → amostra 2 (Themida)
```

### Descompactação das amostras

As amostras são distribuídas em `.zip` protegidos pela senha `infected` (padrão da comunidade de malware).

```powershell
cd C:\Experimentos\Amostras

# descompacta amostra 1
powershell -c "Expand-Archive -Path 36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.zip -DestinationPath . -Password infected"

# descompacta amostra 2
powershell -c "Expand-Archive -Path 0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.zip -DestinationPath . -Password infected"
```

Serão criados os executáveis:

* `36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe`
* `0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe`

### Execução exemplo — módulos leves

Intercepta APIs e grava o *trace* de chamadas externas na amostra 1:

```powershell
C:\Experimentos\pin\pin.exe `
  -t C:\Experimentos\ContradefDll\contradef.dll `
  -intercept_fcn -trace_exfcn -- `
  C:\Experimentos\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe
```

### Execução completa — todos os módulos

Executar todos os módulos na amostra 2:

```powershell
C:\Experimentos\pin\pin.exe `
  -t C:\Experimentos\ContradefDll\contradef.dll `
  -intercept_fcn -trace_exfcn -trace_mem `
  -trace_instr -trace_dasm -- `
  C:\Experimentos\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe
```

> **Nota:** os arquivos de saída são criados no diretório corrente.
> Se desejar manter resultados segregados, crie uma pasta por execução
> e invoque o comando dentro dela **ou** forneça caminhos absolutos para `pin.exe`,
> `contradef.dll` e o executável-alvo.

### Observações de desempenho

* O tempo de (\~ 36 min) da amostra 2 decorre de uma chamada
  `Sleep(2000000)`.
* Em hardware **bare-metal** ou em SSD/NVMe a coleta é consideravelmente mais rápida,
  pois o gargalo principal é a escrita de *logs*.
* Arquivos até **2 GB** abrem sem esforço no **Visual Studio Code**; arquivos maiores
  podem ser inspecionados com **EmEditor** ([https://www.emeditor.com/](https://www.emeditor.com/)).

Seguindo estes passos é possível replicar, com pequenas variações, os experimentos apresentados no estudo.

---

## 10. Observações finais

* Os módulos são **complementares**: dados de memória podem ser correlacionados com a linha temporal de chamadas e com o fluxo exato de instruções.
* O desempenho depende do perfil do alvo; use apenas os traços necessários ou condicione a ativação via detector de sequência.
* A ferramenta atualmente suporta **apenas executáveis PE 64-bit nativos**; não há suporte direto a .NET, Java ou scripts. Contribuições são bem-vindas!