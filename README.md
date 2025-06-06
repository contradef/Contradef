# Contradef – pintool para investigação de executáveis Windows (x64)

**Contradef** é uma *pintool* construída sobre o Intel Pin cujo objetivo principal é analisar _malware_ evasivo em ambiente Windows 64 bits.  
Embora possua contramedidas específicas para técnicas de _anti-analysis_ (anti-debug, anti-VM, anti-instrumentation), **também pode ser empregada na análise de executáveis legítimos** sempre que se deseje observar (ou manipular) o comportamento em tempo de execução com alta granularidade.

---

## Características principais
* **FunctionInterceptor** — *hooking* seletivo de mais de 100 APIs sensíveis (p. ex. `GetProcAddress`, `VirtualProtect`, `NtQueryInformationProcess`), registrando parâmetros e valor de retorno.  
* **TraceFcnCall** — dois métodos complementares para registrar chamadas:  
  1. instruções `call` convencionais;  
  2. saltos indiretos obtidos em tempo de execução (`GetProcAddress`, `LoadLibrary`, etc.).  
  A combinação é necessária porque _malwares_ protegidos alternam entre os dois esquemas para mascarar APIs críticas.
* **TraceMemory** — log de leituras/escritas (até 16 bytes) com auto-detecção de _strings_ ASCII/Unicode, alerta de transição RW → RX (indício de desempacotamento) e exibição de dados decifrados (URLs C2, chaves, nomes de janela…).
* **TraceInstructions / TraceDisassembly** — registro sequencial de cada instrução executada, valores de registradores, *flags* e operandos imediatos; essencial para reconstituir o fluxo em binários ofuscados.
* **Análise estática opcional com YARA** — o parâmetro `-yara <regras.yar>` aponta um arquivo de regras; detecções prévias podem **ajustar automaticamente o escopo** dos módulos (p. ex. ativar apenas *hooks* de interesse em binários UPX, VMProtect etc.).  
  *Esta funcionalidade não foi necessária durante os experimentos.*

---

## Arquitetura da ferramenta

<p align="center">
  <img src="docs/Contradef-Arquitetura.png" alt="Arquitetura da Contradef" width="75%">
</p>

| Componente | Função resumida |
|------------|-----------------|
| **Instrumentation** | Núcleo que injeta *callbacks* em tempo de execução e despacha eventos para os módulos especializados. |
| **TraceMemory / TraceInstructions / TraceFcnCall / TraceDisassembly** | Módulos de coleta responsáveis, respectivamente, por acessos à memória, instruções executadas, chamadas de função e trechos desassemblados. Todos gravam resultados em **arquivos de log** independentes. |
| **FunctionInterceptor** | Implementa *hooking* seletivo de APIs sensíveis, redirecionando parâmetros e retornos ao respectivo arquivo de log. |
| **Instrumentation Strategy + Strategies** | Conjunto de regras de instrumentação que pode ser ativado ou trocado em tempo de execução (p. ex. interceptar apenas `GetWindowTextA`, `GetWriteWatch` etc.). |
| **Yara Lib** | Integração opcional para escanear o binário antes da execução; detecções podem definir quais estratégias ou módulos serão habilitados. |
| **Notifier → Observer** | Implementa o padrão *publish/subscribe*, permitindo que estratégias gerem eventos que serão registrados nos logs. |
| **Arquivos de log** | Ponto de convergência dos *traces*; cada módulo escreve no seu próprio arquivo, facilitando a correlação posterior. |

A natureza modular da Contradef permite ativar apenas os blocos necessários sem recompilar o restante da ferramenta.

---

## Compilação

> ⚠️ **Observação:** não é necessário compilar para reproduzir os experimentos; um binário pronto encontra-se em `Contradef-main\Ambiente_Experimentacao\ContradefDll`.  
> Caso você queira compilar a ferramenta a partir do código-fonte, siga as instruções abaixo.

Contradef exige C++11 (compatível com a STLport incluída no Pin).

```text
Requisitos
• Visual Studio 2019 (recomendado) ou 2022  
• Intel Pin 3.28  
• Windows 10 SDK
````

```console
# Clonar o repositório
git clone https://github.com/contradef/Contradef.git
cd Contradef-main
```

> Ao abrir a solução no VS 2022, **não atualize** o “Conjunto de Ferramentas da Plataforma”; mantenha **Visual Studio 2019 (v142)** para garantir compatibilidade com o Pin.

1. Abra `Contradef.sln`.
2. Selecione **x64 / Debug**.
3. Compile (`Ctrl + Shift + B`).
4. O binário `contradef.dll` será gerado em `x64\Debug\`.

---

## Execução

### Parâmetros comuns

| Parâmetro         | Descrição                                             |
| ----------------- | ----------------------------------------------------- |
| `-intercept_fcn`  | Ativa o **FunctionInterceptor**                       |
| `-trace_exfcn`    | Ativa o **TraceFcnCall**                              |
| `-trace_mem`      | Ativa o **TraceMemory**                               |
| `-trace_instr`    | Ativa o **TraceInstructions**                         |
| `-trace_dasm`     | Ativa o **TraceDisassembly**                          |
| `-yara <arquivo>` | Aplica regras YARA antes da instrumentação (opcional) |

---

### Sintaxe básica

```powershell
<PATH_PIN_x64>\pin.exe -t <PATH_CONTRADEF>\contradef.dll -intercept_fcn -trace_exfcn -trace_mem -trace_instr -trace_dasm -- C:\Samples\alvo.exe
```

*Os arquivos de log são gravados no diretório atual do terminal.
Para outra pasta, forneça caminhos absolutos para `pin.exe` e `contradef.dll`.*

### Exemplo completo

```powershell
"C:\pin-3.28\intel64\bin\pin.exe" -t "C:\Contradef\x64\Debug\contradef.dll" -intercept_fcn -trace_exfcn -trace_mem -trace_instr -trace_dasm -- "C:\Samples\alvo.exe"
```

---

# Preparando o Ambiente de Experimentação

## 1. Ambiente de Execução Recomendado

Para instrumentar binários grandes e gerar *traces* volumosos com estabilidade, sugerimos a configuração abaixo (reduza proporcionalmente se o hardware for mais modesto):

| Camada              | Especificação recomendada |
|---------------------|---------------------------|
| **Máquina hospedeira** | • CPU multi-core com VT-x/AMD-V habilitado<br>• **RAM:** ≥ 32 GB<br>• **Armazenamento:** SSD NVMe ≥ 1 TB |
| **Hypervisor**      | Oracle **VirtualBox 7.0** (ou superior) |
| **Máquina virtual** | • **SO convidado:** Windows 10/11 Pro x64<br>• **vCPU:** ≥ 4 núcleos dedicados<br>• **RAM:** 6 – 8 GB<br>• **Disco:** 80 – 200 GB (VDI, tamanho fixo recomendado)<br>• **Snapshots:** estado base + checkpoints incrementais |

> **Por quê VirtualBox?** Suporte robusto a snapshots e VT-x/AMD-V, além de compatibilidade com Intel Pin.

---

## 2. Instalar o VirtualBox

1. Acesse <https://www.virtualbox.org/>  
2. Clique em **Download VirtualBox** para seu sistema operacional.  
3. Execute o instalador com as opções padrão.

---

## 3. Baixar a imagem ISO do Windows

* ISO de avaliação do **Windows 10 Enterprise x64**  
  <https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x416&culture=pt-br&country=BR>

* Outras opções (inclui Windows 11):  
  <https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise>

---

## 4. Criar a VM no VirtualBox \[[Ver detalhes](./docs/Configuracao_ambiente_analise/1_VirtualBox/)\]

1. **Máquina → Novo** → selecione *Windows 10/11 x64*.  
2. Aloque **4 – 8 GB de RAM**, **4 – 6 vCPUs** e **80 – 200 GB** de disco (VDI).  

---

## 5. Instalar o Windows na VM \[[Ver detalhes](./docs/Configuracao_ambiente_analise/2_Instalacao_Windows/)\]

1. Selecione a ISO como mídia de boot.  
2. Siga o assistente de instalação normalmente (idioma, partição, usuário).  

---

## 6. Criar snapshot da VM “limpa” \[[Ver detalhes](./docs/Configuracao_ambiente_analise/3_VBox_snapshot_limpo/)\]

* No VirtualBox, abra a guia **Snapshots** → **Criar** → nomeie como **Ambiente Limpo**.

---

## 7. Ajustes no Windows convidado (VM) \[[Ver detalhes](./docs/Configuracao_ambiente_analise/4_Configuração_Windows/)\]

1. **Instalar Guest Additions** (opcional para compartilhamento de pastas).  
2. **Baixar e descompactar o Contradef** (ZIP do GitHub).  
   Descompactar o arquivo no diretório `C:\Users\analista\Experimento`, assim, o diretório principal do repositório será `C:\Users\analista\Experimento\Contradef-main`.
   * *Depois de descompactar, o nome padrão da pasta do repositório será `Contradef-main`*
3. **Desativar “Proteção contra Violações”**:  
   * *Configurações → Atualização e Segurança → Segurança do Windows → Proteção contra vírus e ameaças → Gerenciar configurações → Proteção contra violações* → **Desativar**.  
4. **Acessar a pasta principal do repositório**:

    ```powershell
    cd "C:\Users\analista\Experimento\Contradef-main"
    ```

5. **Executar o script de desativação de Defender e UAC**:  
    ```text
    .\Scripts\desativar_defender_uac.bat  (executar como Administrador)
    ```

    Após a execução do script, **Reinicie a VM** quando solicitado.

6. **Criar snapshot “Base-Tools”** para preservar esse estado antes de iniciar testes reais.

---

# Reproduzindo os Experimentos \[[Ver detalhes](./docs/Configuracao_ambiente_analise/5_Execução_experimentos/)\]

A seguir apresentamos um roteiro mínimo para repetir os experimentos descritos no artigo.  

>## ⚠️ **Importante:** 
>    - Execute cada passo a seguir **somente dentro da VM de análise** para evitar comprometimento do host.
>    - Todos os comandos partem do diretório **`Ambiente_Experimentacao`** do repositório, ex.: `C:\Users\analista\Experimento\Contradef-main\Ambiente_Experimentacao`.

---

## 1. Preparação

1. **Instale o 7-Zip**  
   <https://www.7-zip.org/a/7z2409-x64.exe>
2. Extraia os arquivos `Ambiente_Experimentacao\Amostras\*.zip` na **mesma pasta** usando a senha `infected`.  
3. **Desative a rede da VM** antes de executar qualquer amostra com a Contradef.

### Estrutura de pastas esperada

```text
Contradef-main                 → diretório principal do repositório
├── pin\                       → binários originais do Pin 3.28
└── Ambiente_Experimentacao\
    ├── ContradefDll\          → contradef.dll já compilado
    └── Amostras\              → amostras compactadas
        ├── 36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.zip     → amostra 1 (VMProtect)
        └── 0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.zip     → amostra 2 (Comportamento evasivo)
````

Após descompactar:

```text
Contradef-main\Ambiente_Experimentacao\Amostras\
├── 36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe         → amostra 1 (VMProtect)
└── 0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe         → amostra 2 (Comportamento evasivo)
```

---
## 2. Terminal de execução

**Abra o PowerShell como Administrador** (`Iniciar → digite “powershell” → clique com o botão direito → Executar como administrador`).

```powershell
cd "C:\Users\analista\Experimento\Contradef-main\Ambiente_Experimentacao"
```

> *Dica:* use aspas se o caminho contiver espaços.

* Todos os **logs** serão salvos no diretório de trabalho atual (`Ambiente_Experimentacao`). Se quiser separar execuções, crie uma subpasta antes de rodar os comandos, mude para a pasta e forneça caminhos absolutos para `pin.exe`, `contradef.dll` e para a amostra.
* ⚠️ **Restabeleça o snapshot limpo** após cada análise para evitar contaminação cruzada entre amostras.

---

## 3. Medição de tempo (opcional)

Use `Measure-Command` para cronometrar a execução do Pin/Contradef, Ex.:

```powershell
# Execmplo de medição de tempo com Measure-Command
Measure-Command {
    ..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_exfcn -- .\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe
}
```

---

## 4. Execução da Amostra 1 (VMProtect)

### 4.1 Módulos isolados

#### FunctionInterceptor:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -intercept_fcn -- .\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe
```

#### TraceFcnCall:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_exfcn -- .\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe
```

#### TraceMemory:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_mem -- .\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe
```

#### TraceInstructions:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_instr -- .\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe
```

#### TraceDisassembly:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_dasm -- .\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe
```

### 4.2 Execução completa

```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -intercept_fcn -trace_exfcn -trace_mem -trace_instr -trace_dasm -- .\Amostras\36685efcf34c7a7a6f6dd2e48199e4700b5ab8fe3945a50297703dd8daced74f.exe
```

---

## 5. Execução da Amostra 2 (Comportamento evasivo)

### 5.1 Módulos isolados

#### FunctionInterceptor:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -intercept_fcn -- .\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe
```

#### TraceFcnCall:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_exfcn -- .\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe
```

#### TraceMemory:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_mem -- .\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe
```

#### TraceInstructions:
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_instr -- .\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe
```

#### TraceDisassembly
```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -trace_dasm -- .\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe
```

### 5.2 Execução completa

```powershell
..\pin\intel64\bin\pin.exe -t .\ContradefDll\contradef.dll -intercept_fcn -trace_exfcn -trace_mem -trace_instr -trace_dasm -- .\Amostras\0f20b0c906f3ad95dbf75ed526b2fe4341fdf62ab8c971fc10e340091af75b3b.exe
```

---

## 6. Observações de desempenho

* Em hardware **bare-metal** com SSD/NVMe a geração de *logs* é significativamente mais rápida (I/O é o principal gargalo).
* Arquivos de até **2 GB** podem ser abertos no **VS Code**; para tamanhos maiores, utilize o **EmEditor** ([https://www.emeditor.com/](https://www.emeditor.com/)).

---

# Observações finais

* Os módulos da Contradef são **complementares**: dados de memória podem ser correlacionados com a linha temporal de chamadas e o fluxo exato de instruções.
* Atualmente a ferramenta suporta **apenas executáveis PE 64-bit nativos**; não há suporte direto a .NET, Java ou scripts. Contribuições são bem-vindas!

