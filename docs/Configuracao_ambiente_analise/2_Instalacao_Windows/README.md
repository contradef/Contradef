## Instalar o Windows na VM

> As telas abaixo seguem a sequência típica de instalação do Windows 10 em uma máquina virtual recém-criada.  
> Ajuste idioma, região e tamanho de disco conforme sua preferência.

---

### 1 Selecionar idioma e formato

* Escolha **Idioma a instalar**, **Formato de hora e moeda** e **Teclado**.  
* Clique em **Avançar**.

<p align="center">
  <img src="01.png" alt="Janela inicial do instalador - seleção de idioma" width="75%">
</p>

---

### 2 Iniciar a instalação

* Clique em **Instalar agora**.

<p align="center">
  <img src="02.png" alt="Botão Instalar agora" width="75%">
</p>

---

### 3 Aceitar o contrato de licença

* Marque **Aceito os termos de licença**.  
* Clique em **Avançar**.

<p align="center">
  <img src="03.png" alt="Termos de licença do Windows" width="75%">
</p>

---

### 4 Tipo de instalação

* Selecione **Personalizada: instalar apenas o Windows (avançado)**.

<p align="center">
  <img src="04.png" alt="Escolha do tipo de instalação personalizada" width="75%">
</p>

---

### 5 Selecionar partição

* Escolha o espaço não alocado (ou a partição desejada).  
* Clique em **Avançar**.

<p align="center">
  <img src="05.png" alt="Seleção de partição para instalar" width="75%">
</p>

_Recomendado: usar o disco virtual inteiro criado na etapa de hardware (ex.: 200 GB)._

---

### 6 Cópia e preparação dos arquivos

* Aguarde a etapa de **Instalando o Windows** ser concluída; a VM reiniciará automaticamente. Caso não aconteça, reinicie manualmente.

<p align="center">
  <img src="06.png" alt="Barra de progresso da instalação" width="75%">
</p>

---

### 7 Configurar região

* Selecione o país/região (ex.: **Brasil**).  
* Clique em **Sim**.

<p align="center">
  <img src="07.png" alt="Seleção de região no OOBE" width="75%">
</p>

---

### 8 Layout do teclado

* Escolha o layout principal (ex.: **Português (Brasil ABNT)**).  
* Clique em **Sim**.

<p align="center">
  <img src="08.png" alt="Seleção de layout de teclado" width="75%">
</p>

---

### 9 Adicionar segundo layout

* Clique em **Pular** para manter apenas um layout (ou **Adicionar layout** se desejar outro).

<p align="center">
  <img src="09.png" alt="Opcional - adicionar segundo layout de teclado" width="75%">
</p>

---

### 10 Usar conta local

* Digite um endereço fictício qualquer como **user@user.com** e clique em **Avançar**.

<p align="center">
  <img src="10.png" alt="Tela de login ou criação de conta Microsoft" width="75%">
</p>

* O instalador mostrará o link **Configure o Windows com uma conta local**;
  Clique nesse link para prosseguir sem conta Microsoft.

<p align="center">
  <img src="11.png" alt="Opção para configurar conta local" width="75%">
</p>

---

### 11 Nome do usuário

* Informe o nome de usuário local (ex.: **analista**).  
* Clique em **Avançar**.

<p align="center">
  <img src="12.png" alt="Definir nome de usuário local" width="75%">
</p>

---

### 12 Definir senha

* Crie uma senha para o usuário local ou deixe em branco se preferir.  
* Clique em **Avançar**.

<p align="center">
  <img src="13.png" alt="Criar senha do usuário" width="75%">
</p>

---

### 13 Privacidade — Localização

* Selecione **Não** para negar acesso à sua localização.  
* Clique em **Aceitar**.

<p align="center">
  <img src="14.png" alt="Permitir localização — selecionar Não" width="75%">
</p>

---

### 14 Privacidade — Localizar meu dispositivo

* Selecione **Não**.  
* Clique em **Aceitar**.

<p align="center">
  <img src="15.png" alt="Localizar meu dispositivo — selecionar Não" width="75%">
</p>

---

### 15 Privacidade — Dados de diagnóstico

* Marque **Enviar dados de diagnóstico necessários** (mínimo).  
* Clique em **Aceitar**.

<p align="center">
  <img src="16.png" alt="Enviar apenas dados de diagnóstico necessários" width="75%">
</p>

---

### 16 Privacidade — Escrita à tinta e digitação

* Selecione **Não** para não enviar dados de digitação.  
* Clique em **Aceitar**.

<p align="center">
  <img src="17.png" alt="Aprimorar escrita à tinta e digitação — selecionar Não" width="75%">
</p>

---

### 17 Privacidade — Experiências personalizadas

* Selecione **Não** para desativar recomendações personalizadas.  
* Clique em **Aceitar**.

<p align="center">
  <img src="18.png" alt="Experiências personalizadas — selecionar Não" width="75%">
</p>

---

### 18 Privacidade — ID de anúncio

* Selecione **Não** para impedir que apps usem um ID de anúncio.  
* Clique em **Aceitar**.

<p align="center">
  <img src="19.png" alt="Permitir que apps usem ID de anúncio — selecionar Não" width="75%">
</p>

---

### 19 Cortana

* Na tela **Deixe a Cortana ajudar você em suas tarefas**, clique em **Agora não**.

<p align="center">
  <img src="20.png" alt="Desativar Cortana — selecionar Agora não" width="75%">
</p>

---

Após essas etapas de conta e privacidade, o Windows concluirá a configuração e carregará a área de trabalho inicial. 

<p align="center">
  <img src="21.png" alt="Instalação Concluída" width="75%">
</p>

Faça um snapshot neste ponto para preservar um estado limpo antes de instalar ferramentas e amostras.

[Voltar para a documentação principal](https://github.com/contradef/Contradef?tab=readme-ov-file#5-instalar-o-windows-na-vm-ver-detalhes)