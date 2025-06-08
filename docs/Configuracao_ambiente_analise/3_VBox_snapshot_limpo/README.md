### Criar um snapshot “limpo” no VirtualBox

Snapshot é essencial para restaurar rapidamente o estado da VM antes de cada amostra de *malware*.  
Siga os passos a seguir:

---

#### 1. Abrir a guia *Snapshots*

* Selecione a VM desejada.  
* Clique no ícone **Criar** (ou use *Snapshot → Criar*).

<p align="center">
  <img src="01.png" alt="Botão Criar snapshot no VirtualBox" width="75%">
</p>

---

#### 2. Definir nome e (opcional) descrição

* No campo **Nome do Snapshot**, digite algo como **Ambiente Limpo**.  
* (Opcional) Adicione uma descrição — ex.: “Windows recém-instalado, sem amostras”.  
* Clique em **OK**.

<p align="center">
  <img src="02.png" alt="Janela Criar Snapshot" width="75%">
</p>

---

#### 3. Aguardar a conclusão

* O VirtualBox exibirá a barra de progresso em “Criando snapshot…”.  
* Aguarde até chegar a 100 %.

<p align="center">
  <img src="03.png" alt="Progresso de criação do snapshot" width="75%">
</p>

---

> 💡 **Dica:** crie snapshots incrementais antes de cada lote de testes — a restauração é quase instantânea e evita contaminação cruzada entre amostras.

[Voltar para a documentação principal](https://github.com/contradef/Contradef?tab=readme-ov-file#815-criar-snapshot-da-vm-limpa-ver-detalhes)
