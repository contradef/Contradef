## Configurar o Windows convidado para análise

> As etapas abaixo partem de uma instalação “limpa” (snapshot) já concluída.
> Elas incluem: instalar **Guest Additions**, baixar o repositório e ajustar os itens de segurança
> que costumam interferir na instrumentação.

---

### 1 ▪ Instalar o VirtualBox Guest Additions (opcional)

> Habilita drivers de vídeo, sincronização de ponteiros e
> permite o compartilhamento de arquivos entre o sistema host (máquina física) e a máquina virtual (guest), 
> por meio do recurso chamado Shared Folders (Pastas Compartilhadas).
> Também possibilita o compartilhamento de área de transferência (que manteremos desativado por segurança).

> ⚠️ **Importante:** Instalar o VirtualBox Guest Additions é opcional. Use para compartilhar os resultado entre a máquina virtual (guest) e sistema host (máquina física) para análise.

1. No menu da VM, selecione **Dispositivos → Inserir imagem de CD dos Adicionais para Convidado…**  
   <p align="center"><img src="01.png" alt="Inserir imagem de CD Guest Additions" width="75%"></p>

2. Abra o **Este Computador** e clique duas vezes na unidade de CD _VirtualBox Guest Additions_.  
   <p align="center"><img src="02.png" alt="Unidade de CD Guest Additions" width="75%"></p>

3. Execute **VBoxWindowsAdditions.exe**.  
   <p align="center"><img src="03.png" alt="Executar VBoxWindowsAdditions" width="75%"></p>

4. Confirme o **Controle de Conta de Usuário** (UAC) clicando em **Sim**.  
   <p align="center"><img src="04.png" alt="UAC — confirmar Guest Additions" width="70%"></p>

5. Siga o assistente **Next → Next → Install** até o final.  
   <p align="center"><img src="05.png" alt="Assistente Guest Additions" width="70%"></p>

6. Marque **I want to manually reboot later** e clique em **Finish**.  
   <p align="center"><img src="06.png" alt="Finalizar instalação Guest Additions" width="70%"></p>

7. Reinicie a VM manualmente (**Iniciar → Reiniciar**) para aplicar os drivers.

---

### 2 ▪ Baixar o Contradef do repositório

1. Abra o repositório no GitHub e clique em **Code → Download ZIP**.  
   <p align="center"><img src="07.png" alt="GitHub — Download ZIP" width="75%"></p>

2. Quando o download terminar, clique em **Mostrar na pasta**.  
   <p align="center"><img src="08.png" alt="Mostrar download na pasta" width="75%"></p>

3. No Explorador de Arquivos, clique com o botão direito no ZIP e escolha **Extrair tudo…**.  
   <p align="center"><img src="09.png" alt="Extrair arquivo ZIP" width="75%"></p>

4. Na janela “Extrair Pastas Compactadas”, mantenha o destino padrão e clique em **Extrair**.  
   <p align="center"><img src="10.png" alt="Extrair pasta Contradef-main" width="75%"></p>

---

### 3 ▪ Ajustar “Proteção contra Violações”

1. Abra **Configurações → Atualização & Segurança → Segurança do Windows → Proteção contra vírus e ameaças**.  
2. Ir até **Proteção contra Violações** e desative o controle.  
   <p align="center"><img src="11.png" alt="Desativar Proteção contra Violações" width="75%"></p>

* **Tamper Protection** pode bloquear a desativação do Windows Defender, por isso é necessário desativar.

> ⚠️ **Importante:** mantenha esta alteração apenas dentro da VM isolada.

---

### 4 ▪ Desativar Defender, UAC e reiniciar (modo laboratório)

> **Somente** use estas configurações em VMs isoladas para pesquisa de malware.  
> Fora desse contexto, mantenha o antivírus e o UAC ativados.

---

#### 4.1 ▪ Executar o script de desativação do UAC e Windows Defender

1. Navegue até `Contradef-main\Scripts`.  
2. Clique com o botão direito em **desativar_defender_uac.bat** → **Executar como administrador**.  
   <p align="center"><img src="12.png" alt="Executar script como administrador" width="75%"></p>

3. Confirme o UAC clicando em **Sim**.  
   <p align="center"><img src="13.png" alt="Confirmar UAC" width="55%"></p>

4. O script exibirá mensagens indicando:  
   * Desativação do UAC.  
   * Desativação do Windows Defender.  
   * Desativação da proteção em tempo real.  
   <p align="center"><img src="14.png" alt="Saída do script" width="75%"></p>

5. Pressione qualquer tecla quando solicitado e **reinicie a VM** para aplicar as alterações.

---

#### 4.2 ▪ Verificar se o Defender foi desativado

1. Após o reboot, abra **Segurança do Windows → Proteção contra vírus e ameaças**.  
2. A mensagem **Nenhum provedor de antivírus ativo** deve aparecer.  
   <p align="center"><img src="15.png" alt="Defender desativado" width="65%"></p>

---

## 🚫 Limitações:

* Em **Windows 10/11 Home ou versões recentes**, o Defender **pode se reativar automaticamente**.
* O **UAC exige reinicialização** para refletir a mudança.

---

> ✅ A VM agora está pronta para instrumentação com o Intel Pin e execução de amostras, sem interferência do Defender ou do UAC.
  
Crie um novo snapshot (por exemplo, **Base-Tools**) para preservar esse estado antes de iniciar os testes com amostras reais.