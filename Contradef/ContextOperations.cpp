#include "ContextOperations.h"

// From regval.cpp
static void PrintRegisters(CONTEXT* ctxt)
{
    static const UINT stRegSize = REG_Size(REG_ST_BASE);
    for (int reg = (int)REG_GR_BASE; reg <= (int)REG_GR_LAST; ++reg)
    {
        // For the integer registers, it is safe to use ADDRINT. But make sure to pass a pointer to it.
        ADDRINT val;
        PIN_GetContextRegval(ctxt, (REG)reg, reinterpret_cast<UINT8*>(&val));
        std::cout << REG_StringShort((REG)reg) << ": 0x" << std::hex << val << std::endl;
    }
    for (int reg = (int)REG_ST_BASE; reg <= (int)REG_ST_LAST; ++reg)
    {
        // For the x87 FPU stack registers, using PINTOOL_REGISTER ensures a large enough buffer.
        PINTOOL_REGISTER val;
        PIN_GetContextRegval(ctxt, (REG)reg, reinterpret_cast<UINT8*>(&val));
        std::cout << REG_StringShort((REG)reg) << ": " << Val2Str(&val, stRegSize) << std::endl;
    }
}


VOID SetZfToOne(CONTEXT* ctxt)
{
    // Obter os flags atuais
    ADDRINT flags = PIN_GetContextReg(ctxt, REG_RFLAGS);

    // Verificar o valor atual do ZF
    BOOL zf_before = (flags & (1 << 6)) != 0;

    if (zf_before == 0) {

        // Para setar o ZF para 1:
        flags |= (1 << 6); // Seta o bit 6 (ZF) para 1

        // Atualizar os flags
        PIN_SetContextReg(ctxt, REG_RFLAGS, flags);

        PIN_ExecuteAt(ctxt);
    }

}

VOID SetZfToZero(CONTEXT* ctxt)
{
    // Obter os flags atuais
    ADDRINT flags = PIN_GetContextReg(ctxt, REG_RFLAGS);

    // Verificar o valor atual do ZF
    BOOL zf_before = (flags & (1 << 6)) != 0;

    if (zf_before == 1) {

        // Para setar o ZF para 0:
        flags &= ~(1 << 6); // Limpa o bit 6 (ZF) para 0

        // Atualizar os flags
        PIN_SetContextReg(ctxt, REG_RFLAGS, flags);

        PIN_ExecuteAt(ctxt);
    }

}

// Função que redireciona a execução para o endereço de destino
void JumpToAddress(CONTEXT* ctxt, ADDRINT destAddr)
{
    // Redireciona a execução para o endereço destino
    PIN_SetContextReg(ctxt, REG_INST_PTR, destAddr);
    PIN_ExecuteAt(ctxt);
}

/*
Em Assembly x86 / x86 - 64, os** saltos condicionais** são instruções que alteram o fluxo de execução com base no estado de certos** flags** no** registrador de flags** (**EFLAGS** em x86 e** RFLAGS** em x86 - 64).Esses flags são alterados por operações aritméticas, lógicas e de comparação.

-- -

### ✅ * *Principais Flags que Afetam os Saltos Condicionais * *
Os seguintes * *flags * *afetam diretamente os * *jump conditions * *(saltos condicionais) :

    | **Flag * *| **Nome * *| **Descrição * *|
    |---------- | -------------------------- | --------------|
    | **ZF * *| Zero Flag | Indica que o resultado de uma operação foi * *zero * *. |
    | **SF * *| Sign Flag | Indica que o resultado de uma operação foi * *negativo * *(bit mais significativo = 1). |
    | **CF * *| Carry Flag | Indica um * *overflow em operações de adição / subtração * *(carry - out do bit mais significativo em soma ou borrow em subtração). |
    | **OF * *| Overflow Flag | Indica um * *overflow de sinal * *em operações de soma / subtração(quando um resultado não cabe no número de bits disponíveis). |
    | **PF * *| Parity Flag | Indica se o número de bits * *1 * *no resultado é * *par * *. |
    | **AF * *| Auxiliary Carry Flag | Usado em operações de BCD(não muito relevante para saltos condicionais). |

    -- -

    ### ✅ * *Tabela de Saltos Condicionais e Flags Associadas * *
    Os saltos condicionais usam esses flags para decidir se o salto ocorre ou não.

    #### * *🔹 Saltos Baseados no Zero Flag(ZF) * *
    | **Instrução * *| **Condição * *| **Quando é usado ? **|
    |-------------- | ------------ - | --------------------|
    | `JE` / `JZ` | **ZF = 1 * *| Salta se o resultado for zero(ex: `CMP EAX, EBX`). |
        | `JNE` / `JNZ` | **ZF = 0 * *| Salta se o resultado * *não * *for zero. |

        #### * *🔹 Saltos Baseados no Sign Flag(SF) * *
        | **Instrução * *| **Condição * *| **Quando é usado ? **|
        |-------------- | ------------ - | --------------------|
        | `JS` | **SF = 1 * *| Salta se o número for** negativo** . |
        | `JNS` | **SF = 0 * *| Salta se o número for** positivo** . |

        #### * *🔹 Saltos Baseados no Carry Flag(CF) * *
        | **Instrução * *| **Condição * *| **Quando é usado ? **|
        |-------------- | ------------ - | --------------------|
        | `JC` | **CF = 1 * *| Salta se houve um carry / overflow em soma / subtração(útil para comparação de números sem sinal). |
        | `JNC` | **CF = 0 * *| Salta se * *não * *houve carry. |

        #### * *🔹 Saltos Baseados no Overflow Flag(OF) * *
        | **Instrução * *| **Condição * *| **Quando é usado ? **|
        |-------------- | ------------ - | --------------------|
        | `JO` | **OF = 1 * *| Salta se ocorreu * *overflow de sinal * *. |
        | `JNO` | **OF = 0 * *| Salta se * *não * *ocorreu overflow. |

        #### * *🔹 Saltos para Comparação de Valores sem Sinal(Unsigned) * *
        | **Instrução * *| **Condição * *| **Quando é usado ? **|
        |-------------- | ------------ - | --------------------|
        | `JA` / `JNBE` | **(CF = 0) & (ZF = 0) * *| Salta se * *acima * *(A)em comparação sem sinal. |
        | `JAE` / `JNB` | **CF = 0 * *| Salta se * *acima ou igual * *(AE)em comparação sem sinal. |
        | `JB` / `JNAE` | **CF = 1 * *| Salta se * *abaixo * *(B)em comparação sem sinal. |
        | `JBE` / `JNA` | **(CF = 1) OR(ZF = 1) * *| Salta se * *abaixo ou igual * *(BE)em comparação sem sinal. |

        #### * *🔹 Saltos para Comparação de Valores com Sinal(Signed) * *
        | **Instrução * *| **Condição * *| **Quando é usado ? **|
        |-------------- | ------------ - | --------------------|
        | `JG` / `JNLE` | **(ZF = 0) & (SF = OF) * *| Salta se * *maior * *(G)em comparação com sinal. |
        | `JGE` / `JNL` | **SF = OF * *| Salta se * *maior ou igual * *(GE)em comparação com sinal. |
        | `JL` / `JNGE` | **SF ≠ OF * *| Salta se * *menor * *(L)em comparação com sinal. |
        | `JLE` / `JNG` | **(ZF = 1) OR(SF ≠ OF) * *| Salta se * *menor ou igual * *(LE)em comparação com sinal. |

        -- -

        ### ✅ * *Exemplo Prático : Comparação de Dois Números * *
        ```asm
        mov eax, 10; EAX = 10
        mov ebx, 20; EBX = 20
        cmp eax, ebx; Compara EAX com EBX
        jl menor; Se EAX < EBX, salta para "menor"
        ```
        * *Explicação:**
        -`CMP` faz `EAX - EBX` (`10 - 20 = -10`).
            - Como `-10` é negativo, **SF = 1 * *e * *OF = 0 * *, então `SF ≠ OF`.
            - `JL` (`Jump if Less`) verifica `SF ≠ OF`, então o salto ocorre.

                -- -

                ### 🎯 * *Resumo Final * *
                -**ZF(Zero Flag) * *→ Usado para verificar igualdade(`JE/JNE`).
                    - **SF(Sign Flag) * *→ Indica se um resultado é negativo(`JS/JNS`).
                        - **CF(Carry Flag) * *→ Usado para comparação sem sinal(`JA/JB`).
                            - **OF(Overflow Flag) * *→ Usado para comparação com sinal(`JG/JL`).
                                - **PF(Parity Flag) * *→ Pouco usado, mas verifica paridade de bits(`JP/JNP`).

                                    Se precisar de mais detalhes ou exemplos específicos, me avise!🚀
*/