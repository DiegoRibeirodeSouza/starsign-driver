# Passo a Passo: Engenharia Reversa do G&D StarSign CUT S

Este documento detalha o processo metodológico utilizado para quebrar as barreiras do middleware proprietário SafeSign e construir o driver de código aberto nativo para OpenSC. 
O objetivo deste guia é provar que a engenharia reversa de hardware criptográfico não exige a descompilação complexa de binários (como o uso do Ghidra ou IDA Pro), mas sim a **interceptação inteligente e análise comparativa de tráfego (Sniffing APDU)**.

---

## 1. O Ambiente de Interceptação: Fazendo o "Sniffing"

Quando lidamos com tokens Smartcard, toda a comunicação USB passa por um daemon do Linux chamado `pcscd` (PC/SC Smart Card Daemon).
Para descobrir como o driver proprietário falava com o token, precisávamos "escutar" essa conversa.

### Passo 1: Capturando os APDUs do Driver Proprietário
1. Pare o serviço oficial do pcscd que roda em background:
   ```bash
   sudo systemctl stop pcscd.socket pcscd.service
   ```
2. Inicie o pcscd em modo "foreground" (primeiro plano) com a flag mágica `--apdu`, que cospe todo o tráfego USB em hexadecimal na tela, e salve num arquivo:
   ```bash
   sudo pcscd --foreground --apdu 2>&1 | tee pcscd_apdu_log.txt
   ```
3. Em outro terminal, utilize a ferramenta `pkcs11-tool` para forçar o driver proprietário (`libaetpkss.so`) a fazer o login no token:
   ```bash
   pkcs11-tool --module /usr/lib/libaetpkss.so --list-objects --login
   ```
4. Finalize o `pcscd` pressionando `Ctrl+C`. O arquivo `pcscd_apdu_log.txt` conterá toda a conversa secreta.

---

## 2. Analisando o Tráfego e Descobrindo as Travas

Ao abrirmos o arquivo gerado e compararmos com o comportamento padrão documentado pelo padrão ISO-7816, notamos três grandes diferenças.

### Descoberta A: O "Handshake de Atestação" (Trava de Licenciamento)
Logo após a inicialização (ATR), vimos que o driver proprietário enviava uma APDU estranha, da classe `00 DA 01 00` (um comando `PUT DATA`). 
Ao convertermos o payload em hexadecimal (`49 20 61 6d...`) para ASCII, a mensagem era clara:
```text
I am A.E.T. Europe B.V. SafeSign or BlueX approved software.
```
**O Problema:** Sem receber exatamente essa frase de "senha" em texto puro, o applet do StarSign ignorava os próximos comandos de seleção de arquivos. O token literalmente exigia ser saudado pelo nome do software original.

### Descoberta B: Canais Lógicos Ocultos
O padrão ISO-7816 opera no canal `0` (indicado pelo primeiro byte da APDU, o `CLA = 00`).
Observamos no log que o SafeSign enviava o comando:
```text
00 70 00 00 01
```
Isso é um `MANAGE CHANNEL` pedindo para abrir um canal lógico alternativo. A partir desse momento, todas as APDUs capturadas do SafeSign passavam a começar com `01` (Ex: `01 A4...`). O applet forçava a comunicação a ocorrer em um canal isolado (Canal 1).

### Descoberta C: A Bizarra Anomalia do `SELECT FILE`
Quando o OpenSC (driver genérico) tenta ler um arquivo no smartcard, ele envia o comando `SELECT` padrão: `00 A4 00 00`. O parâmetro `P2=00` significa: *"Selecione o arquivo e me devolva o cabeçalho FCI com o tamanho do arquivo"*.
O G&D StarSign respondia a isso com silêncio ou erro.

Observando o log do SafeSign, reparamos que ele sempre enviava `P2=0x0C` (`01 A4 00 0C`). No protocolo ISO-7816, `0C` significa *"Selecione o arquivo, mas não me responda nada (No FCI expected)"*.
**O Problema:** Como o token não responde com o tamanho do arquivo, a função padrão do OpenSC assume que o arquivo tem **0 bytes**, impossibilitando a leitura dos certificados.

---

## 3. A Engenharia em Ação: Escrevendo o Driver em C

Com os três segredos na mão, a solução era escrever um driver (chamamos de `card-starsign.c`) embutido no OpenSC que imitasse esse comportamento.

1. **Injetando a Saudação (Handshake):**
   Na função `starsign_init`, forçamos a APDU `00 DA 01 00` contendo a string mágica ASCII, disparando-a duas vezes (conforme visto nos logs) antes de qualquer coisa.
2. **Forçando o Canal Lógico:**
   Logo após a saudação, enviamos a abertura do canal (`00 70 00 00 01`) e fixamos internamente no OpenSC que todas as próximas conversas devem usar o prefixo de canal `card->cla = 0x01`.
3. **Enganando o OpenSC no `SELECT FILE`:**
   Criamos a função customizada `starsign_select_file`. Nela, forçamos todas as seleções para usar `P2=0x0C`. E para o problema do "tamanho 0"? Injetamos uma gambiara elegante: dizemos ao OpenSC que o tamanho do arquivo é `0x8000` (gigante). A inteligência de baixo nível do OpenSC (`sc_read_binary`) começa a ler sem parar até atingir o fim real do arquivo, superando a falta do FCI.
4. **Customização de PIN e Assinatura:**
   Com os canais de leitura prontos, vimos que o comando MSE (Manage Security Environment) também era único (`84 01 01 80 01 02`). Sobrescrevemos `starsign_set_security_env` e forçamos um padding de 15 bytes no envio do PIN (`starsign_pin_cmd` com `P2=0x02`).

---

## 4. O Obstáculo Final: O Algoritmo RAW e a Morte do Java 8

Mesmo com o driver lendo perfeitamente, o **PJe Office** (do sistema judiciário) se recusava a assinar.
Descobrimos, gerando mais logs de assinatura no terminal (`pkcs11-tool --sign`), que o hardware StarSign rejeitava hashes pre-formatados (padded).

- **A Solução no Driver:** Injetamos a flag `SC_ALGORITHM_RSA_RAW` no C, o que faz o token receber o hash cru, deixando que o OpenSC apenas lidasse com o padding PKCS#1.
- **O Fator Externo (PJe):** Descobrimos que a linguagem Java 8 subjacente ao PJe Office oficial *não tem suporte* à assinatura RSA RAW via Smartcards. Quando ela falha, o BouncyCastle tenta extrair a sua Chave Privada do hardware para assinar por software. Como o token bloqueia isso (`CKA_SENSITIVE`), o PJe entra em colapso.

**A Cartada Final:** Substituímos o ultrapassado PJe Office em Java pela solução contemporânea **`pje_headless`** escrita em Go, que dialogou perfeitamente com nosso driver OpenSC, fechando o ciclo de engenharia reversa com uma assinatura digital ICP-Brasil funcional em Linux nativo, sem absolutamente nada proprietário.
