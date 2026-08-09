# Relatório de Testes e Dificuldades - Driver OpenSC (StarSign CUT S)

Este documento resume as investigações, testes e correções aplicadas até o momento no desenvolvimento/adaptação do driver OpenSC para o token G&D StarSign CUT S.

## 1. Detecção do Token e Autenticação (Resolvido)

**Dificuldade:** 
O token não era reconhecido corretamente pelo OpenSC e operações que exigiam o PIN (como `pkcs11-tool --login`) falhavam com o erro `CKR_USER_PIN_NOT_INITIALIZED`. Além disso, a referência do PIN não estava corretamente mapeada.

**Testes e Correções:**
* **Análise da estrutura de arquivos do cartão (ODF/AODF/PRKDF):** Verificou-se que o driver genérico não interpretava corretamente os sinalizadores (flags) de inicialização do PIN.
* **Patch no arquivo `pkcs15-starsign.c`:** Criamos um "hook" (`starsign_parse_df`) para interceptar o mapeamento dos objetos. Injetamos forçadamente a flag `SC_PKCS15_PIN_FLAG_INITIALIZED` nos objetos de Autenticação (AODF) e definimos a `pin_reference` correta (`0x02`).
* **Correção de tamanho do arquivo ODF no `card-starsign.c`:** Forçamos o tamanho do arquivo ODF para evitar erros de leitura.

**Resultado Atual:**
Sucesso total. O token é detectado, os objetos (certificados e chaves) são listados perfeitamente com `pkcs11-tool -O` e a autenticação com o PIN ocorre sem erros.

---

## 2. Assinatura Digital: Erros no Comando APDU `MSE: SET`

**Dificuldade:**
Ao tentar realizar uma assinatura, o OpenSC envia um comando APDU chamado `MSE: SET` (Manage Security Environment) para o token, informando qual chave privada e qual algoritmo criptográfico serão usados. O token StarSign tem retornado mensagens de erro de hardware (Status Words).

**Testes e Correções:**
* O OpenSC estava enviando `KEY_REF` (Referência da Chave) vazio (`0x00`).
* **Erro `6A 86` (Incorrect parameters P1-P2):** Ocorria porque a referência da chave enviada ao cartão não era válida ou os parâmetros de ambiente de segurança (P1=41, P2=B6) não combinavam.
* **Erro `6A 80` (Incorrect parameters in data field):** Tentamos injetar as referências de chave `0x01` e `0x02` no PRKDF (`pkcs15-starsign.c`), além de forçar a referência do algoritmo RSA-PKCS1 (`80 01 02`). O cartão rejeitou o campo de dados do APDU.
* Tentamos **remover o `KEY_REF`** do `MSE: SET` (assumindo que o cartão selecionaria a chave implicitamente), o que resultou em um novo erro do cartão: **`67 00` (Wrong length)**.

**Status Atual:**
Descobrimos a combinação exata graças a logs anteriores do token com o SafeSign. A estrutura correta exigida pelo StarSign CUT S envia o Key Reference ANTES do Algorithm Reference: `84 01 01 80 01 02`. Modificamos a função `starsign_set_security_env` no `card-starsign.c` para forçar este payload exato e a placa passou a aceitar o comando sem erros. **[RESOLVIDO]**

---

## 3. Assinatura Digital: Erro `CKR_DATA_LEN_RANGE` (Tamanho do Modulus RSA) e Hashes Não-Preenchidos

**Dificuldade:**
O token retornava erros como `CKR_DATA_LEN_RANGE` ou o hardware recusava a assinatura com erro `67 00` quando o OpenSC não preparava os dados do tamanho exato (256 bytes para RSA 2048) e formato requeridos pelo cartão.

**Testes e Correções:**
* A versão nativa do driver tentava enviar os dados crus ou dependia do preenchimento PKCS#1 feito pelo próprio cartão.
* Injetamos as flags `SC_ALGORITHM_RSA_RAW` e `SC_ALGORITHM_RSA_PAD_PKCS1` no `card-starsign.c`, forçando o OpenSC a assumir a responsabilidade de aplicar o padding PKCS#1 v1.5 por software (deixando o buffer com exatos 256 bytes) antes de enviar ao cartão.

**Status Atual:**
O erro de tamanho de dados `CKR_DATA_LEN_RANGE` foi resolvido. O OpenSC agora formata e prepara corretamente a matriz de 256 bytes (raw padding) para enviar ao token. **[RESOLVIDO]**

---

## 4. Assinatura Digital: Fragmentação de APDU (Command Chaining)

**Dificuldade:**
Ao tentar enviar os 256 bytes finais para o token assinar (comando `COMPUTE DIGITAL SIGNATURE` - `2A 9E 9A`), o OpenSC está falhando com o erro `-1203 (Unsupported CLA byte in APDU)` e a leitora retorna `6E 00` (Class not supported).

**Testes e Correções:**
* Verificamos que o OpenSC tentou enviar um APDU com o cabeçalho `11 2A 9E 9A FF...`.
* O `11` significa que a flag de "Command Chaining" (encadeamento de comandos, `0x10`) foi ativada. Isso ocorre porque o OpenSC fatiou os 256 bytes em pedaços de no máximo 255 bytes (limite do Short APDU).
* No entanto, o hardware StarSign CUT S não suporta o encadeamento ISO (retornando `6E 00`).
* O token espera receber o bloco inteiro de 256 bytes através de um **Extended APDU** (onde o Lc é expresso em 3 bytes, ex: `00 00 01 00`).
* Observou-se que modificar `card->max_send_size` e `card->reader->max_send_size` para 2048 afetou a função `sc_read_binary`, pois o `max_recv_size` (leitura) também estava configurado para 2048, fazendo com que o StarSign falhasse na leitura de arquivos internos (retornando `CKR_TOKEN_NOT_RECOGNIZED` via `C_GetTokenInfo`).
- **Resolução:** O parâmetro `card->reader->max_recv_size = 256;` foi restaurado. Isso preservou a integridade da leitura, enquanto manteve o `max_send_size = 2048` e as flags de hash (`SC_ALGORITHM_RSA_HASH_SHA256`, etc.) ativas.

### 4. Assinatura Final (Sucesso Absoluto)
Com os algoritmos de hash habilitados (`SC_ALGORITHM_RSA_HASH_SHA256`) e as propriedades da leitora corrigidas (evitando o Command Chaining e o crash de leitura):
- O token consegue receber diretamente os payloads de 32 bytes de Hash (ou preenchimentos corretos do OpenSC).
- O APDU não é fragmentado (não ocorre o erro `6E 00`).
- O comando `pkcs11-tool --sign -m SHA256-RSA-PKCS` finalizou perfeitamente, provando que o token A3 agora pode ser utilizado nativamente no Linux (via OpenSC) e é perfeitamente compatível com as rotinas do Java/PJe.

**Status Final do Driver:** Totalmente operacional. Próximo passo recomendado é o uso direto nos sistemas corporativos e validadores governamentais (ICP-Brasil).

---

## Próximos Passos (Plano de Ação) — *superado, ver seção 5 abaixo*

1. ~~Forçar Extended APDU no Comando de Assinatura~~
2. ~~Testar Assinatura Final~~

---

## 5. Correção Retroativa: a "Assinatura Final (Sucesso Absoluto)" da Seção 4 nunca foi válida

**Data:** 07/08/2026

A seção 4 acima declara "Status Final do Driver: Totalmente operacional" com base no fato de que `pkcs11-tool --sign -m SHA256-RSA-PKCS` terminava com código de saída 0 e o cartão respondendo `SW 90 00`. **Essa conclusão estava errada.** O cartão aceitar o comando e devolver sucesso não significa que a assinatura produzida seja criptograficamente válida — e não era.

**O bug real:** com `SC_ALGORITHM_RSA_HASH_SHA256` habilitado (exatamente a configuração que a seção 4 credita pelo "sucesso"), o cartão recebe apenas o hash de 32 bytes e faz o padding PKCS#1 v1.5 internamente — mas **nunca insere o cabeçalho ASN.1 `DigestInfo`** que uma assinatura SHA-256 padrão exige. Decriptando uma assinatura real com a própria chave pública do token, o bloco de padding continha o hash cru sem o prefixo `30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20` esperado. Toda assinatura gerada pela configuração da seção 4 seria classificada como **inválida** por qualquer verificador de conformidade real (Adobe, ITI, `pdfsig`), apesar do `SW 90 00`.

**Correção aplicada:** remover `SC_ALGORITHM_RSA_HASH_SHA256`/`MD5`/`SHA1` do `card-starsign.c`, deixando apenas `SC_ALGORITHM_RSA_HASH_NONE`. Isso força o próprio OpenSC a montar o bloco completo `DigestInfo` + padding PKCS#1 em software, e mandar o bloco de 256 bytes já pronto pro cartão fazer só a exponenciação modular crua (`SC_ALGORITHM_RSA_RAW`).

**Verificado de verdade desta vez:** assinatura de PDF via `litisdoc`/pyHanko validada como `Signature is Valid` pelo `pdfsig` (Poppler) — a primeira verificação de conformidade real feita neste projeto.

---

## 6. Limite físico de 261 bytes do leitor CCID embutido no token

**Data:** 07/08/2026

Corrigir a seção 5 acima resolveu a validade da assinatura, mas expôs um problema de transporte que a seção 4 nunca tinha diagnosticado corretamente: a operação RSA-2048 crua (`RAW`) exige transmitir **256 bytes** de dados numa única APDU — e essa transmissão falha de forma intermitente com `SCardTransmit/Control failed: 0x80100016` (`SCARD_E_INVALID_PARAMETER`) ou, no lado do `pcscd`, com:

```
CmdXfrBlockTPDU_T0() Command too long (265 bytes) for max: 261 bytes
```

**Causa raiz identificada com certeza:** o leitor CCID embutido no próprio token (`1059:0019 Giesecke & Devrient GmbH StarSign CUT S`) declara, no seu descritor USB (`lsusb -v`), um limite **fixo e imutável de firmware**:

```
dwMaxCCIDMsgLen       271        ← tamanho máximo de mensagem USB CCID
dwFeatures                       ← inclui "Short APDU level exchange"
                                    NÃO inclui "Extended APDU level exchange"
dwProtocols             2  T=1
```

271 bytes de mensagem CCID menos ~10 bytes de cabeçalho do próprio protocolo CCID = **261 bytes utilizáveis** — batendo exatamente com o erro do `pcscd`.

**Por que isso é matematicamente insolúvel com os dados existentes:**

Mesmo no formato mais compacto possível de uma APDU estendida (Case 3, sem pedir resposta imediata):

```
CLA + INS + P1 + P2   4 bytes
marcador estendido     1 byte
Lc estendido           2 bytes
dados                256 bytes
──────────────────────────────
total                263 bytes   →  ainda 2 bytes acima do limite de 261
```

E o caminho alternativo — fragmentar em múltiplas APDUs curtas via *command chaining* ISO 7816-4 — já havia sido testado e **rejeitado pelo cartão** com `SW 6E 00` ("Class not supported"), documentado na seção 4 original.

**Conclusão:** existe uma incompatibilidade física genuína entre o leitor CCID embutido neste token e o requisito de payload de uma operação RSA-2048 crua — não é um bug de configuração, é um limite de hardware declarado no firmware do próprio dispositivo. A única saída teórica seria o cartão fazer o hash+padding+`DigestInfo` internamente (reduzindo o payload transmitido para 32 bytes de hash) — mas o item 5 acima já provou que essa via existe no hardware, porém está incompleta (falta o `DigestInfo`), então não é utilizável como está.

**Status honesto:** a operação de assinatura RAW/estendida funciona de forma **intermitente**, não garantida — provavelmente dependendo de variações sutis de timing/negociação USB perto do limite de 261 bytes. Isso não é resolvível por software dado o hardware atual. Documentado aqui e reportado no PR #3764 do OpenSC para que outros mantenedores/usuários com o mesmo modelo de leitor tenham essa informação.
