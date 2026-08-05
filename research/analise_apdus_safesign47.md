# Análise APDU — StarSign CUT S (SafeSign 4.7)
# Captura de referência: pcscd --apdu, operação: --list-objects --login

---

## ⚠️ AVISO DE SEGURANÇA

O arquivo `pcscd_apdu_log.txt` contém o PIN do token em texto claro.
**Mova ou delete o log após usar para análise.**

---

## Sequência completa de operações (443 APDUs, 886 linhas)

### Fase 0 — Autenticação do software ("handshake DRM")

Este é o mecanismo pelo qual o driver prova ao cartão que é software autorizado.

```
C→T  00 DA 01 00 3C
     "I am A.E.T. Europe B.V. SafeSign or BlueX approved software."
T→C  6D 00  (INS not supported — cartão ainda não conhece o driver)

C→T  00 A4 04 00 0C A0 00 00 00 63 50 4B 43 53 2D 31 35 00
     SELECT AID PKCS#15
T→C  "I am the SafeSign Applet of A.E.T. Europe B.V. please authenticate yourself.\n"
     90 00  (aceito — mensagem de desafio embutida na resposta)

C→T  00 DA 01 00 3C
     "I am A.E.T. Europe B.V. SafeSign or BlueX approved software."
T→C  90 00  ✅ autenticação bem-sucedida
```

**Conclusão crítica:** Não há criptografia assimétrica no handshake.
O cartão aceita qualquer software que envie esse string literal exato via PUT DATA (INS=DA, P1=01, P2=00).
Nosso driver open source PODE implementar esse handshake diretamente.

---

### Fase 1 — Identificação do token

```
C→T  00 A4 00 0C 02 50 31        SELECT DF 5031 (tentativa)
T→C  6A 86                        Parâmetros incorretos

C→T  00 CA 01 01 0A               GET DATA — Token Model
T→C  C2 08 19 C4 BA 06 01 0D 00 00  90 00
     modelo: 19 C4 BA 06 01 0D 00 00

C→T  00 CA 01 00 08               GET DATA — Serial Number
T→C  00 1F 00 31 00 28 E5 10  90 00
     serial: 001F00310028E510  ← confirma serial do nosso token

C→T  00 CA 01 05 00               GET DATA — desconhecido
T→C  03 04 01 00 00 98  90 00

C→T  00 CA 01 03 04               GET DATA — desconhecido
T→C  03 01 00 10  90 00

C→T  00 CA 01 08 02 00 02         GET DATA — desconhecido
T→C  6A 88  (not found)

C→T  80 54 01 01 00               GET DATA proprietário (CLA=80)
T→C  6D 00  (not supported)
```

---

### Fase 2 — Abertura de canal lógico

```
C→T  00 A4 00 0C 02 3F 00        SELECT MF
T→C  90 00

C→T  00 70 00 00 01              MANAGE CHANNEL (abrir novo canal)
T→C  01 90 00                     ← canal 1 alocado
```

**A partir daqui, TODAS as operações PKCS#15 usam CLA=01 (canal lógico 1).**

---

### Fase 3 — Inicialização PKCS#15 no canal 1

```
C→T  01 A4 04 00 0C A0 00 00 00 63 50 4B 43 53 2D 31 35 00
     SELECT AID PKCS#15 no canal 1
T→C  90 00

C→T  01 A4 00 0C 02 3F 00        SELECT MF no canal 1
T→C  90 00

C→T  01 A4 00 0C 02 50 31        SELECT DF 5031
T→C  90 00

C→T  01 A4 02 00 02 AE 0A 00     SELECT EF AE0A (tentativa)
T→C  6A 82  (not found)

C→T  01 CA 01 02 06               GET DATA no canal 1
T→C  73 25 20 1E 0C 0B  90 00

C→T  01 A4 02 00 02 50 32 00     SELECT EF 5032
T→C  6F 07 80 02 00 75 82 01 01  90 00
     ← EF existe, tamanho = 0x0075 = 117 bytes

C→T  01 B0 00 00 75              READ BINARY (117 bytes)
T→C  [TokenInfo TLV — 117 bytes contendo serial, manufacturer, etc.] 90 00
```

---

### Fase 4 — Polling proprietário

Repetido constantemente entre operações:

```
C→T  81 34 00 02 03              Comando proprietário (CLA=81)
T→C  03 03 01  90 00

C→T  81 34 00 01 03
T→C  03 03 01  90 00
```

**CLA=81** não é padrão ISO. Provavelmente são heartbeat/polling do driver para manter a sessão ativa.
Aparece com delay de ~4s (valor `04399702` no timestamp = 4.4s). O SafeSign faz polling regular.

> **Para o driver open source:** não precisamos implementar esse polling. O pcscd gerencia a conexão. Podemos ignorar completamente.

---

### Fase 5 — Leitura dos objetos de dados (Data Objects)

#### EF 44 07 — Diretório de objetos de dados (DODF)
```
C→T  01 A4 02 00 02 44 07 00     SELECT EF 4407
T→C  6F 07 80 02 02 00 82 01 01  90 00  (tamanho = 0x0200 = 512 bytes)

C→T  01 B0 00 00 80              READ BINARY (128 bytes, offset 0)
T→C  [ASN.1/PKCS#15 data objects directory]:
     keepass.keyx  → EF 3FFF 43 02 0A AA
     chave de criptografia  → EF 3FFF 43 02 1A 59
     SHA-256       → EF 3FFF 43 02 2D 55
     SHA-256_1     → EF 3FFF 43 02 2A 56
     SHA-256_2     → EF 3FFF 43 02 2F 58
     SHA-256_3     → EF 3FFF 43 02 14 68
     SHA-256_4     → EF 3FFF 43 02 23 46
     (leitura continua em offsets 0x80 e 0x100)
```

#### EF 0A AA — keepass.keyx
```
C→T  01 A4 02 00 02 0A AA 00
T→C  6F 07 80 02 01 16 82 01 01  (tamanho = 0x0116 = 278 bytes)

C→T  01 B0 00 00 FE + 01 B0 00 FE 18
T→C  [XML KeePass keyfile — 278 bytes total]
     <?xml version="1.0" encoding="UTF-8"?>
     <KeyFile>
       <Meta><Version>2.0</Version></Meta>
       <Key><Data Hash="D8E42E79">
         92CB2FE5 C2EE25BB C071EE38 2028DB7C
         9B68DB1D 54CAC5D7 0ED1E567 574DDD7E
       </Data></Key>
     </KeyFile>
```

> **Nota:** Chave KeePass armazenada no token como objeto de dados privado. Protegida pelo PIN.

#### EF 1A 59 — chave de criptografia (RSA 2048 bits)
```
Tamanho: 0x0200 = 512 bytes (= 2048 bits / 8 * 2)
Dados: blob RSA binário lido em múltiplos READ BINARY
```

#### EF 2D 55, 2A 56, 2F 58, 14 68, 23 46 — SHA-256 hashes
```
Cada EF tem 0x3C00 = 15360 bytes (!)
São objetos SHA-256 de uso privado (possivelmente hashes de documentos assinados ou timestamps)
```

---

### Fase 6 — Objetos PKCS#15 (após VERIFY PIN)

#### VERIFY PIN
```
C→T  01 20 00 02 0F [15 bytes: PIN + padding NUL]
     CLA=01, INS=20, P1=00, P2=02, Lc=0F
T→C  90 00  ✅
```

**Formato do PIN:**
- PIN em ASCII puro
- Completado com bytes `00` até 15 bytes (tamanho máximo do token)
- P2=02 = referência ao User PIN (PIN #2)

#### Certificado de assinatura (EF de certificado X.509)
```
Múltiplos READ BINARY de 0xFE bytes em sequência
Cada response = fragmento do DER-encoded X.509
Total: ~6 KB (certificado ICP-Brasil + cadeia completa)
```

---

## Estrutura do sistema de arquivos PKCS#15

```
MF (3F 00)
└── DF PKCS#15 (AID: A0 00 00 00 63 50 4B 43 53 2D 31 35)
    ├── EF 5032 — TokenInfo (117 bytes)
    ├── EF 4407 — DODF — Data Object Directory (512 bytes)
    │   ├── EF 0A AA — keepass.keyx (278 bytes) [PRIVADO]
    │   ├── EF 1A 59 — chave de criptografia RSA (512 bytes) [PRIVADO]
    │   ├── EF 2D 55 — SHA-256 blob (15360 bytes) [PRIVADO]
    │   ├── EF 2A 56 — SHA-256_1 blob (15360 bytes) [PRIVADO]
    │   ├── EF 2F 58 — SHA-256_2 blob (15360 bytes) [PRIVADO]
    │   ├── EF 14 68 — SHA-256_3 blob (15360 bytes) [PRIVADO]
    │   └── EF 23 46 — SHA-256_4 blob (15360 bytes) [PRIVADO]
    ├── EF 43 02 — PrKDF — Private Key Directory File (192 bytes)
    │   ├── RSA 2048 — chave expirada (ID: 2cda5770ba19033f)
    │   └── RSA 2048 — chave ativa ICP-Brasil (ID: 444945474f...) [ATIVA]
    ├── EF 44 08 — AuthObjectDF (PIN info) (255 bytes)
    └── EF [cert] — Certificado X.509 DER (~6 KB total, fragmentado em leituras de 254 bytes)
```

---

## Comandos proprietários identificados

| APDU | SW | Hipótese |
|---|---|---|
| `80 F6 00 01 0A` | `6D 00` | Proprietary GET — não suportado na versão atual |
| `80 54 01 01 00` | `6D 00` | Proprietary — não suportado |
| `81 34 00 02 03` | `03 03 01 90 00` | Polling/heartbeat (canal 1) |
| `81 34 00 01 03` | `03 03 01 90 00` | Polling/heartbeat (canal 1, variante) |

---

## Comandos FALTANTES nesta captura (precisam de próxima sessão)

Para implementar assinatura digital, ainda precisamos capturar:

1. **`COMPUTE DIGITAL SIGNATURE`** — CLA=01, INS=2A, P1=9E, P2=9A
   - Como capturar: `pkcs11-tool --sign --mechanism SHA256-RSA-PKCS --login`

2. **`MSE SET`** (Manage Security Environment) — CLA=01, INS=22, P1=41, P2=B6
   - Seleção do algoritmo antes da assinatura

3. Possível **PSO:COMPUTE DIGITAL SIGNATURE** alternativo

---

## Implementação do protótipo — sequência mínima

Com o que temos, já é possível implementar C_FindObjects e C_GetAttributeValue:

```python
# 1. Handshake DRM
card.transmit([0x00, 0xDA, 0x01, 0x00, 0x3C] + list(b"I am A.E.T. Europe B.V. SafeSign or BlueX approved software."))
card.transmit([0x00, 0xA4, 0x04, 0x00, 0x0C] + AID_PKCS15 + [0x00])
card.transmit([0x00, 0xDA, 0x01, 0x00, 0x3C] + list(b"I am A.E.T. Europe B.V. SafeSign or BlueX approved software."))

# 2. Abrir canal lógico
card.transmit([0x00, 0x70, 0x00, 0x00, 0x01])  # → canal 1

# 3. SELECT AID no canal 1
card.transmit([0x01, 0xA4, 0x04, 0x00, 0x0C] + AID_PKCS15 + [0x00])

# 4. VERIFY PIN
pin_padded = pin.encode() + b'\x00' * (15 - len(pin))
card.transmit([0x01, 0x20, 0x00, 0x02, 0x0F] + list(pin_padded))

# 5. SELECT e READ BINARY dos EFs de certificado
# ... (ver mapeamento de arquivos acima)
```

---

## Próximos passos para o projeto

1. **[PRIORIDADE 1]** Capturar APDUs de assinatura RSA com `pkcs11-tool --sign`
2. **[PRIORIDADE 2]** Implementar `starsign_proto.py` Phase 2 com sequência completa
3. **[PRIORIDADE 3]** Testar protótipo contra PKCS#11 standard (C_Login, C_FindObjects, C_Sign)
