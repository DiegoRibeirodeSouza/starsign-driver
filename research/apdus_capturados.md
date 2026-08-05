# APDUs e Sequência PKCS#11 Capturados — G&D StarSign CUT S

**Data:** 2026-08-03  ✅ FASE 1 COMPLETA
**Hardware:** G&D StarSign CUT S | VID:1059 PID:0019 | Serial: 001F00310028E510

> ⚠️ Este arquivo não contém o PIN. O log bruto (pkcs11spy_output.txt) foi deletado
> após extração das informações necessárias.

---

## 1. ATR

```
3B F9 96 00 00 81 31 FE 45 53 43 45 37 20 0E 00 20 20 28
```

- TS: `3B` (Convenção direta)
- OS: **StarSign Card Engine 7 (SCE7)** — G&D JavaCard
- Protocolo: **T=1** (CCID puro)
- Histórico: `FE 45 53 43 45 37 20 0E 00` = "...SCE7..."

---

## 2. Identificação do Token (C_GetTokenInfo)

| Campo | Valor |
|---|---|
| label | `DIEGO RIBEIRO DE SOUZA` |
| manufacturerID | `A.E.T. Europe B.V.` |
| model | `19C43A06010D0000` |
| serialNumber | `001F00310028E510` |
| slotID | `0xcd01` (52481) |
| ulMinPinLen | 4 |
| ulMaxPinLen | 15 |
| flags | CKF_RNG, CKF_LOGIN_REQUIRED, CKF_USER_PIN_INITIALIZED, CKF_TOKEN_INITIALIZED |

**Nota:** SafeSign cria 5 slots virtuais (52481–52485) — apenas o slot 0xcd01 tem token presente.

---

## 3. Sequência PKCS#11 Completa (call sequence)

### Inicialização
```
C_GetInterface("PKCS 11")     → CKR_OK
C_Initialize(NULL)            → CKR_OK
C_GetSlotList(tokenPresent=0) → 5 slots: [52481, 52482, 52483, 52484, 52485]
C_GetSlotList(tokenPresent=0) → idem (segunda chamada para obter ponteiros)
C_GetSlotInfo(0xcd01)         → slot com token presente
C_OpenSession(0xcd01, flags=CKF_SERIAL_SESSION=0x4) → hSession=0xcd0101
C_GetTokenInfo(0xcd01)        → ver tabela acima
```

### Autenticação
```
C_Login(hSession=0xcd0101, userType=CKU_USER, PIN=[bytes do PIN]) → CKR_OK
```
- Formato do PIN: **bytes ASCII do PIN digitado, sem padding**
- Comprimento do PIN: variável (min 4, max 15 bytes)

### Enumeração de Objetos
```
C_FindObjectsInit(hSession, pTemplate=NULL, ulCount=0)  ← template VAZIO = lista tudo
→ CKR_OK

loop:
  C_FindObjects(hSession, ulMaxObjectCount=1) → Object handle
  C_GetAttributeValue(hObject, CKA_CLASS)     → tipo do objeto
  
  if CKO_DATA:
    C_GetAttributeValue(CKA_LABEL)
    C_GetAttributeValue(CKA_APPLICATION)
    C_GetAttributeValue(CKA_OBJECT_ID)
    C_GetAttributeValue(CKA_MODIFIABLE)
    C_GetAttributeValue(CKA_PRIVATE)
  
  if CKO_CERTIFICATE:
    C_GetAttributeValue(CKA_CERTIFICATE_TYPE)
    C_GetAttributeValue(CKA_LABEL)
    C_GetAttributeValue(CKA_SUBJECT)    ← DER-encoded DN
    C_GetAttributeValue(CKA_SERIAL_NUMBER)
    C_GetAttributeValue(CKA_ID)         ← SHA1 do Subject Public Key
    C_GetAttributeValue(CKA_UNIQUE_ID)  ← retorna CKR_ATTRIBUTE_TYPE_INVALID (ignorar)
  
  if CKO_PUBLIC_KEY:
    CKA_KEY_TYPE, CKA_LABEL, CKA_ID, CKA_MODULUS_BITS, CKA_LOCAL, CKA_ENCRYPT, etc.
  
  if CKO_PRIVATE_KEY:
    CKA_KEY_TYPE, CKA_LABEL, CKA_ID, CKA_SENSITIVE, CKA_EXTRACTABLE, etc.
  
  C_GetTokenInfo()  ← SafeSign chama após CADA objeto (overhead desnecessário — NÃO replicar)
until C_FindObjects retorna ulObjectCount=0

C_FindObjectsFinal()
```

**Nota crítica:** O SafeSign chama `C_GetTokenInfo` após cada objeto enumerado.
Isso é ineficiente e contribui para o alto uso do token. **Nosso driver NÃO fará isso.**

### Finalização
```
C_Finalize() → CKR_OK
```

---

## 4. Objetos no Token

### Objetos de Dados (CKO_DATA) — handle 0x1 a 0x7
| Handle | Label | Privado |
|---|---|---|
| 0x1 | `keepass.keyx` | sim |
| 0x2 | `chave de criptografia` | sim |
| 0x3 | `SHA-256` | sim |
| 0x4 | `SHA-256_1` | sim |
| 0x5 | `SHA-256_2` | sim |
| 0x6 | `SHA-256_3` | sim |
| 0x7 | `SHA-256_4` | sim |

### Certificados X.509 (CKO_CERTIFICATE)
| Handle | Label | ID (hex) |
|---|---|---|
| 0x8 | AC OAB G3 emitido por AC Certisign G7 | `6A3BCF3A BF73E203 AE24CF9F 02CD30F1 2FFE7E66` |
| 0xf | ACRB v5 emitido por ACRB v5 (Raiz) | `4ACADAB1 4B74BF4F BA7BACE6 4B91801C 44B8CC66` |
| 0x11 | AC Certisign G7 emitido por ACRB v5 | `EB1046EA 1980E7E0 B2E95B07 29280A5D 17AD8E28` |
| 0x13 | **DIEGO RIBEIRO DE SOUZA 2024-10-09** | `444945474f 205249424549524f...` (label em ASCII) |

### Chaves
| Tipo | Handle | Label | ID |
|---|---|---|---|
| Pública RSA 2048 | (ver log) | `19602704` | `2CDA5770BA19033F` |
| Privada RSA (antiga, expirada) | (ver log) | `DIEGO RIBEIRO DE SOUZA (18/10/2021 ~ 17/10/2024)` | `2CDA5770BA19033F` |
| **Privada RSA (ativa)** | (ver log) | *(sem label)* | `444945474f...` (label do cert em ASCII) |

---

## 5. Padrão de ID de Chave

O SafeSign usa o **label do certificado como bytes ASCII** para o ID da chave privada correspondente.

```
Certificado: "DIEGO RIBEIRO DE SOUZA 2024-10-09 20:22:25"
ID da chave: 444945474F2052494245... (= ASCII do label acima)
```

Nosso driver deve replicar esse comportamento para que aplicações como o PJeOffice
encontrem a chave correta ao buscar pelo ID do certificado.

---

## 7. Fluxo de Assinatura Digital (CAPTURADO)

### C_SignInit
```
hSession  = 0xcd0101
mechanism = CKM_SHA256_RSA_PKCS  (0x00000040)
params    = NULL, size=0
hKey      = handle da chave privada (primeiro CKO_PRIVATE_KEY encontrado)
```
- O mecanismo `CKM_SHA256_RSA_PKCS` faz **hash SHA-256 + assinatura RSA-PKCS#1 v1.5** no cartão
- O token recebe os **dados brutos** (não o hash pré-computado)
- Nenhum parâmetro adicional necessário

### C_GetAttributeValue(CKA_ALWAYS_AUTHENTICATE)
- Retorna `CKR_ATTRIBUTE_TYPE_INVALID` — **ignorar, não é suportado pelo StarSign**

### C_Sign
```
hSession         = 0xcd0101
pData            = dados brutos a assinar (qualquer tamanho)
pSignature       = 256 bytes (RSA-2048)
```

### Sequência completa de assinatura
```
C_Initialize(NULL)
C_GetSlotList(tokenPresent=0) → [0xcd01, ...]
C_GetSlotInfo(0xcd01)
C_OpenSession(0xcd01, CKF_SERIAL_SESSION=0x4) → hSession
C_GetTokenInfo(0xcd01)
C_Login(hSession, CKU_USER, pin_bytes)         ← PIN em ASCII puro, sem padding
C_FindObjectsInit(hSession, template=[], count=0)
C_FindObjects(hSession, maxCount=1)             → hKey (private key handle)
C_FindObjectsFinal(hSession)
C_SignInit(hSession, CKM_SHA256_RSA_PKCS, hKey)
C_GetAttributeValue(hKey, CKA_ALWAYS_AUTHENTICATE) → ignorar erro
C_Sign(hSession, data, &signature[256])
C_CloseSession(hSession)
C_Finalize()
```

### Observações para o driver
1. **Não usar CKM_RSA_PKCS** (que exigiria hash pré-computado) — usar `CKM_SHA256_RSA_PKCS`
2. **Não replicar o C_GetTokenInfo** após cada objeto (overhead do SafeSign)
3. **PIN em ASCII puro** — sem padding com 0xFF nem BCD
4. **Saída sempre 256 bytes** para RSA-2048

---

## 8. Status — O que temos para implementar o driver

| Componente | Status | Detalhe |
|---|---|---|
| C_Initialize / C_Finalize | ✅ Mapeado | trivial |
| C_GetSlotList / C_GetSlotInfo | ✅ Mapeado | 5 slots virtuais, 0xcd01 com token |
| C_GetTokenInfo | ✅ Mapeado | todos os campos documentados |
| C_OpenSession / C_CloseSession | ✅ Mapeado | flags=0x4 |
| C_Login / C_Logout | ✅ Mapeado | PIN ASCII puro, CKU_USER |
| C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal | ✅ Mapeado | template vazio = lista tudo |
| C_GetAttributeValue | ✅ Mapeado | 8+ atributos por objeto |
| C_SignInit | ✅ Mapeado | CKM_SHA256_RSA_PKCS, hKey |
| C_Sign | ✅ Mapeado | dados brutos → 256 bytes |
| C_GetMechanismList / C_GetMechanismInfo | ⏳ Estimar | CKM_SHA256_RSA_PKCS mínimo |
| C_GetFunctionList | ✅ Trivial | retorna tabela de ponteiros |

O log capturado cobre: inicialização, login e listagem de objetos.
Falta capturar:

```
C_SignInit(hSession, pMechanism={CKM_RSA_PKCS ou CKM_SHA256_RSA_PKCS}, hKey)
C_Sign(hSession, pData=[hash SHA-256], pSignature)
```

Para capturar isso, rodar:
```bash
# Gerar dados de teste
echo "teste" > /tmp/teste.txt

PKCS11SPY=/usr/lib/safesign-private/libaetpkss.so.3 \
PKCS11SPY_OUTPUT=~/Documentos/starsign-driver/research/spy_sign.txt \
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11-spy.so \
  --sign --mechanism SHA256-RSA-PKCS \
  --input-file /tmp/teste.txt \
  --output-file /tmp/assinatura.bin \
  --login
```

⚠️ Deletar `spy_sign.txt` imediatamente após extração das informações.
