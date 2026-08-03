# APDUs Capturados — G&D StarSign CUT S

**Data:** _(preencher após captura)_
**Hardware:** G&D StarSign CUT S | VID:1059 PID:0019

---

## ATR

```
(resultado do captura_apdu.py)
```

**Interpretação:**
- TS: 
- T0: 
- Protocolo: T=1
- Bytes históricos: 

---

## AID Identificado

| AID (hex) | Nome |
|---|---|
| _(preencher)_ | _(ex: PKCS#15 padrão)_ |

---

## Arquivos Encontrados (FIDs)

| FID | Nome | Conteúdo |
|---|---|---|
| 3F 00 | MF | — |
| _(preencher)_ | EF.DIR | _(bytes)_ |
| _(preencher)_ | EF.ODF | _(bytes)_ |
| _(preencher)_ | EF.TokenInfo | _(bytes)_ |
| _(preencher)_ | EF.CDF (certificado) | _(bytes)_ |

---

## Sequência de APDUs para Assinatura

_(preencher após pcsc_spy — ver pcsc_spy_guide.md)_

### 1. Inicialização

```
→ 00 A4 04 00 ...   SELECT AID
← 90 00
```

### 2. Verificação de PIN

```
→ 00 20 00 01 ...   VERIFY
← 90 00
```

### 3. MSE SET (configura algoritmo/chave)

```
→ 00 22 41 B6 ...
← 90 00
```

### 4. PSO: COMPUTE DIGITAL SIGNATURE

```
→ 00 2A 9E 9A ...
← (assinatura) 90 00
```

---

## Observações

_(anotar comportamentos inesperados, SWs desconhecidos, etc.)_
