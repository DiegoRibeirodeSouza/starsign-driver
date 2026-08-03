# Guia: Captura de APDUs com pcsc_spy

## O que descobrimos até aqui

```
ATR:   3B F9 96 00 00 81 31 FE 45 53 43 45 37 20 0E 00 20 20 28
OS:    StarSign Card Engine 7 (SCE7) — G&D JavaCard
AID:   A0 00 00 00 63 50 4B 43 53 2D 31 35  (PKCS#15 padrão ✅)
```

**Comportamento crítico descoberto:**
O applet SafeSign retorna a string:
```
"I am the SafeSign Applet of A.E.T. Europe B.V. please authenticate yourself."
```
...para qualquer SELECT antes da autenticação com PIN. Os arquivos reais (ODF, CDF,
certificado) só ficam acessíveis **após** o VERIFY com o PIN correto.

Isso é ótimo: significa que a sequência completa é:
1. SELECT AID
2. VERIFY PIN  ← o que precisamos capturar (REF do PIN, formato dos dados)
3. READ EF.ODF / EF.CDF / etc.

---

## Objetivo

Capturar a sequência **exata** de APDUs que o SafeSign envia ao fazer:
- Login com PIN (VERIFY)
- Leitura do certificado X.509
- Uma assinatura digital

---

## Passo 1: Instalar pcsc-tools (se não tiver)

```bash
sudo apt install pcsc-tools
```

---

## Passo 2: Capturar com pkcs11-tool (forma mais simples)

O `pkcs11-tool` já usa o SafeSign e mostra o que ele faz.
Execute isso em um terminal enquanto o `pcsc_spy` roda em outro:

### Terminal 1 — Iniciar pcsc_spy:
```bash
sudo pcsc_spy
```

### Terminal 2 — Disparar operação com SafeSign:
```bash
# Lista objetos (lê ODF, CDF, certificado)
pkcs11-tool --module /usr/lib/safesign-private/libaetpkss.so.3 \
            --list-objects \
            --login \
            --pin SEU_PIN_AQUI

# Ou apenas listar slots (sem PIN):
pkcs11-tool --module /usr/lib/safesign-private/libaetpkss.so.3 \
            --list-slots
```

### Terminal 3 — Testar assinatura:
```bash
echo "teste de assinatura" > /tmp/dados_para_assinar.txt

pkcs11-tool --module /usr/lib/safesign-private/libaetpkss.so.3 \
            --sign \
            --mechanism SHA256-RSA-PKCS \
            --input-file /tmp/dados_para_assinar.txt \
            --output-file /tmp/assinatura.bin \
            --login \
            --pin SEU_PIN_AQUI
```

---

## Passo 3: Salvar output do pcsc_spy

```bash
sudo pcsc_spy 2>&1 | tee ~/Documentos/starsign-driver/research/pcsc_spy_output.txt
```

---

## O que procurar no output

### SELECT AID
```
SCardTransmit
APDU: 00 A4 04 00 0C A0 00 00 00 63 50 4B 43 53 2D 31 35
Réponse: 90 00
```

### VERIFY PIN (este é o mais importante!)
```
SCardTransmit
APDU: 00 20 00 ??  ← P2 = referência do PIN (ex: 01, 81, etc.)
      XX XX XX ... ← dados do PIN (geralmente padded com FF)
Réponse: 90 00
```

### READ EF (ODF, CDF, certificado)
```
SCardTransmit
APDU: 00 A4 00 0C 02 ?? ??  ← SELECT FILE com FID real
Réponse: 90 00

SCardTransmit
APDU: 00 B0 00 00 FF        ← READ BINARY
Réponse: [dados] 90 00
```

### MSE SET + PSO SIGN (assinatura)
```
SCardTransmit
APDU: 00 22 41 B6 ...  ← MSE SET: seleciona chave e algoritmo
Réponse: 90 00

SCardTransmit
APDU: 00 2A 9E 9A ...  ← PSO: COMPUTE DIGITAL SIGNATURE
Réponse: [assinatura RSA] 90 00
```

---

## Alternativa: opensc-tool

Se quiser ver a perspectiva do OpenSC (referência open source):

```bash
# Com OpenSC — tenta ler o cartão sem SafeSign
PKCS11SPY=/usr/lib/safesign-private/libaetpkss.so.3 \
pkcs11-tool --module /usr/lib/pkcs11/pkcs11-spy.so \
            --list-objects --login

# Ou diretamente:
opensc-tool -a  # ATR
pkcs15-tool -D  # Dump PKCS#15 completo (se suportado)
```

---

## Resultado esperado

Após captura, preencher `apdus_capturados.md` com:

1. **REF do PIN** (P2 do VERIFY — ex: `01`, `81`)
2. **Formato do PIN** (ASCII? Padded com FF? BCD?)
3. **FIDs reais** do ODF, CDF, certificado
4. **Parâmetros do MSE SET** (referência da chave, algoritmo)
5. **Formato do hash** enviado no PSO SIGN

Essas 5 informações são **tudo** que precisamos para implementar o driver.
