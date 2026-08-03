# starsign-driver

Driver PKCS#11 open source para o token **G&D StarSign CUT S** (ICP-Brasil).

Substitui o middleware proprietário SafeSign IC 3.8 (`libaetpkss.so.3`) por uma
implementação leve, auditável e moderna, baseada em PC/SC padrão.

## Status

- [x] Fase 1 — Reconhecimento (captura de ATR e APDUs)
- [ ] Fase 2 — Protótipo Python (pyscard)
- [ ] Fase 3 — Biblioteca PKCS#11 (produção)

## Hardware alvo

| Campo | Valor |
|---|---|
| Fabricante | Giesecke & Devrient GmbH |
| Modelo | StarSign CUT S |
| VID:PID | `1059:0019` |
| Protocolo | T=1 (CCID puro, ISO 7816-3) |
| Interface | `bInterfaceClass 11` (Chip/SmartCard) |

## Estrutura

```
research/    ← Fase 1: captura de ATR e APDUs (scripts de exploração)
proto/       ← Fase 2: protótipo Python end-to-end
src/         ← Fase 3: implementação final (Rust ou Python+cffi)
packaging/   ← scripts de empacotamento .deb
build/       ← artefatos compilados (não versiona)
```

## Como rodar a Fase 1

```bash
cd starsign-driver
python3 -m venv venv
source venv/bin/activate
pip install pyscard
python3 research/captura_apdu.py
```

## Base legal

Engenharia reversa para interoperabilidade com hardware próprio.
Equivalente ao processo que originou o OpenSC para dezenas de tokens comerciais.
Não envolve extração de chaves privadas (a chave nunca sai do smartcard).

## Licença

MIT
