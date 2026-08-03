#!/usr/bin/env python3
"""
=============================================================================
captura_apdu.py — Fase 1: Reconhecimento do G&D StarSign CUT S
=============================================================================
PROPÓSITO:
  Conectar ao token via PC/SC puro (sem SafeSign) e extrair:
    - ATR (Answer To Reset) completo
    - Estrutura do filesystem do cartão (MF, DFs, EFs)
    - AID da aplicação PKCS#15
    - Sequência de APDUs necessária para leitura do certificado

COMO RODAR:
  python3 -m venv venv && source venv/bin/activate
  pip install pyscard
  python3 research/captura_apdu.py

IMPORTANTE:
  - Rode com pcscd ativo: systemctl status pcscd
  - O SafeSign pode estar instalado — não há conflito (ambos usam pcscd)
  - NÃO é necessário desinstalar nada
=============================================================================
"""

import sys
import time

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest
    from smartcard.Exceptions import CardRequestTimeoutException, CardConnectionException
except ImportError:
    print("[ERRO] pyscard não encontrado.")
    print("       Execute: pip install pyscard")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constantes — APDUs conhecidos do padrão ISO 7816-4 / PKCS#15
# ---------------------------------------------------------------------------

# AIDs conhecidos a testar (em ordem de probabilidade para ICP-Brasil)
KNOWN_AIDS = [
    # PKCS#15 padrão (ISO 7816-15)
    ([0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35], "PKCS#15 padrão"),
    # G&D StarSign — AID reportado em tokens europeus similares
    ([0xD2, 0x76, 0x00, 0x00, 0x66, 0x01], "G&D StarSign v1"),
    ([0xD2, 0x76, 0x00, 0x00, 0x66, 0x02], "G&D StarSign v2"),
    # ICP-Brasil / SafeSign — AID interno típico
    ([0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xF2, 0x50, 0x4F, 0x54, 0x20, 0x41, 0x4F, 0x53], "SafeSign PKCS#15"),
    # OpenSC PKCS#15 emulation
    ([0xA0, 0x00, 0x00, 0x01, 0x77, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35], "OpenSC PKCS#15"),
]

# FIDs comuns do filesystem PKCS#15
KNOWN_FIDS = [
    ([0x3F, 0x00], "MF (Master File)"),
    ([0x2F, 0x00], "EF.DIR (Application Directory)"),
    ([0x2F, 0x01], "EF.ATR"),
    ([0x5015], "DF.PKCS15"),
    ([0x40, 0x00], "DF.PKCS15 (alternativo)"),
    ([0x50, 0x00], "EF.ODF (Object Directory File)"),
    ([0x50, 0x04], "EF.TokenInfo"),
    ([0x50, 0x08], "EF.UnusedSpace"),
]


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

def hex_str(data):
    """Converte lista de bytes para string hex legível."""
    if not data:
        return "(vazio)"
    return " ".join(f"{b:02X}" for b in data)


def sw_description(sw1, sw2):
    """Interpreta Status Words ISO 7816."""
    sw = (sw1 << 8) | sw2
    table = {
        0x9000: "✅ Sucesso",
        0x6100: "✅ Sucesso — dados disponíveis (use GET RESPONSE)",
        0x6700: "❌ Lc incorreto",
        0x6982: "🔒 Condições de segurança não satisfeitas (PIN necessário?)",
        0x6983: "🔒 Método de autenticação bloqueado",
        0x6985: "❌ Condições de uso não satisfeitas",
        0x6A82: "❌ Arquivo não encontrado",
        0x6A86: "❌ Parâmetros P1/P2 incorretos",
        0x6D00: "❌ INS não suportado",
        0x6E00: "❌ CLA não suportado",
        0x6F00: "❌ Erro não especificado",
    }
    if sw in table:
        return table[sw]
    if sw1 == 0x61:
        return f"✅ Sucesso — {sw2} bytes disponíveis"
    if sw1 == 0x6C:
        return f"⚠️  Le incorreto — use Le={sw2:02X}"
    if sw1 == 0x90:
        return "✅ Sucesso"
    return f"? SW desconhecido"


def transmit_apdu(connection, apdu, label="APDU"):
    """Envia APDU e exibe resultado formatado."""
    print(f"\n  [{label}]")
    print(f"  → CMD: {hex_str(apdu)}")
    try:
        data, sw1, sw2 = connection.transmit(apdu)
        print(f"  ← SW:  {sw1:02X} {sw2:02X}  ({sw_description(sw1, sw2)})")
        if data:
            print(f"  ← DAT: {hex_str(data)}")
            # Tenta interpretar como ASCII se parecer texto
            try:
                txt = bytes(data).decode('ascii', errors='replace')
                if any(32 <= c < 127 for c in data):
                    print(f"  ← TXT: {txt!r}")
            except Exception:
                pass
        return data, sw1, sw2
    except Exception as e:
        print(f"  ✗ Exceção: {e}")
        return [], 0xFF, 0xFF


def select_file_by_fid(connection, fid, label=""):
    """SELECT FILE por File ID (2 bytes)."""
    apdu = [0x00, 0xA4, 0x00, 0x0C, 0x02] + fid
    return transmit_apdu(connection, apdu, label or f"SELECT FID {hex_str(fid)}")


def select_file_by_aid(connection, aid, label=""):
    """SELECT FILE por AID."""
    apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid
    return transmit_apdu(connection, apdu, label or f"SELECT AID {hex_str(aid)}")


def read_binary(connection, offset=0, length=255):
    """READ BINARY a partir do EF selecionado."""
    p1 = (offset >> 8) & 0x7F
    p2 = offset & 0xFF
    apdu = [0x00, 0xB0, p1, p2, length]
    return transmit_apdu(connection, apdu, f"READ BINARY off={offset} len={length}")


def get_response(connection, length):
    """GET RESPONSE após SW 61xx."""
    apdu = [0x00, 0xC0, 0x00, 0x00, length]
    return transmit_apdu(connection, apdu, f"GET RESPONSE len={length}")


def get_data(connection, tag_hi, tag_lo):
    """GET DATA — lê objeto TLV pelo tag."""
    apdu = [0x00, 0xCA, tag_hi, tag_lo, 0x00]
    return transmit_apdu(connection, apdu, f"GET DATA tag={tag_hi:02X}{tag_lo:02X}")


# ---------------------------------------------------------------------------
# Lógica principal de exploração
# ---------------------------------------------------------------------------

def explorar_token(connection):
    """Executa exploração completa do token."""

    print("\n" + "="*60)
    print("  FASE 1.1 — Informações básicas e GET DATA")
    print("="*60)

    # GET DATA para informações do cartão
    get_data(connection, 0x00, 0x66)  # Card Data
    get_data(connection, 0x9F, 0x7F)  # Card Production Life Cycle
    get_data(connection, 0x00, 0x6E)  # Historical bytes (alternativo)

    print("\n" + "="*60)
    print("  FASE 1.2 — Seleção do Master File (MF)")
    print("="*60)

    data, sw1, sw2 = select_file_by_fid(connection, [0x3F, 0x00], "SELECT MF")

    # Se retornou dados (FCI), tenta lê-los
    if sw1 == 0x61:
        get_response(connection, sw2)
    elif data:
        print(f"  → FCI do MF: {hex_str(data)}")

    print("\n" + "="*60)
    print("  FASE 1.3 — Tentando SELECT por AID (busca PKCS#15)")
    print("="*60)

    aid_encontrado = None
    for aid, nome in KNOWN_AIDS:
        data, sw1, sw2 = select_file_by_aid(connection, aid, f"SELECT AID [{nome}]")
        if sw1 == 0x90 or sw1 == 0x61:
            print(f"  🎯 AID ENCONTRADO: {nome} → {hex_str(aid)}")
            aid_encontrado = (aid, nome)
            if sw1 == 0x61:
                get_response(connection, sw2)
            break
        time.sleep(0.05)  # pequena pausa entre tentativas

    print("\n" + "="*60)
    print("  FASE 1.4 — Leitura do EF.DIR (Application Directory)")
    print("="*60)

    # Volta ao MF
    select_file_by_fid(connection, [0x3F, 0x00], "SELECT MF (reset)")
    data, sw1, sw2 = select_file_by_fid(connection, [0x2F, 0x00], "SELECT EF.DIR")
    if sw1 == 0x90 or sw1 == 0x61:
        if sw1 == 0x61:
            data, sw1, sw2 = get_response(connection, sw2)
        # Lê o conteúdo
        read_binary(connection, 0, 128)

    print("\n" + "="*60)
    print("  FASE 1.5 — Exploração do filesystem (FIDs conhecidos)")
    print("="*60)

    select_file_by_fid(connection, [0x3F, 0x00], "SELECT MF (reset)")
    fids_encontrados = []
    for fid_bytes, nome in [
        ([0x2F, 0x00], "EF.DIR"),
        ([0x2F, 0x01], "EF.ATR"),
        ([0x50, 0x15], "DF.PKCS15"),
        ([0x40, 0x00], "DF.PKCS15 (alt)"),
        ([0x50, 0x00], "EF.ODF"),
        ([0x50, 0x04], "EF.TokenInfo"),
        ([0x50, 0x05], "EF.AODF"),
        ([0x50, 0x08], "EF.UnusedSpace"),
        ([0x41, 0x01], "EF.PrKDF"),
        ([0x41, 0x02], "EF.PuKDF"),
        ([0x41, 0x03], "EF.CDF"),
        ([0x41, 0x04], "EF.DODF"),
        ([0x41, 0x11], "EF.Certificado_1"),
        ([0x41, 0x21], "EF.Certificado_2"),
    ]:
        data, sw1, sw2 = select_file_by_fid(connection, fid_bytes, f"SELECT {nome}")
        if sw1 in (0x90, 0x61):
            fids_encontrados.append((fid_bytes, nome))
            print(f"  🗂️  ARQUIVO ENCONTRADO: {nome} (FID {hex_str(fid_bytes)})")
        # Reset ao MF antes do próximo
        select_file_by_fid(connection, [0x3F, 0x00], "reset MF")
        time.sleep(0.03)

    print("\n" + "="*60)
    print("  FASE 1.6 — Leitura dos EFs encontrados")
    print("="*60)

    for fid_bytes, nome in fids_encontrados:
        print(f"\n  --- Lendo {nome} (FID {hex_str(fid_bytes)}) ---")
        select_file_by_fid(connection, [0x3F, 0x00], "reset")
        data, sw1, sw2 = select_file_by_fid(connection, fid_bytes, f"SELECT {nome}")
        if sw1 == 0x61:
            data, sw1, sw2 = get_response(connection, sw2)
        if sw1 == 0x90:
            read_binary(connection, 0, 128)

    print("\n" + "="*60)
    print("  FASE 1.7 — Teste de assinatura (sem PIN — apenas vê mecanismos)")
    print("="*60)

    # Tenta listar mecanismos via GET DATA
    get_data(connection, 0x00, 0x2A)   # PSO supported
    get_data(connection, 0xFF, 0x68)   # Card capabilities

    # MSE SET — tenta configurar RSA sem PIN (esperamos SW 6982 = auth needed)
    mse_set = [0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, 0x12, 0x84, 0x01, 0x01]
    transmit_apdu(connection, mse_set, "MSE SET (RSA-SHA256, sem PIN)")

    return aid_encontrado, fids_encontrados


def main():
    print("=" * 60)
    print("  starsign-driver — Fase 1: Reconhecimento")
    print("  G&D StarSign CUT S (VID:1059 PID:0019)")
    print("=" * 60)

    # Lista leitores disponíveis
    print("\n[1] Listando leitores PC/SC...")
    rs = readers()
    if not rs:
        print("\n❌ Nenhum leitor PC/SC encontrado.")
        print("   Verifique: systemctl status pcscd")
        sys.exit(1)

    print(f"   {len(rs)} leitor(es) encontrado(s):")
    for i, r in enumerate(rs):
        print(f"   [{i}] {r}")

    # Seleciona o leitor (prefere o que tiver "StarSign" no nome)
    reader = rs[0]
    for r in rs:
        if any(k in str(r).lower() for k in ["starsign", "g&d", "giesecke", "star"]):
            reader = r
            break
    print(f"\n   Usando: {reader}")

    # Conecta ao cartão
    print("\n[2] Conectando ao cartão...")
    try:
        connection = reader.createConnection()
        connection.connect()
    except CardConnectionException as e:
        print(f"\n❌ Falha ao conectar: {e}")
        print("   Token inserido? pcscd rodando?")
        sys.exit(1)

    # Lê e exibe o ATR
    atr = connection.getATR()
    print(f"\n{'='*60}")
    print(f"  ATR: {hex_str(atr)}")
    print(f"{'='*60}")

    # Interpreta campos do ATR (ISO 7816-3)
    if len(atr) >= 2:
        ts = atr[0]
        t0 = atr[1]
        n_hist = t0 & 0x0F
        print(f"  TS:      {ts:02X}  ({'Convenção direta' if ts == 0x3B else 'Convenção inversa'})")
        print(f"  T0:      {t0:02X}  ({n_hist} bytes históricos)")
        if len(atr) > 2:
            hist_start = 2
            # Pula bytes de interface (TA, TB, TC, TD)
            td = t0
            while td & 0x80:
                if td & 0x10: hist_start += 1  # TA
                if td & 0x20: hist_start += 1  # TB
                if td & 0x40: hist_start += 1  # TC
                if td & 0x80:
                    td = atr[hist_start]
                    hist_start += 1
                else:
                    break
            if hist_start < len(atr):
                hist = atr[hist_start:hist_start + n_hist]
                print(f"  Histórico: {hex_str(hist)}")
                try:
                    txt = bytes(hist).decode('ascii', errors='replace')
                    print(f"  Histórico (texto): {txt!r}")
                except Exception:
                    pass

    # Exploração
    print("\n[3] Iniciando exploração de APDUs...")
    aid_encontrado, fids_encontrados = explorar_token(connection)

    # Relatório final
    print("\n" + "=" * 60)
    print("  RELATÓRIO FINAL")
    print("=" * 60)
    print(f"\n  ATR:  {hex_str(atr)}")
    if aid_encontrado:
        print(f"  AID:  {hex_str(aid_encontrado[0])}  ({aid_encontrado[1]})")
    else:
        print("  AID:  Não identificado (salvar log e analisar)")
    if fids_encontrados:
        print(f"\n  Arquivos encontrados ({len(fids_encontrados)}):")
        for fid_bytes, nome in fids_encontrados:
            print(f"    FID {hex_str(fid_bytes)}  →  {nome}")
    else:
        print("\n  FIDs: Nenhum arquivo padrão encontrado (estrutura proprietária?)")

    print("\n  📝 Copie este relatório para research/apdus_capturados.md")
    print("     para documentar a estrutura do seu token.")

    connection.disconnect()


if __name__ == "__main__":
    main()
