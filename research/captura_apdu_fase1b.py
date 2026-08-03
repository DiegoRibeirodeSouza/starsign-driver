#!/usr/bin/env python3
"""
=============================================================================
captura_apdu_fase2.py — Exploração DENTRO da aplicação PKCS#15
=============================================================================
DESCOBERTA DA FASE 1:
  - AID PKCS#15 confirmado: A0 00 00 00 63 50 4B 43 53 2D 31 35
  - Os arquivos NÃO estão no MF — estão DENTRO do contexto da aplicação
  - Histórico ATR: "SCE7" → identifica o OS do JavaCard no StarSign
  - ATR completo: 3B F9 96 00 00 81 31 FE 45 53 43 45 37 20 0E 00 20 20 28

OBJETIVO DESTA FASE:
  Após SELECT AID (que muda o contexto para dentro da aplicação), explorar:
  - EF.ODF, EF.TokenInfo, EF.CDF (dentro do DF da aplicação)
  - Ler ODF para descobrir FIDs reais dos objetos PKCS#15
  - Ler EF.TokenInfo para identificar o token
  - Localizar EF.CDF (Certificate Directory File) com o cert X.509
=============================================================================
"""

import sys
import time

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
    from smartcard.Exceptions import CardConnectionException
except ImportError:
    print("[ERRO] Execute: pip install pyscard")
    sys.exit(1)


# AID confirmado na Fase 1
AID_PKCS15 = [0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35]


def hex_str(data):
    if not data:
        return "(vazio)"
    return " ".join(f"{b:02X}" for b in data)


def sw_desc(sw1, sw2):
    sw = (sw1 << 8) | sw2
    m = {
        0x9000: "✅ OK",
        0x6282: "⚠️  End of file",
        0x6700: "❌ Lc errado",
        0x6982: "🔒 Precisa de autenticação",
        0x6983: "🔒 Auth bloqueada",
        0x6985: "❌ Condição não satisfeita",
        0x6A80: "❌ Dados incorretos",
        0x6A82: "❌ Arquivo não encontrado",
        0x6A86: "❌ P1/P2 errado",
        0x6A88: "❌ Objeto não encontrado",
        0x6D00: "❌ INS não suportado",
        0x6E00: "❌ CLA não suportado",
    }
    if sw in m:
        return m[sw]
    if sw1 == 0x61:
        return f"✅ OK + {sw2} bytes"
    if sw1 == 0x6C:
        return f"⚠️  Use Le={sw2:02X}"
    return f"SW {sw1:02X}{sw2:02X}"


def apdu(conn, cmd, label):
    print(f"\n  [{label}]")
    print(f"  → {hex_str(cmd)}")
    try:
        data, sw1, sw2 = conn.transmit(cmd)
        print(f"  ← SW {sw1:02X} {sw2:02X}  {sw_desc(sw1, sw2)}")
        if data:
            print(f"  ← {hex_str(data)}")
        return data, sw1, sw2
    except Exception as e:
        print(f"  ✗ {e}")
        return [], 0xFF, 0xFF


def read_ef_full(conn, label="READ BINARY", max_bytes=4096):
    """Lê um EF completo em chunks de 255 bytes."""
    result = []
    offset = 0
    while offset < max_bytes:
        chunk = min(255, max_bytes - offset)
        p1 = (offset >> 8) & 0x7F
        p2 = offset & 0xFF
        cmd = [0x00, 0xB0, p1, p2, chunk]
        data, sw1, sw2 = conn.transmit(cmd)
        if sw1 == 0x90 and data:
            result.extend(data)
            offset += len(data)
            if len(data) < chunk:
                break  # fim do arquivo
        elif sw1 == 0x62 and sw2 == 0x82:
            result.extend(data)
            break  # end of file warning
        elif sw1 == 0x6C:
            # Tamanho exato indicado
            cmd[-1] = sw2
            data, sw1, sw2 = conn.transmit(cmd)
            if data:
                result.extend(data)
            break
        else:
            break
    if result:
        print(f"  ← [{label}] {len(result)} bytes: {hex_str(result[:64])}{'...' if len(result) > 64 else ''}")
    return result


def select_aid(conn, aid):
    cmd = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid
    return apdu(conn, cmd, f"SELECT AID {hex_str(aid[:4])}...")


def select_fid(conn, fid, p1=0x00, p2=0x04):
    """SELECT FILE: P1=00 (MF/DF/EF by FID), P2=04 (retorna FCI)."""
    cmd = [0x00, 0xA4, p1, p2, 0x02] + fid
    return apdu(conn, cmd, f"SELECT FID {hex_str(fid)}")


def get_response(conn, length):
    cmd = [0x00, 0xC0, 0x00, 0x00, length]
    return apdu(conn, cmd, f"GET RESPONSE {length}")


def main():
    print("=" * 60)
    print("  Fase 1b — Exploração dentro da aplicação PKCS#15")
    print("  AID: A0 00 00 00 63 50 4B 43 53 2D 31 35")
    print("=" * 60)

    rs = readers()
    if not rs:
        print("❌ Nenhum leitor. Verifique pcscd.")
        sys.exit(1)

    reader = rs[0]
    for r in rs:
        if any(k in str(r).lower() for k in ["starsign", "g&d", "giesecke"]):
            reader = r
            break
    print(f"\nLeitor: {reader}")

    try:
        conn = reader.createConnection()
        conn.connect()
    except CardConnectionException as e:
        print(f"❌ {e}")
        sys.exit(1)

    atr = conn.getATR()
    print(f"ATR: {hex_str(atr)}\n")

    # -----------------------------------------------------------------------
    # PASSO 1: SELECT AID — entra no contexto PKCS#15
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("  PASSO 1 — Entrando no contexto PKCS#15 via AID")
    print("="*60)

    data, sw1, sw2 = select_aid(conn, AID_PKCS15)
    if sw1 == 0x61:
        data, sw1, sw2 = get_response(conn, sw2)
    if sw1 != 0x90:
        print("❌ Falha ao selecionar AID PKCS#15")
        sys.exit(1)

    # Se retornou FCI (File Control Information), interpreta
    if data:
        print(f"  FCI da aplicação: {hex_str(data)}")
        # Procura tag 84 (AID) e 85 (proprietário)
        _parse_tlv_basic(data)

    # -----------------------------------------------------------------------
    # PASSO 2: Explorar EFs PKCS#15 dentro da aplicação (sem SELECT MF antes)
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("  PASSO 2 — EFs PKCS#15 dentro da aplicação")
    print("="*60)

    # FIDs PKCS#15 padrão (ISO 7816-15 / OpenSC)
    pkcs15_files = [
        ([0x50, 0x00], "EF.ODF",        "Object Directory File — lista todos os objetos"),
        ([0x50, 0x04], "EF.TokenInfo",  "Informações do token (label, serial, etc.)"),
        ([0x50, 0x05], "EF.AODF",       "Authentication Object Directory File"),
        ([0x50, 0x08], "EF.UnusedSpace","Espaço não usado"),
        ([0x41, 0x01], "EF.PrKDF",      "Private Key Directory File"),
        ([0x41, 0x02], "EF.PuKDF",      "Public Key Directory File"),
        ([0x41, 0x03], "EF.CDF",        "Certificate Directory File ← CERT X.509 AQUI"),
        ([0x41, 0x04], "EF.DODF",       "Data Object Directory File"),
        ([0x31, 0x00], "EF.ODF (alt1)", ""),
        ([0x34, 0x01], "EF.CDF (alt1)", ""),
        ([0x34, 0x02], "EF.PrKDF (alt1)",""),
        ([0xC0, 0x00], "EF.ODF (alt2)", ""),
        ([0x00, 0x01], "EF.ODF (alt3)", ""),
        ([0x00, 0x02], "EF.TokenInfo (alt)",""),
    ]

    encontrados = []
    for fid, nome, desc in pkcs15_files:
        # Tenta SELECT sem retornar FCI (P2=0C = no response)
        cmd_nc = [0x00, 0xA4, 0x00, 0x0C, 0x02] + fid
        data, sw1, sw2 = apdu(conn, cmd_nc, f"SELECT {nome}")

        if sw1 in (0x90, 0x61):
            encontrados.append((fid, nome, desc))
            print(f"  🎯 ENCONTRADO: {nome}")
            if sw1 == 0x61:
                get_response(conn, sw2)

            # Lê o conteúdo do EF
            content = read_ef_full(conn, label=nome)
            if content:
                _salvar_ef(nome, content)

            # Re-entra na aplicação após leitura
            select_aid(conn, AID_PKCS15)
        else:
            # Tenta também com P1=02 (EF relativo ao DF atual)
            cmd_rel = [0x00, 0xA4, 0x02, 0x0C, 0x02] + fid
            data2, sw1_2, sw2_2 = apdu(conn, cmd_rel, f"SELECT {nome} (relativo)")
            if sw1_2 in (0x90, 0x61):
                encontrados.append((fid, nome, desc))
                print(f"  🎯 ENCONTRADO (relativo): {nome}")
                content = read_ef_full(conn, label=nome)
                if content:
                    _salvar_ef(nome, content)
                select_aid(conn, AID_PKCS15)

        time.sleep(0.03)

    # -----------------------------------------------------------------------
    # PASSO 3: Se encontrou ODF, parseia para descobrir FIDs reais
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("  PASSO 3 — Descoberta de objetos via ODF")
    print("="*60)

    # Tenta GET DATA para listar objetos (alguns cartões suportam)
    apdu(conn, [0x00, 0xCA, 0x01, 0xC0, 0x00], "GET DATA ODF via tag 01C0")
    apdu(conn, [0x80, 0xCA, 0x01, 0x01, 0x00], "GET DATA CLA=80 ODF")

    # -----------------------------------------------------------------------
    # PASSO 4: Testa SELECT por nome (string) — alguns tokens usam isso
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("  PASSO 4 — SELECT por nome de arquivo")
    print("="*60)

    nomes_df = [
        b"PKCS-15",
        b"OpenPGP",
        b"ESIGN",
        b"SCE7",
    ]
    for nome_bytes in nomes_df:
        cmd = [0x00, 0xA4, 0x04, 0x00, len(nome_bytes)] + list(nome_bytes)
        apdu(conn, cmd, f"SELECT nome={nome_bytes!r}")
        select_aid(conn, AID_PKCS15)

    # -----------------------------------------------------------------------
    # PASSO 5: Força leitura de EF sem SELECT (se contexto já correto)
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("  PASSO 5 — READ BINARY sem SELECT (offset absoluto)")
    print("="*60)

    select_aid(conn, AID_PKCS15)
    # Alguns tokens permitem READ BINARY direto no DF selecionado
    apdu(conn, [0x00, 0xB0, 0x00, 0x00, 0xFF], "READ BINARY (root, off=0)")
    apdu(conn, [0x00, 0xB2, 0x01, 0x04, 0xFF], "READ RECORD #1")

    # -----------------------------------------------------------------------
    # RELATÓRIO
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("  RELATÓRIO")
    print("="*60)
    print(f"\n  ATR:  {hex_str(atr)}")
    print(f"  OS:   SCE7 (StarSign Card Engine 7 — G&D JavaCard)")
    print(f"  AID:  {hex_str(AID_PKCS15)}  (PKCS#15 padrão ✅)")
    print(f"\n  Arquivos encontrados: {len(encontrados)}")
    for fid, nome, desc in encontrados:
        print(f"    FID {hex_str(fid):8s}  {nome}")
        if desc:
            print(f"              {desc}")

    if not encontrados:
        print("\n  ⚠️  Nenhum EF encontrado com FIDs padrão.")
        print("  → Próximo passo: rodar pcsc_spy durante operação do SafeSign")
        print("  → Ver: research/pcsc_spy_guide.md")

    conn.disconnect()


def _parse_tlv_basic(data):
    """Interpreta TLV básico da FCI."""
    i = 0
    while i < len(data) - 1:
        tag = data[i]
        if tag in (0x00, 0xFF):
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        tags = {
            0x6F: "FCI Template",
            0x84: "AID",
            0xA5: "Dados proprietários",
            0x87: "Versão da aplicação",
            0x73: "Security Compact TLV",
        }
        nome = tags.get(tag, f"tag {tag:02X}")
        print(f"    TLV {nome}: {hex_str(value)}")
        i += 2 + length


def _salvar_ef(nome, data):
    """Salva conteúdo de EF em arquivo para análise."""
    import os
    out_dir = "/home/diego/Documentos/starsign-driver/research/ef_dumps"
    os.makedirs(out_dir, exist_ok=True)
    fname = nome.replace("/", "_").replace(" ", "_").replace("←", "").strip() + ".bin"
    path = os.path.join(out_dir, fname)
    with open(path, "wb") as f:
        f.write(bytes(data))
    print(f"  💾 Salvo: {path}")


if __name__ == "__main__":
    main()
