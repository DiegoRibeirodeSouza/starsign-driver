#!/usr/bin/env python3
"""
=============================================================================
starsign_proto.py — Fase 2: Protótipo Python sem SafeSign
=============================================================================
Conecta ao G&D StarSign CUT S via pyscard puro (sem libaetpkss.so),
autentica com PIN e executa assinatura digital RSA-SHA256.

Sequência baseada em APDUs reais capturados via `pcscd --apdu`
em 2026-08-03 durante operação de assinatura com SafeSign 4.7.0.0.

USO:
  python3 proto/starsign_proto.py [arquivo_a_assinar]
  python3 proto/starsign_proto.py --test-only
  STARSIGN_VERBOSE=1 python3 proto/starsign_proto.py

DEPENDÊNCIA: pip install pyscard
=============================================================================
"""

import sys
import os
import getpass
import hashlib
import argparse
import subprocess
import tempfile

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
    from smartcard.Exceptions import CardConnectionException, NoCardException
except ImportError:
    print("[ERRO] Execute: pip install pyscard")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constantes — confirmadas via pcscd --apdu (2026-08-03)
# ---------------------------------------------------------------------------

# AID da aplicação PKCS#15 no token
AID_PKCS15 = [0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35]

# Handshake DRM: o cartão exige que o driver envie esta string via PUT DATA
# antes de aceitar qualquer operação. Sem criptografia — é um string literal.
# Descoberto: APDU 00 DA 01 00 3C + string abaixo → SW 90 00 após SELECT AID.
DRM_STRING = b"I am A.E.T. Europe B.V. SafeSign or BlueX approved software."

# Referência do PIN de usuário confirmada no log: P2=0x02
PIN_P2 = 0x02

# Tamanho máximo do PIN no token (campo do VERIFY: Lc=0x0F)
PIN_MAX_LEN = 15

# ID da chave privada ativa (label do cert em ASCII = bytes do ID)
# "DIEGO RIBEIRO DE SOUZA 2024-10-09 20:22:25"
KEY_ID = bytes.fromhex(
    "444945474f205249424549524f20444520534f555a41"
    "20323032342d31302d30392032303a32323a3235"
)

# DigestInfo header para SHA-256 (PKCS#1 v1.5, RFC 3447)
# Lc total = 19 (header) + 32 (hash) = 51 = 0x33 — confirmado no log
DIGEST_INFO_SHA256_PREFIX = bytes([
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20
])

VERBOSE = bool(os.environ.get("STARSIGN_VERBOSE"))


# ---------------------------------------------------------------------------
# Primitivas APDU
# ---------------------------------------------------------------------------

class APDUError(Exception):
    """Erro de status word não esperada."""
    def __init__(self, sw1, sw2, msg=""):
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw = (sw1 << 8) | sw2
        super().__init__(msg or f"SW={sw1:02X}{sw2:02X}")


def tx(conn, apdu: list, label: str = "") -> tuple:
    """
    Transmite um APDU e retorna (data_bytes, sw1, sw2).
    Imprime detalhes quando STARSIGN_VERBOSE=1.
    """
    data, sw1, sw2 = conn.transmit(apdu)
    if VERBOSE:
        cmd = " ".join(f"{b:02X}" for b in apdu)
        resp = " ".join(f"{b:02X}" for b in data) if data else ""
        tag = f"[{label}]" if label else "[APDU]"
        print(f"  {tag}")
        print(f"  → {cmd}")
        print(f"  ← SW={sw1:02X}{sw2:02X}  {resp[:80]}")
    return bytes(data), sw1, sw2


def tx_ok(conn, apdu: list, label: str = "") -> bytes:
    """Transmite e exige SW=90 00. Lança APDUError caso contrário."""
    data, sw1, sw2 = tx(conn, apdu, label)
    if sw1 == 0x90 and sw2 == 0x00:
        return data
    raise APDUError(sw1, sw2, f"{label}: SW={sw1:02X}{sw2:02X}")


def tx_ok_or(conn, apdu: list, label: str = "", also_ok: set = None) -> bytes:
    """Transmite e aceita SW=9000 ou qualquer SW em `also_ok`."""
    also_ok = also_ok or set()
    data, sw1, sw2 = tx(conn, apdu, label)
    sw = (sw1 << 8) | sw2
    if sw == 0x9000 or sw in also_ok:
        return data
    raise APDUError(sw1, sw2, f"{label}: SW={sw1:02X}{sw2:02X}")


def read_binary_full(conn, size: int = None, chunk: int = 0xFE, cla: int = 0x00) -> bytes:
    """
    Lê o EF selecionado completo.
    Se `size` for None, lê até receber menos bytes que o pedido ou erro.
    """
    result = bytearray()
    offset = 0
    max_read = size if size else 0x8000
    while offset < max_read:
        n = min(chunk, max_read - offset)
        p1 = (offset >> 8) & 0x7F
        p2 = offset & 0xFF
        cmd = [cla, 0xB0, p1, p2, n]
        data, sw1, sw2 = conn.transmit(cmd)
        if sw1 == 0x6C:
            # Token indica o tamanho real via SW2
            cmd[-1] = sw2
            data, sw1, sw2 = conn.transmit(cmd)
        if sw1 != 0x90 or not data:
            break
        result.extend(data)
        offset += len(data)
        if len(data) < n:
            break  # fim do arquivo
    return bytes(result)


# ---------------------------------------------------------------------------
# Sequência de conexão — exatamente como capturado
# ---------------------------------------------------------------------------

def get_starsign_reader():
    """Retorna o leitor G&D StarSign CUT S (ou o primeiro disponível)."""
    rs = readers()
    if not rs:
        print("❌ Nenhum leitor PC/SC encontrado.")
        print("   Verifique: systemctl status pcscd")
        sys.exit(1)
    for r in rs:
        name = str(r).lower()
        if any(k in name for k in ["starsign", "giesecke", "g&d"]):
            return r
    print(f"⚠  Leitor StarSign não encontrado — usando: {rs[0]}")
    return rs[0]


def connect(reader):
    """Conecta ao cartão e retorna a conexão."""
    try:
        conn = reader.createConnection()
        conn.connect()
        return conn
    except (CardConnectionException, NoCardException) as e:
        print(f"❌ Falha ao conectar ao token: {e}")
        sys.exit(1)


def drm_handshake(conn):
    """
    Handshake DRM obrigatório.

    Sequência capturada (APDUs 1–3 do log):
      C→T  00 DA 01 00 3C [string]   → SW 6D 00  (antes do SELECT, ignorar)
      C→T  00 A4 04 00 0C [AID] 00   → SW 49 20...90 00  (challenge do applet)
      C→T  00 DA 01 00 3C [string]   → SW 90 00  ✅ autenticado

    O cartão aceita qualquer software que envie essa string exata.
    Sem criptografia assimétrica — é segurança por obscuridade.
    """
    drm_apdu = [0x00, 0xDA, 0x01, 0x00, len(DRM_STRING)] + list(DRM_STRING)
    select_apdu = [0x00, 0xA4, 0x04, 0x00, len(AID_PKCS15)] + AID_PKCS15 + [0x00]

    # 1ª PUT DATA — SW 6D 00 esperado (applet ainda não está ativo)
    tx(conn, drm_apdu, "DRM PUT DATA (1)")

    # SELECT AID — ativa o applet, que responde com texto de desafio
    tx(conn, select_apdu, "SELECT AID PKCS#15")

    # 2ª PUT DATA — agora deve responder SW 90 00
    data, sw1, sw2 = tx(conn, drm_apdu, "DRM PUT DATA (2)")
    if sw1 != 0x90:
        raise APDUError(sw1, sw2, f"DRM handshake falhou: SW={sw1:02X}{sw2:02X}")

    if VERBOSE:
        print("  ✅ DRM handshake concluído")


def open_logical_channel_1(conn) -> int:
    """
    Abre o canal lógico 1 para operações PKCS#15.

    Sequência capturada (APDUs 25–27):
      C→T  00 A4 00 0C 02 3F 00   → SELECT MF
      C→T  00 70 00 00 01         → MANAGE CHANNEL → resposta: 01 90 00

    Retorna o número do canal alocado (deve ser 1).
    """
    # SELECT MF no canal 0
    tx_ok(conn, [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00], "SELECT MF")

    # MANAGE CHANNEL — abre canal lógico
    data, sw1, sw2 = tx(conn, [0x00, 0x70, 0x00, 0x00, 0x01], "MANAGE CHANNEL")
    if sw1 != 0x90:
        raise APDUError(sw1, sw2, "MANAGE CHANNEL falhou")

    canal = data[0] if data else 1
    if VERBOSE:
        print(f"  ✅ Canal lógico {canal} aberto")
    return canal


def init_pkcs15_channel1(conn):
    """
    Inicializa o contexto PKCS#15 no canal lógico 1.

    Sequência capturada (APDUs 29–34):
      C→T  01 A4 04 00 0C [AID] 00   → SELECT AID (canal 1)
      C→T  01 A4 00 0C 02 3F 00      → SELECT MF (canal 1)
      C→T  01 A4 00 0C 02 50 31      → SELECT DF 5031
    """
    select_aid_ch1 = [0x01, 0xA4, 0x04, 0x00, len(AID_PKCS15)] + AID_PKCS15 + [0x00]
    tx_ok(conn, select_aid_ch1, "SELECT AID (canal 1)")
    tx_ok(conn, [0x01, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00], "SELECT MF (canal 1)")
    tx_ok(conn, [0x01, 0xA4, 0x00, 0x0C, 0x02, 0x50, 0x31], "SELECT DF 5031 (canal 1)")


def read_retry_counter(conn) -> int:
    """
    Lê contador de tentativas do PIN SEM consumir nenhuma.
    VERIFY sem dados (Lc ausente) → SW 63 Cx onde x = tentativas restantes.
    Retorna -1 se já autenticado, 0 se bloqueado.
    """
    cmd = [0x01, 0x20, 0x00, PIN_P2]
    data, sw1, sw2 = tx(conn, cmd, "VERIFY (ler contador)")
    if sw1 == 0x63:
        return sw2 & 0x0F
    if sw1 == 0x90:
        return -1  # já autenticado
    if sw1 == 0x69 and sw2 == 0x83:
        return 0   # PIN bloqueado
    return -1


def verify_pin(conn, pin: str):
    """
    Autentica o PIN.

    Sequência exata capturada (APDU 63 do log):
      C→T  01 20 00 02 0F [PIN_ASCII + zeros até 15 bytes]
           ↑CLA=01  ↑P2=02  ↑Lc=0F=15

    O SafeSign usa padding NUL (zeros), não 0xFF nem BCD.
    """
    pin_bytes = list(pin.encode('ascii'))
    if len(pin_bytes) > PIN_MAX_LEN:
        raise ValueError(f"PIN muito longo (max {PIN_MAX_LEN} caracteres)")

    padding = [0x00] * (PIN_MAX_LEN - len(pin_bytes))
    apdu = [0x01, 0x20, 0x00, PIN_P2, PIN_MAX_LEN] + pin_bytes + padding

    data, sw1, sw2 = tx(conn, apdu, "VERIFY PIN")

    if sw1 == 0x90:
        return  # ✅ OK

    if sw1 == 0x63:
        tentativas = sw2 & 0x0F
        raise APDUError(sw1, sw2,
            f"PIN incorreto. Tentativas restantes: {tentativas}. "
            f"OPERAÇÃO ABORTADA por segurança.")

    if sw1 == 0x69 and sw2 == 0x83:
        raise APDUError(sw1, sw2, "PIN BLOQUEADO.")

    raise APDUError(sw1, sw2, f"VERIFY PIN falhou: SW={sw1:02X}{sw2:02X}")


# ---------------------------------------------------------------------------
# Assinatura digital
# ---------------------------------------------------------------------------

def sign_sha256_rsa(conn, data_to_sign: bytes) -> bytes:
    """
    Assina `data_to_sign` usando SHA-256 + RSA PKCS#1 v1.5.

    Sequência exata capturada (APDUs 95–98 do log):

    1. MSE SET — seleciona chave e algoritmo:
       C→T  01 22 41 B6 06  84 01 01  80 01 02
            ↑CLA=01  ↑P1=41=SET ↑P2=B6=Sig
            84 01 01 = key ref 0x01
            80 01 02 = algorithm 0x02 (SHA256withRSA)

    2. PSO: COMPUTE DIGITAL SIGNATURE:
       C→T  01 2A 9E 9A 33  [DigestInfo(SHA-256, 51 bytes)]
            ↑CLA=01         ↑Lc=0x33=51
       T→C  [256 bytes RSA-2048 signature]  90 00

    O token faz hash+RSA internamente com os dados do DigestInfo.
    """
    # MSE SET — confirmado no log (linha 95)
    mse_set = [
        0x01, 0x22, 0x41, 0xB6, 0x06,   # CLA INS P1 P2 Lc
        0x84, 0x01, 0x01,                # key reference = 0x01
        0x80, 0x01, 0x02,                # algorithm = 0x02 (SHA256withRSA on card)
    ]
    tx_ok(conn, mse_set, "MSE SET (SHA256withRSA, key ref=01)")

    # Calcula SHA-256 dos dados
    sha256_hash = hashlib.sha256(data_to_sign).digest()

    # Monta DigestInfo (PKCS#1 v1.5 wrapper)
    payload = list(DIGEST_INFO_SHA256_PREFIX) + list(sha256_hash)
    assert len(payload) == 0x33, f"DigestInfo deve ter 51 bytes, tem {len(payload)}"

    # PSO: COMPUTE DIGITAL SIGNATURE — confirmado no log (linha 97)
    pso = [0x01, 0x2A, 0x9E, 0x9A, len(payload)] + payload
    data, sw1, sw2 = tx(conn, pso, "PSO COMPUTE DIGITAL SIGNATURE")

    if sw1 == 0x90:
        return bytes(data)  # 256 bytes

    if sw1 == 0x61:
        # GET RESPONSE para receber o restante
        get_resp = [0x01, 0xC0, 0x00, 0x00, sw2]
        return tx_ok(conn, get_resp, "GET RESPONSE (assinatura)")

    raise APDUError(sw1, sw2, f"PSO SIGN falhou: SW={sw1:02X}{sw2:02X}")


# ---------------------------------------------------------------------------
# Verificação da assinatura com OpenSSL
# ---------------------------------------------------------------------------

def extract_public_key_from_token(conn) -> bytes | None:
    """
    Tenta extrair o certificado X.509 do token para verificar a assinatura.
    O certificado está no EF identificado pelo ID da chave ativa.

    Retorna o DER do certificado, ou None se não conseguir.
    """
    # Seleciona o EF de certificado principal (mapeado na análise)
    # EF 44 00 contém o cert da chave ativa (confirmado no log)
    try:
        data, sw1, sw2 = tx(conn,
            [0x01, 0xA4, 0x02, 0x00, 0x02, 0x44, 0x00, 0x00],
            "SELECT EF cert ativo")
        if sw1 != 0x90:
            return None
        # O certificado costuma ter mais de 1024 bytes (0x400). Lê o EF inteiro.
        # Usa cla=0x01 pois o EF foi selecionado no canal lógico 1.
        cert_der = read_binary_full(conn, size=None, cla=0x01)
        return cert_der if cert_der else None
    except Exception:
        return None


def verify_signature_openssl(data: bytes, signature: bytes, cert_der: bytes) -> bool:
    """Verifica a assinatura com openssl (requer openssl no PATH)."""
    try:
        with (
            tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as fsig,
            tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as fdat,
            tempfile.NamedTemporaryFile(suffix=".der", delete=False) as fcert,
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as fpub,
        ):
            fsig.write(signature); fsig.flush()
            fdat.write(data);      fdat.flush()
            fcert.write(cert_der); fcert.flush()

            # Extrai chave pública do certificado
            result = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-in", fcert.name,
                 "-pubkey", "-noout"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                return False
            fpub.write(result.stdout.encode()); fpub.flush()

            # Verifica assinatura
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", fpub.name,
                 "-signature", fsig.name, fdat.name],
                capture_output=True, text=True
            )
            return result.returncode == 0
    except Exception:
        return False
    finally:
        for f in [fsig.name, fdat.name, fcert.name, fpub.name]:
            try:
                os.unlink(f)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Fluxo principal
# ---------------------------------------------------------------------------

def run(args):
    print("=" * 60)
    print("  starsign-driver — Fase 2: Protótipo Python")
    print("  G&D StarSign CUT S — sem SafeSign (pyscard puro)")
    print("=" * 60)

    # [1] Leitor e conexão
    reader = get_starsign_reader()
    print(f"\n[1] Leitor: {reader}")
    conn = connect(reader)
    atr = conn.getATR()
    print(f"    ATR: {toHexString(atr)}")

    if args.test_only:
        print("\n    Modo --test-only: conexão OK. Encerrando.")
        conn.disconnect()
        return

    # [2] Handshake DRM
    print("\n[2] Handshake DRM...")
    drm_handshake(conn)
    print("    ✅ Driver autenticado pelo applet")

    # [3] Canal lógico 1
    print("\n[3] Abrindo canal lógico 1...")
    canal = open_logical_channel_1(conn)
    print(f"    ✅ Canal {canal} alocado")

    # [4] Inicializar PKCS#15 no canal 1
    print("\n[4] Inicializando PKCS#15 no canal 1...")
    init_pkcs15_channel1(conn)
    print("    ✅ DF 5031 selecionado")

    # [5] Verificar contador de tentativas antes de pedir PIN
    print("\n[5] Verificando contador de PIN...")
    tentativas = read_retry_counter(conn)
    if tentativas == 0:
        print("    ❌ PIN BLOQUEADO. Use o tokenadmin para desbloquear.")
        conn.disconnect()
        sys.exit(1)
    if tentativas > 0:
        print(f"    Tentativas restantes: {tentativas}")
        if tentativas <= 2:
            print("    ❌ Muito poucas tentativas. Abortado por segurança.")
            conn.disconnect()
            sys.exit(1)

    # [6] Autenticação PIN
    print("\n[6] Autenticação...")
    pin = getpass.getpass("    Digite o PIN do token: ")
    if not pin:
        print("    PIN vazio. Abortando.")
        conn.disconnect()
        sys.exit(1)

    try:
        verify_pin(conn, pin)
        print("    ✅ PIN aceito")
    except APDUError as e:
        print(f"\n    ❌ {e}")
        conn.disconnect()
        sys.exit(1)
    finally:
        pin = "\x00" * len(pin)  # zera o PIN da memória (best-effort)

    # [7] Assinatura
    if args.no_sign:
        print("\n    --no-sign: pulando assinatura.")
    else:
        # Determina os dados a assinar
        if args.input_file:
            with open(args.input_file, "rb") as f:
                data_to_sign = f.read()
            print(f"\n[7] Assinando: {args.input_file} ({len(data_to_sign)} bytes)")
        else:
            data_to_sign = b"teste de assinatura starsign-driver open source"
            print(f"\n[7] Assinando dados de teste ({len(data_to_sign)} bytes)")

        try:
            signature = sign_sha256_rsa(conn, data_to_sign)
        except APDUError as e:
            print(f"\n    ❌ Falha na assinatura: {e}")
            conn.disconnect()
            sys.exit(1)

        print(f"    ✅ Assinatura gerada: {len(signature)} bytes")

        # Salva a assinatura
        out_path = args.output_file or "/tmp/starsign_assinatura.sig"
        with open(out_path, "wb") as f:
            f.write(signature)
        print(f"    ✅ Salva em: {out_path}")

        # Verificação com OpenSSL
        print("\n[8] Verificando assinatura com OpenSSL...")
        cert_der = extract_public_key_from_token(conn)
        if cert_der:
            ok = verify_signature_openssl(data_to_sign, signature, cert_der)
            if ok:
                print("    ✅ Assinatura verificada com sucesso!")
            else:
                print("    ⚠  Verificação falhou (pode ser problema no cert lido)")
        else:
            # Verificação manual sem o cert
            print("    (certificado não extraído — verificação manual):")
            print(f"    openssl dgst -sha256 -verify pubkey.pem "
                  f"-signature {out_path} {args.input_file or '/tmp/dado.txt'}")

    conn.disconnect()
    print("\n  Conexão encerrada. ✅")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="starsign-driver — Protótipo Fase 2 (sem SafeSign)"
    )
    parser.add_argument(
        "--test-only", action="store_true",
        help="Só testa conexão e ATR, sem PIN"
    )
    parser.add_argument(
        "--no-sign", action="store_true",
        help="Faz login mas pula a assinatura"
    )
    parser.add_argument(
        "-i", "--input-file", metavar="ARQUIVO",
        help="Arquivo a assinar (padrão: dados de teste)"
    )
    parser.add_argument(
        "-o", "--output-file", metavar="SAÍDA",
        help="Onde salvar a assinatura (padrão: /tmp/starsign_assinatura.sig)"
    )
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
