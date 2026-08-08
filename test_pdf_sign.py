"""
Teste de assinatura de PDF real usando o token G&D StarSign CUT S
via pyHanko + PKCS#11, usando o driver OpenSC compilado para Windows.

Uso:
    python test_pdf_sign.py <entrada.pdf> [saida.pdf]

O arquivo de entrada nunca e alterado; a assinatura e escrita em um
arquivo novo (por padrao, <entrada>_ASSINADO.pdf).
"""
import getpass
import sys
from pathlib import Path

from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.sign.pkcs11 import PKCS11Signer, open_pkcs11_session
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

REPO_ROOT = Path(__file__).resolve().parent
PKCS11_MODULE = str(REPO_ROOT / "OpenSC" / "src" / "pkcs11" / "opensc-pkcs11.dll")

# Ajuste estes dois valores para o seu proprio token (veja com
# `pkcs11-tool --module opensc-pkcs11.dll -L` e `-O`).
TOKEN_LABEL = "DIEGO RIBEIRO DE SOUZA"
CERT_ID = bytes.fromhex(
    "444945474f205249424549524f20444520534f555a4120323032342d3130"
    "2d30392032303a32323a3235"
)


def main():
    if len(sys.argv) < 2:
        print(f"Uso: python {Path(__file__).name} <entrada.pdf> [saida.pdf]")
        sys.exit(1)

    input_pdf = Path(sys.argv[1])
    output_pdf = Path(sys.argv[2]) if len(sys.argv) > 2 else (
        input_pdf.with_name(input_pdf.stem + "_ASSINADO.pdf")
    )

    print(f"[..] Entrada: {input_pdf}")
    print(f"     (o original NUNCA e alterado; saida vai para: {output_pdf})")

    pin = getpass.getpass("Digite o PIN do token: ")

    print("[..] Abrindo sessao PKCS#11 e fazendo login no token...")
    session = open_pkcs11_session(
        lib_location=PKCS11_MODULE,
        token_label=TOKEN_LABEL,
        user_pin=pin,
    )

    signer = PKCS11Signer(
        pkcs11_session=session,
        cert_id=CERT_ID,
        key_id=CERT_ID,
        # O driver StarSign so anuncia SC_ALGORITHM_RSA_HASH_NONE: o hash e o
        # DigestInfo tem que ser montados em software e mandados prontos para
        # o cartao (CKM_RSA_PKCS), em vez do mecanismo combinado
        # CKM_SHA256_RSA_PKCS (que pede pro cartao fazer o hash - nao suportado).
        use_raw_mechanism=True,
    )

    print("[..] Assinando PDF com a chave do token (isso vai falar com o cartao)...")
    with open(input_pdf, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        append_signature_field(
            w, SigFieldSpec(sig_field_name="Signature1")
        )
        out = signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name="Signature1"),
            signer=signer,
        )

    with open(output_pdf, "wb") as f:
        f.write(out.getbuffer())

    print(f"[OK] PDF assinado escrito em: {output_pdf}")

    print("[..] Validando a assinatura (integridade criptografica)...")
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader

    with open(output_pdf, "rb") as f:
        r = PdfFileReader(f)
        sig = r.embedded_signatures[0]
        vc = ValidationContext(allow_fetching=False, trust_roots=[])
        status = validate_pdf_signature(sig, vc, skip_diff=True)
        print(f"    intact (assinatura bate com o conteudo): {status.intact}")
        print(f"    valid  (assinatura criptograficamente valida): {status.valid}")

    if status.intact and status.valid:
        print("\n=== SUCESSO: assinatura real via token, valida criptograficamente ===")
    else:
        print("\n=== ATENCAO: assinatura gerada mas validacao reportou problema ===")
        sys.exit(1)


if __name__ == "__main__":
    main()
