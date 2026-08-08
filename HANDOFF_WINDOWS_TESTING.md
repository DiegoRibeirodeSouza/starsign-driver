# Handoff: Testes no Windows

Status: **completo e bem-sucedido**. O driver do StarSign CUT S compila e
funciona corretamente no Windows nativo (MSVC), contra hardware físico,
validado contra plataformas judiciais reais e o validador oficial de
conformidade de assinaturas do Brasil.

Este documento substitui um handoff anterior perdido por corrupção de
sistema de arquivos no pendrive removível onde ele estava, antes destas
notas serem reescritas do zero.

---

## 1. Ambiente de build

Toolchain, seguindo o mesmo caminho oficial de build `win32/` usado pelo CI
upstream (`.github/workflows/windows.yml`):

- **Visual Studio Build Tools 2022** (workload C++ + Windows 11 SDK) —
  fornece `cl.exe`, `link.exe`, `nmake.exe`.
- **vcpkg**, triplet `x64-windows-static` — fornece `openssl` e `zlib`
  estáticos (`libcrypto.lib`, `libssl.lib`, `zs.lib`). Configure
  `VCPKG_INSTALLED` apontando para `vcpkg\installed` antes de rodar o
  `nmake`; o `win32/Make.rules.mak` detecta as libs automaticamente a
  partir daí.
- **CPDK** (Cryptographic Provider Development Kit) — instalado via
  Chocolatey (`choco install windows-cryptographic-provider-development-kit`),
  necessário para o minidriver (`ENABLE_MINIDRIVER` está sempre ligado em
  `win32/Make.rules.mak`, então é obrigatório mesmo para compilar só o
  módulo PKCS#11).

Comando de build, a partir do diretório `OpenSC/`, dentro de um ambiente
`vcvarsall.bat x64`:

```bat
set VCPKG_INSTALLED=C:\vcpkg\installed
nmake /nologo /f Makefile.mak all
```

(`nmake ... opensc.msi` precisa adicionalmente do WiX Toolset; não é
necessário para compilar/testar o driver em si.)

## 2. Bug encontrado: driver nunca compilava no Windows

`card-starsign.c` e `pkcs15-starsign.c` foram adicionados ao `Makefile.am`
(build Unix/autotools) mas **nunca ao `src/libopensc/Makefile.mak`** (build
win32/nmake, mantido como lista de OBJECTS separada). Consequência:
`opensc.dll` falhava ao linkar —

```
ctx.obj : error LNK2001: unresolved external symbol sc_get_starsign_driver
pkcs15-syn.obj : error LNK2001: unresolved external symbol sc_pkcs15emu_starsign_init_ex
```

— o que se propagava em cascata para `opensc_a.lib` e `opensc-pkcs11.dll`
falharem também em diretórios subsequentes (`pkcs11-tool.exe`/`pkcs15-tool.exe`
falhavam ao linkar por um motivo aparentemente não relacionado:
`pkcs11-display.obj` acaba compilado no diretório errado pela regra de
inferência em lote do nmake, quando seu local "real" — `src/pkcs11/pkcs11-display.obj`
— nunca chegou a ser construído por causa da falha anterior em `opensc_a.lib`).

**Correção:** adicionar `card-starsign.obj` e `pkcs15-starsign.obj` à lista
`OBJECTS` em `src/libopensc/Makefile.mak` (mudança de duas linhas). Enviado
diretamente para o branch do PR #3764
(`DiegoRibeirodeSouza/OpenSC@feature/starsign-cut-s-driver`, commit
`06663b372`) e aplicado aqui também.

## 3. Resultados dos testes

### Detecção do token (`opensc-tool`)

```
opensc-tool -l    # -> detecta "Giesecke & Devrient GmbH StarSign CUT S 0"
opensc-tool -n    # -> "G&D StarSign CUT S" (match por ATR)
```

O Windows reconhece o leitor CCID embutido no token nativamente, via driver
genérico de classe USB CCID da Microsoft (`Microsoft Usbccid Smartcard
Reader (WUDF)`) — sem precisar de driver de fabricante.

### Estrutura PKCS#15 (`pkcs15-tool -D`)

Os 4 certificados, os dois PINs (Usuário/SO) e os dois pares de chave
RSA privada/pública são lidos corretamente — saída idêntica em formato à
estrutura já validada no Linux.

### Módulo PKCS#11 (`opensc-pkcs11.dll`)

- `pkcs11-tool -L` / `-O`: slots, certificados e chaves públicas listam
  corretamente.
- `C_Sign` real contra a chave de assinatura atual: `CKR_OK`, assinatura
  RSA-2048 de 256 bytes, cartão aceita com `SW 90 00`.
- **Ressalva encontrada:** a enumeração completa de objetos do
  `pkcs11-tool --test` (percorre uma chave órfã de antes de 2024 sem
  certificado correspondente, depois os 4 certificados) deixa o DF errado
  selecionado quando finalmente chega na chave de assinatura real, e o
  cartão recusa com `SW 6985` (Conditions of use not satisfied). Isso
  **não** é um bug do driver no caminho de uso real — o cartão reutiliza a
  mesma referência de chave bruta (`Key ref: 1`) para múltiplas chaves,
  desambiguadas apenas pelo DF atualmente selecionado. Isolar a chamada de
  assinatura para a única chave real (`pkcs11-tool --sign --id <hex> ...`)
  funciona sem problemas.

### Minidriver do Windows (`opensc-minidriver.dll`)

Compila normalmente contra os headers do CPDK, sem nenhuma mudança de código
além da correção do item 2 — o minidriver em si é genérico/orientado por ATR
e não tem lógica específica de cartão a adicionar.

### Autenticação real

Autenticação bem-sucedida com o token, através do build Windows, em três
plataformas judiciais brasileiras distintas:

- **TRT 3** (Tribunal Regional do Trabalho) — via `pje_headless`.
- **TJMG / PJe** (tribunal estadual) — via `pje_headless`.
- **e-Proc** (sistema da justiça federal) — fala com o token/minidriver
  **diretamente**, não passa pelo `pje_headless`.

O `pje_headless` (serviço Go complementar,
`github.com/DiegoRibeirodeSouza/pje_headless`) foi compilado com
`CGO_ENABLED=1` usando `gcc` do MinGW-w64 (necessário para o binding cgo do
`miekg/pkcs11`), apontado para `opensc-pkcs11.dll` via `PJE_PKCS11_MODULE`
e `PJE_SIGNER_PRIORITY=pkcs11`.

### Assinatura de PDF (pyHanko)

O `test_pdf_sign.py` neste repositório assina um PDF real usando o
[pyHanko](https://github.com/MatthiasValvekens/pyHanko) com seu signer
PKCS#11 contra `opensc-pkcs11.dll`.

**Pegadinha:** o driver só anuncia `SC_ALGORITHM_RSA_HASH_NONE` (ver a seção
sobre DigestInfo no README principal). A seleção de mecanismo *padrão* do
pyHanko para RSA (`CKM_SHA256_RSA_PKCS`, hash feito no próprio token) falha
com `pkcs11.exceptions.MechanismInvalid`. Correção: construir o
`PKCS11Signer` com `use_raw_mechanism=True`, para que o pyHanko calcule o
hash no lado do cliente, monte o bloco DigestInfo ele mesmo, e envie ao
cartão via `CKM_RSA_PKCS` puro — espelhando exatamente o que
`sc_pkcs15_compute_signature` já faz internamente no lado do OpenSC.

O PDF assinado resultante (uma petição judicial real, com várias páginas)
foi verificado contra o **Verificador de Conformidade / ITI** — o validador
oficial de conformidade de assinaturas do governo brasileiro, publicado
pelo ITI (Instituto Nacional de Tecnologia da Informação, a autarquia
federal que opera a raiz da ICP-Brasil). Resultado:

- `Status de assinatura: Aprovado`
- `Caminho de certificação: Valid` (cadeia completa construída até a raiz
  da ICP-Brasil)
- `Cifra assimétrica: Aprovada`
- `Resumo criptográfico: true`
- `Estrutura: Em conformidade com o padrão`

Esse é o sinal mais forte disponível de que o build Windows produz
assinaturas genuinamente conformes ao padrão e aceitáveis pelos tribunais —
não apenas uma assinatura que o *próprio pyHanko* considera internamente
consistente.

## 4. Status upstream

Checklist do PR [#3764](https://github.com/OpenSC/OpenSC/pull/3764)
atualizado: "Windows minidriver is tested" marcado, com um relatório
completo dos resultados acima publicado como comentário no PR. Só resta em
aberto "macOS token is tested" (sem acesso a hardware macOS).

## 5. Reproduzindo o teste de assinatura de PDF

```powershell
python test_pdf_sign.py caminho\para\algum.pdf
```

Edite `TOKEN_LABEL` e `CERT_ID` no topo do script para o seu próprio token
(`pkcs11-tool --module OpenSC\src\pkcs11\opensc-pkcs11.dll -L` e `-O`).
Nunca sobrescreve o arquivo de entrada; escreve `<entrada>_ASSINADO.pdf` ao
lado dele por padrão.
