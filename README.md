# Open A3 Driver (OpenSC Native Module)

![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)
![License](https://img.shields.io/badge/license-LGPLv2.1-green.svg)
![Status](https://img.shields.io/badge/status-funcional%20%26%20assinatura%20verificada-brightgreen.svg)

Este repositório contém a pesquisa, a engenharia reversa e a implementação final de um driver nativo em C para o **OpenSC**, permitindo o uso do token criptográfico **G&D StarSign CUT S (A3)** em sistemas Linux modernos **sem a necessidade do middleware proprietário SafeSign**.

## A Motivação

O projeto nasceu de uma dor real: a dificuldade extrema de manter o middleware proprietário da A.E.T. Europe (SafeSign) rodando em distribuições Linux modernas (como Debian 13 e Ubuntu 24.04/26.04). 
A instalação da biblioteca proprietária (`libaetpkss.so`) exigia uma verdadeira engenharia de pacotes, com dependências quebradas de versões antigas do `libssl` e `libwxbase`. Além do pesadelo de dependências, identificamos que verificações contínuas de status (polling) causavam o **desligamento sumário** do token devido a bugs de comunicação no middleware proprietário.

A solução definitiva? **Eliminar o SafeSign e criar um driver de código aberto nativo para o OpenSC.**

## Engenharia Reversa e Descobertas Técnicas

O projeto OpenSC já suporta dezenas de smartcards nativamente, mas o G&D StarSign CUT S possuía travas de proteção e peculiaridades no protocolo ISO-7816 que impediam a sua leitura nativa. Iniciamos a engenharia reversa interceptando as chamadas USB e PC/SC (via `pcscd`), desvendando múltiplas barreiras. 

A análise técnica do código (`card-starsign.c`) revela as seguintes inovações essenciais aplicadas ao OpenSC:

### 1. Atestação de Inicialização (Handshake de Compatibilidade)
O token recusava comandos complexos a menos que fosse inicializado com uma atestação textual de que o software em execução é oficial:
`I am A.E.T. Europe B.V. SafeSign or BlueX approved software.`
Nosso driver implementa a injeção exata dessa string em texto puro via comando `PUT DATA` (APDU: `DA 01 00`) logo após o reset do cartão, destravando o acesso ao applet.

### 2. Gestão de Canais Lógicos (Logical Channels)
O applet PKCS#15 recusa operações no canal de comunicação padrão (Canal 0). O driver envia um comando `MANAGE CHANNEL` (`70 00 00`) para abrir um novo canal lógico (Canal 1), forçando todas as APDUs subsequentes no driver a usarem a classe `CLA = 0x01`.

### 3. Bypass de Seleção e Caminhos Virtuais para Certificados/Objetos de Dados
O StarSign CUT S tem duas peculiaridades distintas no tratamento de `SELECT FILE`, ambas reconstruídas por engenharia reversa cruzando o trace de APDUs do nosso driver contra uma captura genuína do middleware proprietário SafeSign 4.7:

- **IDs de arquivo multi-nível usam `P1=0x00`, não `P1=0x01`.** O cartão rejeita `P1=0x01` ("selecionar DF filho") para diretórios especiais, então `starsign_select_file` sempre seleciona pelo File ID puro.
- **Caminhos de certificado e objetos de dados codificam um placeholder fictício `0x3FFF`** (ex.: `3F00 3FFF 4302 05A0`). O cartão responde `SW 6A82` (arquivo não encontrado) se `3FFF` for selecionado diretamente — não é um arquivo real. O componente logo depois dele (ex.: `4302`) **é** um diretório real um nível abaixo do DF da aplicação PKCS#15 (`5031`) e precisa ser selecionado uma vez; selecioná-lo de novo enquanto ele já é o atual *também* falha com `6A82`, então o driver faz cache dele (`starsign_drv_data.mid_fid`) e só reseleciona quando ele de fato muda. O componente final é então endereçado diretamente como EF filho (`P1=0x02`).
- **O tamanho real do arquivo é lido da própria resposta FCP do cartão** (`starsign_parse_fcp_size`) em vez de um valor fixo estimado — necessário para que a checagem de limites `offset + count <= file->size` do `sc_pkcs15_read_file` não rejeite arquivos legitimamente grandes como certificados (até ~1.8 KB), continuando a funcionar para os EFs pequenos de chave/TokenInfo.
- Uma vez que o DF da aplicação PKCS#15 (`5031`) foi selecionado, todo objeto abaixo dele (TokenInfo, EFs de ODF/AODF/PrKDF/CDF/DODF, …) é endereçado como **EF filho direto** em vez de renavegar a partir do MF a cada vez — isso preserva o contexto de "diretório de trabalho" do qual a resolução de caminhos virtuais acima depende.

### 4. Customização de Ambientes de Segurança (MSE)
O driver original do ISO7816 não montava a APDU do `Manage Security Environment` (MSE) exatamente como o chip exigia. Criamos um override em `starsign_set_security_env` para injetar os bytes específicos `84 01 01 80 01 02` para operações de assinatura (`SC_SEC_OPERATION_SIGN`).

### 5. Padding da Assinatura: o cartão omite o `DigestInfo`
As primeiras versões deste driver anunciavam `SC_ALGORITHM_RSA_HASH_SHA256` (e MD5/SHA1), dizendo ao OpenSC "me entregue o hash puro, eu mesmo monto o padding PKCS#1 v1.5 completo *e* o cabeçalho DigestInfo/OID." Decifrar uma assinatura real com a própria chave pública do token mostrou que isso **não era verdade**: o cartão faz o padding do hash cru corretamente (`00 01 FF..FF 00 <hash>`), mas nunca insere o cabeçalho ASN.1 DigestInfo que uma assinatura `SHA256-RSA-PKCS` compatível com o padrão exige — então toda assinatura produzida assim, embora aceita pelo cartão (`SW 90 00`), era criptograficamente inválida e falharia na verificação. A correção foi anunciar apenas `SC_ALGORITHM_RSA_HASH_NONE`, forçando a própria camada de criptografia do OpenSC a montar o bloco DigestInfo + PKCS#1 completo em software e entregar ao cartão um blob já com padding para uma operação RSA crua (`SC_ALGORITHM_RSA_RAW`). Verificado de ponta a ponta: PDFs assinados através do [`litisdoc`](https://github.com/DiegoRibeirodeSouza/litisdoc) (via o assinador de mecanismo raw PKCS#11 do pyHanko) agora voltam do `pdfsig` (Poppler) como `Signature Validation: Signature is Valid.`

### 6. Limitação conhecida: alguns leitores CCID limitam RSA-2048 raw a 261 bytes

Corrigir o item #5 acima (deixar o OpenSC montar o bloco DigestInfo em software) significa que um payload completo de 256 bytes precisa chegar ao cartão numa única operação RSA raw. Em pelo menos uma unidade StarSign CUT S testada, o leitor CCID *embutido* do token falha intermitentemente nessa transferência com `SCardTransmit failed: SCARD_E_INVALID_PARAMETER`, e o `pcscd` registra o motivo claramente:

```
CmdXfrBlockTPDU_T0() Command too long (265 bytes) for max: 261 bytes
```

Isso não é um bug do driver. O próprio descritor USB CCID do leitor (`lsusb -v`) declara um teto de mensagem **fixo no firmware**:

```
dwMaxCCIDMsgLen   271        (≈261 bytes utilizáveis após o cabeçalho CCID)
dwFeatures        ...        apenas "Short APDU level exchange" —
                              sem "Extended APDU level exchange"
```

Mesmo a APDU estendida mais enxuta possível carregando 256 bytes de dados (4 bytes de cabeçalho + 1 byte de marcador estendido + 2 bytes de Lc estendido + 256 bytes = 263 bytes) fica 2 bytes acima desse teto — e o encadeamento de comandos do ISO 7816-4 (command chaining), o workaround usual para payloads grandes demais, é rejeitado de cara por esse cartão (`SW 6E 00`). A única correção real — o cartão fazer hash, padding *e* inserir o DigestInfo corretamente por conta própria, de modo que só um hash de 32 bytes precise atravessar o barramento — não está disponível: ver item #5, o padding no chip não inclui o cabeçalho DigestInfo.

**Efeito prático:** operações RSA-2048 raw (assinatura, decifragem) através desse leitor específico não são 100% confiáveis; podem falhar intermitentemente exatamente nesse limite de bytes e tipicamente têm sucesso ao tentar de novo. É um teto de hardware do controlador CCID, não algo corrigível em `card-starsign.c`. Ver `relatorio_testes_starsign.md` §6 para a investigação completa.

## O Desafio Final: `NONEwithRSA` e o PJe Office

Após o sucesso inicial da leitura do token, nos deparamos com a rejeição da assinatura pelo sistema judiciário brasileiro (**PJe Office**).

### A Restrição do Algoritmo RAW
Para assinar documentos compatíveis com o ICP-Brasil, o sistema exige uma assinatura "bruta", sem formatação prévia de padding via PKCS#11, conhecida como `NONEwithRSA` / `CKM_RSA_X_509`. Os testes mostraram que o G&D StarSign devolvia o erro `67 00` se recebesse hashes já formatados no `C_Sign`.
No código C do nosso driver, ativamos a flag **`SC_ALGORITHM_RSA_RAW`** para os tamanhos de chave (1024, 2048, 4096). Isso capacitou o token a receber hashes crus (RAW RSA) e permitiu ao OpenSC cuidar do padding PKCS#1 de forma compatível.

### O Gargalo do Java 8 e BouncyCastle
Ainda assim, o **PJe Office oficial** travava:
`InvalidKeyException: Supplied key (...) is not a RSAPrivateKey instance`

Descobrimos que a culpa estava a três camadas de distância do hardware:
1. O PJe Office é um aplicativo construído para **Java 8**.
2. O provedor `SunPKCS11` do Java 8 **não suporta `NONEwithRSA`** para smartcards (bug legado).
3. O Java 8 delega a assinatura para a biblioteca de fallback **BouncyCastle**.
4. O BouncyCastle tenta extrair a chave privada do cartão para assinar via software. Como o token impõe `CKA_SENSITIVE = TRUE` (chave inextraível), o sistema entra em colapso.

### A Solução: Integração com `pje_headless`
A barreira final não era o nosso driver, mas o ecossistema legado. Substituímos o cliente oficial pelo [**pje_headless**](https://github.com/MrSchrodingers/pje_headless) (escrito em Go), que remove a dependência do JVM. O `pje_headless` conversa perfeitamente com a nossa compilação nativa do OpenSC (`opensc-pkcs11.so`), eliminando de vez o SafeSign. O uso de tokens no PAM (sudo) também foi restabelecido com absoluto sucesso via módulo PKCS#11.

## Instalação Segura

> [!WARNING]
> Este driver está em processo de submissão ao repositório oficial do OpenSC (upstream). Instalar sobrescrevendo a lib padrão do sistema pode alterar o comportamento de tokens não-StarSign.

**Requisitos Testados:**
- **OS:** Debian 13 / Ubuntu 24.04
- **Token:** G&D StarSign CUT S (ICP-Brasil A3)

### Opção 1: Instalação Fácil (Recomendado)
Acesse a aba **Releases** no GitHub e baixe os pacotes `.deb` pré-compilados.
```bash
sudo apt install ./opensc*.deb
```

### Opção 2: Compilação Manual
Se preferir compilar, use um prefixo customizado para isolar o driver:
```bash
cd OpenSC
./bootstrap
./configure --prefix=/opt/starsign-opensc --enable-pcsc
make
sudo make install
```

### Como usar com o PJe (TJMG / etc)
Devido ao bug do Java 8 com `NONEwithRSA`, **não use o PJeOffice oficial**. Em vez disso, use o excelente cliente em Go, `pje_headless`.
Basta apontar a variável de ambiente para o nosso driver compilado (se você usou os pacotes `.deb`, a biblioteca estará em `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`):

```bash
export PJE_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
./pjeheadless
```

## Agradecimentos (Credits)

- **Comunidade OpenSC:** Pelo fantástico framework de base para comunicação ISO-7816 e PKCS#15.
- **MrSchrodingers / pje_headless:** Pela criação do cliente em Go, que salvou o ICP-Brasil das amarras da JVM legada.
- **Projeto Debian:** Por fornecer as ferramentas e documentações robustas de debug (como `pcscd`) que viabilizaram a engenharia reversa.

## Licença
Este código modifica o OpenSC e herda sua compatibilidade. O projeto e as modificações são distribuídos sob a licença **LGPLv2.1**. (Veja o arquivo `LICENSE` no repositório do OpenSC).