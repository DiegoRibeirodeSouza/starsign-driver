# Open A3 Driver (OpenSC Native Module)

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![License](https://img.shields.io/badge/license-LGPLv2.1-green.svg)
![Status](https://img.shields.io/badge/status-funcional%20|%20aguardando%20revis%C3%A3o%20upstream-orange.svg)

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

### 3. Bypass de Seleção e a Peculiaridade do Sistema de Arquivos
O StarSign CUT S **rejeita silenciosamente** a instrução `SELECT FILE` se a solicitação de controle FCI for feita no padrão tradicional (`P2=00`). 
Nossa engenharia reversa descobriu empiricamente que ele só aceita `P2=0x0C` (Sem resposta FCI esperada). Sem o FCI, o OpenSC nativo enxergava todos os arquivos com `tamanho = 0`. Para resolver, sobrescrevemos a função `starsign_select_file`:
- Forçamos `P2=0x0C`.
- Injetamos um tamanho fictício grande (`0x8000`) na estrutura do OpenSC. O núcleo do OpenSC (`sc_read_binary`) é inteligente o suficiente para parar a leitura quando atinge o fim do arquivo real.
- Implementamos uma correção automática para caminhos que tentavam retornar à MF (`3F00`), re-selecionando o applet correto (`5015`) para evitar falhas em referências relativas do token.

### 4. Customização de Ambientes de Segurança (MSE) e PIN
O driver original do ISO7816 não montava a APDU do `Manage Security Environment` (MSE) como o chip exigia. Criamos um override em `starsign_set_security_env` para injetar os bytes específicos `84 01 01 80 01 02` para operações de assinatura (`SC_SEC_OPERATION_SIGN`).
Da mesma forma, sobrescrevemos o envio de PIN (`starsign_pin_cmd`) para forçar o parâmetro `P2=0x02` e aplicar um padding fixo de 15 bytes no buffer.

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