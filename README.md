# G&D StarSign CUT S - OpenSC Native Driver

Este repositório contém a pesquisa, engenharia reversa e a implementação final de um driver nativo em C para o **OpenSC**, permitindo o uso do token criptográfico **G&D StarSign CUT S (A3)** em sistemas Linux modernos **sem a necessidade do middleware proprietário SafeSign**.

## A Motivação

O projeto nasceu de uma dor real: a dificuldade extrema de manter o middleware proprietário da A.E.T. Europe (SafeSign) rodando em distribuições Linux modernas (como Debian 13 e Ubuntu 24.04/26.04). 
A instalação da biblioteca proprietária (`libaetpkss.so`) exigia uma verdadeira engenharia de pacotes, com dependências quebradas de versões antigas do `libssl` e `libwxbase`. Além do pesadelo de dependências, identificamos que verificações contínuas de status (polling) causavam o **desligamento sumário** do token devido a bugs de comunicação no middleware proprietário.

A solução definitiva? **Eliminar o SafeSign e criar um driver de código aberto nativo para o OpenSC.**

## Engenharia Reversa e Descobertas

O projeto OpenSC já suporta dezenas de smartcards nativamente, mas o G&D StarSign CUT S possuía travas de proteção (DRM) e peculiaridades no protocolo ISO-7816 que impediam a sua leitura nativa. Iniciamos a engenharia reversa interceptando as chamadas USB e PC/SC, desvendando três barreiras principais:

### 1. O "DRM Handshake" (Gate de Licenciamento)
O token recusava comandos complexos a menos que fosse inicializado com uma atestação textual de que o software em execução é oficial:
`I am A.E.T. Europe B.V. SafeSign or BlueX approved software.`
Nosso driver envia esta string exata via um comando `PUT DATA` logo após o reset do cartão (ATR), destravando o acesso ao applet.

### 2. Canais Lógicos (Logical Channels)
O applet PKCS#15 recusa operações no canal de comunicação padrão (Canal 0). O driver envia um comando `MANAGE CHANNEL` para abrir um novo canal lógico (Canal 1), e todas as APDUs subsequentes usam a classe `CLA = 0x01`.

### 3. A Peculiaridade do Sistema de Arquivos
O StarSign CUT S **rejeita** `SELECT FILE` com solicitação de controle FCI (`P2=00`). Ele só aceita `P2=0C` (Sem resposta FCI). Sem o FCI, o OpenSC nativo enxergava todos os arquivos com `tamanho = 0`. Sobrescrevemos a função de seleção de arquivos (`starsign_select_file`) forçando `P2=0x0C` e injetando um "tamanho falso enorme". O núcleo do OpenSC (`sc_read_binary`) é inteligente o suficiente para parar a leitura quando atinge o fim do arquivo.

## A Grande Descoberta Final: O Problema do `NONEwithRSA` e PJe Office

Após o sucesso inicial da leitura do token e do mapeamento dos certificados X.509, nos deparamos com o maior desafio para uso no sistema jurídico brasileiro (ICP-Brasil): a rejeição da assinatura pelo **PJe Office**.

### A Restrição do Algoritmo RAW
Para assinar documentos compatíveis com o ICP-Brasil, o sistema exige uma assinatura "bruta", sem formatação prévia de padding, conhecida tecnicamente como **`NONEwithRSA`** (ou `CKM_RSA_X_509` no PKCS#11).
No código nativo do driver `card-starsign.c`, adicionamos explicitamente a flag **`SC_ALGORITHM_RSA_RAW`** ao registro de algoritmos, o que capacitou o token a receber hashes crus (RAW RSA) e validou a assinatura com sucesso no terminal (`pkcs11-tool --sign`).

### O Gargalo do Java 8 e BouncyCastle
Ainda assim, o **PJe Office oficial** travava com o erro catastrófico:
`InvalidKeyException: Supplied key (sun.security.pkcs11.P11Key$P11PrivateKey) is not a RSAPrivateKey instance`

Descobrimos a causa matriz:
1. O PJe Office é um aplicativo construído para **Java 8**.
2. O provedor `SunPKCS11` do Java 8 **não suporta `NONEwithRSA`** para smartcards.
3. Como o Java 8 falha, ele delega a assinatura para a biblioteca de fallback **BouncyCastle**.
4. O BouncyCastle tenta extrair a chave privada do cartão para assinar via software. Como o token impõe a trava de segurança de chaves inextraíveis (`CKA_SENSITIVE = TRUE`), o BouncyCastle colapsa.

### A Solução Definitiva: `pje_headless`
A barreira final não era o hardware nem o nosso driver C, mas sim o ecossistema legado em Java do tribunal. Para contornar definitivamente o problema, usamos o **`pje_headless`** (escrito em Go, sem dependência do motor Java), que substitui completamente a interface do PJe Office original. O `pje_headless` se comunica nativa e perfeitamente com o nosso módulo recém-compilado, permitindo assinaturas no PJe sem o menor erro, eliminando o SafeSign de vez.

## Instalação e Testes

Para gerar a biblioteca do driver compatível e testar, compile o OpenSC (a flag RAW e os canais lógicos já estão injetados):

```bash
# Compile o módulo
cd OpenSC
./bootstrap
./configure --enable-pcsc
make

# Instale no sistema
sudo cp src/libopensc/.libs/libopensc.so.13 /usr/lib/x86_64-linux-gnu/
sudo cp src/libopensc/.libs/libopensc.so.13.0.0 /usr/lib/x86_64-linux-gnu/
```

Para uso no PJe, recomendamos não utilizar o cliente em Java 8. Baixe, compile e inicialize o serviço [pje_headless](https://github.com/MrSchrodingers/pje_headless), apontando a variável `PJE_PKCS11_MODULE` para o seu `.so` compilado.
