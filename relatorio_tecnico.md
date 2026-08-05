# Relatório Técnico: Resolução do Token StarSign no PJe Office Linux

Este documento detalha toda a nossa jornada investigativa e técnica para fazer o Token A3 (StarSign / AET Europe) funcionar no ambiente Linux (Debian) para assinaturas no PJe.

---

## 1. O Problema Original (Bug no Driver OpenSC)
O sistema PJe e os padrões ICP-Brasil exigem assinaturas usando o esquema `NONEwithRSA` (também conhecido como RAW RSA ou `CKM_RSA_X_509` no nível do PKCS#11).
No entanto, o driver de código aberto **OpenSC** nativamente **não declarava suporte** para esse modo no cartão StarSign (`card-starsign.c`). Como resultado, qualquer tentativa de assinatura bruta era rejeitada antes mesmo de chegar no token.

**✅ A Solução Aplicada:**
Nós editamos o código fonte do OpenSC (`src/libopensc/card-starsign.c`), injetamos a flag `SC_ALGORITHM_RSA_RAW` e recompilamos o driver inteiro (`opensc-pkcs11.so`). 
**Resultado:** O token passou a assinar perfeitamente! Nós testamos e validamos a assinatura localmente com sucesso usando o `pkcs11-tool` e o utilitário `pdfsig`. O hardware e o sistema operacional estão comunicando perfeitamente.

---

## 2. O Bloqueio Atual (Bug Estrutural do Java 8 / BouncyCastle)
Apesar do driver agora estar perfeito, o **PJe Office** falha na hora de assinar com o erro:
> `InvalidKeyException: Supplied key (sun.security.pkcs11.P11Key$P11PrivateKey) is not a RSAPrivateKey instance`

**Por que isso acontece?**
1. O PJe Office foi programado e empacotado para rodar em cima do **Java 8**.
2. A implementação nativa do Java 8 para smartcards (`SunPKCS11`) **não possui suporte** ao algoritmo `NONEwithRSA`. (Isso é uma falha conhecida da Oracle, que só foi consertada a partir do Java 11).
3. Como o Java 8 percebe que não sabe lidar com a assinatura, ele repassa a missão para a biblioteca **BouncyCastle** (que vem dentro do PJe).
4. O BouncyCastle tenta executar a assinatura em "software". Para isso, ele tenta **extrair a sua chave privada** de dentro do Token.
5. O Token, por segurança (`CKA_SENSITIVE = TRUE`), recusa entregar a chave privada. O BouncyCastle entra em colapso dizendo que a chave fornecida não é uma chave lida na memória (`is not a RSAPrivateKey instance`).

*Conclusão: O PJe Office oficial rodando no Java 8 é tecnologicamente incapaz de assinar via PKCS11 com o driver OpenSC padrão.*

---

## 3. O Que Tentamos Fazer (O Upgrade para Java 21)
Para fugir do bug do Java 8, nós fizemos uma "cirurgia" no PJe Office:
- Substituímos a máquina virtual Java (JRE) embutida nele pelo seu **Java 21**.
- No Java 21, a Oracle consertou o motor `SunPKCS11`, o que significa que o BouncyCastle não seria mais chamado, evitando o erro!

**Onde estamos agora:**
O PJe Office abriu no Java 21 (aquele aviso `chmod: Operação não permitida` é inofensivo). No entanto, o sistema modular moderno do Java 21 (`Jigsaw`) **bloqueia** funções antigas do Java 8. Nós adicionamos flags (`--add-exports`) para tentar furar esse bloqueio, mas o aplicativo `signer4j` do PJe Office usa "gambiarras" muito profundas no código do Java 8. O bloqueio persiste nas sombras, o que impede que os seus certificados apareçam na lista da interface do PJe.

---

## 4. O Que Falta (Os Próximos Passos)

Como o PJe Office oficial é um software legado e "engessado" no Java 8, continuar hackeando a interface dele para rodar no Java 21 é uma batalha contra o código fechado (e ofuscado) do tribunal.

Nós temos **DUAS alternativas definitivas** a partir de agora:

### Alternativa A: O `pje_headless` (Recomendado ⭐)
Você mencionou sabiamente o repositório `MrSchrodingers/pje_headless`. 
Ele é um aplicativo levíssimo feito em Go, desenhado especificamente para substituir o PJe Office local. 
- Ele simula a mesma API que o navegador espera (na porta `8800`).
- Ele **não usa Java**! Ele fala diretamente com o nosso driver C compilado (`opensc-pkcs11.so`).
- Ele não sofre de bugs de "BouncyCastle" ou "SunPKCS11". Apenas repassa o documento para o token assinar.
**O que falta fazer:** Compilar o código Go dele e testar a assinatura no navegador.

### Alternativa B: Engenharia Reversa no `signer4j`
Se você fizer questão absoluta de usar o PJe Office oficial, a única saída técnica seria:
- Decompilar o `signer4j.jar` ou escrevermos um provedor criptográfico JCA customizado em Java;
- Empacotar ele dentro do PJe Office para que ele assuma o `NONEwithRSA` antes do BouncyCastle e consiga conversar com a chave impenetrável.
*(Nota: É uma rota complexa e sem garantia de estabilidade, pois mexe no core da segurança do app).*

---
**Status Final:** O hardware está livre e funcional graças ao nosso driver. O obstáculo agora é puramente a barreira de software do aplicativo desktop do tribunal.
