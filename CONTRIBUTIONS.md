# Histórico de Contribuições (Upstream)

Este documento registra as contribuições oficiais derivadas da engenharia reversa do driver nativo G&D StarSign CUT S.

## 1. OpenSC (Driver Nativo)
- **Data:** Agosto de 2026
- **Status:** Pull Request Aberto (Aguardando Revisão)
- **Link Oficial:** [PR #3764 - feat: Add native driver for G&D StarSign CUT S](https://github.com/OpenSC/OpenSC/pull/3764)
- **Issue Relacionada:** Fechou a Issue #2580 (*Giesecke & Devrient GmbH StarSign CUT S Unsupported card*) que estava aberta há dois anos.
- **Descrição:** O código fonte do driver `card-starsign.c` desenvolvido neste repositório foi extraído, adaptado e submetido diretamente para o projeto global OpenSC. Isso permitirá que todas as distribuições Linux do mundo passem a reconhecer o token nativamente via `opensc-pkcs11.so`, sem depender do middleware proprietário SafeSign.

## 2. Debian Bug Tracker
- **Bug Investigado:** [#1125519 - GnuTLS / SafeSign IC module incompatibility](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1125519)
- **Ação:** Nenhuma ação direta via e-mail foi necessária.
- **Motivo:** O bug em questão (aberto em Janeiro de 2026) referia-se a um erro de bloqueio de thread no GnuTLS ao lidar com o driver proprietário falho (`libaetpkss.so`). A comunidade GnuTLS corrigiu o erro internamente (fazendo fallback). Como a nossa solução ataca a raiz do problema no hardware e substitui o middleware via OpenSC, a correção chegará ao Debian automaticamente através dos pacotes oficiais do OpenSC no futuro. O ticket no Debian já havia sido devidamente arquivado e trancado.
