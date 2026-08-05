# Registro de Pesquisa e Tentativas: PJe 2.1 e PJeOffice

Este documento registra todas as abordagens e arquiteturas tentadas para fazer a assinatura eletrônica funcionar no ecossistema do PJe 2.1 no Linux, contornando a necessidade de usar os drivers proprietários problemáticos nativamente.

## 1. Abordagem: Emulação via `pje_headless`

**Objetivo:** Modificar o projeto `pje_headless` (em Go) para interceptar as chamadas do frontend Angular do PJe 2.1 e devolver as assinaturas criadas pelo driver Open Source (`opensc-pkcs11.so`) do usuário.

**O que foi feito:**
- O login via Keycloak (Quarkus) funcionava perfeitamente recebendo JSON puro, validando o certificado.
- Ao tentar assinar documentos, o PJe chamava endpoints legados JSF Seam (ex: `arquivoAssinadoUpload.seam`).
- O código do `pje_headless` foi adaptado para reconhecer URLs terminadas em `.seam` e converter o payload de `application/json` para `application/x-www-form-urlencoded`.
- O cabeçalho `Authorization` foi propagado adequadamente.

**O Problema (Bloqueio Técnico):**
- Apesar do envio correto do formulário, o backend do PJe retornava o erro: `Erro:A assinatura do arquivo não foi fornecida!`.
- **Diagnóstico da Causa Raiz:** O PJe 2.1 usa o Keycloak para autenticação em domínio cruzado, mas a aplicação monolítica antiga depende fortemente do cookie `JSESSIONID` para manter a Conversação (o parâmetro `cid=673752` na URL). 
- O frontend Angular manda um envelope JSON para o PJeOffice contendo a chave `sessao`. No entanto, como o cookie `JSESSIONID` costuma ter a flag `HttpOnly`, o Javascript do navegador (Angular) **não consegue lê-lo**. Consequentemente, o envelope chega ao `pje_headless` sem o cookie vital.
- Sem o `JSESSIONID`, a requisição POST do `pje_headless` para o `.seam` chega sem estado. O backend não encontra o arquivo temporário em memória (que estava atrelado à sessão do usuário) e dispara o erro de que a assinatura não foi fornecida.

---

## 2. Abordagem: Isolamento (Sandbox) via Distrobox

**Objetivo:** Abandonar o `pje_headless` e usar o PJeOffice oficial em Java, porém isolando o driver proprietário problemático (`libaetpkss.so`) em um contêiner para não sujar/conflitar com o ecossistema Debian do usuário (que usa o driver OpenSC).

**O que foi feito:**
- Utilizou-se o Distrobox (identificado através do projeto LinuxToys) para criar uma "gaiola" baseada em Debian 12 (`pje_sandbox`).
- O Java (default-jre) e a versão mais recente do instalador do PJeOffice (v2.5.16) foram instalados no contêiner.
- O arquivo do driver proprietário foi movido para um caminho persistente no hospedeiro e acessado pelo contêiner.
- O atalho do PJeOffice foi exportado para o menu do Debian hospedeiro, tornando a integração transparente.
- **Arquitetura validada:** O `pcscd` roda no host gerenciando o hardware e permite multiplexação. O Sudo/Host usa OpenSC e o Contêiner/Java usa o driver Proprietário de forma paralela e simultânea sem choque de porta USB.

**O Problema (Bloqueio Técnico):**
- Ao rodar, o PJeOffice na gaiola só aceitava o driver proprietário (como esperado), mas o ecossistema do driver proprietário da SafeSign se provou fundamentalmente falho/instável na versão Linux, impossibilitando a operação de assinatura mesmo dentro do ambiente "perfeito" do contêiner.
- Vendo que o defeito residia no próprio binário/stack do driver proprietário do tribunal, optou-se por realizar o **rollback total**, destruindo a gaiola do Distrobox e apagando os atalhos.

---

## Conclusão Atual
A arquitetura do PJe 2.1 atual dificulta imensamente a emulação de assinador via *headless* puro devido à mistura de APIs modernas REST (Quarkus) com endpoints antigos stateful (JSF/Seam) e bloqueios de cookies de sessão (`HttpOnly`). Por outro lado, a via de contêineres Linux expõe os problemas crônicos dos drivers proprietários fornecidos para Linux.

**Próximos passos possíveis no futuro:**
- (Para a via Headless) Criar uma extensão de navegador (Chrome/Firefox) que tenha permissão de ler cookies `HttpOnly` e injetá-los no request repassado ao `pje_headless`.
- (Para a via Sandbox) Usar o "WinBoat" (Linux Subsystem for Windows) para criar um contêiner Docker rodando *Windows*, e assim instalar o PJeOffice e o driver Proprietário em suas versões Windows (que são vastamente superiores e mais estáveis).
