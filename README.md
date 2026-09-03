# Cofre

Um gerenciador de senhas pessoal, estático e criptografado no navegador — sem back-end, sem banco de dados, sem servidor. O app roda inteiro em HTML/CSS/JS puro e pode ser hospedado gratuitamente no GitHub Pages.

**[Ver demo ao vivo →](#)** · senha mestra de demonstração: `cofre-demo-2024`

> A demo usa dados fictícios (`vault.json` de exemplo) só para você explorar a interface. Para uso real, cada pessoa gera o próprio cofre com a própria senha mestra — veja "Como usar" abaixo.

## Como funciona

Toda a criptografia acontece no navegador, do lado do cliente:

1. Sua senha mestra nunca é enviada a lugar nenhum — ela existe só na memória da aba enquanto o cofre está aberto.
2. Uma chave AES-256 é derivada da senha mestra via **PBKDF2-SHA256 com 600.000 iterações** (Web Crypto API nativa, sem dependências externas).
3. Todas as entradas (site, usuário, senha, notas) são cifradas com **AES-256-GCM** e salvas em um único arquivo `vault.json`.
4. Esse arquivo cifrado é o único dado que fica no repositório — mesmo em um repositório público, ele é ilegível sem a senha mestra.

```
Senha mestra ──▶ PBKDF2 (600k iterações) ──▶ Chave AES-256
                                                   │
Entradas (JSON) ──▶ AES-256-GCM ──────────────────┴──▶ vault.json (salt + iv + ciphertext)
```

## Recursos

- Criar, editar, buscar e remover entradas
- Gerador de senhas aleatórias fortes
- Copiar senha com um clique
- Funciona em qualquer dispositivo com navegador (desktop e celular)
- Zero dependências — HTML, CSS e JS puros
- Nenhum dado sensível é persistido em `localStorage` ou enviado a qualquer servidor

## Stack

- HTML5 + CSS3 (sem frameworks)
- JavaScript vanilla
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (`SubtleCrypto`) para toda a criptografia

## Estrutura do projeto

```
.
├── index.html    # marcação e estrutura
├── style.css     # visual
├── script.js     # lógica: criptografia, estado do cofre, UI
└── vault.json    # cofre cifrado (gerado pelo app — não editar manualmente)
```

## Como usar (para seu próprio cofre)

1. Faça um fork ou baixe estes três arquivos (`index.html`, `style.css`, `script.js`) para um repositório seu.
2. Ative o GitHub Pages em *Settings → Pages* apontando para a branch e pasta onde estão os arquivos.
3. Abra o link gerado. Como não existe `vault.json` ainda, o app vai te guiar para criar um cofre novo com sua própria senha mestra.
4. Adicione suas senhas, clique em "Baixar cofre atualizado" e faça o commit do `vault.json` gerado no repositório.
5. Pronto — acesse o mesmo link de qualquer dispositivo para consultar ou atualizar suas senhas.

## Nota sobre segurança

Como o GitHub Pages publica o conteúdo publicamente (a menos que você use GitHub Enterprise), o `vault.json` cifrado fica acessível a qualquer pessoa com o link. Isso é seguro *desde que a senha mestra seja forte* — toda a proteção do sistema depende dela resistir a tentativas de força bruta offline contra os 600 mil rounds de PBKDF2. Recomenda-se uma senha mestra longa, única e não reutilizada (ex: uma frase de 5–6 palavras aleatórias).

## Licença

MIT — sinta-se à vontade para usar, estudar e adaptar.
