# Portal de acesso restrito

Site estático que serve documentos cifrados. O navegador pede uma passphrase,
deriva a chave localmente e decifra o conteúdo em memória. Nada em claro existe
neste repositório, e nada em claro chega ao disco de quem abre a página.

Publicado em GitHub Pages a partir da raiz do ramo `main`.

## Modelo de ameaça

Este repositório é público. O ciphertext é descarregável por qualquer pessoa e
o ataque é **offline**, sem limite de tentativas. Não existe rate-limit,
bloqueio por tentativas ou captcha que sirva de alguma coisa aqui: quem tem os
ficheiros ataca-os na sua própria máquina, ao ritmo que quiser.

A defesa é uma só, e é o produto de dois factores:

    custo por tentativa (Argon2id)  ×  entropia da passphrase

Por isso o `build.mjs` recusa passphrases abaixo de 60 bits de entropia. Uma
KDF cara não compensa uma senha fraca — só torna o ataque mais lento, e "mais
lento" não é "inviável".

O que este esquema **não** faz: impedir que alguém com a passphrase guarde o
documento decifrado. Nenhuma página web o consegue impedir, e fingir o
contrário seria pior do que não prometer nada.

## Esquema

    passphrase --Argon2id(64 MiB, t=4, p=1, salt 16B)--> chave mestra (256 bits)
    chave mestra --HKDF-SHA256(info por documento)-----> chave do documento
    documento --gzip--> AES-256-GCM(aad = nome do ficheiro) --> IV | ct | tag

| Decisão | Porquê |
|---|---|
| **Argon2id**, não PBKDF2 | PBKDF2 é barato de paralelizar: precisa de pouca memória, e por isso GPUs e ASICs escalam bem nele. O Argon2id fica preso à largura de banda de memória — 64 MiB por tentativa, que nenhum atacante consegue contornar comprando mais núcleos. |
| **AES-GCM**, não AES-CBC | GCM é cifra autenticada: ciphertext adulterado é rejeitado em vez de ser decifrado em lixo. Com CBC seria preciso um MAC à parte para ter a mesma garantia. |
| **A tag GCM verifica a senha** | Não há hash de senha publicado. Um atacante não tem nenhum valor derivado, mais barato de testar, para atacar antes de pagar o custo do Argon2id em cada tentativa. |
| **gzip antes de cifrar** | Corta o tamanho a metade e deixa de haver relação entre o tamanho publicado e o tamanho do original. |
| **Chave só em memória** | Não vai para `localStorage` nem `sessionStorage`. Recarregar a página volta a pedir a passphrase. Um "lembrar-me" seria uma chave derivada a dormir no disco de quem abriu a página. |
| **64 MiB e não mais** | Um dos documentos é para telemóvel. Alocações muito maiores falham em aparelhos antigos, e um portal que não abre não protege nada. |
| **Catálogo cifrado** | Os rótulos dos documentos dizem o que está atrás da senha. Ficam no catálogo cifrado; o `vault/manifest.json` em claro só tem parâmetros de criptografia. Os próprios nomes dos ficheiros são derivados do salt. |
| **Nenhum script externo** | O portal não pede nada a CDN nenhum. O JavaScript de terceiros que os documentos usavam foi embutido antes de serem cifrados: um CDN comprometido correria código dentro de conteúdo protegido por senha. |

## O que vive fora deste repositório

Em `../visoleo-source/`, nunca aqui:

| Ficheiro | Conteúdo |
|---|---|
| `*.html` | Os documentos em claro |
| `.env` | `VISOLEO_PASSPHRASE=<passphrase>` |
| `docs.json` | Lista dos documentos: ficheiro, rótulo, nota |
| `leak-markers.json` | Termos que não podem aparecer em claro num ficheiro publicado |
| `.wordlist.txt` | Lista de palavras, para o build estimar a entropia da passphrase |

Isto não é arrumação: é a barreira. Tudo o que está dentro da pasta do repo
acaba publicado mais cedo ou mais tarde — num `git add .` distraído, num zip,
num backup — mesmo estando no `.gitignore`. Fora da pasta, o vazamento passa a
ser estruturalmente impossível em vez de depender de disciplina.

`docs.json` está lá fora pela mesma razão: nomear os documentos e os seus
rótulos num ficheiro público entregaria de graça parte do que a senha protege.

## Construir e publicar

```bash
npm install
npm run build      # gera index.html e vault/
git add -A && git commit -m "..." && git push
```

O build **aborta** — não avisa, aborta — se:

1. Qualquer termo de `leak-markers.json` aparecer em claro num ficheiro
   publicado. A varredura é ao repositório inteiro, não só ao que acabou de ser
   gerado: cifrar um documento não protege nada se o mesmo texto estiver
   legível num ficheiro ao lado.
2. Um marcador não corresponder a nada nos documentos fonte. Um marcador morto
   dá uma sensação falsa de segurança.
3. A ida e volta falhar. Cada blob é decifrado logo a seguir a ser cifrado e
   comparado byte a byte com o original — senão o build pode publicar lixo com
   ar de cifrado.
4. Uma chave errada conseguir decifrar alguma coisa.
5. A passphrase tiver menos de 60 bits de entropia.
6. O código inline do portal contiver uma marca de fecho de script. O parser de
   HTML cortaria o script aí e leria o resto do ficheiro como marcação, sem dar
   erro nenhum: os listeners simplesmente nunca se ligariam.
7. `.env`, `docs.json` ou `leak-markers.json` forem encontrados dentro do repo.

Trocar a passphrase é correr o build outra vez com o `.env` novo. Cada build
gera salt e IVs novos, e por isso também nomes de ficheiro novos dentro de
`vault/`.

## Requisitos do navegador

Chrome, Edge, Firefox ou Safari recentes, por causa de `DecompressionStream` e
da WebCrypto. A página precisa de contexto seguro (HTTPS ou `localhost`) — a
WebCrypto não existe fora dele. Abrir o ficheiro por `file://` não funciona.

## Direitos

Conteúdo proprietário. Todos os direitos reservados, Emergeware Technologies.

O portal embute o [hash-wasm](https://github.com/Daninet/hash-wasm) (Dani Biro,
licença MIT) para o Argon2id, com o aviso de licença preservado no código
gerado.
