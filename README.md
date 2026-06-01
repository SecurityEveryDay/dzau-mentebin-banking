# MenteBinaria Banking

Aplicação Flask em Docker para demonstrar, em sala de aula, vulnerabilidades de
aplicação web cobrindo a **tríade CIA** (Confidencialidade, Integridade,
Disponibilidade) e duas falhas clássicas do OWASP Top 10.

> Ambiente didático **propositalmente inseguro**. Não deve ser exposto na
> internet nem rodado em produção.

---

## Pré-requisitos

- **Docker** (testado com 29.x)
- **Docker Compose** (v2 — comando `docker compose`)
- Porta **5000** livre na máquina host
- Para a demonstração de SQL Injection e parameter tampering:
  **Burp Suite** (Community Edition serve), proxy configurado no navegador

Nenhum Python local é necessário — todas as dependências são instaladas dentro
do container.

---

## Como subir

```bash
docker compose up --build -d
```

Em seguida, acesse:

<http://localhost:5000>

Para acompanhar os logs do servidor em tempo real:

```bash
docker logs -f banco-mente-idor
```

Para derrubar:

```bash
docker compose down
```

---

## Estrutura do projeto

```
MenteBin/
├── app.py                     # Aplicação Flask + rotas vulneráveis
├── usuarios.txt               # Fonte de verdade dos usuários (JSON)
├── banco.db                   # SQLite gerado automaticamente
├── logs.txt                   # Log de eventos (JSONL, criado em runtime)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── static/
│   └── icon_1.png             # Logo do banco
└── templates/
    ├── base.html
    ├── login.html
    ├── cadastro.html
    ├── conta.html
    ├── recarga.html
    ├── pix.html
    ├── admin_logs.html
    └── acesso_negado.html
```

---

## Usuários iniciais

| ID   | Senha       | Nome           | Papel  |
|------|-------------|----------------|--------|
| 1001 | senha123    | João Silva     | comum  |
| 1002 | maria2026   | Maria Oliveira | comum  |
| 1003 | carlos@pass | Carlos Mendes  | comum  |
| 1004 | admin       | Ana Diretora   | admin  |

Alunos podem se cadastrar em `/cadastro` e recebem IDs sequenciais (1005,
1006, ...). Cada novo cadastro vem com saldo aleatório e transações fake
geradas no momento do registro.

O admin (ID 1004) é o único que enxerga o link **Painel** no menu, com acesso
a `/admin/logs`.

---

## Vulnerabilidades demonstradas

### 1. IDOR (Confidencialidade) — `GET /conta?id=`

O endpoint lê o ID diretamente do parâmetro GET sem comparar com o usuário da
sessão. Após autenticado, altere `?id=` para qualquer outro número e acesse a
conta alheia.

Roteiro:

1. Login com `1001 / senha123`
2. Você cai em `/conta?id=1001`
3. Mude para `?id=1002`, `?id=1003`, `?id=1004` — todos abrem

### 2. SQL Injection (Confidencialidade / Autenticação) — `POST /login`

O `/login` monta a query por concatenação de strings com o que o usuário envia.
Payloads testados:

| Campo "Número de cliente" | Senha          | Efeito                              |
|---------------------------|----------------|-------------------------------------|
| `1004' --`                | qualquer       | login como **admin** (Ana Diretora) |
| `' OR '1'='1' --`         | qualquer       | login como o primeiro usuário       |
| qualquer                  | `' OR '1'='1`  | mesmo efeito, injetando pela senha  |

Após o bypass, o atacante pode encadear com IDOR alterando `?id=` na URL.

### 3. Parameter Tampering (Integridade) — `POST /recarga`

A página de recarga de celular envia ao servidor tanto `valor_credito` (valor
do crédito enviado ao celular) quanto `total_pagar` (valor que será debitado
do saldo). O servidor confia no `total_pagar` recebido, sem recalcular.

Roteiro com Burp Suite:

1. Login normal, clique em **Recarga**
2. Digite um número de celular e selecione R$ 50
3. Intercepte o `POST /recarga` no Burp
4. Modifique apenas `total_pagar` de `50.00` para `0.01`
5. Forward — saldo será debitado em R$ 0,01, mas o crédito de R$ 50 é
   "aplicado" ao celular

### 4. Indisponibilidade (Disponibilidade) — `GET /pix`

Página de Pix retorna HTTP 503 com mensagem "temporariamente indisponível".
Usado em aula para abrir a discussão sobre o pilar de Disponibilidade da CIA
— SLAs, redundância, capacity planning, DDoS, etc.

---

## Painel administrativo de logs

`/admin/logs` (visível só para o usuário 1004) lista todas as requisições e
eventos em tempo real. Cada linha do `logs.txt` é JSONL.

**Eventos especiais registrados:**

| Evento          | Quando                                 | Campos extras                           |
|-----------------|----------------------------------------|-----------------------------------------|
| `login_sucesso` | Senha correta no `/login`              | `user_id`, `nome`                       |
| `login_falha`   | Senha errada / usuário inexistente     | `user_id` (id tentado)                  |
| `login_falha`   | ID enviado não é numérico              | `tentativa_id_invalido`                 |
| `cadastro`      | Nova conta criada via `/cadastro`      | `user_id`, `nome`                       |
| `recarga`       | Recarga processada                     | `numero`, `valor_credito`, `total_pagar`|

**No painel:**

- Badges coloridos por tipo de evento
- Recargas em que `valor_credito != total_pagar` aparecem com badge laranja
  `recarga ⚠` (sinal automático de tampering)
- Filtros por usuário, URL e tipo de evento
- Botão **Apagar logs** para resetar entre turmas

---

## Inspecionando o banco SQLite

O arquivo `banco.db` fica no diretório do projeto, pode ser inspecionado
diretamente:

```bash
sqlite3 banco.db "SELECT id, nome, admin FROM usuarios"
```

Ou pelo container:

```bash
docker exec banco-mente-idor sqlite3 /app/banco.db "SELECT * FROM usuarios"
```

O SQLite é reconstruído a partir do `usuarios.txt` a cada startup. Cadastros
feitos pela aplicação são gravados em ambos.

---

## Resetando o ambiente

Para começar uma nova turma do zero:

```bash
docker compose down
rm -f logs.txt banco.db
# opcional: restaurar usuarios.txt para o seed original (4 usuários)
docker compose up -d
```

Ou simplesmente apague `logs.txt` para zerar o painel sem perder os cadastros.

---

## Roteiro sugerido para uma aula de ~50 minutos

1. **Abertura (5 min)** — apresentar a aplicação como um banco real e a tríade
   CIA.
2. **IDOR (15 min)** — login com 1001, troca de `?id=`, discussão sobre
   Broken Access Control (OWASP A01:2021) e como prevenir.
3. **SQL Injection (15 min)** — bypass com `1004' --`, encadeamento com IDOR,
   discussão sobre prepared statements / parameter binding.
4. **Parameter Tampering (10 min)** — recarga com Burp, integridade,
   server-side validation, princípio "nunca confie no cliente".
5. **Indisponibilidade (3 min)** — clicar em Pix, discutir o pilar A.
6. **Detecção (2 min)** — abrir o painel admin como Ana Diretora, mostrar
   `recarga ⚠`, brute-force aparecendo em `login_falha`, IDOR aparecendo em
   `path = /conta?id=...`.
