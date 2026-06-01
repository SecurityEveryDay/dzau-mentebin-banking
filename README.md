# MenteBinaria Banking

Aplicação Flask em Docker para demonstrar, em sala de aula, vulnerabilidades de
aplicação web cobrindo a **tríade CIA** (Confidencialidade, Integridade,
Disponibilidade) e falhas clássicas do OWASP Top 10 (A01 Broken Access Control,
A03 Injection, A04 Insecure Design).

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

OWASP A03:2021 — Injection. O endpoint `/login` monta a query SQL por
**concatenação direta de strings** com o que o usuário envia no formulário, sem
qualquer sanitização ou uso de prepared statements.

Trecho vulnerável em `app.py`:

```python
sql = (
    "SELECT id, nome FROM usuarios "
    "WHERE id = '" + raw_id + "' AND senha = '" + senha + "'"
)
row = DB.execute(sql).fetchone()
```

Como o conteúdo dos dois campos é colocado direto na query, o atacante pode
"fechar" a string com uma aspa simples e injetar lógica SQL arbitrária. O
truque clássico é comentar o resto da query com `--`, eliminando a verificação
de senha.

**Payloads para demonstrar em aula:**

| Campo "Número de cliente"            | Senha           | SQL resultante                                                                   | Efeito                                  |
|--------------------------------------|-----------------|----------------------------------------------------------------------------------|-----------------------------------------|
| `1004' --`                           | qualquer        | `... WHERE id = '1004' --' AND senha = '...'`                                    | login como **admin** (Ana Diretora)     |
| `' OR '1'='1' --`                    | qualquer        | `... WHERE id = '' OR '1'='1' --' AND senha = '...'`                             | login como o primeiro usuário (1001)    |
| qualquer                             | `' OR '1'='1`   | `... WHERE id = '...' AND senha = '' OR '1'='1'`                                 | mesmo efeito, injetando pela senha      |
| `1001' UNION SELECT '1004','Hacker'` | qualquer        | `... UNION SELECT '1004','Hacker' --`                                            | sessão fica com id 1004 sem credenciais |

Roteiro:

1. Acesse a tela de login
2. Em **Número de cliente** digite: `1004' --`
3. Em **Senha** digite qualquer coisa
4. Você cai diretamente na conta da Ana Diretora (admin), sem ter sabido a
   senha real

**Encadeamento com IDOR:** depois do bypass, troque o `?id=` na URL para ver
qualquer outra conta — duas falhas em sequência, ataque realista.

**Detecção via painel `/admin/logs`:** payloads suspeitos com aspas
desbalanceadas geram erro de sintaxe SQL e aparecem como `login_falha` com o
campo `tentativa_id_invalido` preenchido com o que foi enviado.

**Como corrigir** (discussão de aula):

```python
# Prepared statement / parameter binding — SQLite escapa automaticamente
row = DB.execute(
    "SELECT id, nome FROM usuarios WHERE id = ? AND senha = ?",
    (raw_id, senha),
).fetchone()
```

Outras camadas de defesa: ORM (SQLAlchemy), validação de input,
princípio de menor privilégio no usuário do banco, hashing de senha
(bcrypt/argon2), e WAF.

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
