import ipaddress
import json
import os
import random
import sqlite3
import threading
import urllib.request
from datetime import date, datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, session, flash

# ============================================================================
# AMBIENTE DIDÁTICO PROPOSITALMENTE INSEGURO — NÃO USAR EM PRODUÇÃO
# ============================================================================
# Esta aplicação contém vulnerabilidades intencionais usadas em sala de aula
# para demonstrar a tríade CIA (Confidencialidade, Integridade,
# Disponibilidade) e categorias do OWASP Top 10.
#
# VULNERABILIDADES INTENCIONAIS (procure por <<< VULNERABILIDADE >>>):
#   1. IDOR em GET /conta?id=           → Confidencialidade  (A01)
#   2. SQL Injection em POST /login     → Confidencialidade  (A03)
#   3. Parameter Tampering em /recarga  → Integridade        (A04)
#   4. Indisponibilidade em /pix        → Disponibilidade    (demo CIA)
#
# OUTRAS FALHAS PRESENTES (não exploradas em aula, mas dignas de discussão):
#   - Senhas em texto plano (usuarios.txt + tabela usuarios)
#       → Correto: hash com bcrypt/argon2/scrypt + salt único por usuário.
#   - secret_key hardcoded e curta; sessão Flask é só assinada (não cifrada)
#       → Correto: secret_key longa via os.urandom(32), lida de env var.
#   - Sem proteção CSRF nos formulários POST (/cadastro, /recarga, ...)
#       → Correto: Flask-WTF + CSRFProtect, ou tokens manuais.
#   - Sem rate limiting no /login — brute force trivial
#       → Correto: Flask-Limiter, fail2ban, WAF, captcha após N falhas.
#   - X-Forwarded-For lido sem validar proxy de origem
#       → Correto: ProxyFix do Werkzeug atrás de proxy reverso confiável.
#   - debug=True (Werkzeug debugger expõe RCE se PIN for descoberto)
#       → Correto: gunicorn/uwsgi em produção, debug=False.
# ============================================================================

app = Flask(__name__)
app.secret_key = "chave-de-exemplo-aula-idor"

ARQUIVO_USUARIOS = os.path.join(os.path.dirname(__file__), "usuarios.txt")
ARQUIVO_LOGS     = os.path.join(os.path.dirname(__file__), "logs.txt")
ARQUIVO_DB       = os.path.join(os.path.dirname(__file__), "banco.db")

_lock     = threading.Lock()
_log_lock = threading.Lock()
_db_lock  = threading.Lock()
_geo_lock = threading.Lock()

_geo_cache = {}


def _ip_privado(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except (ValueError, TypeError):
        return False


def geolocate_batch(ips):
    """Resolve cidade/país para os IPs informados, usando cache + ip-api.com.

    Retorna dict {ip: {"interna": bool, "country": str|None, "city": str|None}}
    """
    resultado = {}
    a_consultar = []

    for ip in set(ips):
        if not ip:
            continue
        with _geo_lock:
            if ip in _geo_cache:
                resultado[ip] = _geo_cache[ip]
                continue
        if _ip_privado(ip):
            entrada = {"interna": True, "country": None, "city": None}
            with _geo_lock:
                _geo_cache[ip] = entrada
            resultado[ip] = entrada
        else:
            a_consultar.append(ip)

    if a_consultar:
        try:
            body = json.dumps([
                {"query": ip, "fields": "status,country,city,query"}
                for ip in a_consultar
            ]).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                respostas = json.loads(resp.read().decode())
        except Exception:
            respostas = []

        respostas_por_ip = {r.get("query"): r for r in respostas if isinstance(r, dict)}
        for ip in a_consultar:
            r = respostas_por_ip.get(ip, {})
            if r.get("status") == "success":
                entrada = {"interna": False, "country": r.get("country"), "city": r.get("city")}
            else:
                entrada = {"interna": False, "country": None, "city": None}
            with _geo_lock:
                _geo_cache[ip] = entrada
            resultado[ip] = entrada

    return resultado


def is_admin(uid):
    user = USUARIOS.get(uid) if uid is not None else None
    return bool(user and user.get("admin"))


def carregar_usuarios():
    if not os.path.exists(ARQUIVO_USUARIOS):
        return {}
    with open(ARQUIVO_USUARIOS, "r", encoding="utf-8") as f:
        try:
            dados = json.load(f)
        except json.JSONDecodeError:
            return {}
    return {int(u["id"]): u for u in dados}


def salvar_usuarios(usuarios):
    with open(ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(list(usuarios.values()), f, ensure_ascii=False, indent=2)


def proximo_id(usuarios):
    if not usuarios:
        return 1001
    return max(usuarios.keys()) + 1


DESCRICOES_CREDITO = [
    "Salário", "Pix recebido", "Transferência TED recebida",
    "Reembolso", "Devolução de compra", "Rendimento poupança",
    "Resgate CDB", "Cashback Nubank",
]
DESCRICOES_DEBITO = [
    "Supermercado Pão de Açúcar", "Uber", "iFood", "Netflix",
    "Spotify Premium", "Pix enviado", "Conta de luz Enel",
    "Internet Vivo Fibra", "Restaurante", "Posto Shell",
    "Farmácia Drogasil", "Academia SmartFit", "Amazon Prime",
    "AliExpress", "Conta de água Sabesp", "Cinema Cinépolis",
    "Mensalidade faculdade", "Plano de saúde Unimed",
]


def gerar_dados_fakes():
    saldo = round(random.uniform(800, 12500), 2)
    n = random.randint(6, 10)
    transacoes = []
    for _ in range(n):
        dias_atras = random.randint(1, 45)
        dt = (date.today() - timedelta(days=dias_atras)).isoformat()
        if random.random() < 0.3:
            transacoes.append({
                "data": dt,
                "descricao": random.choice(DESCRICOES_CREDITO),
                "valor": round(random.uniform(80, 4800), 2),
            })
        else:
            transacoes.append({
                "data": dt,
                "descricao": random.choice(DESCRICOES_DEBITO),
                "valor": -round(random.uniform(15, 950), 2),
            })
    transacoes.sort(key=lambda t: t["data"], reverse=True)
    return saldo, transacoes


USUARIOS = carregar_usuarios()


def init_db(usuarios):
    db = sqlite3.connect(ARQUIVO_DB, check_same_thread=False)
    db.execute("DROP TABLE IF EXISTS usuarios")
    db.execute("""
        CREATE TABLE usuarios (
            id    TEXT PRIMARY KEY,
            senha TEXT,
            nome  TEXT,
            admin INTEGER DEFAULT 0
        )
    """)
    for u in usuarios.values():
        db.execute(
            "INSERT INTO usuarios (id, senha, nome, admin) VALUES (?, ?, ?, ?)",
            (str(u["id"]), u["senha"], u["nome"], 1 if u.get("admin") else 0),
        )
    db.commit()
    return db


DB = init_db(USUARIOS)


def registrar_log(entry):
    with _log_lock:
        with open(ARQUIVO_LOGS, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def registrar_evento(tipo, **extras):
    entry = {
        "ts":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "evento": tipo,
        "ip":     request.headers.get("X-Forwarded-For", request.remote_addr),
    }
    entry.update(extras)
    registrar_log(entry)


def ler_logs(limite=1000):
    if not os.path.exists(ARQUIVO_LOGS):
        return []
    with open(ARQUIVO_LOGS, "r", encoding="utf-8") as f:
        linhas = f.readlines()
    logs = []
    for linha in linhas[-limite:]:
        linha = linha.strip()
        if not linha:
            continue
        try:
            logs.append(json.loads(linha))
        except json.JSONDecodeError:
            continue
    logs.reverse()
    return logs


@app.context_processor
def injetar_contexto():
    uid = session.get("usuario_id")
    return {
        "usuario_logado": USUARIOS.get(uid),
        "is_admin": is_admin(uid),
    }


@app.before_request
def log_request():
    if request.path.startswith("/static") or request.path.startswith("/admin/logs"):
        return
    uid = session.get("usuario_id")
    nome = USUARIOS[uid]["nome"] if uid in USUARIOS else None
    path = request.full_path
    if path.endswith("?"):
        path = path[:-1]
    registrar_log({
        "ts":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": uid,
        "nome":    nome,
        "method":  request.method,
        "path":    path,
        "ip":      request.headers.get("X-Forwarded-For", request.remote_addr),
    })


@app.route("/")
def index():
    if "usuario_id" in session:
        return redirect(url_for("conta", id=session["usuario_id"]))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        raw_id = request.form.get("id", "")
        senha  = request.form.get("senha", "")

        # =================================================================
        # <<< VULNERABILIDADE: SQL INJECTION — OWASP A03:2021 (Injection) >>>
        # -----------------------------------------------------------------
        # A query é montada por concatenação direta de strings com o input
        # do usuário. Payloads como `1004' --` ou `' OR '1'='1' --` quebram
        # a lógica do WHERE e permitem bypass de autenticação.
        #
        # COMO CORRIGIR — usar prepared statement com bind de parâmetros:
        #
        #   sql = "SELECT id, nome FROM usuarios WHERE id = ? AND senha = ?"
        #   with _db_lock:
        #       row = DB.execute(sql, (raw_id, senha)).fetchone()
        #
        # O driver do SQLite (ou qualquer DB-API) escapa os valores ao fazer
        # o bind, eliminando a injeção independente do conteúdo do input.
        #
        # Defesa em profundidade adicional:
        #   - usar ORM (SQLAlchemy) que parametriza queries por padrão
        #   - armazenar hash de senha (bcrypt/argon2), nunca senha em claro
        #   - princípio de menor privilégio no usuário do banco
        #   - rate limiting + WAF + logs de auditoria
        # =================================================================
        sql = (
            "SELECT id, nome FROM usuarios "
            "WHERE id = '" + raw_id + "' AND senha = '" + senha + "'"
        )
        try:
            with _db_lock:
                row = DB.execute(sql).fetchone()
        except sqlite3.Error:
            registrar_evento("login_falha", user_id=None, tentativa_id_invalido=raw_id)
            flash("ID ou senha inválidos.", "erro")
            return render_template("login.html")

        if row:
            try:
                user_id = int(row[0])
            except (TypeError, ValueError):
                registrar_evento("login_falha", user_id=None, tentativa_id_invalido=raw_id)
                flash("ID ou senha inválidos.", "erro")
                return render_template("login.html")
            session["usuario_id"] = user_id
            registrar_evento("login_sucesso", user_id=user_id, nome=row[1])
            return redirect(url_for("conta", id=user_id))

        registrar_evento("login_falha", user_id=raw_id)
        flash("ID ou senha inválidos.", "erro")
    return render_template("login.html")


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome  = request.form.get("nome", "").strip()
        cpf   = request.form.get("cpf", "").strip()
        email = request.form.get("email", "").strip()
        senha = request.form.get("senha", "")
        senha_conf = request.form.get("senha_confirma", "")

        if not nome or not cpf or not email or not senha:
            flash("Preencha todos os campos.", "erro")
            return render_template("cadastro.html")

        if senha != senha_conf:
            flash("As senhas não coincidem.", "erro")
            return render_template("cadastro.html")

        with _lock:
            global USUARIOS
            USUARIOS = carregar_usuarios()
            novo_id = proximo_id(USUARIOS)
            saldo, transacoes = gerar_dados_fakes()
            USUARIOS[novo_id] = {
                "id": novo_id,
                "senha": senha,
                "nome": nome,
                "cpf": cpf,
                "email": email,
                "saldo": saldo,
                "transacoes": transacoes,
            }
            salvar_usuarios(USUARIOS)

        with _db_lock:
            DB.execute(
                "INSERT INTO usuarios (id, senha, nome, admin) VALUES (?, ?, ?, ?)",
                (str(novo_id), senha, nome, 0),
            )
            DB.commit()

        registrar_evento("cadastro", user_id=novo_id, nome=nome)
        session["usuario_id"] = novo_id
        flash(f"Conta criada com sucesso. Seu número de cliente é {novo_id}.", "alerta")
        return redirect(url_for("conta", id=novo_id))

    return render_template("cadastro.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =====================================================================
# <<< VULNERABILIDADE: IDOR — OWASP A01:2021 (Broken Access Control) >>>
# ---------------------------------------------------------------------
# Insecure Direct Object Reference. O endpoint usa o `id` recebido na
# query string sem verificar se ele pertence ao usuário autenticado na
# sessão. Atacante logado troca `?id=` por qualquer outro ID e acessa
# contas alheias (dados pessoais, saldo, transações).
#
# COMO CORRIGIR — validar autorização antes de devolver o recurso:
#
#   if id_consultado != session["usuario_id"]:
#       abort(403)
#
# Ou, mais expressivo, ignorar o ID da URL e usar apenas o da sessão:
#
#   usuario = USUARIOS.get(session["usuario_id"])
#
# Defesa em profundidade adicional:
#   - usar identificadores não enumeráveis (UUIDs no lugar de IDs sequenciais)
#   - decorator centralizado de autorização (ex.: @requires_owner)
#   - registrar tentativas de acesso a recursos de terceiros (detecção)
# =====================================================================
@app.route("/conta")
def conta():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    id_param = request.args.get("id", session["usuario_id"])
    try:
        id_consultado = int(id_param)
    except ValueError:
        return redirect(url_for("login"))

    # <<< VULNERABILIDADE: nenhum check de autorização aqui >>>
    # (veja bloco acima para a correção)
    usuario = USUARIOS.get(id_consultado)

    if usuario is None:
        return render_template("conta.html", usuario=None, id_consultado=id_consultado), 404

    return render_template("conta.html", usuario=usuario, id_consultado=id_consultado)


# =====================================================================
# Demonstração do pilar CIA: DISPONIBILIDADE
# ---------------------------------------------------------------------
# Não é uma vulnerabilidade explorável — é uma indisponibilidade
# intencional usada para discutir o pilar A da tríade CIA. Em sistemas
# reais a perda de disponibilidade pode vir de DDoS, falha de capacity
# planning, dependência externa caída, deploys mal feitos, etc.
#
# HTTP 503 (Service Unavailable) é o código correto para indicar
# indisponibilidade temporária — clientes/CDNs sabem que podem tentar
# de novo. Em produção, vir acompanhado do header `Retry-After`.
#
# Como mitigar perda de disponibilidade:
#   - redundância (múltiplas instâncias, multi-AZ/multi-região)
#   - circuit breakers e fallback para serviços degradados
#   - autoscaling baseado em métricas
#   - SLOs/SLAs claros e medidos (ex.: 99.9% = ~8h indisponível/ano)
#   - rate limiting / DDoS protection (Cloudflare, AWS Shield, ...)
# =====================================================================
@app.route("/pix")
def pix():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    return render_template("pix.html"), 503


@app.route("/recarga", methods=["GET", "POST"])
def recarga():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    usuario = USUARIOS.get(session["usuario_id"])
    if not usuario:
        return redirect(url_for("login"))

    if request.method == "POST":
        numero = request.form.get("numero", "").strip()
        try:
            valor_credito = float(request.form.get("valor_credito", "0"))
            total_pagar   = float(request.form.get("total_pagar",   "0"))
        except ValueError:
            flash("Dados inválidos.", "erro")
            return render_template("recarga.html", usuario=usuario)

        if not numero:
            flash("Informe o número do celular.", "erro")
            return render_template("recarga.html", usuario=usuario)

        # =================================================================
        # <<< VULNERABILIDADE: PARAMETER TAMPERING — OWASP A04:2021 >>>
        # Pilar CIA: INTEGRIDADE
        # -----------------------------------------------------------------
        # O servidor confia no `total_pagar` enviado pelo cliente em vez
        # de recalcular o preço a partir do `valor_credito`. Atacante
        # intercepta o POST (Burp), mantém `valor_credito=100` e troca
        # `total_pagar=0.01` — recebe R$ 100 de crédito pagando R$ 0,01.
        #
        # COMO CORRIGIR — ignorar o total_pagar do cliente e recalcular
        # server-side a partir de uma tabela de preços autorizada:
        #
        #   PRECOS = {20: 20.00, 30: 30.00, 50: 50.00, 100: 100.00, 200: 200.00}
        #   if int(valor_credito) not in PRECOS:
        #       abort(400)
        #   total_pagar = PRECOS[int(valor_credito)]
        #
        # Princípio: NUNCA confie em dados controláveis pelo cliente para
        # decisões de segurança ou financeiras. Qualquer cálculo de preço,
        # papel/role, permissão, deve ser feito ou validado no servidor.
        #
        # Defesa em profundidade adicional:
        #   - validar saldo suficiente antes de processar
        #   - idempotência (token único por transação)
        #   - HMAC no payload (defesa secundária, não substitui validação)
        #   - alertas para divergências (já implementado em /admin/logs:
        #     recargas com valor_credito != total_pagar viram badge ⚠)
        # =================================================================
        with _lock:
            usuario["saldo"] = round(usuario["saldo"] - total_pagar, 2)
            usuario["transacoes"].insert(0, {
                "data":      date.today().isoformat(),
                "descricao": f"Recarga celular {numero} (R$ {valor_credito:.2f})",
                "valor":     -round(total_pagar, 2),
            })
            salvar_usuarios(USUARIOS)

        registrar_evento(
            "recarga",
            user_id=session["usuario_id"],
            nome=usuario["nome"],
            numero=numero,
            valor_credito=round(valor_credito, 2),
            total_pagar=round(total_pagar, 2),
        )

        flash(
            f"Recarga de R$ {valor_credito:.2f} enviada para o celular {numero}. "
            f"Valor debitado: R$ {total_pagar:.2f}.",
            "alerta",
        )
        return redirect(url_for("conta", id=session["usuario_id"]))

    return render_template("recarga.html", usuario=usuario)


@app.route("/admin/logs")
def admin_logs():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    if not is_admin(session["usuario_id"]):
        return render_template("acesso_negado.html"), 403

    filtro_user   = request.args.get("user_id", "").strip()
    filtro_path   = request.args.get("path", "").strip().lower()
    filtro_evento = request.args.get("evento", "").strip()

    logs = ler_logs()
    if filtro_user:
        logs = [l for l in logs if str(l.get("user_id")) == filtro_user]
    if filtro_path:
        logs = [l for l in logs if filtro_path in (l.get("path") or "").lower()]
    if filtro_evento:
        logs = [l for l in logs if l.get("evento") == filtro_evento]

    geo_by_ip = geolocate_batch([l.get("ip") for l in logs])

    return render_template(
        "admin_logs.html",
        logs=logs,
        filtro_user=filtro_user,
        filtro_path=filtro_path,
        filtro_evento=filtro_evento,
        geo_by_ip=geo_by_ip,
    )


@app.route("/admin/logs/limpar", methods=["POST"])
def admin_logs_limpar():
    if "usuario_id" not in session or not is_admin(session["usuario_id"]):
        return redirect(url_for("login"))
    with _log_lock:
        if os.path.exists(ARQUIVO_LOGS):
            os.remove(ARQUIVO_LOGS)
    flash("Logs apagados.", "alerta")
    return redirect(url_for("admin_logs"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
