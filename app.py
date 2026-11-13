"""
Лабораторная работа №2. Уязвимое веб-приложение на Flask.

Реализованы две учебные уязвимости из OWASP Top 10 (2021):

1. A03:2021 - Injection (SQL Injection) -- маршрут /login
   Запрос к базе данных собирается конкатенацией строк, без
   параметризации и без экранирования пользовательского ввода.

2. A01:2021 - Broken Access Control (IDOR,
   Insecure Direct Object Reference) -- маршрут /profile/<user_id>
   Любой аутентифицированный пользователь может запросить профиль
   любого другого пользователя, просто подставив чужой id,
   без проверки, что запрошенный id совпадает с id владельца сессии.

"""

import sqlite3
from pathlib import Path

from flask import Flask, g, request, session, redirect, url_for, render_template_string

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "database.db"

app = Flask(__name__)
app.secret_key = "dev-secret-key-not-for-production"  # демо-ключ, не для прод


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            secret_note TEXT NOT NULL
        );
        """
    )
    db.executemany(
        "INSERT INTO users (username, password, email, secret_note) VALUES (?, ?, ?, ?)",
        [
            ("alice", "alice_pass123", "alice@example.com", "Alice's private note: pet name is Rex"),
            ("bob", "bob_pass456", "bob@example.com", "Bob's private note: bank PIN is 4521"),
            ("admin", "SuperSecretAdminPass!", "admin@example.com", "Admin root token: TOKEN-XJ29K"),
        ],
    )
    db.commit()
    db.close()


LOGIN_PAGE = """
<h2>Вход в систему</h2>
<form method="post">
    Логин: <input name="username"><br>
    Пароль: <input name="password" type="password"><br>
    <input type="submit" value="Войти">
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""

PROFILE_PAGE = """
<h2>Профиль пользователя #{{ user.id }}</h2>
<p>Имя пользователя: {{ user.username }}</p>
<p>Email: {{ user.email }}</p>
<p>Секретная заметка: {{ user.secret_note }}</p>
<p><a href="{{ url_for('logout') }}">Выйти</a></p>
"""


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("profile", user_id=session["user_id"]))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    УЯЗВИМОСТЬ 1 (A03:2021 - Injection, SQL Injection).

    SQL-запрос строится конкатенацией строк из полей формы,
    без параметризованного запроса и без какой-либо фильтрации
    ввода. Это позволяет атакующему внедрить произвольный SQL-код,
    например, обойти проверку пароля с помощью payload вида
    "' OR '1'='1' -- ".
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()
        # НЕБЕЗОПАСНО: конкатенация пользовательского ввода в SQL-запрос
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        cursor = db.execute(query)
        user = cursor.fetchone()

        if user:
            session["user_id"] = user["id"]
            return redirect(url_for("profile", user_id=user["id"]))
        else:
            error = "Неверный логин или пароль"

    return render_template_string(LOGIN_PAGE, error=error)


@app.route("/profile/<int:user_id>")
def profile(user_id):
    """
    УЯЗВИМОСТЬ 2 (A01:2021 - Broken Access Control, IDOR).

    Проверяется только факт, что пользователь аутентифицирован
    (наличие user_id в сессии), но НЕ проверяется, что запрошенный
    user_id совпадает с id владельца текущей сессии. Поэтому любой
    авторизованный пользователь может просмотреть чужой профиль,
    просто подставив другой id в URL.
    """
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return "Пользователь не найден", 404

    return render_template_string(PROFILE_PAGE, user=user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    if not DB_PATH.exists():
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
