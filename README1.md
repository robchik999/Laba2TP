# Лабораторная работа №2. Уязвимости OWASP Top 10, эксплуатация и патч

**Автор:** Вагнер Роберт, группа 5131001/60601

## Структура репозитория

```
.
├── requirements.txt           # зависимости (Flask, requests)
├── vulnerable_app/
│   └── app.py                 # Часть 1: уязвимое веб-приложение на Flask
├── exploits/
│   ├── exploit_sqli.py        # Часть 2: эксплойт SQL Injection
│   └── exploit_idor.py        # Часть 2: эксплойт IDOR
└── patch/
    ├── app_patched.py         # Часть 3: исправленная версия приложения
    └── fix.diff                # Часть 3: патч в формате diff
```

## Часть 1. Уязвимое приложение

Приложение `vulnerable_app/app.py` — простой сервис на Flask с SQLite:
вход по логину/паролю и просмотр профиля пользователя. В нём намеренно
реализованы две уязвимости из OWASP Top 10 (2021):

| № | Категория OWASP Top 10 | Где | Суть |
|---|---|---|---|
| 1 | **A03:2021 – Injection** (SQL Injection) | `/login` | SQL-запрос собирается конкатенацией строк из полей формы без параметризации |
| 2 | **A01:2021 – Broken Access Control** (IDOR) | `/profile/<user_id>` | Не проверяется, что запрошенный `user_id` принадлежит владельцу текущей сессии |

### Запуск приложения

```bash
pip install -r requirements.txt
cd vulnerable_app
python app.py
```

Приложение поднимется на `http://127.0.0.1:5000`. При первом запуске
автоматически создаётся `database.db` с тремя тестовыми пользователями
(`alice`, `bob`, `admin`).

## Часть 2. Эксплуатация уязвимостей

### SQL Injection (`exploits/exploit_sqli.py`)

Отправляет в форму логина payload `' OR '1'='1' -- `, который делает
условие `WHERE username = '...' AND password = '...'` всегда истинным
и позволяет войти в систему без знания пароля.

```bash
python exploits/exploit_sqli.py
```

### IDOR (`exploits/exploit_idor.py`)

Логинится легитимно под пользователем `alice`, а затем, используя ту же
сессию, перебирает `/profile/1`, `/profile/2`, `/profile/3`… и показывает,
что приложение отдаёт чужие профили (включая профиль `admin` с секретным
токеном) без проверки прав доступа.

```bash
python exploits/exploit_idor.py
```

## Часть 3. Патч

`patch/app_patched.py` — исправленная версия приложения:

1. **SQL Injection** устранена переходом на параметризованный запрос
   (`db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))`)
   вместо конкатенации строк.
2. **IDOR** устранён добавлением проверки
   `if user_id != session["user_id"]: abort(403)` в маршруте `/profile/<user_id>`.

Патч в формате unified diff — `patch/fix.diff`. Применить его к исходной
версии можно так:

```bash
cp vulnerable_app/app.py /tmp/app_to_patch.py
patch /tmp/app_to_patch.py < patch/fix.diff
```

### Проверка, что патч закрывает уязвимости

Оба эксплойта из части 2 были повторно запущены против пропатченной
версии (`patch/app_patched.py`):

- `exploit_sqli.py` → `[-] Эксплойт не сработал` — вход по SQL-инъекции
  больше невозможен.
- `exploit_idor.py` → при обращении к чужим `id` сервер возвращает
  `403 Forbidden`, скрипт сообщает `[-] IDOR не подтверждён`.
