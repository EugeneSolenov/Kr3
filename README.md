# Контрольная работа №3: FastAPI

Проект реализует задания из PDF: Basic Auth, регистрацию с bcrypt-хэшами, JWT-аутентификацию, rate limiting, RBAC, защищённую документацию в DEV, отключённую документацию в PROD и CRUD для Todo в SQLite без SQLAlchemy.

## Установка и запуск

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python create_tables.py
uvicorn main:app --reload
```

Для Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python create_tables.py
uvicorn main:app --reload
```

## Переменные окружения

- `MODE`: `DEV` или `PROD`.
- `DOCS_USER`, `DOCS_PASSWORD`: логин и пароль для `/docs` и `/openapi.json` в DEV.
- `DATABASE_PATH`: путь к SQLite-файлу, по умолчанию `app.db`.
- `JWT_SECRET_KEY`: секретный ключ JWT. В реальном проекте замените значение из примера.
- `JWT_EXPIRE_MINUTES`: срок жизни JWT в минутах.

Файл `.env` добавлен в `.gitignore`, реальные секреты публиковать не нужно.

## Проверка эндпоинтов

### Документация

DEV-режим:

```bash
curl -u valid_user:valid_password http://localhost:8000/docs
curl -u valid_user:valid_password http://localhost:8000/openapi.json
```

PROD-режим:

```bash
MODE=PROD uvicorn main:app --reload
curl http://localhost:8000/docs
```

В PROD `/docs`, `/openapi.json` и `/redoc` возвращают `404 Not Found`.

### Регистрация и Basic Auth

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"correctpass","role":"user"}'

curl -u user1:correctpass http://localhost:8000/login
curl -u user1:wrongpass http://localhost:8000/login
```

`POST /register` ограничен одним новым пользователем в минуту с одного клиента. Повторная регистрация уже существующего пользователя возвращает `409 Conflict`.

### JWT

```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"correctpass"}'
```

Сохраните `access_token` из ответа и передайте его в защищённый ресурс:

```bash
curl http://localhost:8000/protected_resource \
  -H "Authorization: Bearer <access_token>"
```

`POST /login` ограничен пятью попытками в минуту для одного пользователя и клиента.

### RBAC

Роли: `admin`, `user`, `guest`.

```bash
curl http://localhost:8000/rbac/read -H "Authorization: Bearer <access_token>"
curl -X POST http://localhost:8000/rbac/create -H "Authorization: Bearer <admin_token>"
curl -X PUT http://localhost:8000/rbac/update -H "Authorization: Bearer <access_token>"
curl -X DELETE http://localhost:8000/rbac/delete -H "Authorization: Bearer <admin_token>"
```

`/protected_resource` доступен только ролям `admin` и `user`.

### Todo CRUD

```bash
curl -X POST http://localhost:8000/todos \
  -H "Content-Type: application/json" \
  -d '{"title":"Buy groceries","description":"Milk, eggs, bread"}'

curl http://localhost:8000/todos/1

curl -X PUT http://localhost:8000/todos/1 \
  -H "Content-Type: application/json" \
  -d '{"title":"Buy groceries","description":"Milk, eggs, bread and cheese","completed":true}'

curl -X DELETE http://localhost:8000/todos/1
```
"# Kr3" 
