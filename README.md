# Password Manager API

Менеджер паролей с шифрованием, хешированием и проверкой сложности.

## Что умеет
- Генерация криптостойких паролей (secrets)
- Проверка сложности пароля (регулярки)
- Хеширование мастер-пароля (bcrypt)
- Шифрование хранилища паролей (Fernet)
- Регистрация пользователя (POST /register)
- Добавление пароля (POST /passwords)
- Просмотр паролей (POST /passwords/list)

## Технологии
- Python 3.13
- FastAPI
- SQLAlchemy
- SQLite
- bcrypt (хеширование)
- cryptography / Fernet (шифрование)
- secrets (генерация)
- Pydantic

## Установка
```bash
pip install fastapi uvicorn sqlalchemy bcrypt cryptography

## Запуск
uvicorn password_api:app --reload

## Документация
После запуска: http://127.0.0.1:8000/docs

## Как использовать
Запустить сервер

Открыть /docs

POST /register — зарегистрировать пользователя

POST /passwords — добавить пароль (с мастер-паролем)

POST /passwords/list — посмотреть пароли (с мастер-паролем)

## Безопасность
Мастер-пароль хранится в виде хеша (bcrypt) — необратимо

Пароли от сервисов хранятся в зашифрованном виде (Fernet)

Даже если база украдена — пароли не восстановить без мастер-пароля

## Автор
izavetam — студентка 2 курса ИБ
GitHub: @izavetam

Автор
izavetam — студентка 2 курса ИБ
GitHub: @izavetam
