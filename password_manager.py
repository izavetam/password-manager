import secrets
import string
import re
import bcrypt
from cryptography.fernet import Fernet

def generate_password(length: int = 16) -> str:
    """Генерирует криптостойкий пароль."""
    #набор символов: буквы(заглавные + строчные) + цифры + спецсимволы
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    #secrets.choice - криптостойкий выбор (лучше, чем random.choice)
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def check_strength(password: str) -> dict:
    """Проверяет сложность пароля."""
    result = {
        "length": len(password),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
    }
    #считаем, сколько критериев выполнено
    score = sum([
        result["length"]>= 12,
        result["has_lower"],
        result["has_upper"],
        result["has_digit"],
        result["has_special"],
    ])
    #оценка
    if score>= 5:
        result["rating"] = "Сильный"
    elif score >= 3:
        result["rating"] = "Средний"
    else:
        result["rating"] = "Слабый"

    return result
def hash_password(password: str) -> str:
    """Хеширует пароль (необратимо)."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Проверяет, соответствует ли пароль хешу."""
    password_bytes = password.encode('utf-8')
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(password_bytes,hashed_bytes)
def generate_key() -> bytes:
    """Генеирует ключ шифрования (сохрани его в надежном месте!)."""
    return Fernet.generate_key()

def encrypt_data(data: str, key: bytes) -> str:
    """Шифрует данные"""
    f = Fernet(key)
    encrypted = f.encrypt(data.encode('utf-8'))
    return encrypted.decode('utf-8')

def decrypt_data(encrypted: str, key: bytes) -> str:
    """Расшифровывает данные"""
    f= Fernet(key)
    decrypted = f.decrypt(encrypted.encode('utf-8'))
    return decrypted.decode('utf-8')

#проверка
if __name__ == "__main__":
    print('='*50)
    print('ХЕШИРОВАНИЕ (bcrypt)')
    print('='*50)

    password = 'MySecretPassword123'
    hashed = hash_password(password)
    print(f'Пароль: {password}')
    print(f'Хеш: {hashed}')
    print(f"Проверка правильного : {'OK' if verify_password(password, hashed) else 'FAIL'}")
    print(f"Проверка неправильного : {'FAIL' if verify_password(password, hashed) else 'OK'}")
    print()

    print('='*50)
    print('ШИФРОВАНИЕ (Fernet)')
    print('='*50)

    key = generate_key()
    print(f"Ключ: {key.decode('utf-8')}")
    print()

    secret = "Пароль от почты: qwerty123"
    encrypted = encrypt_data(secret, key)
    print(f'Оригинал: {secret}')
    print(f'Зашифровано: {encrypted[:60]}...')

    decrypted = decrypt_data(encrypted,key)
    print(f'Расшифровано: {decrypted}')
    print(f'Совпадает: {'OK' if decrypted == secret else 'FAIL'}')