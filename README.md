## Требования
- Python 3.8+
- cryptography >= 3.0
- OpenSSL (для верификации)

## Установка

```bash
# Клонировать репозиторий
git clone git@github.com:FanOfLitov/MicroPKI.git
cd MicroPKI

# Создать виртуальное окружение
python3 -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate

# Установить зависимости
pip install -r requirements.txt

# Установить пакет в режиме разработки
pip install -e .

Инициализация корневого CA (RSA)

Bash

# Создать файл с паролем
echo "my-secure-passphrase" > secrets/ca.pass

# Сгенерировать RSA Root CA
micropki ca init \
    --subject "/CN=Demo Root CA/O=MicroPKI/C=US" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./pki \
    --validity-days 3650 \
    --log-file ./logs/ca-init.log

Инициализация корневого CA (ECC)

Bash

# Сгенерировать ECC Root CA
micropki ca init \
    --subject "CN=ECC Root CA,O=MicroPKI,C=RU" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./pki

Проверка сертификата

Bash

# Просмотр деталей сертификата
openssl x509 -in pki/certs/ca.cert.pem -text -noout

# Верификация самоподписанного сертификата
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem

# Или использовать встроенную команду
micropki ca verify --cert pki/certs/ca.cert.pem

Структура проекта

text

micropki/
├── micropki/
│   ├── __init__.py
│   ├── cli.py              # CLI интерфейс
│   ├── ca.py               # Операции CA
│   ├── certificates.py     # Работа с сертификатами
│   ├── crypto_utils.py     # Криптографические утилиты
│   └── logger.py           # Система логирования
├── tests/
│   ├── __init__.py
│   └── test_ca.py          # Юнит-тесты
├── pki/                    # Генерируемые файлы PKI
│   ├── private/            # Приватные ключи (зашифрованы)
│   ├── certs/              # Сертификаты
│   └── policy.txt          # Документ политики
├── requirements.txt
├── setup.py
└── README.md
Тестирование

Bash

# Запустить все тесты
pytest

# С подробным выводом
pytest -v

# С покрытием кода
pytest --cov=micropki --cov-report=html
Безопасность

    Приватные ключи шифруются с помощью AES-256-CBC
    Права доступа: директория private/ (0700), приватные ключи (0600)
    Пароли никогда не логируются
    Использование криптографически стойкого генератора случайных чисел
    Без собственных реализаций криптопримитивов

