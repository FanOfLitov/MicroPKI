# MicroPKI runtime compatibility patch

Запускать из корня проекта, где лежит папка `micropki`.

```powershell
python .\fix_micropki_runtime.py
```

или, если на Windows работает только Python Launcher:

```powershell
py .\fix_micropki_runtime.py
```

Что исправляет:

1. `micropki/__main__.py` теперь возвращает правильный exit code через `sys.exit(main())`.
2. Добавляет совместимость со старыми версиями `cryptography`, где нет:
   - `not_valid_before_utc`
   - `not_valid_after_utc`
   - `next_update_utc`
   - `revocation_date_utc`
3. Исправляет импорт `AuthorityInformationAccessOID` в `revocation_check.py`.

После патча:

```powershell
python -m pytest -q
bash ./demo/demo.sh
```
