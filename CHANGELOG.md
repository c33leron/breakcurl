# История изменений

## 0.1.0 — готовится к первому релизу

- Интерактивная вставка Copy as cURL и безопасный предварительный просмотр.
- Профили `quick`, `negative`, `security` и `full` с лимитом до 200 проверок.
- Breadth-first распределение мутаций по JSON paths.
- Boundary, structure, protocol и безопасные injection-проверки.
- Auth-probes без credentials и с невалидными credentials.
- Строгий security-контракт `--expect-auth`.
- Пользовательские `--set`, `--remove`, `--only`, `--exclude` и JSON-конфиг.
- `--dry-run` с гарантированными нулём HTTP-запросов.
- Классификации `PASS`, `INFO`, `WARN`, `FAIL`, `ERROR`, severity и confidence.
- Поиск stack trace, внутренних путей, database errors, credentials и небезопасного HTML reflection.
- Усиленное маскирование секретов и безопасные replay cURL.
- Человеческий `report.md` и очищенный `report.json` без response body.
- CI для Node.js 20/22/24, Dependabot и CodeQL security-extended.
