# BreakCurl v0.1

> **Один рабочий cURL превращается в управляемый набор negative и security-проверок API.**

BreakCurl локально разбирает скопированный cURL, проверяет исходный запрос, затем изменяет по одному элементу запроса и показывает, где API падает, слабо валидирует данные, принимает запрос без корректной авторизации или раскрывает внутреннюю информацию.

Без OpenAPI. Без написания автотестов. Без аккаунта и облака.

## Самый простой запуск

Требуется [Node.js 20 или новее](https://nodejs.org/). После публикации BreakCurl в npm ничего устанавливать глобально не нужно:

```bash
npx --yes breakcurl@0.1.0 --dry-run
```

Дальше:

1. В браузере откройте `DevTools → Network`.
2. Нажмите правой кнопкой на рабочий API-запрос и выберите `Copy → Copy as cURL (bash)`.
3. Вставьте весь cURL в терминал.
4. Нажмите `Enter` на пустой строке.

`--dry-run` покажет план и отправит ровно `0` HTTP-запросов. Если адрес, профиль и количество проверок верны, запустите реальные проверки:

```bash
npx --yes breakcurl@0.1.0
```

Снова вставьте cURL, проверьте очищенный адрес и количество запросов, затем подтвердите запуск через `y`.

> Команды `npx breakcurl@0.1.0` заработают после публикации пакета в npm. До публикации используйте запуск из исходников ниже.

### Установить один раз

Если удобнее иметь постоянную команду `breakcurl`:

```bash
npm install --global breakcurl@0.1.0
breakcurl --dry-run
```

### Запустить из исходников прямо сейчас

Склонируйте репозиторий и перейдите в папку проекта:

```bash
git clone https://github.com/c33leron/BreakCurl.git
cd BreakCurl
npm install
npm run check -- --dry-run
```

После проверки плана:

```bash
npm run check
```

Для безопасной локальной демонстрации без своего API:

```bash
npm run demo
```

По умолчанию используется профиль `negative` — до 60 проверок, распределённых по разным JSON paths. Без подтверждения ни исходный, ни проверочные запросы не отправляются.

## Сначала посмотреть план без запросов

```bash
npm run check -- --dry-run
```

BreakCurl покажет:

- очищенный целевой адрес;
- выбранный профиль;
- количество проверок по категориям;
- полный список мутаций и ожиданий;
- предупреждения о потенциальных side effects.

В режиме `--dry-run` отправляется ровно `0` HTTP-запросов.

## Профили проверок

```bash
npm run check -- --profile quick
npm run check -- --profile negative
npm run check -- --profile security
npm run check -- --profile full
```

| Профиль | Лимит по умолчанию | Что проверяет |
| --- | ---: | --- |
| `quick` | 15 | Удаление, `null`, неправильный тип, пустое значение, числовая граница |
| `negative` | 60 | Quick + пробелы, длинные строки, Unicode, отрицательные, большие и дробные числа |
| `security` | 80 | Auth boundary, безопасные injection probes, protocol и базовые structural-проверки |
| `full` | 120 | Negative + Security в одном запуске |

Жёсткий предел — `200` проверочных запросов:

```bash
npm run check -- --profile full --max-cases 150
```

BreakCurl распределяет проверки по полям breadth-first: сначала затрагиваются разные JSON paths, а не генерируются все варианты только для первого поля.

## Security-режим

Короткая команда:

```bash
npm run check -- --security
```

Это alias для `--profile security`.

### Проверка authentication boundary

Если в cURL есть `Authorization`, cookies, API key или auth query-параметр, BreakCurl добавляет два auth-probe:

1. Удаляет все credentials.
2. Заменяет их на заведомо невалидные значения.

Если endpoint по требованиям обязан быть защищён:

```bash
npm run check -- --security --expect-auth
```

Oracle становится строгим:

- `401/403` → `PASS`;
- успешный `2xx` → `FAIL` с высоким security-риском;
- другой `4xx` → `WARN`, потому что он не доказывает auth-отказ.

Без `--expect-auth` успешный ответ считается `WARN`, а не доказанной дырой: endpoint может быть публичным.

> Auth-probe повторяет валидное тело запроса без корректных credentials. Если endpoint реально уязвим, операция может выполниться. Используйте disposable test data и непродуктивное окружение.

### Безопасные security probes

Для строковых полей используются ограниченные неисполняемые маркеры:

- SQL syntax marker;
- NoSQL-объект с `$ne` для проверки type validation;
- путь к заведомо несуществующему файлу;
- неисполняемый HTML markup;
- template expression marker;
- CRLF/newline marker.

BreakCurl не выполняет эксплуатацию, не извлекает данные и не заявляет уязвимость только потому, что API принял строку. Он повышает результат до `WARN/FAIL`, когда есть доказательство: `5xx`, database error, stack trace, credential leak, небезопасное HTML-отражение или нарушенный auth-контракт.

### Анализ ответа

BreakCurl ищет:

- stack traces и внутренние пути;
- SQL/ORM/database errors;
- JWT, cloud keys и private keys;
- `X-Powered-By`;
- неэкранированное отражение markup probe в HTML.

Ответ API не записывается на диск. Для сравнения сохраняется только fingerprint статуса, Content-Type и структуры JSON без значений.

## Свои параметры и проверки

### Проверять конкретные поля

```bash
npm run check -- \
  --only '$.email' \
  --only '$.profile' \
  --exclude '$.profile.internalNote'
```

`--only` включает указанный path и его дочерние поля. `--exclude` имеет приоритет.

### Передать своё значение

Значение после `=` должно быть валидным JSON:

```bash
npm run check -- \
  --set '$.email="qa@"' \
  --set '$.age=-1' \
  --set '$.active=null'
```

По умолчанию пользовательский `--set` ожидает отклонение API.

### Удалить своё поле

```bash
npm run check -- --remove '$.profile.middleName'
```

### Использовать конфиг

```bash
cp breakcurl.config.example.json breakcurl.config.json
npm run check -- --config breakcurl.config.json
```

Формат custom case:

```json
{
  "name": "Неизвестный enum должен быть отклонён",
  "path": "$.status",
  "operation": "set",
  "value": "BREAKCURL_UNKNOWN",
  "expect": "reject"
}
```

Поддерживаемые ожидания:

- `reject` — ожидается контролируемый `4xx`;
- `accept` — ожидается `2xx`;
- `auth-reject` — ожидается строго `401/403`;
- `observe` — жёсткого oracle нет, результат будет `INFO`, если не найдено падение или security-сигнал.

Полный пример находится в [breakcurl.config.example.json](breakcurl.config.example.json).

## Результаты

- `FAIL` — `5xx`, невалидный JSON-контракт, доказанное нарушение `--expect-auth` или другая сильная находка;
- `WARN` — подозрительное принятие данных, утечка внутренних деталей, timeout либо security-риск без полного oracle;
- `INFO` — наблюдение без жёсткого ожидания; это не баг и не успешная проверка требования;
- `PASS` — конкретное ожидание подтверждено;
- `ERROR` — проблема ввода, исходного запроса, redirect или самого BreakCurl.

Разделение `severity` и `confidence` не даёт смешивать потенциальный ущерб с силой доказательства.

## Создаваемые файлы

```text
breakcurl-output/
├── report.md
├── report.json
└── findings/
    ├── fail-auth-auth-missing.curl
    └── warn-email-wrong-type.curl
```

- `report.md` — отчёт для человека;
- `report.json` — очищенный machine-readable результат для CI;
- `findings/*.curl` — безопасные replay-команды только для `FAIL/WARN`.

`Authorization`, cookies, API keys, auth query, чувствительные JSON-поля, JWT и известные значения credentials заменяются на `<REDACTED>`. Если credential повторён под нейтральным именем вроде `value`, BreakCurl отслеживает исходное секретное значение и также удаляет его из артефактов.

## Запуск из файла и CI

Из файла:

```bash
npm run check -- request.curl
```

Через stdin или в CI:

```bash
cat request.curl | npm run check -- --profile quick --allow-mutation
```

Опубликованный npm-пакет можно запустить с файлом напрямую:

```bash
npx --yes breakcurl@0.1.0 request.curl --profile full
```

## Все параметры

```text
--profile <name>       quick, negative, security или full
--security             alias для --profile security
--max-cases <number>   максимум проверок, от 1 до 200
--timeout <ms>         тайм-аут одного запроса
--expect-auth          требовать 401/403 для auth-probes
--dry-run              показать план, отправить 0 запросов
--config <file>        JSON-конфиг
--only <json-path>     включить path; параметр можно повторять
--exclude <json-path>  исключить path; параметр можно повторять
--set <path=json>      пользовательская замена; можно повторять
--remove <json-path>   пользовательское удаление; можно повторять
--allow-mutation       запуск без интерактивного подтверждения
--output <directory>   каталог результатов
--no-color             отключить цветной вывод
--help                 показать справку
--version              показать версию
```

## Коды завершения

```text
0  FAIL и ERROR отсутствуют
1  найден хотя бы один FAIL
2  ERROR, невалидный ввод, неуспешный исходный запрос или ошибка BreakCurl
```

Намеренные `FAIL/WARN` внутри `demo` возвращают `0`, если демонстрация работает корректно.

## Границы продукта

Поддерживаются один `POST`, `PUT`, `PATCH` или `DELETE`, один HTTP/HTTPS URL и JSON-объект в корне тела. Copy as cURL разбирается как данные и никогда не исполняется через shell.

Не поддерживаются multipart, file bodies, redirects, shell variables, pipes, substitutions, client certificates, brute force, SSRF, race/load и автоматическая эксплуатация. BreakCurl — security-focused negative testing, но не замена pentest, DAST или QA-команды.

## Разработка

```bash
npm run lint
npm run typecheck
npm test
npm run build
npm run verify
```

Правила безопасного использования: [SECURITY.md](SECURITY.md).
