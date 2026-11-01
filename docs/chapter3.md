# 3 Разработка микросервисов

В разделе реализован программный прототип паттерна контролируемого удаления данных при угрозе УБИ.060. Проектные компоненты раздела 2 преобразованы в HTTP API, функции проверки, фоновые обработчики и декларативные файлы развёртывания. Исходные файлы подготовлены в едином репозитории ubi060-delete-guard [36]. В тексте приведены основные фрагменты работающего кода; полные файлы, зависимости, тесты и команды запуска находятся в репозитории.

## 3.1 Функции микросервисов

Прикладная часть написана на Python 3.12 с использованием FastAPI и Uvicorn. Проверка JWT выполняется библиотекой PyJWT, криптографические операции — cryptography, работа с PostgreSQL — SQLAlchemy и psycopg, с Cassandra — cassandra-driver, с RabbitMQ — aio-pika. Зависимости основных библиотек закреплены в requirements.txt. Сервис выбирается переменной SERVICE: один общий образ запускает отдельные процессы auth-service, delete-guard, quarantine-service, audit-service и data-api. Общие функции вынесены в модули, перечисленные в таблице 11. Такое разделение позволяет проверять правила независимо от HTTP и транспорта сообщений [20, 21].

Таблица 11 – Основные файлы реализации

| Файл | Реализованные функции |

| --- | --- |

| app/api.py | HTTP-маршруты, валидация входа, проверка JWT, метрики и обработка ошибок |

| app/security.py | Канонизация JSON, SHA-256, RSA-PSS, выдача и проверка JWT, хеширование паролей |

| app/domain.py | Правила R1–R5, идемпотентность, карантин, восстановление, окончательное удаление и аудит |

| app/db.py | Таблицы и границы SQL-транзакций, общая блокировка каталога |

| app/storage.py | CQL-запросы Cassandra и отдельный локальный адаптер SQLite |

| app/messaging.py | Публикация outbox, потребление очереди, подтверждения и обработчик карантина |

| scripts/ | Инициализация, генерация Secret и YAML, развёртывание и демонстрация |

### Аутентификация и передача полномочий

Сервис auth-service принимает логин и пароль методом POST /token. В файле users.json хранятся роли и результаты PBKDF2-HMAC-SHA256 с индивидуальной случайной солью и 600 000 итераций. Пароли открытым текстом в образ не включаются. Для неизвестного пользователя выполняется такая же операция хеширования, чтобы отказ не превращался в простой признак существования учётной записи. При успешной проверке выдаётся JWT сроком на 900 секунд. В токен входят идентификатор пользователя sub, роль, времена выдачи и окончания, издатель, аудитория и уникальный jti.

JWT подписывается отдельным ключом RSA по алгоритму RS256. Закрытый ключ доступен только auth-service; остальные сервисы получают открытый ключ. Функция verify_token задаёт разрешённый алгоритм явно и проверяет издателя ubi060-auth, аудиторию ubi060 и обязательные поля. Это предотвращает принятие токена другого назначения или токена с алгоритмом, выбранным клиентом. Применение Bearer JWT в FastAPI соответствует официальной схеме работы зависимостей безопасности [30]. Выдача и проверка токена показаны в листинге 1.

**Листинг 1 – Выдача и проверка JWT**

Файл: `app/security.py`

```python

def issue_token(subject: str, role: str, private: bytes, lifetime: int = 900) -> str:
    now = int(time.time())
    return jwt.encode({"sub": subject, "role": role, "iat": now, "exp": now + lifetime,
                       "iss": "ubi060-auth", "aud": "ubi060", "jti": str(uuid.uuid4())},
                      private, algorithm="RS256")

def verify_token(token: str, public: bytes) -> dict:
    claims = jwt.decode(token, public, algorithms=["RS256"], audience="ubi060",
                        issuer="ubi060-auth", options={"require": ["sub", "role", "exp", "iat", "jti"]})
    if claims["role"] not in {"analyst", "owner", "admin", "scheduler"}:
        raise jwt.InvalidTokenError("Unknown role")
    return claims

```

Роли прототипа соответствуют разграничению полномочий раздела 2: analyst читает доступные ему данные; owner удаляет и восстанавливает собственные наборы; admin загружает наборы и меняет подписанные политики; scheduler выполняет задание очистки. Владение проверяется по каталогу, а не по переданному клиентом полю. При обращении без токена возвращается 401, при недостаточных полномочиях — 403. Внутренние сервисы повторно проверяют JWT: полученные заголовки X-Role и X-User не считаются доказательством прав.

### Подписанный эталон политики хранения

Каждый эталон содержит dataset_id, версию, срок хранения, минимальный срок, порог запросов, длительность окна счётчика и срок карантина. JSON сериализуется с сортировкой ключей, без лишних пробелов и без нечисловых значений NaN; по полученным байтам вычисляется SHA-256. Подписывается именно вычисленный дайджест с использованием RSA-PSS и Prehashed(SHA256). Проверка подписи использует те же параметры (листинг 2). Привязка эталона к идентификатору набора исключает его штатную подстановку для другого набора, а монотонная версия запрещает откат через API. Подход развивает контроль целостности политики из [6]; выбор канонизации и RSA-PSS является решением данной реализации.

**Листинг 2 – Подпись и проверка эталона политики**

Файл: `app/security.py`

```python

def sign_policy(policy: dict, private: bytes) -> str:
    key = serialization.load_pem_private_key(private, password=None)
    signature = key.sign(bytes.fromhex(digest(policy)),
                         padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                         utils.Prehashed(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")

def valid_policy(policy: dict, signature: str, public: bytes) -> bool:
    try:
        key = serialization.load_pem_public_key(public)
        key.verify(base64.b64decode(signature, validate=True), bytes.fromhex(digest(policy)),
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                   utils.Prehashed(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

```

Функция policy принимает новый эталон только от администратора, проверяет его подпись, положительные значения параметров, соответствие dataset_id и увеличение версии. Закрытый ключ эталона используется при инициализации или административном подписании и не устанавливается в delete-guard. Во время карантина изменения политики запрещены. Минимальный срок задаётся требованиями владельца данных; измерение нагрузки в разделе 4 должно уточнять порог запросов, а не сокращать этот минимальный срок.

### Каталог данных и согласование операций

PostgreSQL хранит каталог datasets, граф dependency_graph, результаты deletion_requests, таблицу outbox, журнал audit_log и уведомления notifications. Политики и сообщения имеют тип JSONB в PostgreSQL; для эталона задан индекс GIN, для входящих связей и счётчика — индексы B-Tree [22]. Сами записи наборов располагаются в таблице payloads Cassandra. В каталоге сохраняется ожидаемый SHA-256 содержимого, по которому контролируется прочитанное значение.

В реализации уточнена проектная пометка «удалено»: её авторитетное состояние хранится в транзакционном каталоге PostgreSQL. Данные скрываются приложением только в QUARANTINED, PURGING и PURGED. После ответа 409 состояние DEFERRED сохраняет признак отложенной операции, но оставляет данные читаемыми. Таким образом, невозможность удаления не превращается в бессрочную потерю доступности. Состояния данных отличаются от двух состояний решения allow/deny на рисунке 5: решение allow соответствует ответу 202, deny — ответам 403 или 409.

Перед изменением каталога выполняется SELECT ... FOR UPDATE строки transaction_mutex. Блокировка общая для реплик guard и обработчика карантина; она упорядочивает проверку счётчика, изменение зависимостей, restore и подготовку purge. Для учебного прототипа выбран один общий замок. Это упрощает доказательство отсутствия гонки, но ограничивает параллелизм. Производительность такого решения подлежит измерению в разделе 4. В локальном режиме аналогичная граница транзакции задаётся BEGIN IMMEDIATE в SQLite.

### Сервис безопасности delete-guard

Основная операция DELETE /deletions/{id} вызывает request_delete. Заголовок Idempotency-Key обязателен. В таблице deletion_requests ключ связывается с пользователем и отпечатком запроса. Повтор идентичного обращения возвращает уже сохранённые код и результат, не продлевая карантин и не добавляя повторное событие. Повторное использование ключа для другого набора отклоняется с кодом 409. Порядок основной транзакционной обработки показан на рисунке 14.

Проверки выполняются последовательно. R1 проверяет подпись эталона; R2 сопоставляет SHA-256 действующей политики и эталона; R3 проверяет минимальный срок; R4 считает ранее зарегистрированные обращения данного пользователя в общем временном окне. Общий счётчик находится в PostgreSQL, поэтому два pod delete-guard не получают независимые лимиты. В демонстрационном эталоне заданы 20 запросов за 60 секунд; это начальная настройка примера, а не результат измерения обычной нагрузки. R5 запрещает удаление набора с входящими связями или неподтверждённым содержимым. Дополнительно проверяется фактическое истечение срока хранения. Основной код проверок приведён в листинге 3.

**Листинг 3 – Последовательная проверка правил удаления**

Файл: `app/domain.py`

```python

def _rules(self, c, row, actor, count=True, age=True):
    p = row["policy"]
    if not valid_policy(row["baseline"], row["signature"], self.public_key):
        return 403, "R1"
    if digest(p) != digest(row["baseline"]):
        return 403, "R2"
    if p["retention_seconds"] < p["minimum_seconds"]:
        return 403, "R3"
    if count:
        attempts = c.execute(select(func.count()).select_from(requests).where(
            requests.c.actor == actor["sub"], requests.c.created_at > self.clock()-p["window_seconds"])).scalar_one()
        if attempts >= p["delete_limit"]:
            return 403, "R4"
    if c.execute(select(dependencies.c.source).where(dependencies.c.target == row["id"])).first():
        return 409, "R5_dependencies"
    try:
        body = self.storage.get(row["id"])
    except StorageUnavailable:
        return 409, "R5_unavailable"
    if body is None or digest(body) != row["content_hash"]:
        return 409, "R5_content"
    if age and self.clock() < row["created_at"]+p["retention_seconds"]:
        return 409, "retention_not_expired"
    return 202, None

```

При обращении к Cassandra используется ConsistencyLevel.ALL. Проверка выполняется в соответствии с replication factor keyspace; сравнение ответов отдельных адресов как якобы локальных реплик не применяется. Уровень согласованности определяет необходимое число ответивших реплик [33]. Прочитанный набор сравнивается с ожидаемым хешем каталога. Ошибка чтения приводит к 409 и отложенному удалению; уровень согласованности автоматически не понижается. Базовый стенд с RF=1 пригоден для проверки алгоритма, но не доказывает устойчивость к потере одной из нескольких реплик.

![Рисунок 14 – Диаграмма деятельности обработки запроса в delete-guard](figures/fig14.png)

После успешных проверок в одной SQL-транзакции фиксируются QUARANTINED, срок окончания карантина, событие outbox и результат запроса. Для отказа по R1–R4 записываются ACTIVE и событие blocked; для отложенной операции — DEFERRED и событие deferred. Только после COMMIT клиент получает сохранённый ответ. Если недоступна сама БД, операция не разрешается и API возвращает 503: при отсутствии надёжной записи состояния ответ 202 не формируется. Фрагмент транзакционной функции приведён в листинге 4.

**Листинг 4 – Фиксация решения и идемпотентного результата**

Файл: `app/domain.py`

```python

def request_delete(self, id, key, actor):
    if actor["role"] not in {"owner", "admin", "scheduler"}:
        raise Problem(403, "Удаление запрещено для роли")
    if not key or len(key) > 100:
        raise Problem(422, "Нужен Idempotency-Key длиной 1–100")
    scope = actor["sub"]+":"+key
    fingerprint = digest({"dataset_id": id, "actor": actor["sub"]})
    with self.db.transaction() as c:
        row = self._row(c, id)
        self.authorize(row, actor)
        old = c.execute(select(requests).where(requests.c.id == scope)).mappings().first()
        if old:
            if old["fingerprint"] != fingerprint:
                raise Problem(409, "Ключ уже использован для другого запроса")
            return old["code"], old["response"]
        if row["state"] == "QUARANTINED":
            code, rule = 202, None
        elif row["state"] == "PURGED":
            raise Problem(410, "Набор уже удалён")
        elif row["state"] == "PURGING":
            raise Problem(409, "Окончательное удаление уже началось")
        else:
            code, rule = self._rules(c, row, actor)
            state = "QUARANTINED" if code == 202 else ("ACTIVE" if code == 403 else "DEFERRED")
            deadline = self.clock()+row["policy"]["quarantine_seconds"] if code == 202 else None
            c.execute(update(datasets).where(datasets.c.id == id).values(state=state, deadline=deadline))
            self.event(c, row, actor, {202: "quarantined", 403: "blocked", 409: "deferred"}[code], rule)
        response = {"dataset_id": id, "decision": "allow" if code == 202 else "deny", "rule": rule,
                    "status": code}
        c.execute(insert(requests).values(id=scope, actor=actor["sub"], dataset_id=id,
            fingerprint=fingerprint, created_at=self.clock(), code=code, response=response))
        return code, response

```

### Карантин, восстановление и окончательное удаление

Сервис quarantine-service предоставляет список карантина и POST /quarantine/{id}/restore. Восстановление доступно владельцу и администратору. После повторного чтения содержимого и проверки хеша состояние переводится в ACTIVE, срок карантина очищается, а событие restored записывается в outbox. Повторное восстановление уже активного набора возвращает текущее состояние. Для PURGING и PURGED восстановление запрещено. Условия чтения и восстановления реализуют сохранение доступности до принятия необратимого решения [15].

Фоновый обработчик выбирает QUARANTINED с истёкшим сроком и незавершённые PURGING. Перед окончательным удалением заново проверяются подпись, политика, зависимости и содержимое. Повторная проверка необходима, поскольку между первым запросом и истечением карантина могли пройти минуты или часы. Изменения политики и новые связи с карантинным набором через API запрещены. Алгоритм с учётом перезапуска представлен на рисунке 15.

SQL-транзакция не может атомарно включить CQL DELETE другой СУБД. Поэтому purge_one сначала надёжно фиксирует PURGING, затем выполняет идемпотентный DELETE в Cassandra и только после подтверждения записывает PURGED и событие purged. Если процесс падает между этими этапами, сохранённый PURGING попадает в следующую выборку и DELETE повторяется. Возврат такого набора в ACTIVE не допускается. Это исключает ситуацию, когда Cassandra уже выполнила удаление, а каталог после отката SQL разрешил восстановление. Реализация приведена в листинге 5.

**Листинг 5 – Двухэтапное окончательное удаление**

Файл: `app/domain.py`

```python

def purge_one(self, id):
    # Phase 1 is durable BEFORE the nontransactional Cassandra DELETE.
    # PURGING is retried after crashes and can never be restored or linked.
    system = {"sub": "quarantine-worker", "role": "scheduler"}
    with self.db.transaction() as c:
        row = self._row(c, id)
        if row["state"] == "QUARANTINED":
            if row["deadline"] > self.clock():
                return False
            code, rule = self._rules(c, row, system, count=False)
            if code != 202:
                self.event(c, row, system, "purge_deferred", rule)
                return False
            c.execute(update(datasets).where(datasets.c.id == id).values(state="PURGING"))
        elif row["state"] != "PURGING":
            return False
    self.storage.delete(id)  # Idempotent tombstone; a crash here leaves PURGING, never ACTIVE.
    with self.db.transaction() as c:
        row = self._row(c, id)
        if row["state"] == "PURGING":
            c.execute(update(datasets).where(datasets.c.id == id).values(state="PURGED"))
            c.execute(delete(dependencies).where(dependencies.c.source == id))
            self.event(c, row, system, "purged")
    return True

```

![Рисунок 15 – Диаграмма деятельности окончательного удаления с восстановлением после сбоя](figures/fig15.png)

Термин «окончательное удаление» в API означает выполнение CQL DELETE и закрытие возможности восстановления через прототип. В Cassandra такая команда создаёт tombstone; освобождение места на диске выполняется позднее при compaction. В стенде default_time_to_live таблицы равен нулю, а прикладной код не задаёт TTL для записей. Этот режим относится к вновь создаваемой таблице: при внедрении в существующую систему отдельно требуется проверить уже записанные TTL и сторонние задания очистки.

### Журналирование и уведомления audit-service

Изменение состояния и создание события согласуются через transactional outbox. Каждое событие получает UUID, время, идентификатор набора, владельца, инициатора, тип и правило отказа. Обработчик delete-guard выбирает неопубликованные события, отправляет persistent messages в durable-очередь ubi060.audit и ожидает publisher confirm. Только затем строка outbox помечается опубликованной. Подтверждение издателю и ACK потребителя решают разные задачи, поэтому используются совместно [34]. Код публикации приведён в листинге 6; схема обработки — на рисунке 16.

**Листинг 6 – Публикация событий outbox с подтверждением**

Файл: `app/messaging.py`

```python

async def publish_once(db, channel):
    with db.engine.connect() as c:
        batch = list(c.execute(select(outbox).where(outbox.c.published.is_(False))
                              .order_by(outbox.c.created_at).limit(100)).mappings())
    for row in batch:
        await channel.default_exchange.publish(aio_pika.Message(canonical(row["payload"]),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT, message_id=row["id"], content_type="application/json"),
            routing_key="ubi060.audit", mandatory=True, timeout=10)
        # A crash between confirmation and this update causes a duplicate, not a lost event.
        with db.transaction() as c:
            c.execute(update(outbox).where(outbox.c.id == row["id"]).values(published=True))
    return len(batch)

```

![Рисунок 16 – Диаграмма деятельности доставки и записи события аудита](figures/fig16.png)

При сбое после подтверждения брокера, но до обновления outbox возможна повторная доставка. Потребитель audit-service проверяет event_id по уникальному ограничению. Для нового события он в одной транзакции добавляет журнал и уведомление; для дубликата не создаёт вторую запись. ACK отправляется после успешного COMMIT. Некорректные сообщения переводятся в отдельную очередь ubi060.dead. Гарантия exactly-once для транспорта не заявляется: повторная доставка устраняется на уровне хранения результата. Функция записи журнала приведена в листинге 7.

**Листинг 7 – Запись события, хеш-цепочки и уведомления**

Файл: `app/domain.py`

```python

def consume(self, event):
    with self.db.transaction() as c:
        if c.execute(select(audit.c.seq).where(audit.c.event_id == event["id"])).first():
            return False
        previous = c.execute(select(audit.c.record_hash).order_by(audit.c.seq.desc()).limit(1)).scalar()
        previous = previous or "0"*64
        record_hash = digest({"previous_hash": previous, "event": event})
        c.execute(insert(audit).values(event_id=event["id"], record=event,
            previous_hash=previous, record_hash=record_hash))
        recipient = "admin" if event["kind"] in {"blocked", "purge_deferred"} else event["owner"]
        c.execute(insert(notifications).values(event_id=event["id"], recipient=recipient, payload=event, read=False))
    return True

```

Хеш записи включает предыдущее значение хеша и каноническое представление события. Функция verify_audit последовательно пересчитывает цепочку. Роль PostgreSQL audit имеет права SELECT и INSERT на журнал, но не UPDATE или DELETE. Это позволяет обнаруживать изменение отдельных записей в принятой модели доверия. Администратор СУБД способен пересчитать всю цепочку, поэтому абсолютная неизменяемость без внешней подписанной фиксации контрольного хеша не утверждается. Научная идея связанного журналирования из [17] используется с указанной границей гарантий.

Уведомления сохраняются в таблице notifications и выдаются через защищённый GET /notifications. При blocked и purge_deferred адресатом является администратор, для остальных событий — владелец набора. В прототипе это внутренний почтовый ящик приложения; отправка писем и сообщений внешним получателям не настраивалась. События дополнительно выводятся в stdout как JSON по одному объекту в строке, что создаёт основу для подключения сборщика журналов [28], но само по себе не доказывает интеграцию с конкретной SIEM.

### Шлюз и защищаемое приложение

Шлюз nginx-gateway принимает HTTPS на порту 8443, опубликованном как NodePort 30443. Внутренний подзапрос auth_request обращается к /verify auth-service. Положительный ответ разрешает обработку, 401 и 403 прекращают её [31]. Лимит запросов задаётся limit_req_zone; превышение приводит к 429. Это локальный лимит одной реплики NGINX, а общий лимит удаления реализован R4 в PostgreSQL. Главные маршруты и роли приведены в таблице 12.

Таблица 12 – Основные операции HTTP API

| Операция | Назначение | Доступ |

| --- | --- | --- |

| POST /token | Получение JWT | Зарегистрированный пользователь |

| GET /datasets/{id} | Чтение доступного набора | Владелец или администратор |

| POST /datasets | Загрузка набора через guard | Администратор |

| PUT /policies/{id} | Утверждение нового подписанного эталона | Администратор |

| DELETE /deletions/{id} | Проверка удаления и постановка в карантин | Владелец, администратор, scheduler |

| POST /quarantine/{id}/restore | Восстановление | Владелец или администратор |

| GET /audit/verify | Проверка хеш-цепочки | Администратор |

| GET /notifications | Получение своих уведомлений | Авторизованный адресат |

Маршрут проверки токена объявлен internal, поэтому клиент не может обращаться к нему как к обычному API. Проксирование сохраняет Authorization, а произвольные заголовки роли очищаются. Фрагмент конфигурации приведён в листинге 8; полная TLS-конфигурация находится в deploy/nginx.conf.

**Листинг 8 – Проверка токена и маршрутизация на шлюзе**

Файл: `deploy/nginx.conf`

```python

limit_req_status 429;
server {
        internal;
        proxy_pass http://auth-service.pattern.svc.cluster.local:8001/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Authorization $http_authorization;
    }
    location / {
        limit_req zone=api burst=20 nodelay;
        auth_request /_verify;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-User "";
        proxy_set_header X-Role "";
        proxy_pass http://delete-guard.pattern.svc.cluster.local:8002;
    }
    location /quarantine {

```

Data-api читает каталог перед обращением к Cassandra и не выдаёт скрытые наборы. Его учётная запись Cassandra имеет только SELECT. Загрузка передаётся в доверенный delete-guard с исходным JWT, который проверяется повторно. Такое ограничение необходимо: NetworkPolicy разрешает или запрещает сетевое соединение, но не различает CQL SELECT, INSERT и DELETE. Учётные записи guard и quarantine имеют отдельные пароли и право MODIFY; именно эти сервисы входят в доверенную границу механизма защиты.

Проверка каталога перед выдачей данных реализована в функции read (листинг 9). Отсутствующий набор даёт 404, скрытый или окончательно удалённый — 410, неподтверждённое содержимое — 503. Для DEFERRED чтение сохраняется.

**Листинг 9 – Проверка доступности данных в data-api**

Файл: `app/domain.py`

```python

def read(self, id, actor):
    with self.db.transaction() as c:
        row = self._row(c, id)
        self.authorize(row, actor, write=False)
        if row["state"] not in {"ACTIVE", "DEFERRED"}:
            raise Problem(410, "Набор скрыт карантином или удалён")
        body = self.storage.get(id)
        if body is None or digest(body) != row["content_hash"]:
            raise Problem(503, "Целостность данных не подтверждена")
        return {"id": id, "state": row["state"], "body": body}

```

## 3.2 Развёртывание микросервисов

Для воспроизводимого развёртывания подготовлены Dockerfile, конфигурация NGINX и 10 YAML-файлов Kubernetes, содержащих 93 ресурса. Файлы находятся в deploy/k8s; скрипт build_manifests.py генерирует их из одного описания, а validate_manifests.py проверяет соответствие строгим JSON-схемам Kubernetes 1.33. YAML остаётся доступным для непосредственного просмотра в репозитории. Проверка схемы подтверждает допустимость структуры объектов, но не заменяет запуск контейнеров и проверку сетевой связности [24, 35].

### Контейнерный образ и конфигурация

Dockerfile использует Python 3.12-slim, устанавливает закреплённые зависимости, копирует app и scripts и переключается на пользователя UID 10001. При запуске команда Uvicorn получает порт из PORT и создаёт только выбранное приложение. Один исходный образ не объединяет сервисы в один процесс: каждый Deployment запускает свой экземпляр с собственной SERVICE и Secret. Общая библиотека сокращает дублирование функций проверки, а логические и сетевые границы сервисов сохраняются [24, 27].

**Листинг 10 – Сборка и запуск контейнерного образа**

Файл: `Dockerfile`

```dockerfile

FROM python:3.12-slim
WORKDIR /opt/ubi060
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --create-home app
COPY app ./app
COPY scripts ./scripts
USER 10001
EXPOSE 8000 8001 8002 8003 8004
CMD ["sh", "-c", "exec uvicorn app.api:create_app --factory --host 0.0.0.0 --port ${PORT:-8002}"]

```

Настройки разделены на ConfigMap и Secret. ConfigMap nginx содержит маршрутизацию; Prometheus и Grafana получают свои конфигурации и панель. Пароли, ключи и сертификат создаёт cluster_secrets.py в каталоге .local/cluster, исключённом из Git и контекста сборки Docker. У каждого сервиса отдельный Secret с необходимыми файлами. Закрытый ключ JWT выдаётся только auth-service, закрытый ключ эталона — bootstrap/администратору. Сервисные роли PostgreSQL и Cassandra не используют суперпользователя при штатной работе. Объект Secret сам по себе не означает шифрование данных при хранении в кластере; для производственной среды требуется отдельная настройка защиты секретов.

### Пространства имён и ресурсы Kubernetes

В namespace pattern размещаются шлюз, сервисы паттерна, PostgreSQL, RabbitMQ, bootstrap Job и CronJob очистки. Namespace data содержит data-api и Cassandra, namespace monitoring — Prometheus и Grafana. Для шлюза и delete-guard задаются две реплики, для остальных прикладных сервисов — одна. PostgreSQL, Cassandra и RabbitMQ развёртываются как StatefulSet с постоянными томами. Это сохраняет каталог, полезные данные и очередь после замены pod; репликация и резервное копирование самими PVC не обеспечиваются.

Для HTTP-сервисов задаются requests/limits ресурсов, startupProbe, readinessProbe и livenessProbe. Живость проверяется через /healthz, готовность — через /readyz. Прикладной процесс работает без root, запрещено повышение привилегий, корневая файловая система доступна только для чтения; временный каталог выделен отдельным emptyDir. Readiness подтверждает готовность API и каталога, но не является гарантией непрерывной доступности каждого внешнего компонента. Ошибки Cassandra и PostgreSQL обрабатываются дополнительно при выполнении операции. Фрагмент Deployment delete-guard приведён в листинге 11.

**Листинг 11 – Фрагмент Deployment сервиса delete-guard**

Файл: `deploy/k8s/30-microservices.yaml`

```yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: delete-guard
  namespace: pattern
spec:
  replicas: 2
  selector:
    matchLabels:
      app: delete-guard
  template:
    metadata:
      labels:
        app: delete-guard
    spec:
      containers:
      - name: delete-guard
        image: ubi060:dev
        env:
        - name: SERVICE
          value: delete-guard
        - name: PORT
          value: '8002'
        - name: SECRET_DIR
          value: /run/config
        ports:
        - containerPort: 8002
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8002
          periodSeconds: 5

```

### Сетевые ограничения и взаимодействие

Для всех трёх пространств имён устанавливается default-deny по входящему и исходящему трафику. Разрешения задаются парами namespaceSelector и podSelector в одном элементе правила: должны одновременно совпадать пространство имён и метка приложения. Отдельно разрешаются DNS-запросы к CoreDNS по TCP/UDP 53. Принцип действия NetworkPolicy и требование поддерживающего сетевого плагина установлены документацией Kubernetes [32]. Стенд создаётся с Calico; наличие YAML без работающего CNI не считается подтверждением изоляции.

Шлюз получает доступ к HTTP-портам сервисов; guard и quarantine — к Cassandra и PostgreSQL; audit — к PostgreSQL и RabbitMQ; data-api — к Cassandra, каталогу и сервису записи. Prometheus обращается к /metrics Python-сервисов, Grafana — к Prometheus. Для Cassandra предусмотрен межузловой трафик, необходимый при расширении стенда. Извне публикуется только прикладной шлюз. Администратор открывает Grafana через локальный kubectl port-forward, не публикуя её Service в Интернет. Пример разрешения соединений guard с Cassandra в дополнение к default-deny приведён в листинге 12.

**Листинг 12 – Запрет по умолчанию и разрешение guard → Cassandra**

Файл: `deploy/k8s/40-network-policies.yaml`

```yaml

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: data
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-10-delete-guard
  namespace: data
spec:
  podSelector:
    matchLabels:
      app: cassandra
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: pattern
      podSelector:
        matchLabels:
          app: delete-guard
    ports:
    - protocol: TCP
      port: 9042

```

Уровни контроля дополняют друг друга: NetworkPolicy ограничивает достижимость pod, права Cassandra ограничивают команды, JWT определяет пользователя и роль, а R1–R5 принимают решение об удалении конкретного набора. Обход приложения с доступом администратора СУБД не входит в принятую модель внутреннего нарушителя Н1. Проверять сетевой тайм-аут и отказ CQL-привилегий необходимо раздельными экспериментами.

### Порядок развёртывания и начальная загрузка

Сценарий deploy.sh выполняется на подготовленном Ubuntu/Minikube. После сборки образа создаются namespaces и Secret, затем применяются NetworkPolicy и ресурсы инфраструктуры. Скрипт ожидает готовности StatefulSet, запускает bootstrap Job и проверяет его успешное завершение. Bootstrap создаёт таблицы и роли PostgreSQL, keyspace и таблицу Cassandra с TTL=0, выдаёт минимальные права, меняет исходный пароль Cassandra и загружает пять синтетических наборов. После этого запускаются API, шлюз, мониторинг и задание очистки. Основные команды приведены в листинге 13.

**Листинг 13 – Автоматизированное развёртывание стенда**

Файл: `scripts/deploy.sh`

```bash

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v minikube >/dev/null
command -v kubectl >/dev/null
python3 -c 'import yaml, cryptography'
minikube status >/dev/null
minikube image build -t ubi060:dev .
python3 scripts/build_manifests.py
kubectl apply -f deploy/k8s/00-namespaces.yaml
python3 scripts/cluster_secrets.py --ip "$(minikube ip)"
kubectl apply -f deploy/k8s/40-network-policies.yaml
kubectl apply -f deploy/k8s/10-postgres.yaml -f deploy/k8s/11-rabbitmq.yaml -f deploy/k8s/12-cassandra.yaml
kubectl -n pattern rollout status statefulset/postgres --timeout=300s
kubectl -n pattern rollout status statefulset/rabbitmq --timeout=300s
kubectl -n data rollout status statefulset/cassandra --timeout=600s
kubectl apply -f deploy/k8s/20-bootstrap.yaml
kubectl -n pattern wait --for=condition=complete job/bootstrap --timeout=600s
kubectl apply -f deploy/k8s/30-microservices.yaml
for name in auth-service delete-guard quarantine-service audit-service; do
  kubectl -n pattern rollout status "deployment/$name" --timeout=300s
done
kubectl -n data rollout status deployment/data-api --timeout=300s
kubectl apply -f deploy/k8s/31-gateway.yaml -f deploy/k8s/50-monitoring.yaml -f deploy/k8s/60-cleanup.yaml
kubectl -n pattern rollout status deployment/nginx-gateway --timeout=300s
echo 'Deployment finished. Verify with scripts/demo.py; do not infer readiness from apply alone.'

```

Задание cleanup выполняется как CronJob раз в пять минут. Оно входит через HTTPS-шлюз под отдельной ролью scheduler, получает перечень просроченных наборов и направляет DELETE в guard с устойчивым ключом Idempotency-Key. Прямого удаления из Cassandra у задания нет. concurrencyPolicy: Forbid запрещает одновременное выполнение двух экземпляров одного задания. Учёт срока карантина и повтор PURGING выполняет quarantine-service; в демонстрационном кластере период его просмотра сокращён до пяти секунд, чтобы результат можно было показать без часового ожидания.

В начальных данных присутствуют свободный набор, справочник, зависимый набор, набор с изменённой действующей политикой и отдельный набор для окончательного удаления. Их дата создания искусственно сдвинута на 31 день назад. Для примера задан срок хранения 30 дней и карантин 60 секунд; локальный режим использует карантин 8 секунд. Эти значения нужны для воспроизводимости демонстрации, а не являются оценкой производственной нагрузки или нормативным сроком хранения.

### Мониторинг и подготовка демонстрации

Prometheus собирает deletion_requests_total{decision}, deletion_blocked_total{rule}, quarantine_datasets и guard_check_seconds. Для двух реплик delete-guard задан отдельный headless Service guard-metrics и DNS-discovery, чтобы опрос включал каждый pod, а не случайный экземпляр за обычным Service. Панель Grafana содержит частоту решений, блокировки по правилам, число наборов в карантине и p95 длительности проверки. Порог предупреждения Prometheus является стартовой настройкой стенда; внешняя доставка оповещений не настраивалась. Измерения нагрузки и их интерпретация относятся к разделу 4 [5, 7, 29].

Скрипт demo.py выполняет вход, чтение, постановку в карантин, повтор запроса, проверку скрытия, восстановление, отказ по входящей ссылке, блокировку изменённой политики, окончательное удаление и проверку журнала. Ответы сравниваются с ожидаемыми кодами, после чего сохраняется JSON-отчёт. При запуске с --direct проверяются пять реальных HTTP-процессов на localhost, но PostgreSQL, Cassandra и RabbitMQ заменены локальными адаптерами. Без --direct используется HTTPS-шлюз развёрнутого кластера. Эти режимы явно различаются в отчёте.

### Репозиторий GitHub и проверка реализации

Репозиторий проекта: https://github.com/Vitaly127-svg/ubi060-delete-guard [36]. В корне находятся Dockerfile, закреплённые зависимости и README с командами; app содержит исходные функции; deploy — конфигурацию сети и манифесты; scripts — воспроизводимые операции; tests — проверки; docs — описание результатов и кластерной демонстрации. В репозиторий не включаются .local, пароли, закрытые ключи, локальные БД и служебные логи.

Процесс GitHub Actions описан в .github/workflows/verify.yml. Он устанавливает зависимости, запускает pytest, проверяет схемы YAML и соответствие файлов генератору, выполняет локальный HTTP-сценарий, собирает Docker-образ и сохраняет отчёты в артефакт verification. Результат процесса должен подтверждаться фактическим запуском во вкладке Actions; наличие файла workflow само по себе не является успешной сборкой [16, 36].

На этапе разработки локально выполнены 26 тестов доменных функций, HTTP API и outbox, а также сценарий из 13 шагов между пятью отдельными HTTP-процессами. Получены ожидаемые ответы 202, 403, 409, восстановление после карантина, завершение PURGING и проверка цепочки аудита. Дополнительно 93 ресурса проверены по строгим JSON-схемам Kubernetes 1.33. Локальный запуск использовал SQLite и не подтверждает эксплуатацию Cassandra, RabbitMQ, сетевых политик или кластера. Для этих компонентов подготовлены манифесты и отдельная методика проверки; результаты кластерных экспериментов должны быть получены в разделе 4.

В результате разработаны функции микросервисов, исходные кодовые элементы и средства их воспроизводимого развёртывания. Проверка реализации показывает, что контролируемое удаление, карантин, восстановление и журналирование выполняются на уровне программного прототипа. Подготовленные команды, отчёты и репозиторий позволяют последовательно показать исходную функцию, её API и наблюдаемое поведение, не подменяя будущий кластерный эксперимент заранее заявленным результатом.

## Дополнительные технические источники

30. [FastAPI. OAuth2 with Password and Bearer with JWT tokens](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/) (дата обращения 01.11.2026).

31. [NGINX. Module ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html) (дата обращения 01.11.2026).

32. [Kubernetes. Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) (дата обращения 01.11.2026).

33. [DataStax Python Driver 3.29. Getting Started](https://docs.datastax.com/en/developer/python-driver/3.29/getting_started/index.html) (дата обращения 01.11.2026).

34. [RabbitMQ. Consumer Acknowledgements and Publisher Confirms](https://www.rabbitmq.com/docs/confirms) (дата обращения 01.11.2026).

35. [Kubernetes. Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) (дата обращения 01.11.2026).

36. [Vitaly127-svg. UBI.060 controlled-deletion prototype. GitHub repository](https://github.com/Vitaly127-svg/ubi060-delete-guard) (дата обращения 01.11.2026).
