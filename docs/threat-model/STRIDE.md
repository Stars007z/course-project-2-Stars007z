# STRIDE Threat Analysis

Анализ угроз по модели STRIDE для ключевых потоков и компонентов сервиса Feature Votes.
Все контроли ссылаются на NFR из P03. Всего: **12 угроз**.

| Поток/Элемент       | Угроза (STRIDE)                              | Категория | Контроль                                              | Ссылка на NFR     | Проверка / Артефакт                     |
|---------------------|----------------------------------------------|-----------|--------------------------------------------------------|-------------------|------------------------------------------|
| F1 (`/vote`)        | Spoofing: подделка `user_id`                 | S         | Валидация через Pydantic: `user_id: int ≥ 1`           | NFR-02            | Контракт-тесты, Pydantic                 |
| F3 (`/features/:id`)| Spoofing: запрос несуществующего ресурса с целью разведки | S | Ошибки не раскрывают существование ресурсов (единый 404) | NFR-03            | e2e-тест на несуществующий ID            |
| F1 (`/vote`)        | DoS: flood запросов на голосование           | D         | Rate-limiting: 5 запросов/мин на `user_id`             | NFR-08            | Locust-тест, middleware (в разработке)    |
| F2/F3 (API)         | DoS: общая перегрузка эндпоинтов              | D         | Мониторинг нагрузки, SLA ≥ 99.5%                       | NFR-04            | Prometheus/Grafana                       |
| F1 → F5             | Tampering: повторное голосование             | T         | Уникальность пары `(user_id, feature_id)` в БД         | NFR-01            | BDD-сценарий "duplicate_vote"            |
| F5 (ORM query)      | Tampering: прямое изменение `vote_count`     | T         | Атомарная транзакция + бизнес-логика в приложении      | NFR-01            | e2e-тест на целостность голосов          |
| F5 (ORM query)      | Elevation of Privilege: SQL-инъекция         | E         | Использование SQLAlchemy ORM (параметризованные запросы)| NFR-05            | SAST (Bandit/Trivy), ручной аудит        |
| DB (хранилище)      | Elevation: несанкционированный доступ к БД   | E         | БД в приватной сети; доступ только через приложение    | NFR-05            | Network policy, firewall                 |
| F3 (`/features/:id`)| Information Disclosure: детали ошибок        | I         | Стандартизированный ответ по RFC7807, без stack trace  | NFR-03            | e2e-тест на несуществующий ID            |
| F7 (логирование)    | Information Disclosure: утечка PII в логах   | I         | Логирование только ID, без полных объектов             | NFR-03, NFR-07    | Аудит логов в Loki                       |
| F1 (`/vote`)        | Repudiation: отсутствие подтверждения голоса | R         | Логирование всех голосов с `user_id`, `feature_id`, timestamp | NFR-07      | Запись в Loki, архивация                 |
| F7 (логирование)    | Repudiation: отсутствие алертов при аномалиях| R         | Алерт при >10 голосов/сек от одного `user_id`          | NFR-07            | Grafana alert, Loki query                |

> - **S**poofing — 2 угрозы
> - **T**ampering — 2 угрозы
> - **R**epudiation — 2 угрозы
> - **I**nformation Disclosure — 2 угрозы
> - **D**enial of Service — 2 угрозы
> - **E**levation of Privilege — 2 угрозы
