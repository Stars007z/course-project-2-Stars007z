# Data Flow Diagram — Feature Votes Service

## Контекст и границы доверия

Диаграмма отображает потоки данных в сервисе голосования за фичи. Выделены четыре зоны доверия:

- **Client**: пользователь (браузер, CLI, мобильное приложение)
- **Edge**: публичная точка входа (HTTPS)
- **Core**: доверенная зона приложения (FastAPI с middleware)
- **Data**: база данных и системы безопасности (логи, сканирование)

Все внешние запросы проходят через HTTPS. Внутренние взаимодействия — через ORM и логирование.

```mermaid
flowchart LR
  subgraph Client["Trust Boundary: Client"]
    U["User Browser/CLI"]
  end

  subgraph Edge["Trust Boundary: Edge"]
    GW["API Gateway / FastAPI Entry"]
  end

  subgraph Core["Trust Boundary: Core"]
    APP["FastAPI Application"]
  end

  subgraph Data["Trust Boundary: Data"]
    DB["PostgreSQL Database"]
    LOG["Logging System Loki/Grafana"]
  end

  %% Data Flows
  U -->|F1: HTTPS POST /features/:id/vote| GW
  U -->|F2: HTTPS GET /features| GW
  U -->|F3: HTTPS GET /features/:id| GW

  GW -->|F4: Forward to App| APP
  APP -->|F5: ORM Query SQLAlchemy| DB
  DB -->|F6: Query Result| APP

  APP -->|F7: Log Events & Errors| LOG

  APP -->|F8: JSON Response RFC7807| GW
  GW -->|F9: HTTPS Response| U
