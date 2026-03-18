### 1. Клонируйте репозиторий

```bash
git clone https://github.com/gr0w1/scamseeker.git
cd scamseeker
```

### 2. Создайте файл `.env`

В корне проекта создайте файл `.env` со следующим содержимым (при необходимости измените значения):

```env
APP_TITLE=Text Risk Analyzer API
APP_DESCRIPTION=Backend сервиса для анализа подозрительных сообщений
APP_VERSION=0.1.0
DEBUG=false

DB_HOST=postgres
DB_PORT=5432
DB_NAME=text_risk_db
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_ECHO=false

JWT_SECRET_KEY=CHANGE_ME_SECRET_KEY
JWT_ALG=HS256
JWT_TTL_SECONDS=86400

MODEL_VERSION=spam_lr_char3-5_tfidf_v1
```

Рекомендуется заменить `JWT_SECRET_KEY` на надёжный уникальный секрет для production-среды.

### 3. Запустите сервис через Docker Compose

```bash
docker compose up --build
```

### 4. (Опционально) Настройте Nginx
