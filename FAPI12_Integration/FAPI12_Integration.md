|||
|---|---|
|ДИСЦИПЛИНА|Технологии разработки серверных приложений|
|ИНСТИТУТ|ИПТИП|
|КАФЕДРА|Индустриального программирования|
|ВИД УЧЕБНОГО МАТЕРИАЛА|Методические указания к практическим занятиям|
|ПРЕПОДАВАТЕЛЬ|Дворецкий Артур Геннадьевич|
|СЕМЕСТР|4 семестр, 2025/2026 уч. год|

Ссылка на материал: <br>
https://github.com/dv0retsky/fastapi-tutorial/blob/main/FAPI12_Integration/FAPI12_Integration.md

---

# Практическое занятие №12: Введение в интеграционное тестирование 🪩

## 💿 Введение в интеграционное тестирование

Интеграционное тестирование в FastAPI включает в себя тестирование взаимодействий между различными частями вашего приложения. В отличие от модульных тестов, которые фокусируются на отдельных блоках кода, интеграционные тесты гарантируют, что интегрированные компоненты работают вместе должным образом. Интеграционные тесты помогают выявить проблемы, которые могут возникнуть при взаимодействии нескольких компонентов, такие как проблемы с зависимостями, подключениями к базе данных или интеграцией API.

<div align="center">
  <img alt="Project Demo" src="./mygif/gif12-1.gif" />
</div>

**Пример различий между модульными и интеграционными тестами:**

```python
# Модульный тест: тестирует только функцию без зависимостей
def test_read_item_unit():
    assert read_item(42) == {"item_id": 42}

# Интеграционный тест: проверяет работу через HTTP
def test_read_item_integration(client: TestClient):
    response = client.get("/items/42")
    assert response.status_code == 200
```

**Схема взаимодействия компонентов:**   
Запрос → TestClient → Роутер → Зависимости (БД, сервисы) → Ответ

---

## 👾 Использование TestClient для интеграционных тестов

FastAPI предоставляет класс `TestClient` из модуля `fastapi.testclient`, который является ценным инструментом для запуска интеграционных тестов. `TestClient` позволяет вам выполнять реальные HTTP-запросы к вашему приложению FastAPI во время тестирования, имитируя реальные сценарии.

Что также немаловажно, `TestClient` позволяет тестировать приложение FastAPI без его запуска, имитируя реальные запросы (без запуска uvicorn'а).

Для асинхронных тестов можно использовать `AsyncClient` из модуля `httpx`. Важно помнить, что `TestClient` используется для синхронных эндпоинтов, а `AsyncClient` — для асинхронных.

**Пример асинхронного теста:**

```python
from httpx import AsyncClient

async def test_async_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/async-route/")
    assert response.status_code == 200
```

---

## 👀 Подготовка тестовой среды

Перед запуском интеграционных тестов с помощью `TestClient` крайне важно настроить тестовую среду, которая очень похожа на производственную, но с контролируемыми данными. Это может включать в себя создание тестовой базы данных, заполнение ее тестовыми данными и настройку любых необходимых зависимостей.

Для изоляции тестов и использования тестовой базы данных можно воспользоваться фикстурами `pytest`.

**Пример настройки тестовой БД с SQLAlchemy и фикстурами:**

```python
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from myapp.models import Base, Item

# Фикстура для создания тестовой базы данных
@pytest.fixture(scope="module")
def test_db():
    # Создание временной БД
    engine = create_engine("sqlite:///test.db")
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)

# Фикстура для сессии БД, создаваемой для каждого теста
@pytest.fixture
def db_session(test_db):
    # Новая сессия для каждого теста
    Session = sessionmaker(bind=test_db)
    session = Session()
    yield session
    session.rollback()
    session.close()
```

В этом примере создается временная база данных, которая будет использоваться только для тестов. После выполнения тестов база данных будет очищена и удалена.

---

## 👻 Тестирование конечных точек и маршрутов

Интеграционные тесты с **"TestClient"** позволяют вам тестировать **конечные точки API** вашего приложения и маршруты точно так же, как это сделал бы реальный пользователь или внешняя служба. Отправляя HTTP-запросы и получая ответы, вы можете убедиться, что ваш API ведет себя корректно в различных условиях.

Вот пример того, как вы можете выполнить интеграционное тестирование с помощью `TestClient`.

Предположим, у вас есть приложение FastAPI со следующим кодом:

```python
# main.py

from fastapi import FastAPI

app = FastAPI()

@app.get("/items/{item_id}")
def read_item(item_id: int):
    # тут какая-то логика, связанная с работой других систем
    return {"item_id": item_id}
```

Теперь давайте напишем интеграционный тест, используя `TestClient`, чтобы протестировать конечную точку `/items/{item_id}`:

```python
# test_main.py

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_read_item():
    # Отправляем запрос на конечную точку /items/{item_id} с item_id=1
    response = client.get("/items/1")

    # Assertions
    assert response.status_code == 200
    assert response.json() == {"item_id": 1}

    # Отправляем запрос на конечную точку /items/{item_id} с item_id=z (неправильный тип данных)
    response = client.get("/items/z")

    # Assertions
    assert response.status_code == 200  # Это завершится ошибкой, поскольку конечная точка не обработает наш тип данных
    assert response.json() == {"item_id": "z"}  # это тоже завершится ошибкой по той же причине
```

В этом примере мы сначала импортируем `TestClient` и наше приложение FastAPI из `main.py`. Затем мы создаем объект `TestClient` с помощью нашего приложения FastAPI.

Функция `test_read_item` выполняет два тестовых примера:

1. Он отправляет запрос GET в `/items/1` и проверяет, что код состояния ответа равен 200, а ответ в формате JSON соответствует ожидаемому результату `{"item_id": 1}`.
2. Он отправляет запрос GET на `/items/z` (неправильный item_id) и вызывает ошибочный assertion, что код статуса ответа равен 200, а ответ в формате JSON равен `{"item_id": "z"}`. Этот тест завершится неудачей.
Или расширенный пример интеграционного теста, но тоже упрощенный. 

Для примера есть приложение:

```python
# main.py
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel


app = FastAPI()

# псевдо-бд
fake_users_db = [
    {
        "user_id": 1,
        "username": "user123",
        "password": "secretpassword",
        "email": "user@example.com"
    }
]

# имитируем хранилище сессий
sessions = {}


# модельки
class UserCredentials(BaseModel):
    username: str
    password: str

class UserData(BaseModel):
    user_id: int
    username: str
    email: str


# роуты
@app.post("/login/") # проверяем наличие юзера и возвращаем куки
def login(user_creds: UserCredentials, response: Response):
    for user in fake_users_db:
        if user["username"] == user_creds.username and user["password"] == user_creds.password:
            response.set_cookie(key="session_cookie", value="my_random_cookie")
            sessions[user_creds.username] = "my_random_cookie" # это чисто для демонстрации, если 5 юзеров зайдут, то всем не нужно одинаковые куки ставить
            return {"message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/protected_data/", response_model=UserData) # возвращаем данные по кукам, если они валидны
def protected_data(request: Request):
    for username, cookie in sessions.items():
        if request.cookies.get("session_cookie") and cookie == request.cookies.get("session_cookie"):
            user = get_user_by_username(username)
            return UserData(**user)
    raise HTTPException(status_code=401, detail="Bad cookie")


def get_user_by_username(username: str): # вспомогательная функция по извлечению юзера из БД
    for user in fake_users_db:
        if user.get("username") == username:
            return user
    else:
        raise HTTPException(status_code=404, detail="User not found")
```

Тогда интеграционный тест мог бы быть таким:

```python
# test_app.py
from fastapi.testclient import TestClient
from main import app # тут замените импорт на правильное расположение файла


client = TestClient(app)

def test_login_and_access_data():
    # тестируем точку логина, направляя учетные данные и получая куки
    login_data = {
        "username": "user123",
        "password": "secretpassword"
    }
    response = client.post("/login/", json=login_data)
    assert response.status_code == 200
    assert "session_cookie" in response.cookies

    # извлекаем куки из ответа
    cookies = response.cookies
    cookie_value = cookies["session_cookie"]

    # проверяем доступ к получению информации через полученные куки
    headers = {
        "Cookie": f"session_cookie= {cookie_value}"
    }
    response = client.get("/protected_data/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "user_id" in data
    assert "username" in data
    assert "email" in data
```

Мы, конечно, можем быть более тщательными, проверять разное поведение юзеров (в т.ч. неблагонадежное). Тут мы не проверяем подмену данных, крайние значения и прочее. Но главное понять **идею** - что мы можем имитировать действия пользователя (что он послал, что ему пришло, какой ответ дала база данных, записались ли значения, и прочее и прочее). То есть отличие интеграционного теста от модульного в том, что при интеграционном тестировании мы проверяем, как приложение работает в совокупности. 

Интеграционное тестирование с помощью **"TestClient"** позволяет вам проверить поведение всего вашего приложения FastAPI, включая его маршруты и взаимодействия с внешними зависимостями, в тестовой среде. Это гарантирует, что конечные точки реагируют должным образом, и помогает вам выявить любые потенциальные проблемы в вашем приложении.

---

## 🛸 Тестирование аутентификации и авторизации

Интеграционные тесты также полезны для тестирования механизмов аутентификации и авторизации в вашем приложении FastAPI. Вы можете смоделировать сценарии, в которых пользователи или службы имеют разные роли и разрешения, чтобы обеспечить надлежащий контроль доступа.

Пример использования аутентификации с токенами JWT:

```python
# main.py

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = {
    "user1": {"username": "user1", "password": "password1", "role": "admin"},
    "user2": {"username": "user2", "password": "password2", "role": "user"},
}

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User(BaseModel):
    username: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_db(username: str):
    return fake_users_db.get(username)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is invalid")
        user = get_user_from_db(username)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is invalid")


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected")
def protected_route(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="You do not have access to this resource")
    return {"message": "Protected content"}
```

Теперь пример тестирования аутентификации и авторизации:

```python
# test_auth.py

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_access_protected_route():
    # Логинимся и получаем токен
    login_data = {"username": "user1", "password": "password1"}
    response = client.post("/token", data=login_data)
    assert response.status_code == 200
    token = response.json().get("access_token")

    # Доступ к защищенному ресурсу с правильным токеном
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"message": "Protected content"}

    # Логинимся с другим пользователем и получаем токен
    login_data = {"username": "user2", "password": "password2"}
    response = client.post("/token", data=login_data)
    assert response.status_code == 200
    token = response.json().get("access_token")

    # Попытка доступа к защищенному ресурсу с неправильной ролью
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json() == {"detail": "You do not have access to this resource"}
```

В этом примере:

1. Мы создаем токен с помощью правильных учетных данных.
2. Выполняем запрос на защищенный ресурс `/protected` с токеном и проверяем, что доступ разрешен для администратора.
3. Попытка доступа с токеном пользователя с другой ролью приводит к ошибке 403 (Forbidden), что подтверждает, что система правильно обрабатывает контроль доступа.

Интеграционные тесты с **"TestClient"** позволяют эффективно проверять работу аутентификации и авторизации, а также убедиться, что ограничения доступа и роли пользователей правильно применяются в приложении.

---

## 🧙🏼 Целостность данных и тестирование базы данных

Для приложений с интеграцией баз данных интеграционные тесты могут проверять целостность данных и тестировать различные операции CRUD. Вы можете создавать тестовые данные, выполнять операции с базой данных и проверять правильность извлечения и обновления данных.

Пример интеграционного тестирования с использованием базы данных SQLite:

```python
# main.py

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session  # Добавлен импорт Session

app = FastAPI()

DATABASE_URL = "sqlite:///./test.db"

Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)

Base.metadata.create_all(bind=engine)

class ItemCreate(BaseModel):
    name: str
    description: str

@app.post("/items/")
def create_item(item: ItemCreate, db: Session = Depends(SessionLocal)):
    db_item = Item(**item.dict())
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

@app.get("/items/{item_id}")
def read_item(item_id: int, db: Session = Depends(SessionLocal)):
    db_item = db.query(Item).get(item_id)
    if not db_item:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item
```

Пример интеграционного теста для проверки целостности данных:

```python
# test_database.py

from fastapi.testclient import TestClient
from main import app, SessionLocal, Item, Base, engine

client = TestClient(app)

def setup_module(module):
    Base.metadata.create_all(bind=engine)

def teardown_module(module):
    db = SessionLocal()
    db.query(Item).delete()
    db.commit()
    db.close()  # Важно закрыть соединение

def test_create_item():
    response = client.post("/items/", json={"name": "Test", "description": "Test"})
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Test"
    assert "id" in data

def test_read_item():
    # Создаем объект напрямую через БД для надежности
    db = SessionLocal()
    test_item = Item(name="Test", description="Test")
    db.add(test_item)
    db.commit()
    
    response = client.get(f"/items/{test_item.id}")
    assert response.status_code == 200
    assert response.json()["id"] == test_item.id
    
    db.close()

def test_item_not_found():
    response = client.get("/items/999")
    assert response.status_code == 404
```

В этом примере:

1. Мы создаем базу данных SQLite для тестирования с помощью SQLAlchemy.
2. Создаем маршруты для добавления и получения элементов из базы данных.
3. В тестах:
    - Проверяем создание элемента и его возвращение в ответе.
    - Проверяем, что данные правильно извлекаются из базы данных.
    - Проводим тест на случай, когда элемент не найден.

Используя интеграционные тесты, можно проверить правильность работы всех операций с базой данных, таких как создание, чтение, обновление и удаление данных, а также удостовериться, что целостность данных сохраняется при выполнении операций.

---

## 🏁 Управление тестовыми базами данных

Для поддержания изоляции и контроля во время интеграционных тестов обычно используется отдельная тестовая база данных. Вы можете настроить свое приложение так, чтобы оно использовало тестовую базу данных во время тестирования, и сбрасывать ее перед каждым тестом, чтобы обеспечить чистый лист для каждого тестового примера.

Один из популярных подходов — создание временной тестовой базы данных для каждого запуска тестов. Это гарантирует, что тесты не будут влиять друг на друга и не затронут реальные данные.

Пример использования SQLAlchemy для настройки тестовой базы данных:

**Настройка тестовой базы данных в FastAPI:**

1. Создайте файл `test_db.py`, который будет управлять созданием и удалением тестовой базы данных.

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import Base  # импортируем базовый класс для моделей

SQLALCHEMY_DATABASE_URL = "postgresql://test_user:test_password@localhost/test_db"

# Настроим соединение с базой данных
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Создаем сессию
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Функция для создания всех таблиц в тестовой базе данных
def init_db():
    Base.metadata.create_all(bind=engine)

# Функция для удаления всех данных из таблиц
def drop_db():
    Base.metadata.drop_all(bind=engine)
```

2. В файле тестов настроим тестовую среду с использованием `TestClient` и сбросом базы данных перед каждым тестом.

```python
from fastapi.testclient import TestClient
import pytest
from main import app
from test_db import init_db, drop_db, TestingSessionLocal

client = TestClient(app)

# Сначала инициализируем базу данных перед тестами
@pytest.fixture(scope="module", autouse=True)
def setup_and_teardown():
    # Создание тестовой базы данных
    init_db()
    
    yield
    
    # Удаление данных после завершения тестов
    drop_db()

# Пример теста
def test_create_item():
    response = client.post("/items/", json={"name": "item1", "price": 10.0})
    assert response.status_code == 201
    assert response.json() == {"name": "item1", "price": 10.0}

def test_read_item():
    response = client.get("/items/1")
    assert response.status_code == 200
    assert response.json() == {"name": "item1", "price": 10.0}
```

<div align="center">
  <img alt="Project Demo" src="./mygif/gif12-2.gif" />
</div>

### ⚠️ Важные моменты:

1. **Инициализация базы данных:** Мы используем функцию `init_db()` для создания всех таблиц в тестовой базе данных. Это нужно делать один раз перед выполнением тестов.
2. **Очистка базы данных:** После выполнения тестов мы вызываем `drop_db()`, чтобы удалить все данные и таблицы.
3. **Изоляция тестов:** Каждый тест выполняется с чистой тестовой базой данных, что гарантирует, что результаты тестов не будут зависеть от предыдущих тестов.

Этот подход позволяет проводить тесты в изолированной среде, где каждый тест начинается с чистого состояния базы данных, что исключает влияние сторонних изменений и улучшает стабильность тестов.

---

<div align="center"> Made with ❤️ by <b>dv0retsky</b> </div>