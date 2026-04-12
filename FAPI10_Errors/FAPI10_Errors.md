|||
|---|---|
|ДИСЦИПЛИНА|Технологии разработки серверных приложений|
|ИНСТИТУТ|ИПТИП|
|КАФЕДРА|Индустриального программирования|
|ВИД УЧЕБНОГО МАТЕРИАЛА|Методические указания к практическим занятиям|
|ПРЕПОДАВАТЕЛЬ|Дворецкий Артур Геннадьевич|
|СЕМЕСТР|4 семестр, 2025/2026 уч. год|

Ссылка на материал: <br>
https://github.com/dv0retsky/fastapi-tutorial/blob/main/FAPI10_Errors/FAPI10_Errors.md

---

# Практическое занятие №10: Обработка ошибок валидации 🧸

Обработка ошибок является важнейшим аспектом создания надежных веб-приложений. Это включает в себя **предвидение** потенциальных ошибок или исключений, которые могут возникнуть во время выполнения приложения, и корректную обработку их. Без грамотной обработки ошибок приложение становится уязвимым к неожиданным сбоям и неудачным сценариям, что может повлиять на качество обслуживания пользователей.

<div align="center">
  <img alt="Project Demo" src="./mygif/gif-10-1.gif" />
</div>

Веб-приложение должно уметь не только ловить ошибки, но и предоставлять пользователю информацию о проблемах в удобном и понятном формате. Плохо обработанные ошибки могут привести к утечке конфиденциальной информации, например, стеков ошибок или данных о внутренней структуре приложения.

На данном занятии мы сосредоточимся на пользовательской (кастомной) обработке ошибок в FastAPI, чтобы обеспечить информативные и удобные для пользователя ответы на ошибки, улучшая тем самым опыт взаимодействия с приложением.

## 🗿 Ответы на ошибки по умолчанию в FastAPI

FastAPI автоматически генерирует ответы об ошибках для распространенных кодов состояния HTTP, таких как 404 (Not Found) или 500 (Internal Server Error). Эти стандартные ответы содержат базовую информацию, которая может быть полезна для разработчиков, но зачастую они не достаточно информативны для пользователей.

Ответы по умолчанию могут включать только краткую информацию, такую как сообщение "`Not Found`" для кода `404` или "`Internal Server Error`" для кода `500`, что не всегда подходит для конечных пользователей. Например, при ошибке `404` можно предоставить дополнительную информацию, объясняющую, почему конкретный ресурс не был найден, или предложить альтернативные действия.

Хотя эти ответы по умолчанию полезны для большинства случаев, пользовательская обработка ошибок позволяет нам адаптировать ответы на ошибки, делая их более информативными и понятными. Это дает нам возможность контролировать формат и содержание сообщений об ошибках, улучшая взаимодействие с пользователем и повышая надежность приложения.

## 🎬 Создание пользовательских классов исключений

В FastAPI мы можем создавать пользовательские классы исключений, которые наследуются от встроенного класса `HttpException`. Эти пользовательские классы исключений позволяют нам определять конкретные сообщения об ошибках, коды состояния и дополнительные сведения для включения в ответ на ошибку.

```python
from fastapi import FastAPI, HTTPException

app = FastAPI()


# класс кастомного исключения для ошибок
class CustomException(HTTPException):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(status_code=status_code, detail=detail)


# пример маршрута, который райзит (выбрасывает) кастомное исключение 
@app.get("/items/{item_id}/")
async def read_item(item_id: int):
    if item_id == 42:
        raise CustomException(detail="Item not found", status_code=404)
    return {"item_id": item_id}
```

В приведенном выше примере мы создали пользовательский класс исключений `CustomException`, который наследуется от `HttpException`. Класс `CustomException` принимает два параметра: `detail` (сообщение об ошибке) и `status_code` (код состояния HTTP). Мы вызываем метод `__init__` родительского класса `HttpException` с предоставленными аргументами `detail` и `status_code`.

В маршруте `read_item` мы проверяем, равен ли `item_id` 42. Если это так, мы создаем наше пользовательское исключение с сообщением об ошибке "Элемент не найден" и кодом состояния 404 (Not found). В противном случае мы возвращаем словарь с `item_id`.

Использование пользовательских классов исключений, подобных этому, позволяет вам создавать более значимые и конкретные ответы на ошибки для вашего API. Вы можете адаптировать сообщения об ошибках и коды состояния в соответствии с требованиями вашего приложения и предоставлять клиентам четкую информацию при возникновении ошибки.

## 📓 Регистрация пользовательских обработчиков исключений

После создания пользовательских классов исключений мы можем зарегистрировать обработчики исключений для захвата и обработки определенных типов исключений. FastAPI предоставляет декоратор `@app.exception_handler` для связывания классов исключений с их соответствующими обработчиками.

Давайте расширим предыдущий код для регистрации Error handler'а (обработчика исключений):

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# не изменяли
class CustomException(HTTPException):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(status_code=status_code, detail=detail)

# Обработчик ошибок (error handler) для класса CustomException 
@app.exception_handler(CustomException)
async def custom_exception_handler(request: Request, exc: CustomException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

# не изменяли
@app.get("/items/{item_id}/")
async def read_item(item_id: int):
    if item_id == 42:
        raise CustomException(detail="Item not found", status_code=404)
    return {"item_id": item_id}
```

В обновленном коде мы добавили пользовательский обработчик ошибок с именем `custom_exception_handler` для класса `CustomException`, используя декоратор app.`exception_handler()`. Эта функция принимает два параметра: `request` (текущий объект запроса) и `exc` (экземпляр вызванного исключения).

Функция `custom_exception_handler` возвращает `JSONResponse` с соответствующим кодом состояния HTTP и телом JSON, содержащим поле `error` с сообщением `detail` пользовательского исключения.

Теперь всякий раз, когда в приложении возникает `CustomException` (как мы делаем в маршруте `/items/{item_id}/`), будет вызван пользовательский обработчик ошибок, и пользовательский ответ об ошибке будет возвращен клиенту.

Такой подход позволяет вам обрабатывать конкретные исключения с помощью настраиваемых ответов, обеспечивая лучший контроль и согласованность при обработке ошибок во всем вашем приложении FastAPI.

## 🏁 Логгирование ошибок

Логгирование ошибок — это важная практика для любого приложения. Это позволяет отслеживать, какие ошибки произошли, когда и где, а также помогает в анализе и устранении проблем. В FastAPI логгирование можно настроить с помощью стандартной библиотеки `logging` в Python.

Для начала, давайте настроим базовое логгирование ошибок:

```python
import logging
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

# Настроим базовый логгер
logging.basicConfig(level=logging.INFO)

app = FastAPI()

class CustomException(HTTPException):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(status_code=status_code, detail=detail)

@app.exception_handler(CustomException)
async def custom_exception_handler(request, exc: CustomException):
    # Логируем информацию о возникшей ошибке
    logging.error(f"Ошибка: {exc.detail}, Статус: {exc.status_code}")
    return JSONResponse(content={"error": exc.detail, "status_code": exc.status_code})

@app.get("/items/{item_id}/")
async def read_item(item_id: int):
    if item_id == 42:
        raise CustomException(detail="Item not found", status_code=404)
    return {"item_id": item_id}
```

В этом примере мы настроили базовый логгер с уровнем `INFO` с помощью функции `logging.basicConfig`. Логирование ошибок происходит в обработчике исключений, когда мы регистрируем ошибку с помощью `logging.error()`, где указываем сообщение об ошибке и код состояния.

Логгирование помогает отслеживать, что именно происходит при возникновении ошибок, и облегчает процесс отладки. Вы также можете использовать различные уровни логирования, такие как `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`, в зависимости от серьезности ситуации.

Как только вы научитесь работать с основным логгированием, можно будет рассматривать более сложные системы логирования, например, интеграцию с внешними сервисами или использование продвинутых библиотек для более гибкого контроля.

## 🥥 Отправка пользовательских сообщений об ошибках

С помощью пользовательских обработчиков исключений мы можем настроить **ответы на ошибки**, возвращаемые нашим приложением FastAPI. Это позволяет нам предоставлять пользователям значимые сообщения об ошибках и полезную информацию при возникновении проблем. В коде в приведённом примере мы это и сделали. Вы можете настроить возвращаемый ответ в соответствии с вашими потребностями. 

## 🪨 Глобальные обработчики исключений

В дополнение к регистрации обработчиков исключений для конкретных исключений, FastAPI также позволяет нам определять **глобальные обработчики исключений**, которые перехватывают все необработанные исключения. Эти глобальные обработчики могут обеспечить резервный ответ **на непредвиденные ошибки**, чтобы предотвратить утечку конфиденциальной информации пользователям.

Давайте добавим глобальный обработчик исключений:

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI()


# не изменяли
class CustomException(HTTPException):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(status_code=status_code, detail=detail)


# не изменяли
@app.exception_handler(CustomException)
async def custom_exception_handler(request: Request, exc: CustomException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )


# Обработчик глобальных исключений, который "ловит" все необработанные исключения 
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"}
    )


# добавили непредусмотренное исключение
@app.get("/items/{item_id}/")
async def read_item(item_id: int):
    # симулируем непредусмотренное исключение
    result = 1 / 0
    return {"item_id": item_id}
```

В приведенном выше коде у нас есть два обработчика исключений. Первый, `custom_exception_handler`, специфичен для класса `CustomException`, как показано в предыдущем примере.

Второй обработчик исключений, `global_exception_handler`, не указывает какой-либо конкретный тип исключения, что делает его глобальным обработчиком исключений. Этот обработчик будет перехватывать все необработанные исключения в приложении FastAPI.

В маршруте `/items/{item_id}/` мы имитируем необработанное исключение, разделив `1` на `0`. Поскольку это явно не перехватывается каким-либо конкретным обработчиком исключений, оно будет перехвачено глобальным обработчиком исключений.

Глобальный обработчик исключений возвращает общий ответ об ошибке с кодом состояния `500` (внутренняя ошибка сервера) и сообщением, указывающим на то, что произошла внутренняя ошибка сервера. Это предотвращает утечку конфиденциальной информации к пользователям в случае непредвиденных ошибок.

Определив глобальный обработчик исключений, вы можете корректно обрабатывать неожиданные исключения и предоставлять согласованные ответы на ошибки во всем вашем приложении FastAPI.

## 🦭 Модели валидации ошибок

FastAPI позволяет нам определять **модели** валидации ошибок, используя модели **Pydantic**. Определяя структуру ответов об ошибках, мы можем обеспечить ***согласованное форматирование*** и данные в наших сообщениях об ошибках.

Тут пример будет достаточно лаконичным:

```python
from pydantic import BaseModel

# Pydantic модель ответов на ошибки
class CustomExceptionModel(BaseModel):
    status_code: int 
    er_message: str 
    er_details: str
```

В данном примере мы наследовались от стандартного Pydantic класса `BaseModel`, определив, что наш кастомной класс будет содержать 3 поля: код ошибки, сообщение и детали. Вы можете настроить его любым необходимым образом, например добавив категорирование, тип или любую другую релевантную информацию.

Теперь давайте применим эти схемы. 

Допустим у нас есть такой код:

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()


# пример модели ответа для успешного запроса
class ItemsResponse(BaseModel):
    item_id: int
    

# не изменяли
class CustomException(HTTPException):
    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(status_code=status_code, detail=detail)


# не изменяли - обработчик ошибок (error handler) для класса CustomException 
@app.exception_handler(CustomException)
async def custom_exception_handler(request: Request, exc: CustomException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )


# добавили модель ответа
@app.get("/items/{item_id}/", response_model=ItemsResponse)
async def read_item(item_id: int):
    if item_id == 42:
        raise CustomException(detail="Item not found", status_code=404)
    return ItemsResponse(item_id=item_id)
```

Тогда документация к такому коду будет выглядеть так:

<div align="center">
  <img alt="Project Demo" src="./image/fig_10-1.jpg" />
</div>

Ошибка будет нормально перехватываться и вернёт нам такой ответ:

<div align="center">
  <img alt="Project Demo" src="./image/fig_10-2.jpg" />
</div>

**Кейс номер 1** для использования пидантика в целях валидации ошибок:

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder  # добавили импорт энкодера
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()


# не изменяли
class ItemsResponse(BaseModel):
    item_id: int
    

# ДОБАВИЛИ модель пидантика для ошибок  
class CustomExceptionModel(BaseModel):
    status_code: int
    er_message: str
    er_details: str 
    

# ДОБАВИЛИ кастомное поле в модель кастомной ошибки
class CustomException(HTTPException):
    def __init__(self, detail: str, status_code: int, message: str):
        super().__init__(status_code=status_code, detail=detail)
        self.message = message


# ДОБАВИЛИ энкодинг ошибки в json 
@app.exception_handler(CustomException)
async def custom_exception_handler(request: Request, exc: CustomException) -> JSONResponse:
    error = jsonable_encoder(CustomExceptionModel(status_code=exc.status_code, er_message=exc.message, er_details=exc.detail))
    return JSONResponse(status_code=exc.status_code, content=error)


# не изменяли
@app.get("/items/{item_id}/", response_model=ItemsResponse)
async def read_item(item_id: int):
    if item_id == 42:
        raise CustomException(detail="Item not found", status_code=404, message="You're trying to get an item that doesn't exist. Try entering a different item_id.")
    return ItemsResponse(item_id=item_id)
```

Тут мы уже получим внутреннюю поддержку, что наши ошибки содержат все необходимые поля в нужном формате. Ответ теперь будет таким:

<div align="center">
  <img alt="Project Demo" src="./image/fig_10-3.jpg" />
</div>

Теперь приступим к **кейсу номер 2** (наиболее частый) использования пидантик схем при работе с ошибками.

Обновим наш код таким образом:

```python
from fastapi import FastAPI, HTTPException, Request, status  # ДОБАВИЛИ импорт статусов, чтобы в тексте статус коды понятнее читались
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel


app = FastAPI()


# не изменяли
class ItemsResponse(BaseModel):
    item_id: int
    

# не изменяли
class CustomExceptionModel(BaseModel):
    status_code: int
    er_message: str
    er_details: str 
    

# не изменяли
class CustomException(HTTPException):
    def __init__(self, detail: str, status_code: int, message: str):
        super().__init__(status_code=status_code, detail=detail)
        self.message = message


# не изменяли
@app.exception_handler(CustomException)
async def custom_exception_handler(request: Request, exc: CustomException) -> JSONResponse:
    error = jsonable_encoder(CustomExceptionModel(status_code=exc.status_code, er_message=exc.message, er_details=exc.detail))
    return JSONResponse(status_code=exc.status_code, content=error)


# ДОБАВИЛИ много мета-информации для описания нашей конечной точки
@app.get(
    "/items/{item_id}/",
    response_model=ItemsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Items by ID.",
    description="The endpoint returns item_id by ID. If the item_id is 42, an exception with the status code 404 is returned.",
    responses={
        status.HTTP_200_OK: {'model': ItemsResponse},
        status.HTTP_404_NOT_FOUND: {'model': CustomExceptionModel},  # вот тут применяем схемы ошибок пидантика
    },
)
async def read_item(item_id: int):
    if item_id == 42:
        raise CustomException(detail="Item not found", status_code=404, message="You're trying to get an item that doesn't exist. Try entering a different item_id.")
    return ItemsResponse(item_id=item_id)
```

Посмотрите как теперь понятно и красиво выглядит наша конечная точка:

<div align="center">
  <img alt="Project Demo" src="./image/fig_10-4.jpg" />
</div>

И в добавок к этому возвращаемый ответ не подсвечивается, что мы его не задокументировали:

<div align="center">
  <img alt="Project Demo" src="./image/fig_10-5.jpg" />
</div>

Надеемся, что грамотная работа с ошибками поможет вам при взаимодействии в вашим фронтендом и пользователями. 

## 🪩 Введение в ошибки проверки (валидации) данных

Ошибки проверки (валидации) данных возникают, когда данные, отправленные пользователем в веб-приложение, не соответствуют заранее заданным правилам. Это может происходить, если данные не соответствуют ожидаемым типам, значениям или ограничениям, заданным в модели данных. Важность обработки таких ошибок заключается в том, чтобы обеспечить безопасность приложения, предотвратить ошибки в бизнес-логике и улучшить взаимодействие с пользователем.

## 🎮 Проверка данных запроса

В рамках обработки ошибок валидации, FastAPI автоматически проверяет данные, переданные в запросах, с помощью Pydantic. Это включает не только тело запросов, но и параметры пути, параметры запроса, а также заголовки. Когда данные не соответствуют ожиданиям (например, неправильный тип данных, отсутствие обязательных полей или несоответствие другим ограничениям), FastAPI немедленно генерирует ошибку с кодом состояния `422` (`Unprocessable Entity`).

Для эффективной обработки ошибок валидации важно понимать, как настраивать модели Pydantic для валидации, а также как правильно настраивать ответы на ошибки.

Предположим, у нас есть модель, которая ожидает, что `price` будет положительным числом, а `name` не будет пустым:

```python
from pydantic import BaseModel, Field

class Item(BaseModel):
    name: str
    price: float = Field(..., gt=0)  # price должен быть больше 0
```

Здесь, если клиент отправит запрос с `price` равным или меньше нулю, FastAPI автоматически сгенерирует ошибку валидации. Важно понимать, что Pydantic, помимо базовых проверок типов, может применять и дополнительные ограничения, такие как минимум и максимум для чисел, минимальная длина строк и многое другое.

Когда ошибка валидации возникает, FastAPI автоматически возвращает подробный ответ с информацией о том, что именно не так с переданными данными. Эта информация важна для того, чтобы пользователи могли исправить ошибку и повторно отправить запрос.

Пример:

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI()

class Item(BaseModel):
    name: str
    price: float = Field(..., gt=0)

@app.post("/items/")
async def create_item(item: Item):
    return {"item": item}
```

Если вы попытаетесь отправить запрос с `price=-5`, FastAPI автоматически сгенерирует ошибку с кодом 422 и сообщением о том, что `price` должен быть больше нуля.

Таким образом, обработка ошибок валидации начинается с настройки моделей данных, а FastAPI возьмёт на себя всю работу по проверке этих данных.

## 🏍️ Понимание ошибок проверки (валидации) данных в FastAPI

В FastAPI ошибки валидации данных обрабатываются через исключение `RequestValidationError`, которое является подклассом `Pydantic ValidationError`. Это исключение возникает, когда входные данные не соответствуют ожидаемым моделям Pydantic, используемым для валидации.

### 🎧 Структура `RequestValidationError`

Класс `RequestValidationError` предоставляет подробную информацию об ошибках валидации, что облегчает диагностику проблем с входными данными. Основные атрибуты этого класса:

- **`errors()`:** Метод, возвращающий список ошибок валидации. Каждая ошибка представлена как словарь с ключами:
    - **`loc`:** Местоположение ошибки (например, путь к полю в теле запроса).
    - **`msg`:** Сообщение об ошибке, описывающее проблему.
    - **`type`:** Тип ошибки (например, тип данных).

- **`body`:** Сырые данные запроса, которые вызвали ошибку валидации.

### 🐾 Как читать ошибки валидации

Ошибка будет содержать информацию о том, что именно в запросе не так:

```json
{
  "detail": [
    {
      "loc": ["body", "price"],
      "msg": "ensure this value is greater than 0",
      "type": "value_error.number.gt"
    }
  ]
}
```

- **`loc`:** Указывает на местоположение ошибки. В данном случае это параметр price в теле запроса.
- **`msg`:** Сообщение об ошибке. В данном случае это описание того, что значение должно быть больше нуля.
- **`type`:** Тип ошибки. В данном случае это ошибка значения типа данных, которое должно быть больше чем 0 (`gt` — "greater than").

С помощью этих данных можно точно определить, в чём заключается ошибка валидации и как её исправить.

## 🧊 Настройка ответов на ошибки проверки

FastAPI позволяет нам настраивать ответы на ошибки проверки, чтобы предоставить пользователям более содержательную обратную связь. Это делается с помощью создания пользовательских обработчиков ошибок, используя декоратор `@app.exception_handler`. Мы можем настроить как содержимое ответа, так и код состояния, чтобы ошибки стали более понятными и информативными для пользователей.

Мы можем создать обработчик ошибок, который будет перехватывать все ошибки валидации (например, `RequestValidationError`) и возвращать кастомизированный ответ. Для этого используется декоратор `@app.exception_handler`.

Пример:

```python
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"message": "Invalid input", "errors": exc.errors()},
    )
```

В этом примере мы создаём обработчик для всех ошибок `RequestValidationError`. Когда ошибка валидации происходит, FastAPI передаёт её в обработчик, который генерирует ответ с кодом состояния 422 и возвращает сообщение о том, что данные некорректны, вместе с подробными ошибками.

### 🔎 Пример кастомизированного ответа

Допустим, мы отправили запрос с ошибочными данными:

```json
{
    "name": "Item",
    "price": -10
}
```

Ответ будет выглядеть следующим образом:

```json
{
  "message": "Invalid input",
  "errors": [
    {
      "loc": ["body", "price"],
      "msg": "ensure this value is greater than 0",
      "type": "value_error.number.gt"
    }
  ]
}
```

Таким образом, пользователь получит не только ошибку с пояснением, но и дополнительные данные (в нашем случае message), которые помогут ему понять, как исправить запрос.

Вы можете настроить обработку ошибок по-разному в зависимости от нужд вашего приложения, например, добавлять дополнительные данные, логировать ошибки или перенаправлять пользователей на страницу с инструкциями.

## 🔈 Обработка ошибок кастомной валидации в FastAPI

В данном шаге мы рассмотрим два сценария обработки ошибок кастомной валидации в FastAPI. Первый сценарий показывает, как ловить вручную вызванное исключение `ValueError` в эндпоинте. Второй — как обрабатывать ошибки, возникающие в валидаторах Pydantic, которые преобразуются в `RequestValidationError`.

### 💤 1. Ловим вручную вызванное исключение ValueError

В этом примере мы вручную проверяем данные в эндпоинте и, если условие не выполняется, вызываем исключение `ValueError`. Затем с помощью пользовательского обработчика ошибок возвращаем кастомный ответ.

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

# Кастомный обработчик для ValueError
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=400,
        content={
            "error": "Manual validation failed",
            "message": str(exc)
        }
    )

class ManualItem(BaseModel):
    name: str
    price: float

@app.post("/manual/")
async def create_manual_item(item: ManualItem):
    # Ручная проверка данных
    if item.price < 0:
        raise ValueError("Price must be non-negative")
    
    return {"message": "Item created", "item": item}
```

**Объяснение кода:**

- **Обработчик ошибок:** Мы создаём обработчик для исключения `ValueError`, который будет вызываться, если цена товара отрицательная. Ответ будет содержать статус 400 (ошибка запроса) и кастомное сообщение об ошибке.
- **Модель данных:** Модель `ManualItem` описывает структуру данных, которая ожидается в теле запроса.
- **Ручная проверка:** В функции `create_manual_item` мы вручную проверяем, что поле `price` не меньше нуля. Если это условие не выполняется, выбрасываем `ValueError`.

**Пример запроса:**

```bash
curl -X POST http://localhost:8000/manual/ -H "Content-Type: application/json" -d '{"name":"Test", "price":-5}'
```

**Ответ:**

```json
{
  "error": "Manual validation failed",
  "message": "Price must be non-negative"
}
```

### 🍪 2. Ловим ошибки, возникающие в валидаторе Pydantic

В этом примере мы используем валидатор внутри модели Pydantic. Если условие проверки не выполняется, валидатор вызывает `ValueError`, что приводит к генерации `RequestValidationError` от FastAPI. Мы перехватываем это исключение и возвращаем кастомизированный ответ.

```python
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationInfo, field_validator

app = FastAPI()

# Кастомный обработчик для ошибок валидации
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation error",
            "details": [
                {
                    "field": err["loc"][-1],
                    "message": err["msg"]
                } 
                for err in exc.errors()
            ]
        }
    )

class ValidatorItem(BaseModel):
    name: str
    price: float

    @field_validator("price")
    @classmethod
    def validate_price(cls, value: float, info: ValidationInfo):
        if value < 0:
            raise ValueError("Price must be non-negative")
        return value

@app.post("/validator/")
async def create_validator_item(item: ValidatorItem):
    return {"message": "Item created", "item": item}
```

**Объяснение кода:**

- **Обработчик ошибок валидации:** Когда данные не проходят валидацию в модели Pydantic, генерируется исключение `RequestValidationError`, которое мы перехватываем с помощью кастомного обработчика. В ответе будет статус `422` и описание ошибок.
- **Валидация данных:** В модели `ValidatorItem` для поля `price` определён валидатор, который проверяет, что цена не отрицательная. Если условие не выполняется, вызывается `ValueError`, и ошибка передаётся в обработчик.
- **Ответ с деталями ошибки:** Мы формируем более понятный и структурированный ответ, в котором выделяем поле с ошибкой и сообщение.

**Пример запроса:**

```bash
curl -X POST http://localhost:8000/validator/ -H "Content-Type: application/json" -d '{"name":"Test", "price":-5}'
```

**Ответ:**

```json
{
  "error": "Validation error",
  "details": [
    {"field": "price", "message": "Price must be non-negative"}
  ]
}
```

## 🍩 Использование тела ошибки RequestValidationError для отладки и обработки

Когда данные, отправленные в ваше приложение, не соответствуют ожидаемым типам или форматам, FastAPI генерирует ошибку валидации. Эта ошибка автоматически включает не только описание проблемы, но и исходное тело запроса, которое вызвало ошибку. Это позволяет вам более эффективно отлаживать приложение и предоставлять пользователю подробную информацию о том, что пошло не так.

Предположим, что вы хотите отлавливать ошибки валидации и предоставить более детальную информацию о том, что произошло. В таком случае, мы можем использовать тело ошибки (`exc.body`), чтобы вернуть пользователю как описание ошибки, так и сам запрос, который вызвал ошибку. Это может быть полезно, например, для логирования, отладки или предоставления более точной обратной связи пользователям.

Давайте посмотрим, как это работает на примере:

```python
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

# Обработчик ошибок валидации
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Возвращаем подробный ответ с ошибками и исходным запросом
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({"detail": exc.errors(), "body": exc.body}),
    )

# Модель данных для элемента
class Item(BaseModel):
    title: str
    size: int

# Конечная точка для создания элемента
@app.post("/items/")
async def create_item(item: Item):
    return item
```

В данном примере у нас есть модель `Item`, которая ожидает два поля: `title` (строка) и `size` (целое число). Когда данные, которые отправляются в запросе, не соответствуют этим ожиданиям, например, если вместо целого числа для поля `size` приходит строка, возникает ошибка валидации.

**Объяснение кода:**

1. **Обработчик ошибок валидации:** Мы создаём специальный обработчик для исключения `RequestValidationError`, которое генерируется FastAPI, если данные не проходят проверку. Этот обработчик перехватывает ошибки и возвращает более детализированный ответ с помощью `JSONResponse`. В ответе мы указываем как описание ошибки (`exc.errors()`), так и тело запроса (`exc.body`).

2. **Модель данных:** Модель `Item` описывает структуру данных, которые мы ожидаем. В нашем случае, это два поля: `title`, которое должно быть строкой, и `size`, которое должно быть целым числом.

3. **Конечная точка API:** В данном случае мы создаём POST-метод, который ожидает данные типа `Item`. Если данные не соответствуют ожиданиям, будет вызван обработчик ошибок, и пользователь получит подробную информацию о том, что пошло не так.

**Пример запроса с ошибкой:**

Предположим, что мы отправляем запрос с неверными данными, где вместо целого числа для поля `size` передаём строку:

```json
{
  "title": "Towel",
  "size": "XL"
}
```

Этот запрос вызовет ошибку, так как `size` должно быть числом. В ответе мы получим не только сообщение об ошибке, но и сам запрос, который вызвал её:

```json
{
  "detail": [
    {
      "loc": [
        "body",
        "size"
      ],
      "msg": "value is not a valid integer",
      "type": "type_error.integer"
    }
  ],
  "body": {
    "title": "Towel",
    "size": "XL"
  }
}
```

**Разбор ответа:**

- **`detail`:** Это список ошибок, где каждая ошибка описана с помощью трёх ключей:
    - **`loc`:** Местоположение ошибки в запросе (в нашем случае это поле `size` в теле запроса).
    - **`msg`:** Описание ошибки (например, "value is not a valid integer").
    - **`type`:** Тип ошибки (например, "type_error.integer").

- **`body`:** Это исходные данные запроса, которые привели к ошибке. Мы видим, что в поле `size` передано не число, а строка.

**Зачем это нужно:**

- **Отладка:** Когда запросы не проходят валидацию, вы можете использовать тело ошибки для более точной диагностики. Особенно это полезно в процессе разработки, когда вы хотите увидеть, что именно отправил клиент, и какие данные были некорректными.

- **Обратная связь для пользователей:** Вы можете вернуть подробную информацию пользователю, объяснив, что именно было не так с его запросом. Это помогает улучшить пользовательский опыт.

- **Логирование ошибок:** Отправка тела запроса вместе с ошибками помогает вам логировать данные, которые приводят к сбоям, что важно для анализа и исправления проблем.

<div align="center">
  <img alt="Project Demo" src="./mygif/gif-10-2.gif" />
</div>

Таким образом, использование тела ошибки помогает не только в отладке, но и в организации более понятной и полезной обратной связи с пользователями вашего приложения.

---

<div align="center"> Made with ❤️ by <b>dv0retsky</b> </div>