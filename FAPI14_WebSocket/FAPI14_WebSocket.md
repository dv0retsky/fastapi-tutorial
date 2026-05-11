|||
|---|---|
|ДИСЦИПЛИНА|Технологии разработки серверных приложений|
|ИНСТИТУТ|ИПТИП|
|КАФЕДРА|Индустриального программирования|
|ВИД УЧЕБНОГО МАТЕРИАЛА|Методические указания к практическим занятиям|
|ПРЕПОДАВАТЕЛЬ|Дворецкий Артур Геннадьевич|
|СЕМЕСТР|4 семестр, 2025/2026 уч. год|

Ссылка на материал: <br>
https://github.com/dv0retsky/fastapi-tutorial/blob/main/FAPI14_WebSocket/FAPI14_WebSocket.md

---

# Практическое занятие №14: Поддержка WebSocket 🪆

## 🎀 Понимание веб-сокетов в веб-приложениях

До появления WebSocket разработчики имитировали «пуш» с сервера через Comet-техники: долгие HTTP-запросы (long-polling) и потоковую передачу (streaming). Это позволяло серверу присылать обновления без частого опроса, но имело накладные расходы и ограничения протокола HTTP/1.1. Позже в HTML-стандарте появился однонаправленный push через Server-Sent Events (SSE). WebSocket решает задачу двунаправленной постоянной связи, снимая многие ограничения Comet/SSE. 

<div align="center">
  <img alt="Project Demo" src="./mygif/gif14-1.gif" />
</div>

### 🛍️ Что такое WebSocket и как он стартует

WebSocket — это двунаправленный, полно-дуплексный канал поверх TCP. Соединение начинается с обычного HTTP/1.1-запроса с заголовком `Upgrade: websocket`; сервер отвечает статусом **101 Switching Protocols** и далее обе стороны переходят на рамочный протокол WebSocket. Этот подход совместим с портами 80/443 и большинством прокси.

В рукопожатии участвуют и специальные заголовки: `Sec-WebSocket-Key`/`Sec-WebSocket-Accept` (подтверждение намерения апгрейда) и `Sec-WebSocket-Version` (обычно 13).

### 🌸 Как устроен протокол «под капотом»

После апгрейда данные передаются **кадрами** (frames). Есть **данные** (text/binary) и **управляющие** кадры: `ping` (0x9), `pong` (0xA), `close` (0x8); управляющие кадры короткие и не фрагментируются. Фрагментация разрешена для больших сообщений; между их частями могут вставляться лишь управляющие кадры. 

Важная особенность безопасности/совместимости с посредниками: **клиент обязан маскировать** все кадры, и сервер должен разорвать соединение при немаскированном клиентском кадре; **сервер, наоборот, не должен маскировать** свои кадры.

### 🍬 Субпротоколы и расширения

В рукопожатии можно договориться о субпротоколе (заголовок `Sec-WebSocket-Protocol`) — это «язык» поверх WebSocket: от WAMP/SIP до вашего собственного (`json`, версии `my-protocol-v2` и т.п.). Сервер выбирает один из предложенных клиентом.

Отдельно согласуются **расширения** (заголовок `Sec-WebSocket-Extensions`). Наиболее распространено **permessage-deflate** (RFC 7692): сжатие полезной нагрузки на уровне сообщений, с параметрами вроде `*_max_window_bits` и `*_no_context_takeover`.

### 💄 Чем WebSocket отличается от HTTP и когда нужен SSE

Классический HTTP — это модель **запрос-ответ**: сервер не может сам «толкнуть» событие без нового запроса клиента. WebSocket после рукопожатия держит **одно долговременное соединение**, по которому **обе стороны** могут слать сообщения когда угодно. Для простых однонаправленных фидов (уведомления, тикеры), где клиенту слать почти нечего, **SSE** проще и дешевле в эксплуатации — это поток текстовых событий по HTTP. 

### 🦩 Производительность и бэкпрешсур

Классический браузерный `WebSocket`-API не предоставляет явного механизма бэкпрешсура (ограничения скорости обработки сообщений). Экспериментальный `WebSocketStream` интегрирует стримы и автоматически регулирует чтение/запись, что помогает при высоких скоростях потока. Проверьте совместимость браузеров перед использованием.

### 💝 Где это применяется

Чаты и игры в реальном времени, совместное редактирование, лайв-панели мониторинга, торговые терминалы — любые сценарии, где требуются низкая задержка и двунаправленный обмен без постоянного повторного открытия HTTP-запросов. Базовая модель: краткое HTTP-рукопожатие → долговременный канал → сообщения/пинги/закрытие.

---

## 👻 Поддержка WebSocket в FastAPI

Думайте о WebSocket как о «постоянном телефонном звонке» между браузером и сервером. FastAPI умеет в такие звонки «из коробки», опираясь на библиотеку Starlette. Вы берёте класс `WebSocket`, подключаете клиента (`accept`), читаете сообщения (`receive_*`) и отправляете ответы (`send_*`).

### 🎬 Из чего это состоит

- **Где лежит API.** Класс `WebSocket` импортируем прямо из `fastapi`, но под капотом это Starlette. Это нормально и так задумано.

- **Что можно отправлять/получать.**

    - отправка: `send_text()`, `send_bytes()`, `send_json()`- приём: `receive_text()`, `receive_bytes()`, `receive_json()`. Если клиент закрылся — ловим `WebSocketDisconnect`. 

### 🗿 Как это выглядит в коде (минимум)

```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI()

@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()                # «поднять трубку»
    try:
        while True:
            msg = await ws.receive_text()
            await ws.send_text(f"эхо: {msg}")
    except WebSocketDisconnect:
        pass                          # «абонент положил трубку»
```

Этот шаблон — основа большинства WS-обработчиков в FastAPI.

### 🥥 Пара приятных фишек

- **`send_json` и `receive_json`**. Очень удобно слать не строки, а структуры данных (словарь/список) — сервер сам сериализует/десериализует.
- **Класс-эндпоинт (по желанию)**. Вместо функции можно использовать `WebSocketEndpoint` из Starlette — удобно, если любите классы. 

### 🪨 Где мой эндпоинт в Swagger?

В Swagger UI (`/docs`) WebSocket-маршруты **не отображаются**, потому что OpenAPI описывает HTTP-запросы/ответы. Это известное ограничение — не пугайтесь. Тестируйте WS через клиент (браузер/скрипт) или отдельные тулзы. 

### 🦭 А как тестировать

Встроенный `TestClient` умеет подключаться к WebSocket через контекстный менеджер `websocket_connect()`. Это удобно для автотестов: открыть соединение, отправить сообщение, проверить ответ — и всё в одном процессе. 

---

## 🧸 Создание маршрутов WebSocket

Маршрут WebSocket — это как «дверь» с адресом, например `/ws` или `/ws/{room}`. Через эту дверь клиент заходит один раз, и дальше вы разговариваете в обе стороны по одному открытому каналу. Как и в HTTP-маршрутах, можно использовать **path-параметры** и **query-параметры**. В FastAPI всё это поддержано прямо из коробки. 

### 🐳 Пример 1: маршрут с параметрами (комнаты + токен)

```python
from fastapi import FastAPI, WebSocket, Query, WebSocketDisconnect

app = FastAPI()

# ws://localhost:8000/ws/chat?token=abc
@app.websocket("/ws/{room}")
async def ws_room(ws: WebSocket, room: str, token: str | None = Query(None)):
    # здесь можно проверить token и решить, пускать ли в комнату
    await ws.accept()                      # «поднять трубку»
    try:
        while True:
            msg = await ws.receive_text()  # ждём сообщение от клиента
            await ws.send_text(f"[{room}] эхо: {msg}")  # отвечаем
    except WebSocketDisconnect:
        pass                               # «абонент положил трубку»
```

Идея повторяет официальный минимальный пример FastAPI с `receive_text()` / `send_text()` и перехватом `WebSocketDisconnect`. 

### 🪩 Пример 2: «менеджер подключений» с комнатами

Представьте дом: **комнаты** — это чаты, **жильцы** — подключённые клиенты. Мы храним словарь `комната → набор WebSocket-подключений` и даём три простых действия: **connect** (впустить жильца), **broadcast** (сказать всем в комнате), **disconnect** (убрать жильца, если ушёл).

```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect


app = FastAPI()


class RoomManager:
    def __init__(self):
        # Словарь: имя комнаты -> множество активных WebSocket-подключений.
        # Почему множество (set)? Чтобы легко добавлять/удалять и не держать дубликаты.
        self.rooms: dict[str, set[WebSocket]] = {}

    async def connect(self, room: str, ws: WebSocket):
        # 1) Завершаем рукопожатие WebSocket (поднять «трубку»).
        await ws.accept()
        # 2) Добавляем подключение в нужную комнату.
        self.rooms.setdefault(room, set()).add(ws)

    def disconnect(self, room: str, ws: WebSocket):
        # Аккуратно убираем подключение из комнаты (если такое было).
        conns = self.rooms.get(room)
        if not conns:
            return
        conns.discard(ws)
        # Если в комнате больше никого — удаляем её из словаря (необязательно, но опрятно).
        if not conns:
            self.rooms.pop(room, None)

    async def broadcast(self, room: str, message: str):
        # Рассылаем сообщение всем жильцам комнаты.
        # Оборачиваем в list(...) — на случай, если кто-то вырубится прямо во время рассылки.
        for client in list(self.rooms.get(room, ())):
            await client.send_text(message)

manager = RoomManager()

@app.websocket("/ws/{room}")
async def ws_room(ws: WebSocket, room: str):
    # Клиент пришёл — впускаем его в нужную комнату.
    await manager.connect(room, ws)
    try:
        while True:
            # Ждём входящее сообщение от клиента.
            msg = await ws.receive_text()
            # Говорим «всем в комнате», включая отправителя.
            await manager.broadcast(room, f"[{room}] кто-то написал: {msg}")
    except WebSocketDisconnect:
        # Клиент ушёл — убираем его из комнаты.
        manager.disconnect(room, ws)
```

Этот приём — учебная версия идеи из официальной документации (там используют `ConnectionManager` и общий список подключений). Он отлично подходит для локальных/небольших проектов. Для масштабирования на несколько процессов/серверов используйте внешний pub/sub (например, `encode/broadcaster` поверх Redis/Kafka/Postgres).

### 🍩 Альтернатива: классовый обработчик

Если любите классы и разнести логику по методам — можно использовать `WebSocketEndpoint` из Starlette (FastAPI полностью совместим). ([**Starlette**](https://starlette.dev/endpoints/))

---

### 🍪 Пример приложения со списком подключенных клиентов

Этот пример больше вдохновлен официальной документацией FastAPI - там они демонстрируют хранение подключений в простом питоновском списке (что на самом деле не очень удобно в реальной жизни, но для демонстрации - пригодится).

```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI()

# список для хранения подключённых WebSocket клиентов
connected_clients = []


# WebSocket-роут для обработки WebSocket подключений 
@app.websocket("/ws/")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Message text was: {data}")
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


# роут для массовой рассылки сообщений всем подключённым клиентам 
@app.get("/broadcast/")
async def broadcast_message(message: str):
    for client in connected_clients:
        await client.send_text(f"Broadcast message: {message}")
```

Как видно из кода, у нас есть отдельный веб-сокет роут (**/ws/**), который мы сделали с использованием соответствующего декоратора. Наша асинхронная конечная точка (**websocket_endpoint**) будет удерживать соединение.

В этой точке мы сначала принимаем (акцептируем) вебсокет-соединение. Далее добавляем клиента в список подключённых. Потом в бесконечном цикле мы "слушаем" соединения (ждём получения текста). Если получили, то отправили это сообщение обратно, чуть изменив. Если клиент отключается, то мы его удаляем из нашего списка и цикл прерывается.

Дополнительно мы создали **обычный роут** для получения сообщений. Если сообщение получим, то разошлем его всем вебсокет-клиентам из списка. 

---

## 🧊 Обработка событий WebSocket

Как вы поняли, WebSocket-соединение — это «долгий звонок»:

1. сервер принимает звонок (`accept`),
2. вы обмениваетесь сообщениями (чтение/запись),
3. кто-то корректно завершает разговор (`close`).
В FastAPI это делается через объект `WebSocket` (под капотом — Starlette). 

### 💿 Ping/Pong и «пульс» соединения (heartbeat)

В самом протоколе есть контрольные кадры: `Ping` (0x9) и `Pong` (0xA) — они помогают понять, «жив» ли канал. Но **браузерный WebSocket-API не даёт прямого доступа** к отправке/ловле ping/pong: бывает, что реализуют пульс на уровне приложения (например, раз в N секунд сервер шлёт `{type:"ping"}`, а клиент отвечает `{type:"pong"}`).

### 💤 Нужно ли «следить за пульсом» вручную?

Чаще всего — **нет**: за «пульс» отвечает сервер/библиотека.

- В самом протоколе есть контрольные кадры **Ping**/**Pong** — стандартный способ проверять, «жив» ли канал. 
- **Uvicorn** (типичный сервер для FastAPI) уже умеет регулярно слать ping и ждать pong: параметры `--ws-ping-interval` (по умолчанию ~20 сек) и `--ws-ping-timeout`. Обычно достаточно **настроить сервер**, а не писать свой цикл.

Зачем это вообще нужно? Промежуточные узлы часто **рвут «тихие» соединения:**

- **Nginx** по умолчанию закрывает WS, если **60 сек** нет трафика; лечится `proxy_read_timeout` или регулярным ping.
- **AWS ALB** имеет **idle timeout 60** сек по умолчанию (можно увеличить).

> **Вывод:** начинайте с настройки сервера/прокси (интервалы ping, таймауты). Ручной `heartbeat` в приложении нужен, если у вас особая логика «присутствия» (онлайн-статус) или нестандартная инфраструктура.

### ☀️ Жизненный цикл: что важно знать

- **Принятие соединения:** `await websocket.accept()` — после HTTP-рукопожатия вы переходите на двунаправленный обмен.
- **Обмен:** `receive_text/bytes/json()` ↔ `send_text/bytes/json()` — основной канал.
- **Отключение клиента:** ловите `WebSocketDisconnect` и убирайте клиента из своих структур.
- **Закрытие с сервера:** `await websocket.close(code=..., reason=...)`.

### 🦔 Коды закрытия (короткая памятка)

- **1000** — нормальное завершение,
- **1001** — клиент/сервер «ушёл»,
- **1008** — нарушена политика/доступ запрещён,
- **1011** — внутренняя ошибка на сервере.
(Коды и их смысл описаны в руководствах по WebSocket.)

### 📒 Если всё же нужен heartbeat на уровне приложения

Иногда вы хотите именно **прикладной пинг** (например, чтобы обновлять «last seen» пользователя). Тогда можно отправлять обычные текстовые сообщения `"ping"`/`"pong"` поверх WebSocket. Ниже — **теоретический** пример; в проде это, как правило, дублирует уже работающий под капотом серверный `ping`/`pong`.

```python
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI()

@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()

    async def heartbeat():
        # раз в 25 сек шлём «пинг» как обычный текст
        while True:
            await asyncio.sleep(25)
            await ws.send_text("ping")  # прикладной пинг (не протокольный кадр)

    hb = asyncio.create_task(heartbeat())
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "pong":
                # здесь можно обновлять «последняя активность»
                pass
            # ...обработка других сообщений...
    except WebSocketDisconnect:
        pass
    finally:
        hb.cancel()
```

> [!WARNING]
> *Напоминание: **протокольные** `ping`/`pong`-кадры уже обрабатываются сервером (например, Uvicorn+`websockets`), а задача разработчика — правильно настроить **интервалы** и **таймауты**, чтобы соединения не «умирали» в прокси.*

### 🎳 Событийная модель (on_connect / on_message / on_disconnect)

**Идея простая:** WebSocket-маршрут можно организовать «по событиям» (довольно распространённый кейс для вебсокетам): **кто-то подключился** → `on_connect`, **пришло сообщение** → `on_message`, **кто-то отключился** → `on_disconnect`. Это не «магические» события фреймворка (в функциональном обработчике вы их придумываете сами), но такой стиль хорошо ложится на **event-driven** подход и упрощает расширение логики. Для классового варианта у Starlette есть готовые хуки с теми же именами (`on_connect`, `on_receive`, `on_disconnect`).

**Зачем так делается**

- Логику легко «расщеплять» на независимые обработчики: аутентификация и учёт присутствия — в `on_connect`, бизнес-сообщения — в `on_message`, очистка ресурсов — в `on_disconnect`.
- Такой подход естественно сочетается с **pub**/**sub** и другими паттернами событийной архитектуры (`publisher` → `channel`/`broker` → `subscribers`).

### 🎄 Классовый вариант (готовые хуки Starlette)

Если нравится строгая схема «событие → метод», используйте `WebSocketEndpoint`:

```python
from starlette.endpoints import WebSocketEndpoint

class ChatEndpoint(WebSocketEndpoint):
    encoding = "text"

    async def on_connect(self, ws):
        await ws.accept()

    async def on_receive(self, ws, data):
        await ws.send_text(f"echo: {data}")

    async def on_disconnect(self, ws, close_code):
        pass
```

[**Starlette**](https://starlette.dev/endpoints/) вызывает эти методы автоматически при соответствующих событиях — это прямой событийный интерфейс.

---

## 🍟 Двунаправленная связь

WebSocket — это постоянный канал «в обе стороны»: клиент может писать серверу когда угодно, и сервер — клиенту. Чтобы обмен был предсказуемым, стоит договориться о **простом JSON-протоколе** (типы сообщений, версии, подтверждения) и опираться на удобные методы FastAPI: `receive_json()` / `send_json()`.

### 🍦 1. Мини-протокол: типы, версия, подтверждения

Введем условный JSON-протокол с тремя видами сообщений: сообщение чата, системный пинг и системное  подтверждение:

```python
from enum import StrEnum
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

app = FastAPI()

# 1) Типы сообщений (удобно маршрутизировать по enum)
class MsgType(StrEnum):
    CHAT = "chat.message"
    PING = "system.ping"
    ACK  = "system.ack"

# 2) Базовая форма любого сообщения
class BaseMsg(BaseModel):
    type: MsgType
    id: str | None = None
    version: int = 1

# 3) Конкретные сообщения
class ChatMessage(BaseMsg):
    type: MsgType = MsgType.CHAT
    text: str

class Ping(BaseMsg):
    type: MsgType = MsgType.PING

class Ack(BaseMsg):
    type: MsgType = MsgType.ACK
    ok: bool = True

@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            data = await ws.receive_json()          # пришёл dict из клиента
            # аккуратно приводим тип
            try:
                mtype = MsgType(data.get("type", ""))   # -> MsgType | исключение
            except ValueError:
                mtype = None

            match mtype:
                case MsgType.CHAT:
                    msg = ChatMessage.model_validate(data)  # валидация Pydantic v2
                    # ...бизнес-логика...
                    await ws.send_json({"type": "chat.delivery",
                                        "id": msg.id, "text": msg.text})
                case MsgType.PING:
                    ping = Ping.model_validate(data)
                    await ws.send_json(Ack(id=ping.id).model_dump())  # подтверждение
                case _:
                    await ws.send_json({"type": "system.error",
                                        "error": "unknown_type"})
    except WebSocketDisconnect:
        pass
```

Почему так:

- **Ясный контракт:** у каждого сообщения есть `type` и (по желанию) `version`, чтобы фронт/бэк развивались без «ломающих» изменений.
- **Ack по `id`:** удобно подтверждать доставку.
- **Валидация на границе:** `model_validate()` / `model_dump()` — идиоматический способ Pydantic v2.

На выходе у нас получился простенький собственный JSON-протокол поверх вебсокета, чтобы у нас с фронтедом "было взаимопонимание".

### 🌝 2. Текст vs бинарь и «крупняк»

В протоколе WebSocket есть **текстовые** и **бинарные кадры**; большие сообщения могут приходить **фрагментами** — это норма спецификации. В FastAPI соответствуют методы `receive_text()/send_text()` и `receive_bytes()/send_bytes()`. Для JSON, как вы поняли, удобнее `receive_json()/send_json()`.

Если шлёте много текста (JSON), рассмотрите **permessage-deflate** — сжатие «на сообщение» согласуется в рукопожатии и поддерживается многими серверами/библиотеками. Это снижает трафик при активном чате/стриме. (Проверяйте поддержку и тюнинг в вашем стеке.) [**Per-Message Deflate**](https://websockets.readthedocs.io/en/stable/topics/compression.html)

### 🚘 3. «Не захлёбываемся»: скорость и бэкпрешсур

- На клиенте у классического `WebSocket` смотрите `bufferedAmount`: если число растёт — делайте паузы в отправке, чтобы не перегрузить канал. ([**MDN Web Docs**](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/bufferedAmount))
- Альтернатива — `WebSocketStream` (клиентское API): использует Streams API и **автоматически** применяет бэкпрешсур (там, где поддерживается). Это упрощает работу с большими потоками. ([**MDN Web Docs**](https://developer.mozilla.org/en-US/docs/Web/API/WebSocketStream))

### 🥡 4. Немного про «провода» (понимать полезно)

- Сообщения идут **кадрами** (frames) с опкодами: text=1, binary=2, close=8, ping=9, pong=10.
- **Клиент обязан маскировать свои кадры;** сервер маску не ставит (это требование стандарта).
Эти детали обычно скрыты библиотекой, но помогают при отладке и общении с фронтендом/девопсами.

### 🥄 5. Тестируем двунаправленный сценарий

FastAPI позволяет тестировать WS без реального сокета: `TestClient().websocket_connect()` открывает соединение в том же процессе — отправляйте JSON, читайте ответы, проверяйте утверждения.

#### ⚠️ Памятка по применению

- Для «болталки» — выберите простой JSON-контракт (типы, ack по `id`).
- Для файлов/аудио — используйте **бинарные** сообщения и, при необходимости, договаривайтесь о формате (MIME, длина, чанки).
- Для экономии трафика — включайте/договаривайтесь о **permessage-deflate**. 
- Для стабильности UX — следите на клиенте за `bufferedAmount` или используйте **WebSocketStream** там, где он есть.

---

## 🐩 Безопасность веб-сокета

В проде WebSocket должен быть **WSS** (TLS), вход разрешаем только «своим» сайтам (проверка `Origin`), пускаем в канал **только аутентифицированных пользователей**, валидируем входящие сообщения и ограничиваем размеры/частоту. Ниже — простые правила и живой код под FastAPI.

### 🚖 1. Кто к нам стучится: проверяем Origin

Браузер при рукопожатии шлёт заголовок `Origin`. Сервер обязан сравнить его с белым списком доменов и **отклонить чужие** (иначе возможен CSWSH — cross-site WebSocket hijacking). CORS тут не выручит: это HTTP-механизм, а для WS сервер сам должен проверять `Origin`.

### 🎡 2. Чем докажете, что вы — вы: токен, а не «голые» cookie

В браузере **нельзя добавить произвольные заголовки** в WS-рукопожатие — только URL и список субпротоколов. Поэтому обычно **передают токен** в query-параметре или первым сообщением, а сервер проверяет его до принятия соединения. (Cookie тоже работают, но тогда продумайте `SameSite/Secure/HttpOnly` и особенно защиту от CSWSH.)

> [!WARNING]  
> *Примечание: если вы всё-таки опираетесь на cookie, учтите, что для кросс-сайтового сценария браузеры требуют `SameSite=None;` `Secure;`, и это открывает дверь для CSWSH, если вы не проверяете Origin.*

### 📝 3. FastAPI: проверяем `Origin` и JWT до `accept()`

Ниже — учебный скелет на Python 3.11+ (Pydantic не обязателен). Логика: достаём `Origin` и токен, валидируем, в противном случае — закрываем кодом **1008** («нарушение политики»).

```python
from urllib.parse import urlparse
from typing import Final
from fastapi import FastAPI, WebSocket
import jwt  # PyJWT
from jwt import InvalidTokenError

app = FastAPI()

# Белый список источников, которым позволено открывать WS
ALLOWED_ORIGINS: Final[set[str]] = {
    "app.example.com",
    "admin.example.com",
}

JWT_SECRET: Final[str] = "change-me"         # храните в переменных окружения
JWT_ALG: Final[str] = "HS256"

def is_allowed_origin(origin: str | None) -> bool:
    if not origin:
        return False
    host = urlparse(origin).netloc.lower()
    return host in ALLOWED_ORIGINS

def verify_token(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except InvalidTokenError:
        return None

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    origin = ws.headers.get("origin")
    if not is_allowed_origin(origin):
        # Чужой сайт — вежливо отказываем
        await ws.close(code=1008, reason="bad origin")
        return

    # Токен можно прислать ?token=... или cookie "access_token"
    token = ws.query_params.get("token") or ws.cookies.get("access_token")
    claims = verify_token(token)
    if not claims:
        await ws.close(code=1008, reason="unauthorized")
        return

    # Только теперь принимаем соединение
    await ws.accept(subprotocol=None)  # при желании согласуйте субпротокол

    # ...дальше ваша бизнес-логика обмена сообщениями...
```

Почему так:
- **Origin-чек** — базовая защита от CSWSH.
- **JWT** — независим от cookie/сессий и работает из браузера (в query или первом сообщении).
- **Код 1008** — стандартное «policy violation» при отказе. (RFC 6455).

### 🅰️ 4. Валидация и лимиты — базовый минимум»

- **Валидация входящих сообщений** (схемы, типы, длины).
- **Ограничение размера** сообщений и **частоты** (rate-limit) по пользователю/IP/комнате.
- **Закрывать соединение** при нарушениях (например, кодом 1008/1011). Эти рекомендации — часть общих практик безопасности HTML5/WS. ([cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html))

### 🍄 5. WSS и прокси

- В проде используйте `wss://` (TLS). Конструктор WebSocket поддерживает `ws`/`wss`, а для апгрейда через прокси нужен корректный проброс заголовков.
- **Nginx:** для туннелирования WS включите HTTP/1.1 и проброс `Upgrade/Connection`:

```nginx
location /ws/ {
    proxy_pass         http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header   Upgrade $http_upgrade;
    proxy_set_header   Connection "upgrade";
}
```

Это официально рекомендованный шаблон. ([**nginx.org**](https://nginx.org/en/docs/http/websocket.html))

(Если у вас AWS ALB, помните про **idle timeout** по умолчанию 60 с — иногда его поднимают, но это уже про устойчивость, не про безопасность.) ([**docs.aws.amazon.com**](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html))

### 🖍️ 6. Субпротоколы и расширения — с умом

Субпротокол (`Sec-WebSocket-Protocol`) — это «язык поверх WS». Его можно использовать для версионирования или выбора формата, **но не как единственный механизм аутентификации**. Расширение **permessage-deflate** обсуждайте отдельно (полезно для JSON-трафика).

#### 🌽 Чек-лист безопасности (сводка)

- ✅ `wss://` везде (TLS). 
- ✅ Проверять `Origin` на рукопожатии (белый список).
- ✅ Токен-аутентификация (query/первое сообщение), для cookie — `SameSite/Secure/HttpOnly` и **строгая** проверка `Origin`. 
- ✅ Валидация схемы сообщений, лимиты на размер/частоту. 
- ✅ Правильная прокси-настройка (Upgrade/Connection). 

---

## 📺 Приложения реального времени с FastAPI и WebSockets

**Идея простая:** начните с малого (один процесс и список подключений в памяти), а как только появляется н**есколько воркеров/инстансов**, вынесите «общение между комнатами» и «кто онлайн» во внешние сервисы — брокер сообщений и хранилище присутствия.

### 🦠 Базовый план архитектуры

**1. Один процесс (один воркер).** 
Держим подключения прямо в памяти: «комнаты» → наборы активных WebSocket-клиентов. Любое пришедшее сообщение из комнаты рассылаем всем участникам этой комнаты. Это учебный, понятный базовый слой — и он официально демонстрируется в документации FastAPI. (fastapi.tiangolo.com)

**2. Несколько воркеров / несколько инстансов.**  
Арбуз «разрезается»: `uvicorn --workers N` поднимает **N отдельных процессов**, у каждого — своя память. Локальный список подключений видит только «своих» клиентов, поэтому **кластерной рассылки не получится** без внешнего канала. Для масштабирования делаем обработчик WebSocket **stateless**, а пересылку сообщений и «кто онлайн» выносим во **внешние сервисы**: брокер сообщений (Redis/Kafka/Postgres) + хранилище presence (обычно Redis с TTL). 

> *Резюме: стартуем с in-memory (учебно/прототип). Когда появляется горизонтальное масштабирование — добавляем брокер Pub/Sub и отдельное хранение присутствия.*

### 🔥 Практика для одного воркера: комнаты в памяти (с пояснениями)

```python
# Python 3.11+
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI()

class RoomManager:
    def __init__(self):
        # Карта: имя_комнаты -> набор активных WebSocket-подключений
        self.rooms: dict[str, set[WebSocket]] = {}

    async def connect(self, room: str, ws: WebSocket) -> None:
        # 1) Подтверждаем рукопожатие (после этого канал двунаправленный)
        await ws.accept()
        # 2) Добавляем клиента в комнату
        self.rooms.setdefault(room, set()).add(ws)

    def disconnect(self, room: str, ws: WebSocket) -> None:
        # Аккуратно удаляем клиента; если комната опустела — убираем её
        conns = self.rooms.get(room)
        if not conns:
            return
        conns.discard(ws)
        if not conns:
            self.rooms.pop(room, None)

    async def broadcast(self, room: str, message: str) -> None:
        # Рассылаем всем в комнате (итерируемся по копии, чтобы не падать,
        # если кто-то отвалится прямо во время отправки)
        for client in list(self.rooms.get(room, ())):
            await client.send_text(message)

manager = RoomManager()

@app.websocket("/ws/{room}")
async def ws_room(ws: WebSocket, room: str):
    # Клиент пришёл — впускаем в нужную комнату
    await manager.connect(room, ws)
    try:
        while True:
            # Ждём сообщение от клиента
            msg = await ws.receive_text()
            # Отдаём его всем в комнате (включая отправителя)
            await manager.broadcast(room, f"[{room}] {msg}")
    except WebSocketDisconnect:
        # Клиент ушёл — подчистим учёт
        manager.disconnect(room, ws)
```

Этот же код приводился ранее - тут дублируется для удобства.

### 🌈 Когда вместо WebSocket взять SSE 

Если нужен **только поток сервер → клиент** (уведомления, тикеры, логи, лайв-метрики), берите **Server-Sent Events**. Это обычный долгоживущий HTTP-ответ с типом `text/event-stream`. В браузере используется API `EventSource`, которое само держит соединение и умеет переподключаться. Формат простой: сервер шлёт строки вида `data: ...\n\n`; можно задавать имя события (`event:`) и идентификатор (`id:`) для восстановления после обрыва. 

**Мини-сервер на FastAPI (SSE):**

```python
import asyncio
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

app = FastAPI()

@app.get("/sse")
async def sse():
    async def event_stream():
        # Каждую секунду отправляем одно событие "message"
        # Формат SSE: блок заканчивается пустой строкой
        i = 0
        while True:
            i += 1
            yield f"id: {i}\n" \
                  f"event: message\n" \
                  f"data: hello #{i}\n\n"
            await asyncio.sleep(1)

    # Важно: правильный Content-Type
    return StreamingResponse(event_stream(), media_type="text/event-stream")
```

**Клиент (браузер):**

```html
<script>
  const es = new EventSource("/sse");           // открываем поток
  es.onmessage = (e) => console.log("SSE:", e.data);  // событие "message"
  // можно слушать именованные события:
  // es.addEventListener("price", (e) => { ... })
</script>
```

MDN чётко описывает работу `EventSource` и формат `text/event-stream`, включая авто-переподключение и обработку `Last-Event-ID`.

### 💦 Где применяются real-time приложения

- **Чаты и мессенджеры** (комнаты/каналы, online-presence).
- **Котировки и торговые терминалы** (стрим цен, стакан заявок).
- **Системы уведомлений** (пуши внутри веб-интерфейсов, алерты).
- **Совместное редактирование** (синхронизация документов/досок; поверх WS часто живут CRDT/OT протоколы).
- **Лайв-дашборды и мониторинг** (метрики, логи, телеметрия).
- **Игровые лобби и матчинги** (сигналинг, состояние комнат/очередей).
- **Трекеры статусов** (долгие фоновые задачи с прогрессом, статусы билдов/деплоев).

Большинство этих сценариев естественно ложатся на схему из этого шага: **один процесс → комнаты в памяти** на старте; дальше — **горизонтальный рост** с брокером и presence-хранилищем, когда понадобится. Для самого факта «несколько воркеров = несколько процессов» и необходимости внешнего канала см. раздел про workers в руководстве FastAPI/Uvicorn.

--

## 🍞 Пример приложения с использованием WebSocket’ов для нескольких воркеров

В этом шаге — «учебно-боевой» вариант на **FastAPI + Redis**: менеджер комнат (локальный) + комнаты + авторизация (JWT + проверка `Origin`) + простой **JSON-протокол + Pub/Sub через Redis** (через `Broadcaster`) + **heartbeat** с очисткой. 

### 🍐 Сразу поясним почему вообще нужен локальный менеджер комнат, если есть Redis?

**Redis решает “межпроцессную/межинстансную доставку”, а не “отправку в конкретный WebSocket”.** Сокет существует **в памяти конкретного процесса**, и чтобы физически записать кадр в этот сокет, процесс должен иметь **локальную ссылку** на объект WebSocket. Поэтому без лёгкого локального учёта подключений не обойтись.

Вот, что делает локальный менеджер и зачем он остаётся даже с Redis:

- **Фактическая доставка в сокет.** Pub/Sub приносит событие в процесс-подписчик; дальше нужен список местных соединений, чтобы вызвать `ws.send_*()` на каждом. Без этого «глобальная» рассылка не попадёт в реальный сокет. Это же подчёркнуто в доках FastAPI: in-memory список работает только в одном процессе; для мульти-воркеров добавляем брокер, но локальная рассылка по сокетам всё равно нужна. 
- **Данные на соединение.** Здесь удобно держать метаданные: `user_id`, последняя активность, права в комнате, счётчики rate-limit, локальные задачи (heartbeat), чтобы быстро очищать «мертвые» подключения и не ходить за каждым чихом в Redis.
- **Контроль качества канала.** Проще реализовать локальные политики (ограничение размера/частоты, фильтрация по комнате, «не отправлять самому себе» и т.п.) до Redis или после него — без перегона лишнего трафика через брокер.
- **Границы процессов.** В проде `uvicorn --workers N` — это **N разных процессов с раздельной памятью**; шарить один общий менеджер «с локами» между ними нельзя — нужны межпроцессные решения (Redis/БД/очередь). Локальный же менеджер — это осмысленная «часть» узла кластера. 
- **Модель «stateless сверху, stateful снизу»**. Сверху — статлесс-обработчик и Pub/Sub (Redis/Kafka/Postgres), снизу — небольшой локальный state ради фактической отдачи в сокеты этого процесса. Это типовой паттерн real-time-приложений. ([**Redis**](https://redis.io/docs/latest/develop/pubsub/))

### 🏀 Идея архитектуры (коротко)

- Каждый клиент подключается к **комнате** (`/ws/{room}`).
- Сообщения публикуются в **канал** Redis `room:{room}` и раздаются всем подписчикам (всем инстансам приложения).
- **Авторизация** проверяется **до** `accept()` (JWT + белый список `Origin`) — отказываем кодом `1008` при нарушении политики.
- **Heartbeat** на уровне приложения шлёт `system.ping`; клиент отвечает `system.ack` — по ответам обновляем presence в Redis и закрываем «молчаливые» соединения по таймауту.
- **Presence** — ключ `rt:presence:user:{user_id}:{room}` c TTL (обновляется на каждое сообщение/ack).

### 🔅 Код: менеджер + комнаты + авторизация + JSON-протокол + Redis Pub/Sub + heartbeat

> *Зависимости: `fastapi`, `uvicorn[standard]`, `websockets`, `pydantic>=2`, `pyjwt`, `redis>=5`, `broadcaster[redis]`.  
ENV пример: `REDIS_URL=redis://localhost:6379` • `JWT_SECRET=change-me` • `ALLOWED_ORIGINS=http://app.example.com,https://admin.example.com`*

#### 🏃‍♂️‍➡️ Структура проекта

```text
app/
  __init__.py
  config.py
  logger.py
  protocol.py
  auth.py
  state.py
  managers.py
  subscriptions.py
  lifespan.py
  websocket_routes.py
  main.py
```

#### 🍍 `app/__init__.py`

```py
# пусто или можно оставить метаданные пакета
```

#### 🍍`app/logger.py`

```py
import os
import logging

logger = logging.getLogger("rt-app")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
```

#### 🍍`app/config.py`

```py
import os
import re
from urllib.parse import urlparse

# ---------- Конфигурация окружения ----------
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

# Живость/присутствие
PRESENCE_TTL = int(os.getenv("PRESENCE_TTL", "60"))  # сек
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "25"))
IDLE_TIMEOUT = int(os.getenv("IDLE_TIMEOUT", "70"))

# Валидация имени комнаты
ROOM_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

def normalize_origin(origin: str | None) -> str | None:
    """Канонизирует Origin (scheme+host[:port], без стандартных портов)."""
    if not origin:
        return None
    p = urlparse(origin)
    if not p.scheme or not p.hostname:
        return None
    host = p.hostname.lower()
    port = p.port
    default_port = 443 if p.scheme == "https" else 80
    if port in (None, default_port):
        return f"{p.scheme}://{host}"
    return f"{p.scheme}://{host}:{port}"

# ALLOWED_ORIGINS: список origin'ов (scheme+host[:port]), через запятую
_ALO_RAW = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
ALLOWED_ORIGINS: set[str] = {o for o in (normalize_origin(x) for x in _ALO_RAW) if o}
```

#### 🍍 `app/protocol.py`

```py
import time
from enum import StrEnum
from pydantic import BaseModel, Field

class MsgType(StrEnum):
    CHAT = "chat.message"
    DELIVERY = "chat.delivery"
    ACK = "system.ack"
    PING = "system.ping"
    PONG = "system.pong"
    ERROR = "system.error"

class BaseMsg(BaseModel):
    type: MsgType
    id: str | None = None
    version: int = 1

class ChatMessage(BaseMsg):
    type: MsgType = MsgType.CHAT
    room: str
    text: str

class Ping(BaseMsg):
    type: MsgType = MsgType.PING
    ts: float = Field(default_factory=lambda: time.time())

class Ack(BaseMsg):
    type: MsgType = MsgType.ACK
    ref: str | None = None
```

#### 🍍 `app/auth.py`

```py
import jwt
from jwt.exceptions import InvalidTokenError
from .config import JWT_SECRET, JWT_ALG

def verify_token(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except InvalidTokenError:
        return None
```

#### 🍍 `app/state.py`

```py
from typing import Optional
from broadcaster import Broadcast
import redis.asyncio as redis

broadcast: Optional[Broadcast] = None
rds: Optional[redis.Redis] = None
```

#### 🍍 `app/managers.py`

```py
import json
import asyncio
from typing import Dict, Set, List
from fastapi import WebSocket
from .logger import logger

class RoomManager:
    """Хранит локальные WebSocket-соединения этого процесса для фактической отправки."""

    def __init__(self):
        self.rooms: Dict[str, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def add(self, room: str, ws: WebSocket) -> None:
        async with self._lock:
            self.rooms.setdefault(room, set()).add(ws)

    async def remove(self, room: str, ws: WebSocket) -> None:
        async with self._lock:
            conns = self.rooms.get(room)
            if not conns:
                return
            conns.discard(ws)
            if not conns:
                self.rooms.pop(room, None)

    async def snapshot(self, room: str) -> List[WebSocket]:
        async with self._lock:
            return list(self.rooms.get(room, ()))

    async def count(self, room: str) -> int:
        async with self._lock:
            return len(self.rooms.get(room, ()))

    async def send_local(self, room: str, payload: dict | str) -> None:
        data = json.dumps(payload) if not isinstance(payload, str) else payload
        targets = await self.snapshot(room)
        for ws in targets:
            try:
                await ws.send_text(data)
            except Exception as e:
                logger.warning("send_local failed: %s", e, exc_info=True)
                await self.remove(room, ws)

manager = RoomManager()
```

#### 🍍 `app/subscriptions.py`

```py
import json
import asyncio
from .logger import logger
from .managers import manager
from .protocol import MsgType
from . import state

class RoomSubscriptions:
    """Задачи подписки на каналы Redis по комнатам (уровень процесса)."""

    def __init__(self):
        self._tasks: dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def ensure(self, room: str) -> None:
        async with self._lock:
            task = self._tasks.get(room)
            if task and not task.done():
                return
            self._tasks[room] = asyncio.create_task(self._runner(room), name=f"sub:{room}")

    async def maybe_stop(self, room: str) -> None:
        if await manager.count(room) > 0:
            return
        async with self._lock:
            task = self._tasks.pop(room, None)
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    logger.debug("subscriber task error on cancel", exc_info=True)

    async def cancel_all(self) -> None:
        async with self._lock:
            tasks = list(self._tasks.values())
            self._tasks.clear()
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.debug("subscriber task error on cancel_all", exc_info=True)

    async def _runner(self, room: str) -> None:
        channel = f"room:{room}"
        backoff = 1.0
        while True:
            if await manager.count(room) == 0:
                logger.info("subscriber: room %s empty -> stop", room)
                return
            try:
                if not state.broadcast:
                    raise RuntimeError("Broadcast is not initialized")
                async with state.broadcast.subscribe(channel=channel) as sub:
                    logger.info("subscriber: subscribed to %s", channel)
                    backoff = 1.0
                    async for event in sub:
                        if await manager.count(room) == 0:
                            logger.info("subscriber: room %s empty during stream -> stop", room)
                            return
                        try:
                            payload = json.loads(event.message)
                        except Exception:
                            payload = {"type": MsgType.ERROR, "error": "bad_payload"}
                        await manager.send_local(room, payload)
            except asyncio.CancelledError:
                logger.debug("subscriber: cancelled for %s", room)
                raise
            except Exception as e:
                logger.warning(
                    "subscriber error for %s: %s; retry in %.1fs",
                    room, e, backoff, exc_info=True
                )
                await asyncio.sleep(min(backoff, 10.0))
                backoff = min(backoff * 2.0, 10.0)

SUBSCRIPTIONS = RoomSubscriptions()
```

#### 🍍 `app/lifespan.py`

```py
from contextlib import asynccontextmanager
from broadcaster import Broadcast
import redis.asyncio as redis
from . import state
from .subscriptions import SUBSCRIPTIONS
from .config import REDIS_URL
from .logger import logger

@asynccontextmanager
async def lifespan(app):
    # Инициализация Redis и Broadcast
    state.rds = await redis.from_url(REDIS_URL, decode_responses=True)
    state.broadcast = Broadcast(REDIS_URL)
    await state.broadcast.connect()
    try:
        yield
    finally:
        try:
            await SUBSCRIPTIONS.cancel_all()
        except Exception:
            logger.debug("cancel_all failed", exc_info=True)
        try:
            if state.broadcast:
                await state.broadcast.disconnect()
        finally:
            state.broadcast = None
        try:
            if state.rds:
                await state.rds.aclose()
        finally:
            state.rds = None
```

#### 🍍 `app/websocket_routes.py`

```py
import json
import uuid
import time
import asyncio
from fastapi import APIRouter, WebSocket
from fastapi import WebSocketDisconnect

from .auth import verify_token
from .config import (
    normalize_origin, ALLOWED_ORIGINS, ROOM_RE,
    PRESENCE_TTL, HEARTBEAT_INTERVAL, IDLE_TIMEOUT
)
from .protocol import MsgType, ChatMessage, Ping, Ack
from .managers import manager
from .subscriptions import SUBSCRIPTIONS
from . import state
from .logger import logger

ws_router = APIRouter()

@ws_router.websocket("/ws/{room}")
async def ws_room(ws: WebSocket, room: str):
    # 0) Проверка комнаты
    if not ROOM_RE.fullmatch(room):
        await ws.close(code=1008, reason="bad room")
        return

    # 1) Проверка Origin и JWT до accept()
    origin = normalize_origin(ws.headers.get("origin"))
    if ALLOWED_ORIGINS and (origin not in ALLOWED_ORIGINS):
        await ws.close(code=1008, reason="bad origin")
        return

    token = ws.query_params.get("token") or ws.cookies.get("access_token")
    claims = verify_token(token)
    if not claims:
        await ws.close(code=1008, reason="unauthorized")
        return

    user_id = str(claims.get("sub") or claims.get("user_id") or "anon")
    channel = f"room:{room}"
    presence_key = f"rt:presence:user:{user_id}:{room}"

    await ws.accept()

    # presence: ключ на (user, room) с TTL; обновляем на каждое действие
    async def touch_presence() -> None:
        if not state.rds:
            return
        await state.rds.set(presence_key, "1", ex=PRESENCE_TTL)

    await touch_presence()

    # Добавляем сокет и гарантируем подписку
    await manager.add(room, ws)
    await SUBSCRIPTIONS.ensure(room)

    stop = asyncio.Event()
    last_rx = time.time()

    async def reader():
        nonlocal last_rx
        try:
            while not stop.is_set():
                data = await ws.receive_json()
                last_rx = time.time()
                await touch_presence()

                try:
                    mtype = MsgType(data.get("type"))
                except Exception:
                    mtype = None

                if mtype is MsgType.CHAT:
                    msg = ChatMessage.model_validate(data)
                    mid = msg.id or uuid.uuid4().hex
                    payload = {
                        "type": MsgType.DELIVERY,
                        "room": room,
                        "user": user_id,
                        "text": msg.text,
                        "id": mid,
                        "ts": time.time(),
                    }
                    # Публикуем в канал комнаты
                    if state.broadcast:
                        await state.broadcast.publish(channel=channel, message=json.dumps(payload))
                elif mtype is MsgType.PING:
                    await ws.send_json(Ack(ref=(data.get("id") or uuid.uuid4().hex)).model_dump())
                elif mtype in (MsgType.ACK, MsgType.PONG):
                    # уже отметили активность выше
                    pass
                else:
                    await ws.send_json({"type": MsgType.ERROR, "error": "unknown_type"})
        except WebSocketDisconnect:
            logger.info("reader: client disconnected user=%s room=%s", user_id, room)
            stop.set()
        except Exception as e:
            logger.error("reader error: %s", e, exc_info=True)
            stop.set()

    async def heartbeat():
        try:
            while not stop.is_set():
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                # прикладной ping
                try:
                    await ws.send_json(Ping().model_dump())
                except Exception as e:
                    logger.info("heartbeat send failed: %s", e)
                    stop.set()
                    return
                # idle-timeout
                if (time.time() - last_rx) > IDLE_TIMEOUT:
                    logger.info("idle timeout user=%s room=%s", user_id, room)
                    try:
                        await ws.close(code=1000, reason="idle timeout")
                    except Exception:
                        pass
                    stop.set()
                    return
        except WebSocketDisconnect:
            stop.set()
            return
        except Exception as e:
            logger.error("heartbeat error: %s", e, exc_info=True)
            stop.set()
            return

    # Совместный запуск задач с корректным cleanup
    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(reader())
            tg.create_task(heartbeat())
    except* Exception as eg:
        logger.debug("taskgroup exception group: %s", eg)
    finally:
        try:
            await manager.remove(room, ws)
        except Exception as e:
            logger.debug("manager.remove failed: %s", e, exc_info=True)
        try:
            if state.rds:
                await state.rds.delete(presence_key)
        except Exception as e:
            logger.debug("presence delete failed: %s", e, exc_info=True)
        try:
            await SUBSCRIPTIONS.maybe_stop(room)
        except Exception:
            pass
```

#### 🍍 `app/main.py`

```py
from fastapi import FastAPI
from .lifespan import lifespan
from .websocket_routes import ws_router

app = FastAPI(lifespan=lifespan)
app.include_router(ws_router)
```

### 📒 Как запускать

1. Установите зависимости, убедитесь, что Redis доступен по `REDIS_URL`.
2. Экспортируйте переменные окружения по необходимости:

```bash
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="change-me"
export JWT_ALG="HS256"
export ALLOWED_ORIGINS="https://app.example.com,https://admin.example.com:8443"
export LOG_LEVEL="INFO"
```

1. Старт:

```bash
uvicorn app.main:app --workers 2
```

**Подсказки к коду и архитектуре:**
- В проде **несколько воркеров** — это несколько процессов, память не общая; поэтому: Redis Pub/Sub для межпроцессной рассылки, локальный менеджер — для фактической отдачи в сокеты.
- Redis **Pub/Sub** — естественный способ трансляции событий по каналам/шаблонам; presence — через ключи с TTL (`SET ... EX`, `TTL`). 
- `Broadcaster` даёт единый Pub/Sub-слой (Redis/Kafka/Postgres) — удобно для рассылки между процессами/инстансами. Замечание: репозиторий `encode`/`broadcaster` сейчас **архивирован**, но сам паттерн (Pub/Sub через Redis и подписка в каждом инстансе) остаётся корректным; при желании можно заменить на прямой Redis Pub/Sub/Streams.
- Проверка `Origin` защищает от CSWSH (если полагаетесь на cookie/сессию). ([**portswigger.net**](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking), [**cwe.mitre.org**](https://cwe.mitre.org/data/definitions/1385.html))

### 📌 Коротко про специфику деплоя 

- **Reverse-proxy (Nginx):** обязателен проброс апгрейда:
`proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; proxy_http_version 1.1;` — это стандартный рецепт для WS-проксирования. 
- **Idle-timeout балансов:** у многих балансировщиков есть таймаут «тихого» соединения — держите ping/pong ниже этого значения или увеличивайте таймаут. (Практика идёт рука об руку с heartbeat). Можно настроить серверные keep-alive: `--ws-ping-interval 25` `--ws-ping-timeout 10` — подгоняйте под таймауты прокси/балансировщиков.
- **Uvicorn workers:** подбирайте число воркеров под ядра CPU; помните, что каждый — отдельный процесс, и потому нужен внешний канал для широковещания.

#### 📸 Итоги 

- Вы получили цельный «скелет» real-time-приложения: **комнаты → Redis Pub/Sub → локальная выдача в сокеты**, авторизация на рукопожатии, простой JSON-протокол, heartbeat и presence.
- Поняли, **зачем нужен локальный менеджер**: без него событие из Redis не попадёт в конкретный `WebSocket` — у процесса должна быть **локальная ссылка** на сокет для отправки. Это дополняет, а не заменяет брокер.
- Освоили специфику прод-окружения: апгрейд в Nginx, таймауты, мультиворкерный режим. 
- Принципы из этой главы масштабируются на чаты, ленты уведомлений, лайв-дашборды, трекинг прогресса, редакторы в реальном времени и др. — вы можете донастроить безопасность, надёжность доставки и хранение истории, не меняя базовую схему.

<div align="center">
  <img alt="Project Demo" src="./mygif/gif14-2.gif" />
</div>

> [!WARNING]
> *Если нужен код проекта (с докер-компоузом для упрощения поднятия), то смотрите его на [**гитхабе**](https://github.com/Cheater121/fastapi-websocket-broadcast-boilerplate/).*

---

<div align="center"> Made with ❤️ by <b>dv0retsky</b> </div>