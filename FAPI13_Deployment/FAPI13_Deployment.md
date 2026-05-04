|||
|---|---|
|ДИСЦИПЛИНА|Технологии разработки серверных приложений|
|ИНСТИТУТ|ИПТИП|
|КАФЕДРА|Индустриального программирования|
|ВИД УЧЕБНОГО МАТЕРИАЛА|Методические указания к практическим занятиям|
|ПРЕПОДАВАТЕЛЬ|Дворецкий Артур Геннадьевич|
|СЕМЕСТР|4 семестр, 2025/2026 уч. год|

Ссылка на материал: <br>
https://github.com/dv0retsky/fastapi-tutorial/blob/main/FAPI15_Implementation/FAPI15_Implementation.md

---

# Практическое занятие №13: Docker + FastAPI 🐳

## 👾 Что такое Docker

**Docker** — это платформа для разработки, доставки и запуска приложений в контейнерах. Если по простому, то Docker позволяет упаковывать приложение и все его зависимости (библиотеки, файлы конфигурации и т.д.) в изолированный контейнер, который можно запускать на любой машине с установленным Docker, не заботясь о различиях в операционных системах или конфигурации сервера.

<div align="center">
  <img alt="Project Demo" src="./mygif/gif13-1.gif" />
</div>

Образ Docker не является просто сжатым архивом. Он состоит из нескольких слоев, организованных в иерархическую структуру. Каждый слой содержит изменения по отношению к предыдущему слою. Это ключевая особенность Docker, обеспечивающая эффективное хранение и переиспользование компонентов.

- **Базовый слой (Base Layer):** Это самый нижний слой, основа образа. Обычно это базовая операционная система (например, Ubuntu, Alpine). Изменения в этом слое редки и затрагивают саму базовую систему.

- **Промежуточные слои (Intermediate Layers):** Каждая команда в `Dockerfile` создает новый слой. Например, установка пакета `apt-get install <package>` создает слой, содержащий установленный пакет. Команды копирования файлов (`COPY`,  `ADD`) также создают новые слои. Это позволяет Docker эффективно использовать пространство на диске, так как изменения в образе хранятся в виде разностных файлов (deltas).

- **Верхний слой (Top Layer):** Это самый верхний слой, содержащий конкретные данные приложения (код, конфигурационные файлы и т.д.). Этот слой чаще всего изменяется при обновлении приложения.

<div align="center">
  <img alt="Project Demo" src="./Images/img13-1.png" />
</div>

Когда вы запускаете контейнер, Docker создает union файловой системы, объединяя все слои. При изменении данных в контейнере (например, запись в файл), изменения не вносятся в основные слои. Вместо этого, они сохраняются в верхнем слое. Это позволяет Docker быстро создавать и удалять контейнеры, так как только верхний слой нуждается в изменениях. Когда контейнер удаляется, только верхний слой исчезает, базовые слои остаются нетронутыми и могут быть использованы для создания новых контейнеров.

## 🪩 Архитектура и компоненты Docker

Архитектура Docker основана на клиент-серверной модели и включает несколько ключевых компонентов:

**1. Docker Daemon (Сервер):**

Это основной процесс Docker, который выполняется в фоновом режиме на хост-машине. Он отвечает за управление образами, контейнерами, сетями и хранилищем. Он слушает запросы от Docker Client и выполняет все действия, связанные с управлением контейнерами.

**2. Docker Client (Клиент):**

Это интерфейс командной строки (CLI) или API, который используется для взаимодействия с Docker Daemon. Пользователь использует Docker Client для отправки команд (например, docker run, docker build, docker ps), которые затем передаются Docker Daemon для выполнения. Docker Client может работать на той же машине, что и Daemon, или на удалённой машине.

**3. Docker Images (Образы):**

Это неизменяемые шаблоны, используемые для создания контейнеров. Они содержат все необходимые файлы и инструкции для запуска приложения. Образы состоят из слоев (layers), что позволяет Docker эффективно использовать дисковое пространство и кэшировать части образов.

**4. Docker Containers (Контейнеры):**

Это экземпляры Docker Images. Они являются изолированными средами для запуска приложений. Каждый контейнер имеет свою собственную файловую систему, процессы, сеть и т.д., но они делят ядро операционной системы хоста.

**5. Docker Registry (Реестр):**

Это централизованное хранилище для Docker Images. Docker Hub является наиболее популярным публичным реестром, но вы также можете создавать и использовать свои собственные частные реестры. Реестры позволяют хранить, управлять и распространять образы Docker.

**6. Docker Hub:**

Это публичный реестр Docker, предоставляемый Docker Inc. Он содержит огромное количество готовых образов, которые можно использовать для создания контейнеров.

<div align="center">
  <img alt="Project Demo" src="./Images/img13-2.png" />
</div>

## 🏁 Основные команды Docker

Перед выполнением команд нам необходимо установить Docker, для этого перейдем на [**официальный сайт**](https://www.docker.com/get-started/) и установим DockerDesktop. Это приложение для установки в один клик для вашей среды Mac, Linux или Windows, которое позволяет создавать и запускать контейнерные приложения и микросервисы.

Он предоставляет простой графический интерфейс пользователя, который позволяет управлять контейнерами, приложениями и образами непосредственно с вашего компьютера.

> **Внимание!**
>В связи с тем, что компания Docker заблокировала Docker Hub (hub.docker.com) для пользователей из России, необходимо добавить зеркала этого хоста в настройки Docker Desktop.

Для этого откройте страницу настроек `Settings` | `Docker Engine`:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-3.png" />
</div>

И измените содержимое текстового поля следующим образом:

```json
{
  "builder": {
    "gc": {
      "defaultKeepStorage": "20GB",
      "enabled": true
    }
  },
  "experimental": false,
  "registry-mirrors": [
    "https://mirror.gcr.io",
    "https://dockerhub.timeweb.cloud/"
  ]
}
```

После этого нажмите кнопку `Apply & restart`.

## 👻 Что такое Docker Images?

**Docker Images** — это неизменяемые (immutable) шаблоны, используемые для создания контейнеров Docker. Можно представить их как “снимки” файловой системы, содержащие все необходимые файлы и инструкции для запуска приложения. Образ — это статический объект, который не меняется после создания.

**Что содержит Docker Image:**

- **Файлы системы:** Все файлы, необходимые для работы приложения (библиотеки, скрипты, конфигурационные файлы и т.д.).

- **Метаданные:** Информация о образе, например, имя, версия, размер, и теги.

- **Инструкции для запуска:** Информация о том, как запустить приложение внутри контейнера (команда  `CMD` в  `Dockerfile`).

<div align="center">
  <img alt="Project Demo" src="./Images/img13-4.png" />
</div>

### 🎬 Использование Docker Images

- Мы можем легко и эффективно запускать контейнеры с помощью образов.
- Весь код, настройки конфигурации, переменные среды, библиотеки и время выполнения включены в образ Docker.
- Образы Docker не зависят от платформы.
- Слои являются строительными блоками.
- При использовании команды сборки у пользователя есть возможность полностью начать с нуля или использовать существующий образ.

**Разница между Docker Image и Docker Container**

| Образ Docker | Контейнер Docker |
|---|---|
| Образ Docker является исходным кодом контейнера Docker. | Контейнер Docker является экземпляром образа Docker. |
| `Dockerfile` является обязательным условием для образа Docker. | Образ Docker является предварительным условием для контейнера Docker. |
| Образы Docker могут быть переданы пользователям с помощью реестра Docker. | Контейнеры Docker не могут быть разделены между пользователями. |
| Чтобы внести изменения в образ Docker, нам нужно внести изменения в `Dockerfile`. | Мы можем напрямую взаимодействовать с контейнером и вносить необходимые изменения. |

**Структура Образа Docker**

Слои программного обеспечения, которые составляют образ Docker, облегчают настройку зависимостей, необходимых для выполнения контейнера.

- **Базовый образ:** Базовый образ будет отправной точкой для большинства Dockerfiles, и его можно сделать с нуля.
- **Родительский образ:** Родительский образ - это образ, на котором основан наш образ. Мы можем ссылаться на родительский образ в Dockerfile с помощью команды `FROM`, и каждое объявление после этого влияет на родительский образ.
- **Слои:** Образы Docker имеют множество слоев. Чтобы создать последовательность промежуточных образов, каждый слой создается поверх предыдущего.
- **Реестр Docker:** Это система для хранения и распространения образов Docker с определенными именами. Может быть несколько версий одного и того же образа, каждая со своим собственным набором тегов. Реестр Docker разделен на репозитории Docker, в каждом из которых хранятся все модификации образа.

Перед тем, как создать образ Docker нам необходимо написать Dockerfile. 

<div align="center">
  <img alt="Project Demo" src="./Images/img13-5.png" />
</div>

Образы обычно создаются с помощью  `Dockerfile`. Это текстовый файл, содержащий инструкции для создания образа. Каждая строка в `Dockerfile` создает новый слой в образе. 

Например:

```docker
FROM ubuntu:latest # Базовый образ
RUN apt-get update && apt-get install -y nginx # Установка пакета nginx
COPY ./nginx.conf /etc/nginx/sites-available/default # Копирование файла конфигурации
CMD ["nginx", "-g", "daemon off;"] # Команда для запуска nginx
```

Команда `docker build` использует `Dockerfile` для создания образа.

Образ — это шаблон. Контейнер — это запущенный экземпляр образа. Когда вы запускаете контейнер, Docker использует образ для создания файловой системы контейнера. Изменения, внесенные в контейнер во время его работы, не влияют на образ. Это важно, потому что образы неизменяемы.

## 🥥 Файл Dockerfile

`Dockerfile` — это текстовый файл, содержащий набор инструкций, которые Docker Engine использует для сборки Docker Image. Он описывает, как создать образ, содержащий все необходимые файлы и настройки для запуска приложения в контейнере. `Dockerfile` — ключевой элемент в работе с Docker, обеспечивающий повторяемость и портативность приложений.

**Структура `Dockerfile`:**

`Dockerfile` — это набор инструкций, каждая из которых описывает отдельную операцию по созданию слоя в образе. Инструкции записываются в файле в виде строк. Каждая инструкция имеет определенный синтаксис:

```docker
[инструкция] [аргументы]
```

**Примеры инструкций:**

- **`FROM`:** Указывает базовый образ, на основе которого будет создаваться новый образ. Например: `FROM ubuntu:latest`. Это первый и обязательный шаг.

- **`LABEL`:** Добавляет метаданные к образу.

- **`MAINTAINER`:** Указывает имя и электронную почту разработчика. (рекомендуется использовать `LABEL` вместо `MAINTAINER` для более гибких метаданных.)

- **`RUN`:** Выполняет команду в контейнере во время сборки образа. Например, устанавливает пакеты (`RUN apt-get update && apt-get install -y nginx`), копирует файлы (`RUN cp /path/to/file /new/destination`) или выполняет скрипты.

- **`COPY` и `ADD`:** Копирует файлы из хост-системы в контейнер. `COPY` копирует только указанные файлы/каталоги, а `ADD` также может распаковывать архивы.

- **`WORKDIR`:** Устанавливает рабочую директорию в контейнере. Это важно для последующих инструкций `RUN`, `COPY`, `CMD`.

- **`CMD`:** Устанавливает команду, которая будет выполняться при запуске контейнера. Она выполняется только один раз.

- **`ENTRYPOINT`:** Определяет основную точку входа для запуска приложения в контейнере. Команда, указанная в `ENTRYPOINT`, будет выполняться перед командой, указанной в `CMD`. Это позволяет изменять поведение запуска без изменения образа.

- **`ENV`:** Устанавливает переменные среды в контейнере.

- **`EXPOSE`:** Объявляет порты, которые приложение должно слушать. Это необходимо для доступа к приложению извне контейнера.

- **`VOLUME`:** Создает тома (volumes) для сохранения данных, которые не должны теряться при остановке контейнера. Они не входят в сам образ, но могут быть смонтированы во время запуска контейнера.

- **`USER`:** Устанавливает пользователя для выполнения команд.

- **`ARG`:** Объявляет аргументы, которые могут быть переданы при сборке образа.

**Порядок инструкций:**

Инструкции в `Dockerfile` выполняются последовательно. Важно, чтобы порядок инструкций соответствовал логике сборки образа.

**Пример `Dockerfile`:**

```docker
FROM ubuntu:latest

RUN apt-get update && apt-get install -y nginx

COPY ./nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

Этот `Dockerfile` создает образ, содержащий nginx, с копией файла конфигурации `nginx.conf` из текущей директории. При запуске контейнера nginx будет запущен.

Подробности и нюансы можно почерпнуть из официальной документации.

Давайте [**откроем образ Python**](https://github.com/docker-library/python/blob/b7b91ef359a740a91caeabce414ce4ee70fd2b23/3.12/slim-bookworm/Dockerfile) и посмотрим его Dockerfile:

```dockerfile
#
# NOTE: THIS DOCKERFILE IS GENERATED VIA "apply-templates.sh"
#
# PLEASE DO NOT EDIT IT DIRECTLY.
#

FROM debian:bookworm-slim

# ensure local python is preferred over distribution python
ENV PATH /usr/local/bin:$PATH

# http://bugs.python.org/issue19846
# > At the moment, setting "LANG=C" on a Linux system *fundamentally breaks Python 3*, and that's not OK.
ENV LANG C.UTF-8

# runtime dependencies
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		ca-certificates \
		netbase \
		tzdata \
	; \
	rm -rf /var/lib/apt/lists/*

ENV GPG_KEY 7169605F62C751356D054A26A821E680E5FA6305
ENV PYTHON_VERSION 3.12.0

RUN set -eux; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		dpkg-dev \
		gcc \
		gnupg \
		libbluetooth-dev \
		libbz2-dev \
		libc6-dev \
		libdb-dev \
		libexpat1-dev \
		libffi-dev \
		libgdbm-dev \
		liblzma-dev \
		libncursesw5-dev \
		libreadline-dev \
		libsqlite3-dev \
		libssl-dev \
		make \
		tk-dev \
		uuid-dev \
		wget \
		xz-utils \
		zlib1g-dev \
	; \
	\
	wget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz"; \
	wget -O python.tar.xz.asc "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc"; \
	GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
	gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GPG_KEY"; \
	gpg --batch --verify python.tar.xz.asc python.tar.xz; \
	gpgconf --kill all; \
	rm -rf "$GNUPGHOME" python.tar.xz.asc; \
	mkdir -p /usr/src/python; \
	tar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; \
	rm python.tar.xz; \
	\
	cd /usr/src/python; \
	gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
	./configure \
		--build="$gnuArch" \
		--enable-loadable-sqlite-extensions \
		--enable-optimizations \
		--enable-option-checking=fatal \
		--enable-shared \
		--with-lto \
		--with-system-expat \
		--without-ensurepip \
	; \
	nproc="$(nproc)"; \
	EXTRA_CFLAGS="$(dpkg-buildflags --get CFLAGS)"; \
	LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"; \
	LDFLAGS="${LDFLAGS:--Wl},--strip-all"; \
	make -j "$nproc" \
		"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \
		"LDFLAGS=${LDFLAGS:-}" \
		"PROFILE_TASK=${PROFILE_TASK:-}" \
	; \
# https://github.com/docker-library/python/issues/784
# prevent accidental usage of a system installed libpython of the same version
	rm python; \
	make -j "$nproc" \
		"EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" \
		"LDFLAGS=${LDFLAGS:--Wl},-rpath='\$\$ORIGIN/../lib'" \
		"PROFILE_TASK=${PROFILE_TASK:-}" \
		python \
	; \
	make install; \
	\
	cd /; \
	rm -rf /usr/src/python; \
	\
	find /usr/local -depth \
		\( \
			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
			-o \( -type f -a \( -name '*.pyc' -o -name '*.pyo' -o -name 'libpython*.a' \) \) \
		\) -exec rm -rf '{}' + \
	; \
	\
	ldconfig; \
	\
	apt-mark auto '.*' > /dev/null; \
	apt-mark manual $savedAptMark; \
	find /usr/local -type f -executable -not \( -name '*tkinter*' \) -exec ldd '{}' ';' \
		| awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' \
		| sort -u \
		| xargs -r dpkg-query --search \
		| cut -d: -f1 \
		| sort -u \
		| xargs -r apt-mark manual \
	; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	rm -rf /var/lib/apt/lists/*; \
	\
	python3 --version

# make some useful symlinks that are expected to exist ("/usr/local/bin/python" and friends)
RUN set -eux; \
	for src in idle3 pydoc3 python3 python3-config; do \
		dst="$(echo "$src" | tr -d 3)"; \
		[ -s "/usr/local/bin/$src" ]; \
		[ ! -e "/usr/local/bin/$dst" ]; \
		ln -svT "$src" "/usr/local/bin/$dst"; \
	done

# if this is called "PIP_VERSION", pip explodes with "ValueError: invalid truth value '<VERSION>'"
ENV PYTHON_PIP_VERSION 23.2.1
# https://github.com/pypa/get-pip
ENV PYTHON_GET_PIP_URL https://github.com/pypa/get-pip/raw/9af82b715db434abb94a0a6f3569f43e72157346/public/get-pip.py
ENV PYTHON_GET_PIP_SHA256 45a2bb8bf2bb5eff16fdd00faef6f29731831c7c59bd9fc2bf1f3bed511ff1fe

RUN set -eux; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends wget; \
	\
	wget -O get-pip.py "$PYTHON_GET_PIP_URL"; \
	echo "$PYTHON_GET_PIP_SHA256 *get-pip.py" | sha256sum -c -; \
	\
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark > /dev/null; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	rm -rf /var/lib/apt/lists/*; \
	\
	export PYTHONDONTWRITEBYTECODE=1; \
	\
	python get-pip.py \
		--disable-pip-version-check \
		--no-cache-dir \
		--no-compile \
		"pip==$PYTHON_PIP_VERSION" \
	; \
	rm -f get-pip.py; \
	\
	pip --version

CMD ["python3"]
```

Мы видим что у него задан базовый образ Debian Bookworm (`debian:bookworm-slim`), тег `-slim` в названии которого обозначает что используется облегчённый образ, из которого удалено всё лишнее, такое как справочные страницы, документация и прочее, которое не нужно для нормального функционирования контейнера.

Далее идут команды установки необходимых пакетов, таких как инструменты для компиляции, утилиты и различные библиотеки.

Затем идёт скачивание архива исходников Python версии 3.12.0, распаковка, процесс компиляции и установки Python.

Далее происходит скачивание скрипта `get-pip.py` и его запуск - происходит установка Pip версии 23.2.1.

### 🪨 Сборка образа

Сборка Docker Image — это процесс создания образа, содержащего все необходимые файлы и инструкции для запуска приложения в контейнере. Этот процесс использует Dockerfile, который является списком команд, определяющих, как скомпилировать и подготовить приложение для работы в Docker контейнере.

Используйте команду `docker build` для начала процесса сборки. Эта команда принимает несколько аргументов, но ключевым является `context`.

```bash
docker build -t <имя_образа>:<тег> .
```

- `<имя_образа>`: Имя, которое вы дадите вашему образу (например, `my-app`).
- `<тег>`: Тег, который вы дадите образу (например, `latest`, `v1.0`).
- `.` (точка): указывает, что Docker должен использовать текущую директорию как контекст сборки. Если Dockerfile находится в другом месте, укажите путь к нему. Например, `docker build -t my-image:latest ./my-app/`

**Использование нескольких `Dockerfile`**

Использование нескольких `Dockerfile` — распространённая практика, особенно при работе с большими проектами, где один `Dockerfile` может стать слишком громоздким и сложным для обслуживания. Несколько `Dockerfile` могут использоваться в разных сценариях, и каждый подход имеет свои плюсы и минусы.


**Исключение файлов из сборки**

Файл `.dockerignore` используется для исключения файлов и директорий из контекста сборки Docker. Это важно по нескольким причинам:

- **Уменьшение размера контекста:** Исключение ненужных файлов уменьшает размер контекста сборки, что ускоряет процесс сборки. Чем меньше файлов передаётся на Docker Daemon, тем быстрее будет построение образа.

- **Безопасность:** Некоторые файлы, такие как ключи, пароли или конфиденциальные данные, не должны включаться в образ. `.dockerignore` гарантирует, что такие файлы не попадут в образ.

- **Улучшение повторяемости:** Исключение временных или генерируемых файлов делает процесс сборки более воспроизводимым.


**Синтаксис файла `.dockerignore`:**

Файл `.dockerignore` использует простой синтаксис, основанный на шаблонах:

- **Директивы:** Каждая строка в `.dockerignore` представляет собой шаблон, который определяет, какие файлы или директории следует исключить.

- **Шаблоны:** Шаблоны могут содержать подстановочные знаки:

    - `*`: Соответствует любому количеству символов.
    - `?`: Соответствует одному символу.
    - `[]`: Соответствует одному из символов в квадратных скобках.
    - `!`: Исключает исключение.

- **Комментарии**: Строки, начинающиеся с `#`, игнорируются.

- **Пути**: Пути задаются относительно директории, в которой находится `.dockerignore`.

**Примеры:**

- .`DS_Store`: Исключает файлы .DS_Store (macOS).
- `node_modules`: Исключает директорию node_modules.
- `*.log`: Исключает все файлы с расширением .log.
- `/tmp/`: Исключает директорию /tmp (абсолютный путь).
- `build/`: Исключает директорию build.
- `!important.txt`: Исключает все кроме файла important.txt

---

## 🗿 Создание Dockerfile для приложения Python

**Шаг 1: Создание файлов**

Создадим простой Python проект и добавим следующий код в `main.py`:

```python
a = 11
b = 16
print(f'The sum of {a} and {b} is {a+b}')
```

<div align="center">
  <img alt="Project Demo" src="./Images/img13-6.png" />
</div>

**Шаг 2: Создание Dockerfile**

Создадим файл в нашем проекте:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-7.png" />
</div>

И добавим следующий код:

```docker
#Выбор базового образа
FROM python:latest


#Укажем мета данные
LABEL authors="permin0ff"


# Рабочий каталог можно выбрать любой, например, '/' или '/home' и т. д.
WORKDIR /usr/src/app

#Копируем удаленный файл в рабочем каталоге в контейнере
COPY main.py ./
# Теперь структура выглядит следующим образом '/usr/src/app/main.py'


#Для запуска программного обеспечения следует использовать инструкцию CMD

CMD [ "python", "./main.py"]
```

Внутри `Dockerfile` мы начнем с базового образа Python из Docker Hub. Последний тег используется для получения последнего официального образа Python.

Очень важно установить рабочий каталог внутри контейнера. Я выбрал `/usr/src/app`. Все команды будут выполнены здесь, а образы будут скопированы только здесь.

Затем мы копируем файл `main.py` со своего компьютера в текущий рабочий каталог контейнера (`./` или `/usr/src/app`) с помощью команды `COPY`.

** Шаг 3: Создание .dockerignore**

Создадим файл `.dockerignore` в корне нашего проекта:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-8.png" />
</div>

Теперь откроем нашу папку проекта. Мы видим 2 лишние папки, одна с нашей виртуальной средой, другая с настройками Pycharm.

Чтобы они не были добавлены в наш образ, мы должны добавить их имена в файл `.dockerignore`, для игнорирования их:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-9.png" />
</div>

Добавим в файл `.dockerignore` следующий текст:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-10.png" />
</div>

Тем самым мы указали какие папки мы не будем включать в наш образ.

## 🎮 Образ Docker для Python приложения

**Шаг 1: Создание контейнера Docker**

После того, как вы создали скрипт Python и Dockerfile, теперь вы можете использовать команду `docker build` для создания образа Docker.

```docker
docker image build -t python_script:0.0.1 /Users/permin0ff/PycharmProjects/Django_Course_2/pythonProject
```

Здесь используется опция `-t` для добавления тегов, чтобы легко идентифицировать наш образ.

И мы видим что наш образ был успешно создан:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-11.png" />
</div>

**Шаг 2: Запуск контейнера Docker**

Теперь вы можете использовать команду `docker run` для запуска контейнера Docker.

```bash
docker run python_script:0.0.1
```

<div align="center">
  <img alt="Project Demo" src="./Images/img13-12.png" />
</div>

После запуска контейнера Docker вы увидите вывод, напечатанный после сложения двух чисел.

Теперь мы можем через Docker Desktop посмотреть файловую структуру:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-13.png" />
</div>

## 💤 Контейнеризация FastAPI и написание Dockerfile

 За основу возьмем простой проект по типу "Hello world". Для этого создадим файл `main.py` следующего содержания:

 ```python
 from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def welcome() -> dict:
    return {"message": "Hello World"}
```

И следующим шагом выполним команду:

```bash
pip freeze > requirements.txt
```

Чтобы создать файл, содержащий все зависимости нашего проекта.

### 🍩 Создание Dockerfile

Начнем с `Dockerfile` - это текстовый файл, который содержит инструкции о том, как будет создан docker-образ.


В `Dockerfile` используются нижеследующие директивы:

- **`FROM`:** Директива устанавливает базовый образ, из которого будет построен контейнер Docker.
- **`WORKDIR`:** Директива устанавливает рабочий каталог в созданном образе.
- **`RUN`:** Директива выполняет команды в контейнере.
- **`COPY`:** Директива копирует файлы из файловой системы в контейнер.
- **`CMD`:** Директива устанавливает исполняемые команды в контейнере.

В корневом каталоге проекта создайте файл с именем `Dockerfile` без расширения файла:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-14.png" />
</div>

Добавим в этот файл следующие команды:

```docker
# pull the official base image
FROM python:3.12.0-alpine

# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# set work directory
WORKDIR /usr/src/app

# copy requirements.txt file to work directory
COPY requirements.txt .

# update pip and install dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# copy project to work directory
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
```

Разберем содержимое этого файла подробнее:

- `FROM python:3.12.0-alpine`: Устанавливает базовый образ, на основе которого будет создан контейнер Docker.

- `ENV PYTHONDONTWRITEBYTECODE=1`: Не позволяет Python создавать файлы .pyc в контейнере.

- `ENV PYTHONUNBUFFERED=1`: Гарантирует, что вывод Python регистрируется в терминале, что позволяет отслеживать логи FastAPI в режиме реального времени.

- `WORKDIR /usr/src/app`: Устанавливает рабочий каталог внутри контейнера в /usr/src/app.

- `COPY requirements.txt .`: Копирует файл зависимостей requirements.txt в рабочий каталог в контейнере.

- `RUN pip install --upgrade pip && pip install -r requirements.txt`: Устанавливает и обновляет версию pip, которая находится в контейнере, а затем устанавливает все необходимые модули проекта для запуска в контейнере.

- `COPY . .`: Копирует весь исходный код проекта в рабочий каталог в контейнере.

- `CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]`: Устанавливает исполняемые команды в контейнере.

### 🍪 Создание образа Docker

Перед началом создания образа, создадим файл `.dockerignore` следующего содержания:

```bash
.venv
__pycache__
.idea
**/Dockerfile*
.dockerignore
```

И теперь мы можем приступить к созданию образа Docker из файла Dockerfile, который мы создали выше, выполните следующую команду:

```bash
docker build --tag fastapi_hello_word:latest .
```

- `--tag` Устанавливает тег для образа. Например, мы создаем образ Docker из `python:3.12.0` у него есть тег `alpine`.
В нашем образе Docker, `latest` это тег.
- Точка `.` указывает на то, что `Dockerfile` находится в текущем рабочем каталоге.

Результат выполнения данной команды:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-15.png" />
</div>

Чтобы перечислить все доступные образы на вашем компьютере, выполните следующую команду:

```bash
docker image ls
```

<div align="center">
  <img alt="Project Demo" src="./Images/img13-16.png" />
</div>

Также мы можем посмотреть наши образы используя Docker Desktop, перейдя в раздел `Images`:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-17.png" />
</div>

Из приведенного выше списка мы видим созданный нами образ `fastapi_hello_word`. 

### 🧊 Создание и запуск контейнера Docker

Чтобы создать и запустить контейнер Docker из образа, который мы создали выше, выполните команду ниже:

```bash
docker run --name fastapi_hello_word -d -p 80:80 fastapi_hello_word:latest
```
                  
- `--name`: Устанавливает имя контейнера Docker.
- `-d`: Заставляет образ работать  в фоновом режиме.
- `-p 80:80`: Сопоставляет порт `80` в контейнере Docker с портом `80` на локальном хосте.
- `fastapi_hello_word:latest`: Указывает, какой образ используется для сборки контейнера Docker.

После выполнения команды, мы получим следующий ответ:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-18.png" />
</div>

Чтобы перечислить все запущенные контейнеры Docker, выполните следующую команду:

```bash
docker container ps
```

<div align="center">
  <img alt="Project Demo" src="./Images/img13-19.png" />
</div>

Или мы можем посмотреть в Docker Desktop:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-20.png" />
</div>

Теперь мы можем открыть в браузере наш проект в контейнере по адресу - `http://127.0.0.1/`:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-21.png" />
</div>

Как мы видим, наш проект прекрасно работает в контейнере Docker. 

В качестве вводного примера мы рассмотрели автономное приложение, не взаимодействующее с внешними ресурсами. Однако, такие приложения встречаются редко. Большинство реальных проектов представляют собой совокупность взаимодействующих приложений. 

## 🦭 Что такое Docker Compose?

**Docker Compose** — это инструмент для определения и управления многоконтейнерными приложениями. Вместо того, чтобы описывать каждый контейнер по отдельности, вы создаёте один файл (обычно `docker-compose.yml`), описывающий все контейнеры приложения, их зависимости и связи между ними. Это упрощает настройку и запуск сложных приложений, состоящих из нескольких взаимосвязанных контейнеров.

**Ключевые особенности Docker Compose:**

- **Определение многоконтейнерных приложений:**  `docker-compose.yml` описывает все контейнеры, необходимые для приложения, включая их образы, порты, объёмы данных, сети и зависимости друг от друга.

- **Упрощение запуска:**  `docker-compose up` запускает все контейнеры, описанные в файле, автоматически создавая и настраивая необходимые связи. Это значительно проще, чем запускать каждый контейнер по отдельности с помощью `docker run`.

- **Определение связей между контейнерами:** Compose позволяет настраивать сети между контейнерами, устанавливая связи между сервисами (например, между веб-сервером и базой данных). Это важно для приложений, где один сервис должен взаимодействовать с другим.

- **Управление ресурсами:** Compose позволяет задать ресурсы, выделяемые каждому контейнеру (например, количество процессорных ядер, оперативной памяти).

- **Простота масштабирования:** Благодаря описанию в одном файле, Compose упрощает масштабирование приложения путём создания нескольких экземпляров контейнеров.

- **Переиспользование образов:** Compose использует уже существующие Docker Images, уменьшая необходимость повторяющейся работы по построению образов для каждого сервиса.

- **Упрощение разработки и тестирования:** Запуск сложных приложений в нескольких контейнерах с использованием одного файла docker-compose.yml упрощает разработку и тестирование.

### 🧸 Разница между Docker и Docker Compose

Docker и Docker Compose — два взаимосвязанных, но разных инструмента, которые используются для работы с контейнерами. Docker — это основа, а Docker Compose — инструмент, облегчающий работу с несколькими контейнерами.

<div align="center">
  <img alt="Project Demo" src="./Images/img13-22.png" />
</div>

**Когда использовать какой инструмент:**

- **Docker:** Для работы с отдельными контейнерами, например, для запуска и управления одним веб-сервером или базой данных. Идеально, если требуется детальный контроль над каждым контейнером.

- **Docker Compose:** Для работы с приложениями, состоящими из нескольких контейнеров (например, веб-сервер, база данных, кеш), когда важна простота управления и автоматизация связей. Идеально подходит для разработки, тестирования и развертывания.

## ☀️ Docker Compose на примере FastAPI, PostgreSQL

Теперь, когда вы понимаете, для чего предназначен Docker Compose, давайте создадим простое клиент-серверное приложение, используя этот инструмент.

В этом разделе мы рассмотрим Docker Compose на примере небольшого проекта: FastAPI и PostgreSQL будут работать как единое целое в контейнерах. Docker Compose управляет этим кластером контейнеров через файл `docker-compose.yml`.

Файл `docker-compose.yml` — это YAML-конфигурация, определяющая, как запустить и связать между собой контейнеры, а также как они будут взаимодействовать с внешней средой. По сути, инструкции в `docker-compose.yml` аналогичны параметрам команды `docker run`.


Для запуска контейнеров через `docker-compose` используются следующие команды:

- `docker compose build`: собрать проект
- `docker compose up -d`: запустить проект
- `docker compose down`: остановить проект
- `docker compose logs -f [service name]`: посмотреть логи сервиса
- `docker compose ps`: вывести список контейнеров
- `docker compose exec [service name] [command]`: выполнить команду в контейнере
- `docker compose images`: вывести список образов

**Подготовка проекта к Docker Compose**

За основу возьмем проект интернет магазина из 5 модуля данного курса. На данный момент, его файловая структура выглядит следующим образом:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-23.png" />
</div>

Выполним команду:

```bash
pip freeze > requirements.txt
```

Чтобы создать файл, содержащий все зависимости нашего проекта.

И теперь создадим `Dockerfile` в папке `app` нашего приложения.

```docker
FROM python:3.12-alpine

# устанавливаем переменные окружения
ENV HOME=/home/fast \
    APP_HOME=/home/fast/app \
    PYTHONPATH="$PYTHONPATH:/home/fast" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# создаем домашнюю директорию для пользователя(/home/fast) и директорию для проекта(/home/fast/app)
# создаем группу fast
# создаем отдельного пользователя fast
RUN mkdir -p $APP_HOME \
  && addgroup -S fast \
  && adduser -S fast -G fast

# устанавливаем рабочую директорию
WORKDIR $HOME

# копирование проекта FastAPI в рабочую директорию
COPY app app
COPY media media
COPY requirements.txt alembic.ini .env .

# обновление pip
# установка зависимостей из списка requirements.txt
# изменение владельца, для всех директорий и файлов проекта, на пользователя fast
RUN pip install --upgrade pip \
 && pip install -r requirements.txt \
 && chown -R fast:fast .

# изменение рабочего пользователя на fast
USER fast
```

Затем добавьте файл `docker-compose.yml` в корень проекта, со следующим содержимым:

```yml
services:
  web:
    build:
      # Указываем контекст сборки - текущую директорию проекта
      context: .
      # Используем Dockerfile из директории app
      dockerfile: ./app/Dockerfile
    # Запускаем ASGI-приложение через сервер приложений Uvicorn
    command: uvicorn app.main:app --host 0.0.0.0
    # Открываем порт 8000 внутри и снаружи
    ports:
      - 8000:8000
```

В итоге мы получаем следующую файловую структуру:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-24.png" />
</div>

Внутри папки `app` находится наш FastAPI проект и его Dockerfile.

Перед выполнением следующих шагов проверьте в Docker Desktop запущенные контейнеры, их необходимо остановить. Теперь попробуем создать наш образ Docker Compose:

```bash
docker compose build
```

<div align="center">
  <img alt="Project Demo" src="./Images/img13-25.png" />
</div>

После создания образа запустите контейнер:

```bash
docker compose up -d
```
                  
Опция `-d` или`--detach` используется для создания и запуска контейнеров в фоновом режиме.

<div align="center">
  <img alt="Project Demo" src="./Images/img13-26.png" />
</div>

Перейдите на `http://127.0.0.1:8000`, чтобы убедиться что наш FastApi проект работает:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-27.png" />
</div>

Теперь мы можем открыть Docker Desktop и посмотреть на наши контейнеры:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-28.png" />
</div>

В следующем шаге мы добавим сервис PostgreSQL к нашему проекту.

## 💿 PostgreSQL

Для создания базы данных в Docker Compose, добавьте в файл `docker-compose.yml` раздел `db`. В этом разделе укажите имя пользователя, пароль, имя базы данных и том для хранения данных. Обратите внимание на версию образа PostgreSQL — возможно, вам потребуется её изменить.

```bash
services:
  web:
    build:
      # Указываем контекст сборки - текущую директорию проекта
      context: .
      # Используем Dockerfile из директории app
      dockerfile: ./app/Dockerfile
    # Запускаем ASGI-приложение через сервер приложений Uvicorn
    command: uvicorn app.main:app --host 0.0.0.0
    # Открываем порт 8000 внутри и снаружи
    ports:
      - 8000:8000
    # Запускаем контейнер после старта контейнера базы данных
    depends_on:
      - db

  db:
    # Используем официальный образ PostgreSQL версии 16
    image: postgres:16
    # Монтируем том postgres_data в /var/lib/postgresql/data контейнера для хранения данных БД
    volumes:
      - postgres_data:/var/lib/postgresql/data
    # Задаём переменные окружения для инициализации БД и пользователя
    environment:
      - POSTGRES_USER=ecommerce_user
      - POSTGRES_PASSWORD=xxxxxxxx
      - POSTGRES_DB=ecommerce_db

volumes:
  # Определяем том для хранения данных БД
  postgres_data:
```

При запуске базы данных в контейнере без тома данных (`volume`), каждый перезапуск контейнера приведёт к потере данных. Поэтому мы определили внешний Docker-том `postgres_data` для хранения данных базы.

Изменим настройки подключения к БД в FastAPI, для этого в файле `app/database.py` внесем изменения:

```python
DATABASE_URL = "postgresql+asyncpg://ecommerce_user:xxxxxxxx@db:5432/ecommerce_db"
```

Также нам нужно изменить настройки подключения для Alembic, изменим строку подключения в файле `alembic.ini`

```bash
sqlalchemy.url = postgresql+asyncpg://ecommerce_user:xxxxxxxx@db:5432/ecommerce_db
```

Теперь удалим предыдущий контейнер:

```bash
docker compose down -v
```

Выполним билд и запуск наших контейнеров еще раз:

```bash
docker compose up -d --build
```

<div align="center">
  <img alt="Project Demo" src="./Images/img13-29.png" />
</div>

Теперь откроем Docker Desktop и посмотрим на контейнеры:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-30.png" />
</div>

Как мы видим они работают, перейдем к миграциям и применим их:

```bash
docker compose exec web alembic upgrade head
```

Убедимся, что была создана БД нашего проекта FastAPI:

```bash
docker compose exec db psql --username=ecommerce_user --dbname=ecommerce_db

\l
```

<div align="center">
  <img alt="Project Demo" src="./Images/img13-31.png" />
</div>

Также мы можем выполнить команду `\dt` чтобы посмотреть таблицы этой БД (`ecommerce_db`):

<div align="center">
  <img alt="Project Demo" src="./Images/img13-32.png" />
</div>

Для выхода из psql выполним команду `\q`.


На данном этапе мы можем проверить работу с базой данных, добавляя данные, но далее она у нас очиститься, так как мы еще не раз будем пересоздавать наш контейнер. Поэтому пока мы не будем ничего в неё добавлять.

Перейдем по адресу `http://127.0.0.1:8000/docs/` и проверим работает ли наш проект:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-33.png" />
</div>

Попробуем получить все категории:

<div align="center">
  <img alt="Project Demo" src="./Images/img13-34.png" />
</div>

<div align="center">
  <img alt="Project Demo" src="./mygif/gif13-2.gif" />
</div>

---

<div align="center"> Made with ❤️ by <b>dv0retsky</b> </div>