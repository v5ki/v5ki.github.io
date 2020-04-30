---
layout: post
title:  "Что нам стоит CTF устроить? Прокачиваем CTFd"
date:   2020-05-01 10:00:00 +0300
categories: smartrhino backstage
---

<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/main.png" width="500">
</p>

Специально для паблика [SMARTRHINO](https://vk.com/smartrhino).

Сегодня мы исправим баг в панели настроек и добавим новый функционал.

## 0010. Исправляем баг
CTFd редоставляет возможность изменять тему и тело письма, которое отправляется пользователю.  
Давайте, попробуем изменить формат сообщения __Account Registration__.  
Изначально это выглядит следующим образом:
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/account_before.png" width="500">
</p>

Внесём изменения:
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/account.png" width="500">
</p>

Нажимаем на кнопку _Update_ внизу страницы и видим следующее:
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/account_after.png" width="500">
</p>

Тело письма не изменилось, вместо него подставилось значение по умолчанию, печально (  
К счастью данная проблема решается не так уж и сложно. Открываем в браузере инспектор и смотрим, что к чему.
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/html_form.png" width="500">
</p>

Я намеренно выделил на скриншоте две группы, так ошибку видно практически сразу.  
А затаилась она в атрибуте `name` компонента `textarea`. Скорее всего данная ошибка вызвана невнимательностью во время копипасты.  
Чтобы всё поехало, нужно изменить значение на `successful_registration_email_body`, т.е. оно должно быть таким же, как у атрибута `id`.  
Под наш скальпель попадёт один-единственный html-шаблон, находящийся по пути `CTFd/CTFd/themes/admin/templates/config/email.html`.

Исправляем досадную ошибку, выключаем контейнер, перезапускаем сервер, поднимаем контейнер и удостоверяемся, что всё работает должным образом.

## 0011. "Вас много, а я одна!"
CTFd имеет всего два типа пользователей: __Admin__ и __User__. Первый имеет неограниченную власть и огромную ответственность.  
Второй же может зарегаться, создать команду или присоединиться к уже существующей, и поиграть после начала соревнований.  

<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/user_types.png" width="500">
</p>

Данный факт меня несколько расстроил и навёл на мысль: _"А как же быть с ответственными за таски? Не давать же всем админские права, мало ли что.."_.  
После этого у меня родилась идея: _"Может, добавить новый тип пользователя с ограниченными правами админа?"_.  

Окей, погнали, но для начала стоит определиться с правами: данным пользователям можно создавать таски, редактировать их, при необходимости добавлять __Hints__ и смотреть статистику решений.

## 0012. Ловим питона за хвост
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/python.png" width="500">
</p>

Открываем PyCharm, создаём проект из исходного кода и начинаем дивное приключение.  
Файлов и папок просто тьма, поэтому предлагаю заглянуть в самое очевидно место - `admin/challenges.py`.
Практически сразу бросается в глаза строка №11:
```python
from CTFd.utils.decorators import admins_only
```
Ага, декораторы! Спускаемся чуть ниже и видим его использование.  
Так, понятно, разграничение прав пользователей реализовали с помощью декораторов.  
Ну что же, добавим и мы свой декоратор, для этого надо отредактировать файл `decorators/__init__.py`.
Нарекаем новый тип пользователя __TaskDeployer__.

```python
def admins_or_task_deployers_only(f):
    """
    Decorator that requires the user to be authenticated and an admin
    :param f:
    :return:
    """

    @functools.wraps(f)
    def admins_or_task_deployers_only_wrapper(*args, **kwargs):
        if is_admin() or is_task_deployer():
            return f(*args, **kwargs)
        else:
            if request.content_type == "application/json":
                abort(403)
            else:
                return redirect(url_for("auth.login", next=request.full_path))

    return admins_or_task_deployers_only_wrapper
```

Кроме того необходимо добавить проверку `is_task_deployer`, для этого идём в файл `user/__init__.py`:
```python
def is_task_deployer():
    if authed():
        return session["type"] == "task_deployer"
    else:
        return False
```

Не забываем и про модели - `models/__init__.py`:
```python
class TaskDeployers(Users):
    __tablename__ = "task_deployers"
    __mapper_args__ = {"polymorphic_identity": "task_deployer"}
```

Общий смысл такой: ищём файлы, в которых есть декоратор `@admins_only` или проверка `is_admin`, и правим их, в соответствии с правами нового пользователя.

Правок довольно много, поэтому оставлю их под спойлером, вроде ничего не забыл.
<details>
    <summary>Правки</summary>
    
- `models/__init__.py`:
    - (Line 374) add 'TaskDeployers' class

- `utils/user/__init__.py`:
    - (Line 38) add 'is_task_deployer' func

- `decorators/__init__.py`:
    - (Line 22) add assert 'is_task_deployer' in 'during_ctf_time_only_wrapper' func
    - (Line 64) add assert 'is_task_deployer' in '_require_verified_emails' func
    - (Line 120) add decorator 'admins_or_task_deployers_only'

- `admin/__init__.py`:
    - (Line 37) import func 'is_task_deployer'
    - (Line 53) add assert 'is_task_deployer' in 'view' func

- `admin/challenges.py`:
    - (Line 11) import decorator 'admins_or_task_deployers_only'
    - (Line 16) change decorator to 'admins_or_task_deployers_only' for 'challenges_listing' func
    - (Line 24) change decorator to 'admins_or_task_deployers_only' for 'challenges_detail' func
    - (Line 63) change decorator to 'admins_or_task_deployers_only' for 'challenges_new' func

- `admin/notifications.py`:
    - (Line 5) import decorator 'admins_or_task_deployers_only'
    - (Line 10) change decorator to 'admins_or_task_deployers_only' for 'notifications' func

- `admin/scoreboard.py`:
    - (Line 5) import decorator 'admins_or_task_deployers_only'
    - (Line 10) change decorator to 'admins_or_task_deployers_only' for 'scoreboard_listing' func

- `admin/statistics.py`:
    - (Line 5) import decorator 'admins_or_task_deployers_only'
    - (Line 12) change decorator to 'admins_or_task_deployers_only' for 'statistics' func

- `admin/submissions.py`:
    - (Line 5) import decorator 'admins_or_task_deployers_only'
    - (Line 12) change decorator to 'admins_or_task_deployers_only' for 'submissions_listing' func

- `api/v1/challenges.py`:
    - (Line 24) import decorator 'admins_or_task_deployers_only'
    - (Line 34) import func 'is_task_deployer'
    - (Line 68) add assert 'is_task_deployer' in 'get' func
    - (Line 121) change decorator to 'admins_or_task_deployers_only' for 'post' func
    - (Line 134) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 156) add assert 'is_task_deployer' in 'get' func
    - (Line 183) add assert 'is_task_deployer' in 'get' func
    - (Line 215) add assert 'is_task_deployer' in 'get' func
    - (Line 263) add assert 'is_task_deployer' in 'get' func
    - (Line 279) change decorator to 'admins_or_task_deployers_only' for 'patch' func
    - (Line 288) change decorator to 'admins_or_task_deployers_only' for 'delete' func
    - (Line 313) add assert 'is_task_deployer' in 'post' func
    - (Line 424) add assert 'is_task_deployer' in 'post' func
    - (Line 442) add assert 'is_task_deployer' in 'post' func
    - (Line 511) add assert 'is_task_deployer' in 'get' func
    - (Line 530) add assert 'is_task_deployer' in 'get' func
    - (Line 551) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 568) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 585) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 601) change decorator to 'admins_or_task_deployers_only' for 'get' func

- `api/v1/files.py`:
    - (Line 7) import decorator 'admins_or_task_deployers_only'
    - (Line 15) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 28) change decorator to 'admins_or_task_deployers_only' for 'post' func
    - (Line 52) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 64) change decorator to 'admins_or_task_deployers_only' for 'delete' func

- `api/v1/flags.py`:
    - (Line 7) import decorator 'admins_or_task_deployers_only'
    - (Line 15) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 26) change decorator to 'admins_or_task_deployers_only' for 'post' func
    - (Line 48) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 68) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 82) change decorator to 'admins_or_task_deployers_only' for 'delete' func
    - (Line 93) change decorator to 'admins_or_task_deployers_only' for 'patch' func

- `api/v1/hints.py`:
    - (Line 6) import decorator 'admins_or_task_deployers_only'
    - (Line 7) import func 'is_task_deployer'
    - (Line 15) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 26) change decorator to 'admins_or_task_deployers_only' for 'post' func
    - (Line 60) add assert 'is_task_deployer' in 'get' func
    - (Line 72) change decorator to 'admins_or_task_deployers_only' for 'patch' func
    - (Line 91) change decorator to 'admins_or_task_deployers_only' for 'delete' func

- `api/v1/notifications.py`:
    - (Line 6) import decorator 'admins_or_task_deployers_only'
    - (Line 24) change decorator to 'admins_or_task_deployers_only' for 'post' func
    - (Line 63) change decorator to 'admins_or_task_deployers_only' for 'delete' func

- `api/v1/submissions.py`:
    - (Line 7) import decorator 'admins_or_task_deployers_only'
    - (Line 17) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 34) change decorator to 'admins_or_task_deployers_only' for 'post' func
    - (Line 59) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 71) change decorator to 'admins_or_task_deployers_only' for 'delete' func

- `api/v1/tags.py`:
    - (Line 6) import decorator 'admins_or_task_deployers_only'
    - (Line 14) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 27) change decorator to 'admins_or_task_deployers_only' for 'post' func
    - (Line 49) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 61) change decorator to 'admins_or_task_deployers_only' for 'patch' func
    - (Line 79) change decorator to 'admins_or_task_deployers_only' for 'delete' func

- `api/v1/tokens.py`:
    - (Line 10) import func 'is_task_deployer'
    - (Line 58) add assert 'is_task_deployer' in 'get' func
    - (Line 76) add assert 'is_task_deployer' in 'delete' func

- `api/v1/unlocks.py`:
    - (Line 10) import decorator 'admins_or_task_deployers_only'
    - (Line 23) change decorator to 'admins_or_task_deployers_only' for 'get' func

- `api/v1/statistics/challenges.py`:
    - (Line 7) import decorator 'admins_or_task_deployers_only'
    - (Line 14) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 32) change decorator to 'admins_or_task_deployers_only' for 'get' func
    - (Line 83) change decorator to 'admins_or_task_deployers_only' for 'get' func

- `api/v1/statistics/submissions.py`:
    - (Line 6) import decorator 'admins_or_task_deployers_only'
    - (Line 11) change decorator to 'admins_or_task_deployers_only' for 'get' func
</details>

Остался лишь последний штрих - поправить html-шаблоны.

## 0013. Лучший язык программирования
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/html.png" width="500">
</p>
