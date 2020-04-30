---
layout: post
title:  "Что нам стоит CTF устроить? Прокачиваем CTFd"
date:   2020-05-01 10:00:00 +0300
categories: smartrhino backstage
---

<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/main.jpg" width="500">
</p>

Специально для паблика [SMARTRHINO](https://vk.com/smartrhino).

Как и обещал, сегодня мы не только исправим баг в панели настроек, но и добавим новый функционал.  
Поехали!

## 0010. Исправляем баг
CTFd предоставляет возможность изменять тему и тело письма, которое отправляется пользователю.  
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
После чего родилась идея: _"Может, добавить новый тип пользователя с ограниченными правами админа?"_.  

Окей, погнали, но для начала стоит определиться с правами: данным пользователям можно создавать таски, редактировать их, при необходимости добавлять __Hints__ и смотреть статистику решений.

## 0012. Ловим питона за хвост
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/python.png" width="500">
</p>

Открываем PyCharm, создаём проект из существующего кода и начинаем дивное приключение.  
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
    <ul>
        <li>
            models/__init__.py:
            <ul>
                <li>(Line 374) add 'TaskDeployers' class</li>
            </ul>
        </li>
        <br/>
        <li>
            utils/user/__init__.py:
            <ul>
                <li>(Line 38) add 'is_task_deployer' func</li>
            </ul>
        </li>
        <br/>
        <li>
            decorators/__init__.py:
            <ul>
                <li>(Line 22) add assert 'is_task_deployer' in 'during_ctf_time_only_wrapper' func</li>
                <li>(Line 64) add assert 'is_task_deployer' in '_require_verified_emails' func</li>
                <li>(Line 120) add decorator 'admins_or_task_deployers_only'</li>
            </ul>
        </li>
        <br/>
        <li>
            admin/__init__.py:
            <ul>
                <li>(Line 37) import func 'is_task_deployer'</li>
                <li>(Line 53) add assert 'is_task_deployer' in 'view' func</li>
            </ul>
        </li>
        <br/>
        <li>
            admin/challenges.py:
            <ul>
                <li>(Line 11) import decorator 'admins_or_task_deployers_only'</li>
                    <li>(Line 16) change decorator to 'admins_or_task_deployers_only' for 'challenges_listing' func</li>
                    <li>(Line 24) change decorator to 'admins_or_task_deployers_only' for 'challenges_detail' func</li>
                    <li>(Line 63) change decorator to 'admins_or_task_deployers_only' for 'challenges_new' func</li>
            </ul>
         </li>
        <br/>
        <li>
            admin/notifications.py:
            <ul>
                <li>(Line 5) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 10) change decorator to 'admins_or_task_deployers_only' for 'notifications' func</li>
            </ul>
        </li>
        <br/>
        <li>
            admin/scoreboard.py:
            <ul>
                <li>(Line 5) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 10) change decorator to 'admins_or_task_deployers_only' for 'scoreboard_listing' func</li>
            </ul>
        </li>
        <br/>
        <li>
            admin/statistics.py:
            <ul>
                <li>(Line 5) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 12) change decorator to 'admins_or_task_deployers_only' for 'statistics' func</li>
            </ul>
        </li>
        <br/>
        <li>
            admin/submissions.py:
            <ul>
                <li>(Line 5) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 12) change decorator to 'admins_or_task_deployers_only' for 'submissions_listing' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/challenges.py:
            <ul>
                <li>(Line 24) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 34) import func 'is_task_deployer'</li>
                <li>(Line 68) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 121) change decorator to 'admins_or_task_deployers_only' for 'post' func</li>
                <li>(Line 134) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 156) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 183) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 215) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 263) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 279) change decorator to 'admins_or_task_deployers_only' for 'patch' func</li>
                <li>(Line 288) change decorator to 'admins_or_task_deployers_only' for 'delete' func</li>
                <li>(Line 313) add assert 'is_task_deployer' in 'post' func</li>
                <li>(Line 424) add assert 'is_task_deployer' in 'post' func</li>
                <li>(Line 442) add assert 'is_task_deployer' in 'post' func</li>
                <li>(Line 511) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 530) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 551) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 568) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 585) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 601) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/files.py:
            <ul>
                <li>(Line 7) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 15) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 28) change decorator to 'admins_or_task_deployers_only' for 'post' func</li>
                <li>(Line 52) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 64) change decorator to 'admins_or_task_deployers_only' for 'delete' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/flags.py:
            <ul>
                <li>(Line 7) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 15) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 26) change decorator to 'admins_or_task_deployers_only' for 'post' func</li>
                <li>(Line 48) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 68) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 82) change decorator to 'admins_or_task_deployers_only' for 'delete' func</li>
                <li>(Line 93) change decorator to 'admins_or_task_deployers_only' for 'patch' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/hints.py:
            <ul>
                <li>(Line 6) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 7) import func 'is_task_deployer'</li>
                <li>(Line 15) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 26) change decorator to 'admins_or_task_deployers_only' for 'post' func</li>
                <li>(Line 60) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 72) change decorator to 'admins_or_task_deployers_only' for 'patch' func</li>
                <li>(Line 91) change decorator to 'admins_or_task_deployers_only' for 'delete' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/notifications.py:
            <ul>
                <li>(Line 6) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 24) change decorator to 'admins_or_task_deployers_only' for 'post' func</li>
                <li>(Line 63) change decorator to 'admins_or_task_deployers_only' for 'delete' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/submissions.py:
            <ul>
                <li>(Line 7) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 17) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 34) change decorator to 'admins_or_task_deployers_only' for 'post' func</li>
                <li>(Line 59) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 71) change decorator to 'admins_or_task_deployers_only' for 'delete' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/tags.py:
            <ul>
                <li>(Line 6) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 14) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 27) change decorator to 'admins_or_task_deployers_only' for 'post' func</li>
                <li>(Line 49) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 61) change decorator to 'admins_or_task_deployers_only' for 'patch' func</li>
                <li>(Line 79) change decorator to 'admins_or_task_deployers_only' for 'delete' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/tokens.py:
            <ul>
                <li>(Line 10) import func 'is_task_deployer'</li>
                <li>(Line 58) add assert 'is_task_deployer' in 'get' func</li>
                <li>(Line 76) add assert 'is_task_deployer' in 'delete' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/unlocks.py:
            <ul>
                <li>(Line 10) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 23) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/statistics/challenges.py:
            <ul>
                <li>(Line 7) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 14) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 32) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
                <li>(Line 83) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
            </ul>
        </li>
        <br/>
        <li>
            api/v1/statistics/submissions.py:
            <ul>
                <li>(Line 6) import decorator 'admins_or_task_deployers_only'</li>
                <li>(Line 11) change decorator to 'admins_or_task_deployers_only' for 'get' func</li>
            </ul>
        </li>
    </ul>
</details>

Остался лишь последний штрих - поправить html-шаблоны.

## 0013. Лучший язык программирования
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/html.png" width="500">
</p>

Для начала добавим ограничение на доступные страницы, редактируем файл `CTFd/CTFd/themes/admin/templates/base.html`.  
Прокручиваем до 48 строки и вставляем проверку типа пользователя ```{% i f type == 'admin' %}```:
```html
{% i f type == 'admin' %}
    <li class="nav-item dropdown">
        <a href="#" class="nav-link dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="true">Pages</a>
        <div class="dropdown-menu">
            <a class="dropdown-item" href="{{ url_for('admin.pages_listing') }}">All Pages</a>
            <a class="dropdown-item" href="{{ url_for('admin.pages_new') }}">New Page</a>
        </div>
    </li>
    <li class="nav-item"><a class="nav-link" href="{{ url_for('admin.users_listing') }}">Users</a></li>
    {% i f get_config('user_mode') == 'teams' %}
    <li class="nav-item"><a class="nav-link" href="{{ url_for('admin.teams_listing') }}">Teams</a></li>
    {% endif %}
{% endif %}

    <li class="nav-item"><a class="nav-link" href="{{ url_for('admin.scoreboard_listing') }}">Scoreboard</a></li>
    <li class="nav-item"><a class="nav-link" href="{{ url_for('admin.challenges_listing') }}">Challenges</a></li>
    <li class="nav-item dropdown">
        <a href="#" class="nav-link dropdown-toggle" data-toggle="dropdown" role="button"
        aria-haspopup="true" aria-expanded="true">Submissions</a>
        <div class="dropdown-menu">
            <a class="dropdown-item" href="{{ url_for('admin.submissions_listing') }}">All Submissions</a>
            <a class="dropdown-item" href="{{ url_for('admin.submissions_listing', submission_type='correct') }}">Correct Submissions</a>
            <a class="dropdown-item" href="{{ url_for('admin.submissions_listing', submission_type='incorrect') }}">Wrong Submissions</a>
        </div>
    </li>
{% i f type == 'admin' %}
    <li class="nav-item"><a class="nav-link" href="{{ url_for('admin.config') }}">Config</a></li>
{% endif %}
```
Тем самым мы отстранили деплоеров от доступа к пользовательским данным и панели управления бордой.

Даём доступ (частичный) к админской панели - `CTFd/CTFd/themes/core/templates/base.html`, строка 85.
Добавляем проверку ```or type == 'task_deployer'```:
```html
{% i f type == 'admin' or type == 'task_deployer' %}
    <li class="nav-item">
        <a class="nav-link" href="{{ url_for('admin.view') }}">
            <span class="d-block" data-toggle="tooltip" data-placement="bottom" title="Admin Panel">
                <i class="fas fa-wrench d-none d-md-block d-lg-none"></i>
            </span>
            <span class="d-sm-block d-md-none d-lg-block">
                <i class="fas fa-wrench pr-1"></i>Admin Panel
            </span>
        </a>
    </li>
{% endif %}
```

Данных пользователей может создать только админ, поэтому не забываем добавить опцию __TaskDeployer__ в соответствующие формы.  
Изменения коснутся двух файлов - `CTFd/CTFd/themes/admin/templates/modals/users/create.html` и `CTFd/CTFd/themes/admin/templates/modals/users/edit.html`.
В обоих файлах откатываемся на 45 строку и добавляем следующее:
```html
<option value="task_deployer"{% i f user is defined and user.type == 'task_deployer' %} selected{% endif %}>
    Task Deployer
</option>
```

И наконец-то последняя правка - добавляем `badge` для пользователей типа __TaskDeployer__.  
Редактировать придётся тоже два файла - `CTFd/CTFd/themes/admin/templates/users/user.html` (62 строка), `CTFd/CTFd/themes/admin/templates/users/users.html` (114 строка):
```html
{% i f user.type == 'task_deployer' %}
    <span class="badge badge-primary">task deployer</span>
{% endif %}
```

Как обычно перезагружаем сервер и контейнер, после чего можно взглянуть на результат.
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/users.png" width="500">
    <br/>
    <i>Список пользователей</i>
</p>
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/new_user.png" width="500">
    <br/>
    <i>Добавление нового пользователя</i>
</p>

## 0014. На этом всё!
<p align="center">
    <img src="/img/2020-05-01/ctf-setup-part3/final.jpg" width="500">
</p>

Обсудить и задать вопросы можно в [чате](https://t.me/smartrhino_chat).  
Спасибо за внимание!
