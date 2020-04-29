---
layout: post
title:  "Что нам стоит CTF устроить? Развёртывание серверов"
date:   2020-04-29 10:00:00 +0300
categories: smartrhino backstage
---

<p align="center">
    <img src="/img/2020-04-29/ctf-setup-part2/main.png" width="500">
    <br/>
    <i>Именно так выглядят разработчики CTFd в моих глазах</i>
</p>

Специально для паблика [SMARTRHINO](https://vk.com/smartrhino).

Продолжим наше путешествие по закулисью SMARTRHINO.  
Сегодня мы поговорим о развёртывании серверов, возникших проблемах и путях их решений.

## 0004. Docker, привет!
Напомню, разрабочтики CTFd заверяют нас, что самый простой способ развернуть CTFd - воспользоваться Docker.  
Действительно, так и есть, особенно если это касается так называемого Basic Deployment.  
Ну что же, начнём!

От нас требуется установить две вещи: Docker и Docker Compose, реально телодвижений несколько больше.
Для начала удалим старые версии Docker, если такие имеются. Некоторые VPS с установленной Ubuntu Server 18.04 уже включают в себя пакеты Docker'а, только версии у них старые и нам не подойдут :(
```bash
sudo apt remove docker docker-engine docker.io containerd runc
```

Обновляем списки пакетов и ставим необходимые для загрузки и установки Docker.
```bash
sudo apt update
sudo apt install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
```

Добавляем репозиторий docker в систему, а также ключи для него.
```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
```

Снова обновляем списки пакетов и ставим Docker CE.
```bash
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io
```

Теперь необходимо установить docker-compose, именно через него будем управлять контейнером CTFd.  
_P.S. На момент развёртывания серверов последней была версия 1.25.4, сейчас - 1.25.5._
```bash
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
```

Создадим группу `docker` и добавим нашего пользователя в неё. Это позволит запускать Docker без прав суперпользователя и сэкономит кучу времени и нервов.
```bash
sudo groupadd docker
sudo usermod -aG docker $USER
```

Даём права на исполнение и проверяем, что всё встало как надо.
```bash
sudo chmod +x /usr/local/bin/docker-compose
docker-compose --version
docker run hello-world
```

Получим примерно следующий вывод:
```
docker-compose version 1.25.4, build 8d51620a

Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
ca4f61b1923c: Pull complete
Digest: sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7
Status: Downloaded newer image for hello-world:latest

Hello from Docker!
This message shows that your installation appears to be working correctly.
...
```

На этом подготовка завершена, можно приступать к развёртыванию CTFd, но прежде надо перезагрузиться.

```bash
sudo reboot now
```

## 0005. CTFd Basic Deployment
Как видно из названия, данный вариант развёртывания не требует от пользователя сверхъестественных способностей и не доставляет ни капли боли.

Для установки нам потребуется всего три строчки на Bash:
```bash
git clone https://github.com/CTFd/CTFd.git
cd CTFd/
./prepare.sh
```

`prepare.sh` делает за нас всю грязную работу по установке зависимостей, ну хоть где-то :)

Итак, у нас всё готово для запуска борды, что мы и сделаем прямо сейчас.
```
docker-compose up --detach
```
Требуется немного подождать, пока docker скачает необходимые образы и сконфигурирует контейнер в соответствии с `docker-compose.yml`. На самом деле это займёт порядка 10 минут, и за это время вполне можно успеть перекусить!  
После этого борда станет доступна по http://localhost:8000  
Перейдя по ссылке, мы попадём в панель настройки.

<p align="center">
    <img src="/img/2020-04-29/ctf-setup-part2/setup-panel.png" width="500">
</p>

Заполняем поля, жмём _Next_, снова заполняем поля и так далее, ничего особенного и интересного.  
Нажимаем кнопку _Finish_ и попадаем на главную страницу борды. Ура, первый шаг сделан.

## 0006. Доводим до кондиции

Более детальную настройку можно произвести, зайдя в раздел __Config__, что мы и сделаем.  
Прямая ссылка: http://localhost:8000/admin/config

Нас будут интересовать разделы __Accounts__, __Settings__, __Email__.  

В разделе __Accounts__ необходимо указать обязательную верификацию почтовых ящиков, максимальное число участников в команде, а также запретить изменение имён. При случае будет проще искать.

<p align="center">
    <img src="/img/2020-04-29/ctf-setup-part2/accounts.png" width="500">
</p>

В разделе __Settings__ настраивается видимость тех или иных сведений о соревновании: таски, очки, пользователи, регистрация.  
Это уж на свой вкус определяйте, что и как Вам надо)

<p align="center">
    <img src="/img/2020-04-29/ctf-setup-part2/settings.png" width="500">
</p>
На скриншоте виден номер версии - 2.3.3, запомните его, чуть позже мы к нему вернёмся.  


Ну и последний раздел, в который заглянем - __Email__, этот парень доставил массу удовольствий, эмоции били через край 🤬.
Заполняем поля, как это было в прошлой статье и пытаемся зарегать пользователя.

<p align="center">
    <img src="/img/2020-04-27/ctf-setup-part1/mail.png" width="500">
</p>

В тот момент моей наивности можно было только позавидовать. Сколько бы ни ждал, но письмо на почту так и не приходило, странно как-то 🤔.  
Не долго думая, полез в логи, вижу следующее:
```
mail_tester registered (UNCONFIRMED) with <user>@<domain>.com
mail_tester initiated a confirmation email resend
mail_tester initiated a confirmation email resend
mail_tester initiated a confirmation email resend
...
```
В логе ошибок вообще пустота.. что за фигня?!  
Запускаю скрипт для проверки работы почты, письмо приходит, через Thunderbird тоже. Чудеса какие-то..  
Так продолжалось несколько дней, пробовали регистрировать тестовых пользователей снова и снова, картина всё та же.

Ночью решил снова запустить тестовый скрипт, и тут понеслась..

<p align="center">
    <img src="/img/2020-04-29/ctf-setup-part2/smtp_test.png" width="500">
</p>

СПАМ!? Чего?! А вы там не обурели!?  
Уши окружающих изрядно пострадали. Зато теперь стало ясно, где собака зарыта.  

Пришлось писать в поддержку Яндекса, объяснять что к чему.  
К слову, ответили только 10 дней назад. Вот это да, вот это отношение к пользователям.  
Точнее по существу проблемы вообще не ответили, а просто спросили, актуален ли вопрос. Да, ребят, вовремя, я даже успел забыть про вас.

В конечном итоге воспользовались корпоративной почтой и всё пошло-поехало.

<p align="center">
    <img src="/img/2020-04-29/ctf-setup-part2/received_mail.png" width="500">
</p>

## 0007. Так, а что с Advanced?
Политика разработчиков CTFd проста и гениальна до невозможности, ну Вы поняли)

<p align="center">
    <img src="/img/2020-04-29/ctf-setup-part2/just-do-it.jpg" width="500">
</p>

Сразу опишу проблемы, с которыми столкнулся:
- после внесения изменений, особенно в код, перезапустить контейнер порой бывает недостаточно, необходимо перезапустить целиком сервер. Так и не понял, с чем это связано;
- при настройке reverse proxy никак не мог получить доступ к сайту по https на порту для тестирования, грешил, что не работает перенаправление. Испробовал кучу вариантов конфигурации nginx, в итоге вернулся к первоначальному. Оказалось, надо чистить кеш браузера, иначе он тупит с переходами. Выяснилось совершенно внезапно, когда с телефона решил зайти 🤗

Первое, что необходимо сделать - сгенерировать секретный ключ, о чём нам любезно сообщают разработчики платформы.  
Выполняем данный код из папки CTFd.
```bash
python -c "import os; f=open('.ctfd_secret_key', 'a+'); f.write(os.urandom(64));"
```

А вот настройку reverse proxy они оставили в качестве упражнения..

Теперь переходим к `docker-compose.yml`, для начала займёмся разделом `ctfd`:
```yaml
environment:
    - WORKERS=4
    - REVERSE_PROXY=true
    - LOG_FOLDER=/var/log/CTFd
    - ACCESS_LOG=/var/log/CTFd/access.log
    - ERROR_LOG=/var/log/CTFd/error.log
volumes:
    - </path/to/logs>:/var/log/CTFd
    - </path/to/uploads>:/var/uploads
```
Задаём количество Worker'ов и указываем, куда монтировать папки с логами и загрузками на хосте.  
Логи и без того не особо информативные, пусть хотя бы лежат в удобном для нас месте.  
Также не забываем, что будем использовать reverse proxy, о чём сообщаем строкой `REVERSE_PROXY=true`.

Далее создадим раздел для reverse proxy:
```yaml
reverse_proxy:
    image: nginx:mainline-alpine
    restart: always
    hostname: NGINX_HOSTNAME=<domain.org>
    ports:
        - "80:80"
        - "443:443"
    volumes:
        - ./nginx-conf/nginx.conf:/etc/nginx/nginx.conf
        - ./nginx-logs:/var/log/nginx
        - /etc/letsencrypt:/etc/letsencrypt
        - /var/lib/letsencrypt:/var/lib/letsencrypt
    networks:
      default:
      internal:
    depends_on:
      - ctfd
```

Первое, на что надо обратить внимание - поле `hostname`, его обязательно указываем, иначе не поедет.  
Снова монтируем папку с логами на хост, не забываем и про сертификаты, привет, Let’s Encrypt.  
Конфиг nginx также примонтируем, но прежде в раздел `http` файла `nginx.conf` добавим следующее:

```apacheconf
upstream ctfd_app {
    server ctfd:8000 fail_timeout=0;
}
        
server {
    listen 8000 default_server;
    return 444;
}
        
server {
    listen 80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen                  443 ssl;
    server_name             <domain.org>;
    ssl_certificate         /etc/letsencrypt/live/<domain.org>/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/<domain.org>/privkey.pem;
    ssl_ciphers             HIGH:!aNULL:!MD5;
    ssl_protocols           TLSv1 TLSv1.1 TLSv1.2;
    
    location / {
        proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto https;
        proxy_set_header        Host $http_host;
        proxy_redirect          off;
        proxy_buffering         off;
        proxy_pass              http://ctfd_app;
    }
}
```

Как я уже говорил, сертифкат можно заказать у Let’s Encrypt, для этого нам понадобится `certbot`.
Добавим репозиторий и установим его:
```bash
sudo apt update
sudo add-apt-repository universe
sudo add-apt-repository ppa:certbot/certbot
sudo apt update
sudo apt install certbot
```

Обращаемся к `certbot` и следуем его указаниям:
```bash
sudo certbot certonly --standalone -d domain.org
```

В случае успеха по пути `/etc/letsencrypt/live/<domain.org>/` появятся файлы `fullchain.pem` и `privkey.pem`.

Перезагружаемся и запускаем борду с помощью `docker-compose`, советую запускать с флагом `--force-recreate`, чтобы уж наверняка.

Немного ждём, удостоверяемся, что появился доступ по HTTPS и радуемся жизни!

Нетерпеливый читатель, развернувший борду, мог заметить странный баг в панели настройки почты.  
Помните, я обращал внимание на номер версии CTFd? Во время подготовки к CTF была только версия 2.3.1, так вот баг до сих пор остался 😬.  

В следующий раз мы поговорим не только о нём, но и окунёмся с головой в кишки CTFd!
