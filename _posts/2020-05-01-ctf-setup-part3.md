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