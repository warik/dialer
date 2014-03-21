Dialer
============

Приложение для взаимодействия Prom.ua, Tiu.ru, Deal.by, Satu.kz с Asterisk.


Установка
============
.. code-block:: python

  git clone https://github.com/alafin/dialer.git
  virtualenv .env
  source .env/bin/activate
  pip install -r requirements.txt


Настройка
============

Для настройки приложения нужно отредактировать файл config.py

**ASTERISK_ADDRESS** - asterisk адресс.

**ASTERISK_PORT** - asterisk порт.

**ASTERISK_LOGIN** - asterisk логин.

**ASTERISK_PASSWORD** - asterisk пароль.

**RESOURCE_OWNER_KEY** - параметр необходимо получить в CRM.

**RESOURCE_OWNER_SECRET** - параметр необходимо получить в CRM.

**ALLOWED_HOSTS** - список доступных хостов для доступа к приложению. 


Запуск
============
.. code-block:: python
  
  gunicorn dialer_app:app -b 0.0.0.0:8815
