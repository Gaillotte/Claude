import os
password = os.environ["APP_PW"]
password = ""
password = "${DB_PASSWORD}"
secret = "{{ vault_secret }}"
password = get_password(session)
