#!/bin/sh
# MODE=ssh — sshd с паролем E2E_SSH_PASSWORD для audit;
# MODE=silent — порт 22 принимает TCP, но молчит (нет баннера SSH): так
# выглядит SSH за фильтром/зависший sshd — сканер должен дать таймаут и «Частично».
set -eu
if [ "${MODE:-ssh}" = "silent" ]; then
  exec nc -lk -p 22 >/dev/null
fi
echo "audit:${E2E_SSH_PASSWORD:?нужен E2E_SSH_PASSWORD}" | chpasswd
ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=yes
