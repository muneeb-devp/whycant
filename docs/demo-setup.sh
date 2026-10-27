#!/bin/sh
# Builds the small world the demo tape shows. Run as root in a throwaway
# container (make demo does this); it creates a user and files under /srv.
set -e
id deploy >/dev/null 2>&1 || useradd -M deploy
mkdir -p /srv/app/config /srv/shared
echo "password: hunter2" > /srv/app/config/db.yml
chown -R deploy:deploy /srv/app && chmod 750 /srv/app /srv/app/config && chmod 640 /srv/app/config/db.yml
printf '#!/bin/bash\r\necho deploying\r\n' > /srv/deploy.sh && chmod 755 /srv/deploy.sh
chmod 1777 /srv/shared && touch /srv/shared/report.csv && chown deploy /srv/shared/report.csv
# The recording runs in a container; keep the demo about the files themselves.
rm -f /.dockerenv
