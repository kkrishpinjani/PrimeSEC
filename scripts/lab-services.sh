#!/bin/sh
# Runs INSIDE the Wazuh lab container (fed in by scripts/stacks.ps1). The container's own startup command runs only the Wazuh agent,
# so after a restart its SSH server and syslog service are down: logins are then refused, or never logged in the format Wazuh's SSH
# rules read (rsyslog supplies it). "start" brings up what is missing; both modes print "yes" only if both are alive.
# A process counts only if it is not a zombie: finished sshd children linger as <defunct> because the container's PID 1 never reaps them.
alive() { ps -eo stat=,comm= | awk -v n="$1" '$1 !~ /^Z/ && $2 == n { f = 1 } END { exit !f }'; }
if [ "$1" = "start" ]; then
  command -v rsyslogd >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rsyslog >/dev/null 2>&1
  alive rsyslogd || { rm -f /run/rsyslogd.pid; rsyslogd >/dev/null 2>&1; }
  alive sshd || { mkdir -p /run/sshd && /usr/sbin/sshd; }
  sleep 1
fi
alive rsyslogd && alive sshd && echo yes
