# A real syslog collector for the live forwarding check: rsyslog with TLS.
FROM alpine:3.20
RUN apk add --no-cache rsyslog rsyslog-tls
COPY rsyslog.conf /etc/rsyslog.conf
CMD ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf"]
