FROM postgres:17-alpine
RUN apk add --no-cache openssl
COPY start.sh /usr/local/bin/jms-qa-postgres
COPY init.sql /docker-entrypoint-initdb.d/qa.sql
RUN chmod 755 /usr/local/bin/jms-qa-postgres
ENTRYPOINT ["/usr/local/bin/jms-qa-postgres"]
