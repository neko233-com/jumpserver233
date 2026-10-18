FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends freeradius freeradius-utils openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY start.sh /usr/local/bin/jms-radius-qa
COPY site.conf /etc/freeradius/3.0/sites-available/jmsqa
RUN chmod 755 /usr/local/bin/jms-radius-qa && rm /etc/freeradius/3.0/sites-enabled/* && rm -f /etc/freeradius/3.0/mods-enabled/eap && ln -s ../sites-available/jmsqa /etc/freeradius/3.0/sites-enabled/jmsqa
ENTRYPOINT ["/usr/local/bin/jms-radius-qa"]
