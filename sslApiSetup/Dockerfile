FROM mysql:latest

COPY ssl/ /ssl/

RUN chmod 400 /ssl/private.key && \
    chown mysql:mysql /ssl/private.key && \
    chmod 444 /ssl/certificate.crt && \
    chown mysql:mysql /ssl/certificate.crt

CMD ["mysqld", "--ssl-ca=/ssl/certificate.crt", "--ssl-cert=/ssl/certificate.crt", "--ssl-key=/ssl/private.key"]
