
certs:
	openssl req -x509 -nodes -newkey rsa:4096 -keyout client.key -out client.crt -days 365 -subj '/CN=example.com'
	openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -subj '/CN=example.com'
	openssl req -x509 -nodes -newkey rsa:2048 -keyout ssl/private.key -out ssl/certificate.crt -days 365  -subj '/CN=example.com'
	

clean:
	rm -f client.key client.crt
	rm -f server.key server.crt

builddocker:
	nerdctl  build -t mysql-ssl .
rundocker:
	 nerdctl run -d -p 3306:3306 -e MYSQL_ROOT_PASSWORD=my-secret-pw --name mysql-ssl-container mysql-ssl

killmysql:
	 nerdctl rm $(nerdctl ps | cut -d " " -f1) -f


dbcert:
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ssl/private.key -out ssl/certificate.crt -days 365  -subj '/CN=example.com'


# change /etc/hosts file for local resolve