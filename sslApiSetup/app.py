from flask import Flask, request
import ssl
import mysql.connector
from mysql.connector import Error, connect
app = Flask(__name__)

@app.route('/')
def hello():
    user = request.args.get('user')
    return f"Hello, {user}!"

# nerdctl  build -t mysql-ssl .
# nerdctl run -d -p 3306:3306 -e MYSQL_ROOT_PASSWORD=my-secret-pw --name mysql-ssl-container mysql-ssl
@app.route('/db')
def connect_to_mysql():
    try:
        connection = connect(
            host='127.0.0.1',
            user='root',
            password='my-secret-pw',
            # database='testdb',
            ssl_ca='ssl/certificate.crt',
            ssl_cert='ssl/certificate.crt',
            ssl_key='ssl/private.key',
            ssl_verify_cert=True,
        )
      
        if connection.is_connected():

            db_info = connection.get_server_info()
            mycursor = connection.cursor()
            mycursor.execute("SHOW DATABASES")
            print("connection")
            for x in mycursor:
                print(x)
            
            return f'Connected to MySQL Server version: {db_info}'
    except Error as e:
        return f'Error connecting to MySQL: {e}'


if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2 )
    context.load_cert_chain('server.crt', 'server.key')
    app.run(ssl_context=context, debug=True)