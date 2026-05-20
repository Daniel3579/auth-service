AUTH_SERVICE_PORT=:443                  #For TLS
DATABASE_URL=postgresql://<NAME>:<PASSWORD>@<ADDRESS:<PORT>/<DB_NAME>?sslmode=disable
SECRET_KEY=secret_key
AUTH_SERVICE_CERT_FILE=certs/server.crt #Path to server.crt
AUTH_SERVICE_KEY_FILE=certs/server.key  #Path to server.key