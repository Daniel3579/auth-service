AUTH_SERVICE_GRPC_PORT=:443             #For TLS
AUTH_SERVICE_REST_PORT=:8080
DATABASE_URL=postgresql://<NAME>:<PASSWORD>@<ADDRESS:<PORT>/<DB_NAME>?sslmode=disable
SECRET_KEY=secret_key
AUTH_SERVICE_CERT_FILE=certs/server.crt #Path to server.crt
AUTH_SERVICE_KEY_FILE=certs/server.key  #Path to server.ket
AUTH_SERVICE_CA_FILE=certs/ca.crt       #Path to ca.crt