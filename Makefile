## start: start the project
start:
	@echo "Starting the project ..."
	SERVER_ADDRESS=localhost SERVER_PORT=8181 DB_USER=root DB_PASSWD=ductrong DB_ADDR=localhost DB_PORT=3306 DB_NAME=banking go run .