FROM scratch

WORKDIR /app

# Копируем скомпилированный на платформе разработчика Linux-бинарник
COPY cmd/gophkeeper-server/gophkeeper-server /app/gophkeeper-server

# Настраиваем точку входа
ENTRYPOINT ["/app/gophkeeper-server", "start"]