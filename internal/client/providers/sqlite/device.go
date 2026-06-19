package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/google/uuid"
)

const schema = `
CREATE TABLE IF NOT EXISTS local_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);`

// GetOrCreateDeviceID инициализирует базу данных SQLite по указанному пути,
// создает служебные таблицы и возвращает существующий или только что сгенерированный DeviceID.
func GetOrCreateDeviceID(dbPath string) (string, error) {
	if dbPath == "" {
		dbPath = filepath.Join(os.Getenv("HOME"), ".config", "gophkeeper", "gophkeeper.db")
	}

	// Создаем родительские директории с правами 0700 строго по спецификации безопасности
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create storage directory: %w", err)
	}

	// Открываем/создаем файл БД
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return "", fmt.Errorf("open sqlite database: %w", err)
	}
	defer db.Close()

	// Накатываем базовую схему для метаданных
	if _, err := db.Exec(schema); err != nil {
		return "", fmt.Errorf("initialize sqlite schema: %w", err)
	}

	// Пытаемся прочитать существующий DeviceID
	var deviceID string
	err = db.QueryRow("SELECT value FROM local_metadata WHERE key = 'device_id'").Scan(&deviceID)
	if err == nil {
		// Нашли! Возвращаем сохраненный ID
		return deviceID, nil
	}

	if err != sql.ErrNoRows {
		return "", fmt.Errorf("query device id: %w", err)
	}

	// Если ID не найден — генерируем новый честный UUID
	newUUID, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate hardware device uuid: %w", err)
	}
	deviceID = newUUID.String()

	// Записываем его в базу данных «навечно»
	_, err = db.Exec("INSERT INTO local_metadata (key, value) VALUES ('device_id', ?)", deviceID)
	if err != nil {
		return "", fmt.Errorf("save generated device id to sqlite: %w", err)
	}

	// Выставляем права на файл БД 0600 строго по спецификации
	if err := os.Chmod(dbPath, 0600); err != nil {
		return "", fmt.Errorf("set secure file permissions on sqlite db: %w", err)
	}

	return deviceID, nil
}
