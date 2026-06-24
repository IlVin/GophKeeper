// Package commands предоставляет структуры ответов и полезную нагрузку
// для унифицированного форматирования вывода результатов работы CLI GophKeeper.
package commands

import (
	"log/slog"
)

// CreateResponse определяет структуру ответа при успешном запечатывании
// и сохранении нового секрета в хранилище.
type CreateResponse struct {
	Name string `json:"name"` // Уникальное имя созданной записи
	Type string `json:"type"` // Тип сохраненного секрета
}

// GetResponse определяет структуру ответа при успешном извлечении
// и дешифровании запечатанного секретного конверта.
type GetResponse struct {
	Name     string            `json:"name"`     // Человекочитаемое имя секрета
	Payload  string            `json:"payload"`  // Plaintext полезная нагрузка (пароль, токен, данные)
	Metadata map[string]string `json:"metadata"` // Расшифрованные пользовательские метаданные
}

// Destroy осуществляет превентивную очистку ссылок метаданных вGetResponse DTO.
// Текстовые строки в Go иммутабельные, но очистка карты ускоряет деструкцию объектов в куче.
func (g *GetResponse) Destroy() {
	if g == nil {
		return
	}
	for k := range g.Metadata {
		delete(g.Metadata, k)
	}
	g.Payload = ""
	slog.Debug("Confidential GetResponse DTO successfully cleared from memory")
}

// ListResponseItem определяет структуру одной строки таблицы метаданных
// для вывода общего списка секретов в сейфе.
type ListResponseItem struct {
	ID          string `json:"id"`           // Уникальный UUID идентификатор записи
	Name        string `json:"name"`         // Имя записи для локального поиска
	Type        string `json:"type"`         // Категория секрета (credentials, card, text, binary)
	LastUpdated string `json:"last_updated"` // Временная метка модификации в формате RFC3339
}

// SyncResponse определяет структуру результатов проведения сессии
// двусторонней репликации данных с облачным сервером GophKeeper.
type SyncResponse struct {
	Pulled int `json:"pulled"` // Количество записей, скачанных из облака (Pull фаза)
	Pushed int `json:"pushed"` // Количество оффлайн-изменений, закачанных на сервер (Push фаза)
}

// RegisterResponse определяет структуру ответа успешного завершения
// протокола беспарольной регистрации устройства и выдачи mTLS-паспорта.
type RegisterResponse struct {
	UserID    string `json:"user_id"`    // Фингерпринт ключа, привязанного к аккаунту
	ServerURL string `json:"server_url"` // Адрес gRPC сервера авторизации
	Status    string `json:"status"`     // Текущий статус контейнера (REGISTERED)
}
