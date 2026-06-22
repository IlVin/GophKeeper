package commands

// CLIResponse — корневой конверт ответа.
// Позволяет E2E тестам проверять статус операции в едином формате.
type CLIResponse struct {
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type CreateResponse struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type GetResponse struct {
	Name     string            `json:"name"`
	Payload  string            `json:"payload"`
	Metadata map[string]string `json:"metadata"`
}

type ListResponseItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	LastUpdated string `json:"last_updated"`
}

type SyncResponse struct {
	Pulled int `json:"pulled"`
	Pushed int `json:"pushed"`
}

type RegisterResponse struct {
	UserID    string `json:"user_id"`
	ServerURL string `json:"server_url"`
	Status    string `json:"status"`
}
