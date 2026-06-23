//go:build windows

// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// ValidateDirPermissions проверяет безопасность списка контроля доступа (DACL) для директории на платформе Windows.
//
// Функция извлекает дескриптор безопасности папки и верифицирует, что права на чтение,
// запись и изменение предоставлены строго текущему пользователю-владельцу и учетной записи SYSTEM.
func ValidateDirPermissions(path string, info os.FileInfo) error {
	if err := validateWindowsACL(path); err != nil {
		LogFileSystemIncident("insecure windows directory ACL detected", path, info)
		return fmt.Errorf("%w: path %q failed ACL validation: %w", ErrParentDirInsecurePermissions, path, err)
	}
	return nil
}

// ValidateFilePermissions проверяет безопасность списка контроля доступа (DACL) для файла базы данных на платформе Windows.
//
// Гарантирует, что доступ к зашифрованному контейнеру СУБД изолирован от других учетных записей операционной системы.
func ValidateFilePermissions(path string, info os.FileInfo) error {
	if err := validateWindowsACL(path); err != nil {
		LogFileSystemIncident("insecure windows file ACL detected", path, info)
		return fmt.Errorf("%w: file %q failed ACL validation: %w", ErrDatabaseFileInsecurePermissions, path, err)
	}
	return nil
}

// validateWindowsACL осуществляет низкоуровневую верификацию DACL через вызовы Windows API.
func validateWindowsACL(path string) error {
	// Извлекаем дескриптор безопасности объекта файловой системы (Владелец + DACL)
	secDesc, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("failed to retrieve named security info: %w", err)
	}

	// Получаем SID владельца файла/директории
	ownerSID, _, err := secDesc.Owner()
	if err != nil {
		return fmt.Errorf("failed to extract file owner SID: %w", err)
	}

	// Получаем токен текущего запущенного процесса CLI-приложения
	token := windows.Token(0)
	processUser, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("failed to retrieve current process user token: %w", err)
	}

	// Критический ИБ-контроль: Проверяем, совпадает ли владелец файла с текущим пользователем процесса
	if !ownerSID.Equals(processUser.User.Sid) {
		return fmt.Errorf("file owner SID mismatch: current user does not own the crypto container")
	}

	// Извлекаем список DACL
	dacl, _, err := secDesc.DACL()
	if err != nil {
		return fmt.Errorf("failed to extract DACL from security descriptor: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("insecure object: NULL DACL detected (allows full access to everyone)")
	}

	// Конструируем SID встроенной системной учетной записи Windows (NT AUTHORITY\SYSTEM)
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("failed to construct LocalSystem well-known SID: %w", err)
	}

	// Сканируем все записи управления доступом (ACE) внутри DACL
	for i := 0; i < dacl.AceCount(); i++ {
		var ace *windows.ACE
		if err := dacl.GetAce(i, &ace); err != nil {
			return fmt.Errorf("failed to read ACE at index %d: %w", i, err)
		}

		// Извлекаем SID, которому принадлежит текущая запись доступа
		aceHeader := ace.Header()
		if aceHeader.Type == windows.ACCESS_ALLOWED_ACE_TYPE {
			// Приводим указатель к структуре ALLOWED_ACE для извлечения SID
			allowedAce := (*windows.AccessAllowedAce)(ace)
			aceSID := allowedAce.Sid()

			// Доступ разрешен строго владельцу процесса или системной службе SYSTEM.
			// Любые другие явные разрешения сторонним пользователям или группам (Everyone, Users) запрещены.
			if !aceSID.Equals(processUser.User.Sid) && !aceSID.Equals(systemSID) {
				return fmt.Errorf("insecure explicit access granted to non-root SID: %s", aceSID.String())
			}
		}
	}

	return nil
}
