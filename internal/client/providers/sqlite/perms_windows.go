//go:build windows

// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ValidateDirPermissions проверяет безопасность списка контроля доступа (DACL) для директории на платформе Windows.
func ValidateDirPermissions(path string, info os.FileInfo) error {
	if err := validateWindowsACL(path); err != nil {
		LogFileSystemIncident("insecure windows directory ACL detected", path, info)
		return fmt.Errorf("%w: path %q failed ACL validation: %w", ErrParentDirInsecurePermissions, path, err)
	}
	return nil
}

// ValidateFilePermissions проверяет безопасность списка контроля доступа (DACL) для файла базы данных на платформе Windows.
func ValidateFilePermissions(path string, info os.FileInfo) error {
	if err := validateWindowsACL(path); err != nil {
		LogFileSystemIncident("insecure windows file ACL detected", path, info)
		return fmt.Errorf("%w: file %q failed ACL validation: %w", ErrDatabaseFileInsecurePermissions, path, err)
	}
	return nil
}

// validateWindowsACL осуществляет низкоуровневую верификацию DACL через вызовы Windows API и парсинг ACE.
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
	token := windows.GetCurrentProcessToken()
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

	// Извлекаем количество записей ACE из системной структуры ACL (dacl.AceCount — это поле типа uint16)
	aceCount := dacl.AceCount

	// Начальный адрес первой записи ACE в памяти располагается сразу за структурой заголовка ACL
	currentAcePtr := uintptr(unsafe.Pointer(dacl)) + unsafe.Sizeof(*dacl)

	// Сканируем все записи управления доступом (ACE) внутри DACL через арифметику указателей
	for i := uint16(0); i < aceCount; i++ {
		// Читаем общий заголовок ACE для определения его типа и размера
		aceHeader := (*windows.ACE_HEADER)(unsafe.Pointer(currentAcePtr))

		// Нас интересуют только явно разрешающие записи доступа (ACCESS_ALLOWED_ACE_TYPE)
		if aceHeader.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			// Структура ACCESS_ALLOWED_ACE в WinAPI: Header (4B) + Mask (4B) + SidStart (4B)
			// Соответственно, указатель на SID находится со смещением в 8 байт от начала текущего ACE
			sidPtr := (*windows.SID)(unsafe.Pointer(currentAcePtr + 8))

			// Доступ разрешен строго владельцу процесса или системной службе SYSTEM.
			// Любые другие явные разрешения сторонним пользователям или группам (Everyone, Users) запрещены.
			if !sidPtr.Equals(processUser.User.Sid) && !sidPtr.Equals(systemSID) {
				return fmt.Errorf("insecure explicit access granted to non-root SID: %s", sidPtr.String())
			}
		}

		// Сдвигаем указатель в памяти на размер текущего ACE для перехода к следующему элементу
		currentAcePtr += uintptr(aceHeader.AceSize)
	}

	return nil
}
