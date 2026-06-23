# Провайдер идентичности устройства (`internal/client/providers/device`)

Пакет `device` предоставляет низкоуровневые криптографические адаптеры для генерации аппаратных паспортов клиентских контейнеров GophKeeper. Он отвечает за создание пар ключей на эллиптических кривых и формирование подписанных запросов на выпуск сертификатов (CSR) для mTLS 1.3 авторизации.

## 📌 Основные функции пакета

1. **Генерация пар ключей ECDSA P-256**: Перевод MVP-криптографии с медленного и ресурсоемкого алгоритма RSA на современный, высокоскоростной стандарт NIST P-256 (ECDSA), оптимизированный для CLI-утилит.
2. **Контейнеризация PKCS8**: Маршалинг сгенерированных закрытых ключей в универсальный и кроссплатформенный стандарт ASN.1 DER (PKCS#8).
3. **mTLS SAN-Изоляция**: Внедрение жесткого ИБ-инварианта на уровне сетевой привязки — вшивание в поле Subject Alternative Name (SAN) уникального идентификатора контейнера (`urn:gophkeeper:file:deviceID`). Это предотвращает атаки подмены контекста устройства (Identity Spoofing) на стороне центра сертификации сервера.
4. **RAM Hygiene (Экстренная очистка)**: Пресечение утечек ключевого материала. Если конвейер сборки или подписания CSR падает, приватный компонент `D` структуры `ecdsa.PrivateKey` мгновенно выжигается нулями в памяти кучи рантайма.

---

## 🏗 Архитектурные связи компонента

Пакет вызывается на этапе двухшагового Zero-Knowledge протокола регистрации устройства из Composition Root команды `register.go`:

```mermaid
graph TD
    Reg["register.go (Команда регистрации)"] --> Dev["certificate.go (Провайдер идентичности)"]
    Dev --> ECDSA["ecdsa.GenerateKey (Кривая P-256)"]
    Dev --> PKCS["x509.MarshalPKCS8PrivateKey (PKCS8)"]
    Dev --> CSR["x509.CreateCertificateRequest (ECDSA-SHA256)"]

    style Dev fill:#d4edda,stroke:#28a745,stroke-width:2px
```
## Диаграмма конвейера генерации паспорта (GenerateContainerCSR)
Пошаговый процесс вычисления ключей, парсинга доменного URN и сборки подписанного бинарного CSR-блока с защитой от утечек данных в оперативную память.

```mermaid
sequenceDiagram
    autonumber
    participant Reg as "Команда (register.go)"
    participant Core as "Провайдер (certificate.go)"
    participant Crypto as Рантайм crypto-x509

    Reg->>Core: "GenerateContainerCSR(deviceID)"
    activate Core
    
    Core->>Crypto: "ecdsa.GenerateKey(elliptic.P256)"
    Crypto-->>Core: Возврат структуры *ecdsa.PrivateKey

    Core->>Crypto: "x509.MarshalPKCS8PrivateKey()"
    alt Сбой маршалинга
        Crypto-->>Core: Ошибка Marshal
        Core->>Core: "privKey.D.SetInt64(0) (RAM Hygiene)"
        Core-->>Reg: Аварийный выход (Ключ выжжен из памяти)
    end

    Core->>Crypto: "url.Parse(urn-string)"
    alt Передан невалидный deviceID (Сбой URN)
        Crypto-->>Core: Ошибка парсинга URI
        Core->>Core: "privKey.D.SetInt64(0) (RAM Hygiene)"
        Core-->>Reg: Аварийный выход (Предотвращение слепого глушения)
    end

    Core->>Crypto: "x509.CreateCertificateRequest() (ECDSA-SHA256)"
    Crypto-->>Core: Возврат подписанного CSR DER блока
    
    Core-->>Reg: "Возврат rawPrivateKey и csrBytes (Success)"
    deactivate Core
```
