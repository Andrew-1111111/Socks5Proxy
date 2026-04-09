# SimpleSocks5Proxy

Высокопроизводительный SOCKS5-прокси на C#/.NET 9 с поддержкой TCP CONNECT и UDP ASSOCIATE, привязкой исходящего трафика к нужному интерфейсу, встроенным DNS-резолвингом и расширенным логированием.

## Важно: происхождение проекта

Этот репозиторий является глубоко переработанным форком оригинального проекта [RickyLin/SimpleSocks5Proxy](https://github.com/RickyLin/SimpleSocks5Proxy).

## Основные возможности

- Полная базовая поддержка SOCKS5 (RFC 1928) для `CONNECT` и `UDP ASSOCIATE`.
- Поддержка адресов `IPv4`, `IPv6` и доменных имен.
- Асинхронная архитектура с обработкой большого количества параллельных подключений.
- Ограничение числа одновременных соединений (`MaxConnections`), `0` = без ограничений.
- Привязка исходящих TCP/UDP-соединений к заданному IP-интерфейсу (`OutputIPAddress`).
- Разрешение доменов через настраиваемый DNS-сервер (`DnsServer`) с кэшем.
- Поддержка UDP relay с валидацией клиента, фильтрацией источников и idle-timeout.
- Friendly-имена для IP в логах (`IPAddressMappings`) для удобной диагностики.
- Защита от запуска второй копии приложения (single instance guard).
- Корректное завершение по `Ctrl+C` и освобождение ресурсов.
- Структурированное логирование через Serilog.

## Что поддерживается по протоколу

### Поддерживается

- SOCKS5 version `0x05`
- Метод аутентификации `No Authentication` (`0x00`)
- Команда `CONNECT` (TCP)
- Команда `UDP ASSOCIATE` (UDP relay)
- Адреса IPv4, IPv6, Domain

### Не поддерживается

- SOCKS4/SOCKS4a
- Username/Password и другие методы аутентификации SOCKS5

## Требования

- .NET 9 SDK/Runtime
- Windows/Linux/macOS
- Права администратора/root (приложение проверяет это на старте и пытается перезапуститься с повышением прав,повышенные права нужны для доступа к портам 1-1024)

## Быстрый запуск

### 1) Сборка

```bash
dotnet build Socks5Proxy.sln -c Release
```

### 2) Настройка `proxy.json`

Файл расположен в `Socks5Proxy/proxy.json`.

Пример:

```json
{
  "ListenIPAddress": "0.0.0.0",
  "ListenPort": 1080,
  "OutputIPAddress": "10.8.0.1",
  "DnsServer": "8.8.8.8",
  "MaxConnections": 1000,
  "IPAddressMappings": [
    {
      "IPAddress": "192.168.0.100",
      "FriendlyName": "PC 1"
    }
  ]
}
```

### 3) Запуск

Из корня репозитория:

```bash
dotnet run --project Socks5Proxy
```

Или запуск с явным конфигом:

```bash
dotnet run --project Socks5Proxy -- --config "D:\path\to\proxy.json"
```

## Параметры конфигурации

- `ListenIPAddress` - IP, на котором слушает SOCKS5-сервер (например, `127.0.0.1` или `0.0.0.0`)
- `ListenPort` - порт прослушивания (`1..65535`)
- `OutputIPAddress` - локальный IP/интерфейс для исходящих подключений
- `DnsServer` - IP DNS-сервера для резолвинга доменных имен
- `MaxConnections` - лимит одновременных подключений (`0` = без лимита)
- `IPAddressMappings` - массив отображений IP -> FriendlyName для логов

## Логирование

- Настраивается через `Socks5Proxy/appsettings.json` (Serilog).
- По умолчанию используется вывод в консоль.
- Friendly mapping добавляет суффикс вида ` (MyHost)` к IP/endpoint в сообщениях логов.

## Безопасность и эксплуатационные особенности

- Таймауты рукопожатия/запросов для защиты от "медленных" клиентов.
- Контроль источников в UDP relay для снижения риска open-proxy abuse.
- Ограничение количества соединений и корректное завершение активных задач при остановке.
- При отсутствии `proxy.json` приложение завершится с понятной ошибкой и подсказкой по `--config`.

## Структура проекта

- `Socks5Proxy/Program.cs` - точка входа, загрузка конфигурации, запуск сервера
- `Socks5Proxy/Server/ProxyServer.cs` - TCP listener и управление жизненным циклом соединений
- `Socks5Proxy/Server/Protocol/ConnectionHandler.cs` - SOCKS5 handshake, обработка команд, форвардинг
- `Socks5Proxy/Server/Protocol/UDP/UdpRelay.cs` - UDP ASSOCIATE relay
- `Socks5Proxy/Configuration/` - модели и валидация конфигурации
- `Socks5Proxy/Friendly/` - friendly name resolver для логов

## Лицензия и атрибуция

Проект распространяется как форк оригинального [RickyLin/SimpleSocks5Proxy](https://github.com/RickyLin/SimpleSocks5Proxy).
