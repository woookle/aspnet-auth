# 🔐 Auth API на ASP.NET 9.0 & PostgreSQL

![ASP.NET](https://img.shields.io/badge/ASP.NET-9.0-purple?style=for-the-badge&logo=.net)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=for-the-badge&logo=postgresql)

Безопасное и масштабируемое REST API для аутентификации пользователей и управления профилями, построенное на **ASP.NET 9.0** и **PostgreSQL**. Возможности включают аутентификацию через куки, загрузку аватарок и комплексную обработку ошибок. 🚀

## ✨ Возможности

- 🔐 **Аутентификация через куки** - Безопасные HTTP-only куки
- 👤 **Регистрация и вход** - Полный цикл аутентификации
- 🖼️ **Управление аватарками** - Загрузка и удаление фотографий профиля
- 🍪 **Управление сессиями** - Постоянный вход с скользящим expiration
- 🛡️ **Безопасность прежде всего** - Хеширование паролей, CORS и валидация
- 📁 **Валидация файлов** - Проверка типа и размера аватарок
- 📊 **Логирование** - Комплексное логирование ошибок и запросов
- 🎯 **RESTful дизайн** - Чистые API endpoints

## 🏗️ Архитектура

```
Auth API ✅
├── Аутентификация 🔑
│   ├── Сессии через куки
│   ├── Хеширование паролей (SHA256)
│   └── Безопасные HTTP-only куки
├── База данных 🗄️
│   ├── PostgreSQL 15
│   ├── Entity Framework Core
│   └── Автоматические миграции
├── Файловое хранилище 📁
│   ├── Загрузка аватарок
│   ├── Валидация файлов
│   └── Автоматическая очистка
└── API endpoints 🌐
    ├── RESTful дизайн
    ├── Обработка ошибок
    └── JSON ответы
```

## 🚀 Быстрый старт

### Предварительные требования

- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) 📦
- [PostgreSQL 15](https://www.postgresql.org/download/) 🐘

### Установка

1. **Клонируйте репозиторий** 📥
   ```bash
   git clone https://github.com/woookle/aspnet-auth.git
   cd aspnet-auth
   ```

2. **Настройте базу данных** ⚙️
   
   Создайте базу данных в PostgreSQL и обновите строку подключения в `appsettings.json`:
   ```json
   {
     "ConnectionStrings": {
       "DefaultConnection": "Host=localhost;Port=5432;Database=authapi;Username=ваш_username;Password=ваш_пароль;"
     }
   }
   ```

3. **Примените миграции базы данных** 🗃️
   ```bash
   dotnet ef database update
   ```

4. **Запустите приложение** 🏃‍♂️
   ```bash
   dotnet run
   ```

API будет доступно по адресам `https://localhost:7000` и `http://localhost:5000` 🎉

## 📚 API Endpoints

### Endpoints аутентификации 🔑

| Метод | Endpoint | Описание | Требуется аутентификация |
|--------|----------|-------------|---------------|
| `POST` | `/api/auth/register` | Регистрация нового пользователя | ❌ |
| `POST` | `/api/auth/login` | Вход пользователя | ❌ |
| `POST` | `/api/auth/logout` | Выход пользователя | ✅ |
| `GET` | `/api/auth/me` | Получение текущего пользователя | ✅ |

### Управление аватарками 🖼️

| Метод | Endpoint | Описание | Требуется аутентификация |
|--------|----------|-------------|---------------|
| `POST` | `/api/auth/avatar` | Загрузка аватарки | ✅ |
| `DELETE` | `/api/auth/avatar` | Удаление аватарки | ✅ |

## 🎮 Примеры использования API

### Регистрация 👤
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Ответ:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "id": 1,
    "email": "user@example.com",
    "avatarUrl": null,
    "createdAt": "2024-01-15T10:30:00Z"
  }
}
```

### Вход 🔑
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

### Загрузка аватарки 🖼️
```http
POST /api/auth/avatar
Content-Type: multipart/form-data

file: [avatar.jpg]
```

### Получение текущего пользователя 👤
```http
GET /api/auth/me
```

## 🛠️ Разработка

### Структура проекта 📁
```
AuthApi/
├── Controllers/          # API контроллеры
│   ├── AuthController.cs
│   └── ErrorController.cs
├── Models/              # Модели данных
│   ├── User.cs
│   ├── LoginRequest.cs
│   └── ...
├── Services/            # Бизнес-логика
│   ├── IUserService.cs
│   └── UserService.cs
├── Data/               # Контекст базы данных
│   └── AppDbContext.cs
├── Migrations/         # Миграции базы данных
└── wwwroot/           # Статические файлы (аватарки)
    └── avatars/
```

### Запуск в режиме разработки 🔧
```bash
# Режим watch (автоперезагрузка при изменениях)
dotnet watch run

# С указанием окружения
ASPNETCORE_ENVIRONMENT=Development dotnet run
```

### Операции с базой данных 🗄️
```bash
# Создание новой миграции
dotnet ef migrations add AddNewFeature

# Обновление базы данных
dotnet ef database update

# Откат миграции
dotnet ef database update PreviousMigrationName
```

## ⚙️ Конфигурация

### Переменные окружения 🌍
```bash
ASPNETCORE_ENVIRONMENT=Development
ConnectionStrings__DefaultConnection=ваша_строка_подключения
```

### Настройки куки 🍪
- **Имя**: `auth.token`
- **HTTP Only**: ✅ Да
- **Secure**: ✅ Только в production
- **SameSite**: Strict
- **Время жизни**: 7 дней
- **Скользящее expiration**: ✅ Включено

### Настройки загрузки файлов 📁
- **Максимальный размер**: 5MB
- **Разрешенные расширения**: .jpg, .jpeg, .png, .gif, .webp
- **Путь хранения**: `wwwroot/avatars/`

## 🧪 Тестирование

### Ручное тестирование с curl 🔄
```bash
# Регистрация
curl -X POST https://localhost:7000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Вход (сохранение куки)
curl -X POST https://localhost:7000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  -c cookies.txt

# Получение текущего пользователя (использование куки)
curl -X GET https://localhost:7000/api/auth/me \
  -b cookies.txt
```

### Тестирование с Postman 🚀
1. Импортируйте коллекцию из `/docs/postman-collection.json`
2. Установите базовый URL вашего API
3. Включите хранение кук в настройках Postman

## 🔒 Функции безопасности

- **Хеширование паролей**: SHA256
- **HTTP-only куки**: Предотвращает XSS атаки
- **CORS защита**: Настроено для доменов фронтенда
- **Валидация входных данных**: Валидация моделей и проверка типов файлов
- **Защита от SQL инъекций**: Параметризация Entity Framework
- **Безопасность загрузки файлов**: Ограничения по типу и размеру

## 📊 Формат ответов

Все ответы API следуют формату:
```json
{
  "success": boolean,
  "message": "string",
  "data": object | null
}
```

## 🚨 Обработка ошибок

API предоставляет понятные сообщения об ошибках:

| HTTP Status | Сценарий |
|-------------|----------|
| `400 Bad Request` | Неверные входные данные, дубликат email |
| `401 Unauthorized` | Неверные учетные данные, отсутствует аутентификация |
| `404 Not Found` | Ресурс не найден |
| `500 Internal Server Error` | Проблемы на стороне сервера |

---

<br />

<div>
  <p align='center'>
    <img src='https://media1.tenor.com/m/oKZVauJ1LWEAAAAd/anime-fern.gif' />
  </p>
  <h2 align='center'>хорошего дня 😊</h2>
</div>