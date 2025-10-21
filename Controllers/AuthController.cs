using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using AuthApi.Models;
using AuthApi.Services;

namespace AuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IWebHostEnvironment _environment;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IUserService userService, IWebHostEnvironment environment, ILogger<AuthController> logger)
        {
            _userService = userService;
            _environment = environment;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<ActionResult<ApiResponse>> Register([FromBody] RegisterRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Почта и пароль обязательны к заполнению!" 
                    });
                }

                var existingUser = await _userService.GetUserByEmailAsync(request.Email);
                if (existingUser != null)
                {
                    return BadRequest(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Почта уже привязана к другому аккаунту" 
                    });
                }

                var user = await _userService.CreateUserAsync(request.Email, request.Password);
                
                await SignInUser(user);

                var userResponse = new UserResponse
                {
                    Id = user.Id,
                    Email = user.Email,
                    AvatarUrl = GetAvatarUrl(user.AvatarPath),
                    CreatedAt = user.CreatedAt
                };

                return Ok(new ApiResponse 
                { 
                    Success = true, 
                    Message = "Вы успешно зарегистрировались!",
                    Data = userResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при регистрации: {Email}", request.Email);
                return StatusCode(500, new ApiResponse 
                { 
                    Success = false, 
                    Message = "Ошибка при регистрации!" 
                });
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<ApiResponse>> Login([FromBody] LoginRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Почта и пароль обязательны к заполнению!" 
                    });
                }

                var user = await _userService.GetUserByEmailAsync(request.Email);
                if (user == null || !await _userService.VerifyPasswordAsync(user, request.Password))
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Неправильный логин или пароль!" 
                    });
                }

                await SignInUser(user);

                var userResponse = new UserResponse
                {
                    Id = user.Id,
                    Email = user.Email,
                    AvatarUrl = GetAvatarUrl(user.AvatarPath),
                    CreatedAt = user.CreatedAt
                };

                return Ok(new ApiResponse 
                { 
                    Success = true, 
                    Message = "Вы успешно вошли в аккаунт!",
                    Data = userResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при входе: {Email}", request.Email);
                return StatusCode(500, new ApiResponse 
                { 
                    Success = false, 
                    Message = "Ошибка при входе в аккаунт!" 
                });
            }
        }

        [HttpPost("logout")]
        public async Task<ActionResult<ApiResponse>> Logout()
        {
            try
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return Ok(new ApiResponse 
                { 
                    Success = true, 
                    Message = "Вы успешно вышли из аккаунта!" 
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при выходе из аккаунта!");
                return StatusCode(500, new ApiResponse 
                { 
                    Success = false, 
                    Message = "Ошибка при выходе из аккаунта!" 
                });
            }
        }

        [HttpGet("me")]
        public async Task<ActionResult<ApiResponse>> GetCurrentUser()
        {
            try
            {
                if (!User.Identity?.IsAuthenticated ?? false)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Требуется аутентификация!" 
                    });
                }

                var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
                var emailClaim = User.FindFirst(ClaimTypes.Email);

                if (userIdClaim == null || emailClaim == null)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Недопустимый токен аутентификации!" 
                    });
                }

                if (!int.TryParse(userIdClaim.Value, out var userId))
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Неверный идентификатор пользователя!" 
                    });
                }

                var user = await _userService.GetUserByIdAsync(userId);
                if (user == null || user.Email != emailClaim.Value)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Пользователь не найден!" 
                    });
                }

                var userResponse = new UserResponse
                {
                    Id = user.Id,
                    Email = user.Email,
                    AvatarUrl = GetAvatarUrl(user.AvatarPath),
                    CreatedAt = user.CreatedAt
                };

                return Ok(new ApiResponse 
                { 
                    Success = true, 
                    Message = "Пользовательские данные были успешно получены!",
                    Data = userResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при извлечении текущего пользователя!");
                return StatusCode(500, new ApiResponse 
                { 
                    Success = false, 
                    Message = "При извлечении пользовательских данных произошла ошибка!" 
                });
            }
        }

        [HttpPost("avatar")]
        public async Task<ActionResult<ApiResponse>> UploadAvatar(IFormFile file)
        {
            try
            {
                if (!User.Identity?.IsAuthenticated ?? false)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Требуется аутентификация!" 
                    });
                }

                var emailClaim = User.FindFirst(ClaimTypes.Email);
                if (emailClaim == null)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Недопустимый токен аутентификации!" 
                    });
                }

                var user = await _userService.GetUserByEmailAsync(emailClaim.Value);
                if (user == null)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Пользователь не найден!" 
                    });
                }

                if (file == null || file.Length == 0)
                {
                    return BadRequest(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Файл не загружен!" 
                    });
                }

                // Validate file type
                var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
                var fileExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
                if (!allowedExtensions.Contains(fileExtension))
                {
                    return BadRequest(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Недопустимый тип файла. Разрешены только форматы JPG, JPEG, PNG, GIF и WEBP." 
                    });
                }

                // Validate file size (max 5MB)
                if (file.Length > 5 * 1024 * 1024)
                {
                    return BadRequest(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Слишком большой размер файла. Максимальный размер - 5 МБ." 
                    });
                }

                // Create avatars directory if it doesn't exist
                var avatarsFolder = GetAvatarsFolderPath();
                if (!Directory.Exists(avatarsFolder))
                {
                    Directory.CreateDirectory(avatarsFolder);
                }

                // Delete old avatar if exists
                if (!string.IsNullOrEmpty(user.AvatarPath))
                {
                    var oldAvatarPath = GetAvatarFilePath(user.AvatarPath);
                    if (System.IO.File.Exists(oldAvatarPath))
                    {
                        System.IO.File.Delete(oldAvatarPath);
                    }
                }

                // Generate unique filename
                var fileName = $"{user.Id}_{Guid.NewGuid()}{fileExtension}";
                var filePath = Path.Combine(avatarsFolder, fileName);
                var relativePath = $"/avatars/{fileName}";

                // Save file
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                // Update user
                user.AvatarPath = relativePath;
                await _userService.UpdateUserAsync(user);

                var userResponse = new UserResponse
                {
                    Id = user.Id,
                    Email = user.Email,
                    AvatarUrl = GetAvatarUrl(relativePath),
                    CreatedAt = user.CreatedAt
                };

                return Ok(new ApiResponse 
                { 
                    Success = true, 
                    Message = "Аватар успешно загружен!",
                    Data = userResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при загрузке аватара для пользователя!");
                return StatusCode(500, new ApiResponse 
                { 
                    Success = false, 
                    Message = "При загрузке аватара произошла ошибка!" 
                });
            }
        }

        [HttpDelete("avatar")]
        public async Task<ActionResult<ApiResponse>> DeleteAvatar()
        {
            try
            {
                if (!User.Identity?.IsAuthenticated ?? false)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Требуется аутентификация!" 
                    });
                }

                var emailClaim = User.FindFirst(ClaimTypes.Email);
                if (emailClaim == null)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Недопустимый токен аутентификации!" 
                    });
                }

                var user = await _userService.GetUserByEmailAsync(emailClaim.Value);
                if (user == null)
                {
                    return Unauthorized(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Пользователь не найден!" 
                    });
                }

                if (string.IsNullOrEmpty(user.AvatarPath))
                {
                    return BadRequest(new ApiResponse 
                    { 
                        Success = false, 
                        Message = "Нет аватара для удаления!" 
                    });
                }

                // Delete avatar file
                var avatarPath = GetAvatarFilePath(user.AvatarPath);
                if (System.IO.File.Exists(avatarPath))
                {
                    System.IO.File.Delete(avatarPath);
                }

                // Update user
                user.AvatarPath = null;
                await _userService.UpdateUserAsync(user);

                var userResponse = new UserResponse
                {
                    Id = user.Id,
                    Email = user.Email,
                    AvatarUrl = null,
                    CreatedAt = user.CreatedAt
                };

                return Ok(new ApiResponse 
                { 
                    Success = true, 
                    Message = "Аватар успешно удален!",
                    Data = userResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Ошибка при удалении аватара пользователя!");
                return StatusCode(500, new ApiResponse 
                { 
                    Success = false, 
                    Message = "При удалении аватара произошла ошибка!" 
                });
            }
        }

        private string GetAvatarsFolderPath()
        {
            var webRootPath = _environment.WebRootPath;
            if (string.IsNullOrEmpty(webRootPath))
            {
                webRootPath = Path.Combine(_environment.ContentRootPath, "wwwroot");
            }
            
            return Path.Combine(webRootPath, "avatars");
        }

        private string GetAvatarFilePath(string relativePath)
        {
            if (string.IsNullOrEmpty(relativePath))
                throw new ArgumentException("Relative path cannot be null or empty", nameof(relativePath));

            var webRootPath = _environment.WebRootPath;
            if (string.IsNullOrEmpty(webRootPath))
            {
                webRootPath = Path.Combine(_environment.ContentRootPath, "wwwroot");
            }
            
            return Path.Combine(webRootPath, relativePath.TrimStart('/'));
        }

        private async Task SignInUser(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email)
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(7)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);
        }

        private string? GetAvatarUrl(string? avatarPath)
        {
            if (string.IsNullOrEmpty(avatarPath))
                return null;

            return $"{Request.Scheme}://{Request.Host}{avatarPath}";
        }
    }
}