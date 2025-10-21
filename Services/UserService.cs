using Microsoft.EntityFrameworkCore;
using AuthApi.Data;
using AuthApi.Models;
using System.Security.Cryptography;
using System.Text;

namespace AuthApi.Services
{
    public class UserService : IUserService
    {
        private readonly AppDbContext _context;
        private readonly ILogger<UserService> _logger;

        public UserService(AppDbContext context, ILogger<UserService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<User?> GetUserByEmailAsync(string email)
        {
            try
            {
                return await _context.Users
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.Email == email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user by email: {Email}", email);
                throw;
            }
        }

        public async Task<User?> GetUserByIdAsync(int id)
        {
            try
            {
                return await _context.Users
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.Id == id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user by id: {UserId}", id);
                throw;
            }
        }

        public async Task<User> CreateUserAsync(string email, string password)
        {
            try
            {
                var user = new User
                {
                    Email = email,
                    PasswordHash = HashPassword(password),
                    CreatedAt = DateTime.UtcNow
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();
                
                _logger.LogInformation("User created successfully: {Email}", email);
                return user;
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Error creating user: {Email}", email);
                throw new InvalidOperationException("User with this email already exists", ex);
            }
        }

        public async Task<bool> VerifyPasswordAsync(User user, string password)
        {
            var inputHash = HashPassword(password);
            return user.PasswordHash == inputHash;
        }

        public async Task UpdateUserAsync(User user)
        {
            try
            {
                _context.Users.Update(user);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user: {UserId}", user.Id);
                throw;
            }
        }

        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(password);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}