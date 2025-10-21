using AuthApi.Models;

namespace AuthApi.Services
{
    public interface IUserService
    {
        Task<User?> GetUserByEmailAsync(string email);
        Task<User> CreateUserAsync(string email, string password);
        Task<bool> VerifyPasswordAsync(User user, string password);
        Task UpdateUserAsync(User user);
        Task<User?> GetUserByIdAsync(int id);
    }
}