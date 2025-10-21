using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Models
{
    [Table("users")]
    public class User
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [Column("id")]
        public int Id { get; set; }
        
        [Required]
        [EmailAddress]
        [Column("email")]
        public string Email { get; set; } = string.Empty;
        
        [Required]
        [Column("password_hash")]
        public string PasswordHash { get; set; } = string.Empty;
        
        [Column("avatar_path")]
        public string? AvatarPath { get; set; }
        
        [Column("created_at")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}