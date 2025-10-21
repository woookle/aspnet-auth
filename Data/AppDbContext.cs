using Microsoft.EntityFrameworkCore;
using AuthApi.Models;

namespace AuthApi.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("users");
                entity.HasIndex(u => u.Email).IsUnique();
                entity.Property(u => u.CreatedAt).HasDefaultValueSql("NOW()");
                
                entity.Property(u => u.Email)
                    .IsRequired()
                    .HasMaxLength(255);
                    
                entity.Property(u => u.PasswordHash)
                    .IsRequired()
                    .HasMaxLength(500);
                    
                entity.Property(u => u.AvatarPath)
                    .HasMaxLength(500);
            });
        }
    }
}