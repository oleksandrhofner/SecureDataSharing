using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureDataSharing.Models;

namespace SecureDataSharing.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<AuditLog> AuditLogs { get; set; }
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
        public DbSet<StoredData> StoredDatas { get; set; }
        public DbSet<DataPermission> DataPermissions { get; set; }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Налаштування зв'язків та індексів
            // Якщо видаляється Користувач (Власник StoredData), видаляються його StoredData
            builder.Entity<StoredData>()
                .HasOne(sd => sd.OwnerUser)
                .WithMany()
                .HasForeignKey(sd => sd.OwnerUserId)
                .IsRequired()
                .OnDelete(DeleteBehavior.Cascade);

            // Якщо видаляється StoredData, видаляються пов'язані DataPermissions
            builder.Entity<DataPermission>()
                .HasOne(p => p.StoredData)
                .WithMany()
                .HasForeignKey(p => p.StoredDataId)
                .OnDelete(DeleteBehavior.Cascade);

            // Якщо видаляється Користувач (Отримувач в DataPermissions)
            builder.Entity<DataPermission>()
                .HasOne(p => p.RecipientUser)
                .WithMany()
                .HasForeignKey(p => p.RecipientUserId)
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            // Якщо видаляється Користувач (Власник Permission - що те саме, що власник StoredData)
            builder.Entity<DataPermission>()
                .HasOne(p => p.OwnerUser)
                .WithMany()
                .HasForeignKey(p => p.OwnerUserId)
                .IsRequired()
                .OnDelete(DeleteBehavior.Restrict);

            // Налаштування для AuditLog
            builder.Entity<AuditLog>(entity =>
            {
                entity.HasIndex(e => e.Timestamp);
                entity.HasIndex(e => e.EventType);
                entity.HasIndex(e => e.UserId);
                entity.HasOne(al => al.User)
                    .WithMany()
                    .HasForeignKey(al => al.UserId)
                    .OnDelete(DeleteBehavior.SetNull);
            });
        }
    }
}
