using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using SecureDataSharing.Models.Enums;
namespace SecureDataSharing.Models
{
    public class AuditLog
    {
        [Key]
        public long Id { get; set; } // long для великих записів
        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        // ID користувача, який виконав дію
        public string? UserId { get; set; }
        [ForeignKey("UserId")]
        public virtual ApplicationUser? User { get; set; }
        // Email користувача для логів
        [StringLength(256)]
        public string? UserEmail { get; set; }
        [Required]
        public AuditEventType EventType { get; set; } // Тип події
        //тип сутності, якої стосується подія "StoredData", "User"
        [StringLength(100)]
        public string? EntityType { get; set; }
        //ID сутності
        [StringLength(100)]
        public string? EntityId { get; set; }
        [Required]
        public string Details { get; set; } // Опис події, містить JSON
        [StringLength(45)]
        public string? IpAddress { get; set; }
    }
}
