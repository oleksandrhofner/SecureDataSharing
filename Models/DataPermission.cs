using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace SecureDataSharing.Models
{
    public class DataPermission
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public int StoredDataId { get; set; }
        [ForeignKey("StoredDataId")]
        public virtual StoredData? StoredData { get; set; }
        [Required]
        public string? OwnerUserId { get; set; }
        [ForeignKey("OwnerUserId")]
        public virtual ApplicationUser? OwnerUser { get; set; }
        [Required]
        public string? RecipientUserId { get; set; }
        [ForeignKey("RecipientUserId")]
        public virtual ApplicationUser? RecipientUser { get; set; }
        public DateTime GrantedTimestamp { get; set; } = DateTime.UtcNow;
        //DEK зашифрований публічним ключем отримувача
        [Required]
        public byte[]? EncryptedDekForRecipient { get; set; }
    }
}