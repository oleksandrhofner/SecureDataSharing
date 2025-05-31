namespace SecureDataSharing.Models
{
    public class DeleteDataConfirmationViewModel
    {
        public int Id { get; set; }
        public string? DataName { get; set; }
        public StorageEntryType DataType { get; set; }
        public string? OriginalFileName { get; set; }
        public string? OwnerEmail { get; set; } // Для відображення, хто власник
    }
}
