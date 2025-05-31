using System.Threading.Tasks;
using SecureDataSharing.Models.Enums;


namespace SecureDataSharing.Services
{
    public interface IAuditService
    {
        Task LogEventAsync(
            string? userId,
            string? userEmail,
            AuditEventType eventType,
            string details,
            string? entityType = null,
            string? entityId = null,
            string? ipAddress = null
        );
    }
}
