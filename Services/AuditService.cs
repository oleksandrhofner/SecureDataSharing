using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SecureDataSharing.Data;
using SecureDataSharing.Models;
using SecureDataSharing.Models.Enums;

namespace SecureDataSharing.Services
{
    public class AuditService : IAuditService
    {
        private readonly ApplicationDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<AuditService> _logger;

        public AuditService(
            ApplicationDbContext context,
            IHttpContextAccessor httpContextAccessor,
            ILogger<AuditService> logger)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        public async Task LogEventAsync(
            string? userId,
            string? userEmail,
            AuditEventType eventType,
            string details,
            string? entityType = null,
            string? entityId = null,
            string? ipAddress = null)
        {
            try
            {
                string? actualIpAddress = ipAddress ??
                    _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString();

                var auditLog = new AuditLog
                {
                    Timestamp = DateTime.UtcNow,
                    UserId = userId,
                    UserEmail = userEmail,
                    EventType = eventType,
                    EntityType = entityType,
                    EntityId = entityId,
                    Details = details,
                    IpAddress = actualIpAddress
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                // Логуємо помилку запису в аудит
                _logger.LogError(ex, "Помилка при записі події аудиту. EventType: {EventType}, User: {UserEmail}, Details: {Details}",
                    eventType, userEmail ?? "System", details);
            }
        }
    }
}
