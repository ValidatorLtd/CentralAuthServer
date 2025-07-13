using CentralAuthServer.Core.Services;
using CentralAuthServer.Infrastructure.Entities;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace CentralAuthServer.Infrastructure.Services
{
    public class AuditLogger : CentralAuthServer.Core.Services.IAuditLogger
    {
        private readonly AuthDbContext _context;

        public AuditLogger(AuthDbContext context)
        {
            _context = context;
        }

        public async Task LogAsync(string userId, string eventType, string? provider, HttpContext context)
        {
            var log = new AuditLog
            {
                UserId = userId,
                EventType = eventType,
                Timestamp = DateTime.UtcNow,
                IPAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                DeviceInfo = context.Request.Headers["User-Agent"].ToString(),
                LoginProvider = provider
            };

            await _context.AuditLogs.AddAsync(log);
            await _context.SaveChangesAsync();
        }
    }

}
