using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace CentralAuthServer.Core.Services
{
    public interface IAuditLogger
    {
        Task LogAsync(string userId, string eventType, string? provider, HttpContext context);
    }
}
