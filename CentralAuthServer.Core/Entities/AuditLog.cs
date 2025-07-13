using CentralAuthServer.Core.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CentralAuthServer.Core.Entities
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string UserId { get; set; } = default!;
        public ApplicationUser User { get; set; } = default!;
        public string EventType { get; set; } = default!; // e.g. Login, Logout
        public DateTime Timestamp { get; set; }
        public string IPAddress { get; set; } = string.Empty;
        public string DeviceInfo { get; set; } = string.Empty;
        public string? LoginProvider { get; set; } // Google, Facebook, Local
    }

}
