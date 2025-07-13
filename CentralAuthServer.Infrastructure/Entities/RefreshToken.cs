using CentralAuthServer.Core.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CentralAuthServer.Infrastructure.Entities
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; } = default!;
        public string JwtId { get; set; } = default!;
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool Used { get; set; }
        public bool Revoked { get; set; }
        public string? ReplacedByToken { get; set; }

        public string DeviceInfo { get; set; } = string.Empty;
        public string IPAddress { get; set; } = string.Empty;

        public string UserId { get; set; } = default!;
        public ApplicationUser User { get; set; } = default!;
    }

}
