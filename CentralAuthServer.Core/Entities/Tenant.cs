using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CentralAuthServer.Core.Entities
{
    public class Tenant
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = null!;
        public string Code { get; set; } = null!; // e.g. trainerA, companyX
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public ICollection<ApplicationUser> Users { get; set; } = new List<ApplicationUser>();
    }

}
