using CentralAuthServer.Application.DTOs.Auth;
using CentralAuthServer.Core.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CentralAuthServer.Application.Interfaces
{
    public interface IJwtService
    {
        Task<JwtResult> GenerateJwtAsync(ApplicationUser user);
    }
}
