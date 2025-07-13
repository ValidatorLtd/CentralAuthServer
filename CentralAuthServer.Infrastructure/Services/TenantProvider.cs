using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using CentralAuthServer.Core.Services;

public class TenantProvider : ITenantProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public TenantProvider(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Guid? TenantId
    {
        get
        {
            var user = _httpContextAccessor.HttpContext?.User;
            var claim = user?.FindFirst("tenant_id");
            if (claim != null && Guid.TryParse(claim.Value, out var tenantId))
            {
                return tenantId;
            }
            return null;
        }
    }
}
