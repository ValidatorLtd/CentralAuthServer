namespace CentralAuthServer.Core.Services
{
    public interface ITenantProvider
    {
        Guid? TenantId { get; }
    }
}
