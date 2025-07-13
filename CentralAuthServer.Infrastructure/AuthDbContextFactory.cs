using CentralAuthServer.Core.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace CentralAuthServer.Infrastructure
{
    public class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
    {
        public AuthDbContext CreateDbContext(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Path.Combine(Directory.GetCurrentDirectory(), "../CentralAuthServer.API"))
                .AddJsonFile("appsettings.json")
                .Build();

            var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>();
            var connectionString = configuration.GetConnectionString("DefaultConnection");

            optionsBuilder.UseSqlServer(connectionString);

            var tenantProvider = new DesignTimeTenantProvider();


            return new AuthDbContext(optionsBuilder.Options,tenantProvider);
        }

        public class DesignTimeTenantProvider : ITenantProvider
        {
            public Guid? TenantId => null;
        }
    }
}
