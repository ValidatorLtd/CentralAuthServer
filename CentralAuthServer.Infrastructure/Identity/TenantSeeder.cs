using CentralAuthServer.Core.Entities;
using CentralAuthServer.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

public static class TenantSeeder
{
    public static async Task SeedTenantsAsync(IServiceProvider serviceProvider)
    {
        var context = serviceProvider.GetRequiredService<AuthDbContext>();

        var tenants = new List<Tenant>
       {
           new Tenant
           {
               Id = Guid.Parse("11111111-1111-1111-1111-111111111111"),
               Name = "Trainer A",
               Code = "trainer-a"
           },
           new Tenant
           {
               Id = Guid.Parse("22222222-2222-2222-2222-222222222222"),
               Name = "Company B",
               Code = "company-b"
           }
       };

        foreach (var tenant in tenants)
        {
            var exists = await context.Tenants.AnyAsync(t => t.Code == tenant.Code); 
            if (!exists)
            {
                await context.Tenants.AddAsync(tenant);
            }
        }

        await context.SaveChangesAsync();
    }
}
