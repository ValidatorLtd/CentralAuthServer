namespace CentralAuthServer.Tests;

using CentralAuthServer.Application.Services;
using CentralAuthServer.Core.Entities;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Moq;

public class JwtServiceTests
{
    [Fact]
    public async Task GenerateJwtAsync_ShouldReturnValidToken()
    {
        // Arrange
        //var config = new ConfigurationBuilder()
        //    .AddInMemoryCollection(new Dictionary<string, string>
        //    {
        //        { "Jwt:Key", "supersecretkey1234567890" },
        //        { "Jwt:Issuer", "TestIssuer" },
        //        { "Jwt:Audience", "TestAudience" }
        //    })
        //    .Build();

        //var userManagerMock = IdentityMockHelper.CreateUserManagerMock();
        //var user = new ApplicationUser { Id = "123", UserName = "testuser", Email = "test@test.com" };
        //userManagerMock.Setup(x => x.GetRolesAsync(user)).ReturnsAsync(new List<string> { "User" });

        //var service = new JwtService(config, userManagerMock.Object);

        //// Act
        //var result = await service.GenerateJwtAsync(user);

        //// Assert
        //result.Token.Should().NotBeNullOrEmpty();
        //result.JwtId.Should().NotBeNullOrEmpty();
    }
}
