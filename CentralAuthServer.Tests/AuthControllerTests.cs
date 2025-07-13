using CentralAuthServer.API.Controllers;
using CentralAuthServer.API.DTOs;
using CentralAuthServer.Application.Interfaces;
using CentralAuthServer.Core.Entities;
using CentralAuthServer.Core.Services;
using CentralAuthServer.Infrastructure;
using CentralAuthServer.Tests;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Moq;
using System.Threading.Tasks;
using Xunit;

public class AuthControllerTests
{
    private readonly Mock<UserManager<ApplicationUser>> _userManager;
    private readonly Mock<IEmailSender> _emailSender;
    private readonly Mock<AuthDbContext> _dbContext;
    private readonly Mock<IAuditLogger> _auditLogger;
    private readonly Mock<IJwtService> _jwtService;
    private readonly Mock<IConfiguration> _config;

    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        _userManager = IdentityMockHelper.CreateUserManagerMock<ApplicationUser>();
        _emailSender = new Mock<IEmailSender>();
        _dbContext = new Mock<AuthDbContext>(); // Use actual or in-memory if needed
        _auditLogger = new Mock<IAuditLogger>();
        _jwtService = new Mock<IJwtService>();
        _config = new Mock<IConfiguration>();

        _controller = new AuthController(
            _userManager.Object,
            _config.Object,
            _emailSender.Object,
            _dbContext.Object,
            _auditLogger.Object,
            _jwtService.Object
        );
    }

    [Fact]
    public async Task Login_ShouldReturnUnauthorized_WhenUserNotFound()
    {
        // Arrange
        _userManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
                    .ReturnsAsync((ApplicationUser)null);

        var dto = new LoginDto { Email = "unknown@test.com", Password = "123" };

        // Act
        var result = await _controller.Login(dto);

        // Assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }
}
