using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Moq;

public static class IdentityMockHelper
{
    public static Mock<UserManager<TUser>> CreateUserManagerMock<TUser>() where TUser : class
    {
        var store = new Mock<IUserStore<TUser>>();
        return new Mock<UserManager<TUser>>(
            store.Object, null, null, null, null, null, null, null, null);
    }

    public static Mock<SignInManager<TUser>> CreateSignInManagerMock<TUser>() where TUser : class
    {
        var userManager = CreateUserManagerMock<TUser>();
        var contextAccessor = new Mock<IHttpContextAccessor>();
        var claimsFactory = new Mock<IUserClaimsPrincipalFactory<TUser>>();

        return new Mock<SignInManager<TUser>>(
            userManager.Object,
            contextAccessor.Object,
            claimsFactory.Object,
            null, null, null, null);
    }
}
