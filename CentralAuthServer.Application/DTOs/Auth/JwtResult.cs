namespace CentralAuthServer.Application.DTOs.Auth
{
    public class JwtResult
    {
        public string Token { get; set; } = default!;
        public string JwtId { get; set; } = default!;
    }

}
