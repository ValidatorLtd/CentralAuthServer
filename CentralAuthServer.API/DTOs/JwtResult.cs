namespace CentralAuthServer.API.DTOs
{
    public class JwtResult
    {
        public string Token { get; set; } = default!;
        public string JwtId { get; set; } = default!;
    }

}
