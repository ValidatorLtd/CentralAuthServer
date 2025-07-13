namespace CentralAuthServer.API.DTOs
{
    public class RevokeTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
    }
}
