namespace CentralAuthServer.API.DTOs
{
    public class Verify2FADto
    {
        public string Email { get; set; }
        public string Code { get; set; }
    }
}
