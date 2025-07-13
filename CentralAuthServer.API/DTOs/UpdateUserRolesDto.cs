namespace CentralAuthServer.API.DTOs
{
    public class UpdateUserRolesDto
    {
        public List<string> Roles { get; set; } = new();
    }
}
