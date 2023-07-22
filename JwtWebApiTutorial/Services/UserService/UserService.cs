using System.Security.Claims;

namespace JwtWebApiTutorial.Services.UserService;

public class UserService : IUserService
{
  private readonly IHttpContextAccessor _httpContextAccessor;
  public UserService(IHttpContextAccessor httpContextAccessor)
  {
    _httpContextAccessor = httpContextAccessor;
  }

  public string GetUsername()
  {
    return _httpContextAccessor?.HttpContext?.User.FindFirstValue(ClaimTypes.Name) ?? string.Empty;
  }
}