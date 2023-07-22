using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using JwtWebApiTutorial.Models;
using JwtWebApiTutorial.Services.UserService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtWebApiTutorial.Controllers
{
  [ApiController]
  [Route("api/[controller]")]
  public class AuthController : ControllerBase
  {
    IConfiguration _configuration;
    IUserService _userService;

    public static User user = new User();

    public AuthController(IConfiguration configuration, IUserService userService)
    {
      _configuration = configuration;
      _userService = userService;
    }

    [HttpGet, Authorize]
    public ActionResult<object> GetMe()
    {
      // var userName = User?.Identity?.Name;
      // var userName2 = User?.FindFirstValue(ClaimTypes.Name);
      // var role = User?.FindFirstValue(ClaimTypes.Role);

      var userName = _userService.GetUsername();
      return Ok(new { userName });
    }

    [HttpPost("register")]
    public ActionResult<User> Register(UserDto request)
    {
      CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

      user.Username = request.Username;
      user.PasswordHash = passwordHash;
      user.PasswordSalt = passwordSalt;

      return Ok(user);
    }

    [HttpPost("login")]
    public ActionResult<string> Login(UserDto request)
    {
      if (user.Username != request.Username)
      {
        return BadRequest("User not found");
      }
      else if (!verifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
      {
        return BadRequest("Invalid password");
      }

      string token = CreateToken(user);
      return Ok(token);
    }

    private string CreateToken(User user)
    {
      List<Claim> claims = new()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

      var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

      var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

      var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(1), signingCredentials: creds);

      var jwt = new JwtSecurityTokenHandler().WriteToken(token);

      return jwt;
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
      using (var hmac = new HMACSHA512())
      {
        passwordSalt = hmac.Key;
        passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
      }
    }

    private bool verifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
    {
      using (var hmac = new HMACSHA512(passwordSalt))
      {
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        return computedHash.SequenceEqual(passwordHash);
      }
    }
  }
}