using BCrypt.Net;
using Electron_7.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;

namespace Electron_7.Controllers
{
	public class AuthController : Controller
	{

		public static User user = new User();
		private readonly IConfiguration _configuration;
		public AuthController(IConfiguration configuration)
		{
			_configuration = configuration;
		}

		
		[HttpPost("register")]
		public ActionResult<User> Register(UserDto request)
		{
			string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
			user.Username = request.Username;
			user.PasswordHash = passwordHash;
			user.IsAdmin = request.IsAdmin;
			return Ok(user);
		}
		[HttpPost("login")]
		public ActionResult<User> Login(UserFli request)
		{
			if (user.Username != request.Username)
			{
				return BadRequest("User not found.");
			}

			if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
			{
				return BadRequest("Wrong password.");
			}

			string token = CreateToken(user);
			var refreshtoken = GenerateRefreshToken();
			SetRefreshToken(refreshtoken);

			return Ok(token);
		}

		[HttpPost("refresh-token")]
		public async Task<ActionResult<string>> RefreshToken() 
		{
			var refreshToken = Request.Cookies["refreshToken"];
			if (!user.RefreshToken.Equals(refreshToken))
		    {
			return Unauthorized("Invalid Refresh Token");
			
			}
			else if(user.TokenExpires<DateTime.Now)
			{
				return Unauthorized("Token expired");
			}
			string token = CreateToken(user);
			var newRefreshToken = GenerateRefreshToken();
			SetRefreshToken(newRefreshToken);
			return Ok(token);
		}
		[HttpGet("get-name"), Authorize(Roles = "Admin")]
		public ActionResult<string> GetName()
		{
			var userName = User?.Identity?.Name;
			var role = User?.FindFirstValue(ClaimTypes.Role);
			return Ok(new { userName,role });
		}

		private RefreshToken GenerateRefreshToken()
		{
			var refreshToken = new RefreshToken
			{
				Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
				Expired = DateTime.Now.AddDays(7)
			};
			return refreshToken;
		}
		private void SetRefreshToken(RefreshToken newrefreshToken)
		{
			var cookieOptions = new CookieOptions
			{
				HttpOnly = true,
				Expires = newrefreshToken.Expired,
			};
			Response.Cookies.Append("refreshToken", newrefreshToken.Token, cookieOptions);
			user.RefreshToken = newrefreshToken.Token;
			user.TokenCreated = newrefreshToken.Created;
			user.TokenExpires = newrefreshToken.Expired;
		}
		private string CreateToken(User user)
		{
			List<Claim> claims = new List<Claim>
{
	new Claim(ClaimTypes.Name, user.Username),
	user.IsAdmin
		? new Claim(ClaimTypes.Role, "Admin")
		: new Claim(ClaimTypes.Role, "User")
};
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
				_configuration.GetSection("AppSettings:Token").Value!));

			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

			var token = new JwtSecurityToken(
					claims: claims,
					expires: DateTime.Now.AddHours(1),
					signingCredentials: creds
				);

			var jwt = new JwtSecurityTokenHandler().WriteToken(token);

			return jwt;
		}
	}

}


