using BCrypt.Net;
using Electron_7.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Azure.Core;

namespace Electron_7.Controllers
{
	public class AuthController : Controller
	{

		
		private readonly IConfiguration _configuration;
		private readonly ApplicationDbContext _context;
		public AuthController(IConfiguration configuration,ApplicationDbContext context)
		{
			_context = context;
			_configuration = configuration;
		}

		
		[HttpPost("register")]
		public async Task<ActionResult<User>> Register(UserDto request)
		{
			var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
			if (existingUser != null)
			{
				return BadRequest("Username is taken.");
			}
			string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
			User newUser = new User
			{
				Username = request.Username,
				PasswordHash = passwordHash,
				IsAdmin = request.IsAdmin
			};

			_context.Users.Add(newUser); 
			await _context.SaveChangesAsync(); 

			return Ok(newUser);

		}
		[HttpPost("login")]
		public async Task<ActionResult<User>> Login(UserFli request)
		{
			User ?user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
			if (user == null)
			{
				return BadRequest("User not found.");
			}

			if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
			{
				return BadRequest("Wrong password.");
			}

			string token = CreateToken(user);
			var refreshtoken = GenerateRefreshToken();
			await SetRefreshToken(user, refreshtoken);


			return Ok(new
			{
				token,
				refreshToken = new
				{
					token = refreshtoken.Token,
					expires = refreshtoken.Expired
				}
			});
		}

		[HttpPost("refresh-token")]
		public async Task<ActionResult<string>> RefreshToken(string username,string refreshtoken) 
		{
			if(username==null)
			{ return BadRequest("username is null"); }
			User? user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
			;
			string decodedToken = Uri.UnescapeDataString(user.RefreshToken.Replace('+', ' '));
			if (!decodedToken.Equals(refreshtoken))
		    {
			return Unauthorized("Invalid Refresh Token");
			
			}
			else if(user.TokenExpires<DateTime.Now)
			{
				return Unauthorized("Token expired");
			}
			string token = CreateToken(user);
			var newRefreshToken = GenerateRefreshToken();
			SetRefreshToken(user, newRefreshToken).ConfigureAwait(false);
			return Ok(new
			{
				token,
				refreshToken = new
				{
					token = newRefreshToken.Token,
					expires = newRefreshToken.Expired
				}
			});
		}
		[HttpGet("get-name")]
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
				Created = DateTime.Now,
				Expired = DateTime.Now.AddMinutes(59),
			};
			return refreshToken;
		}
		private async Task SetRefreshToken(User user, RefreshToken newRefreshToken)
		{
			var cookieOptions = new CookieOptions
			{
				HttpOnly = true,
				Expires = newRefreshToken.Expired,
			};

			Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

			user.RefreshToken = newRefreshToken.Token;
			user.TokenCreated = newRefreshToken.Created;
			user.TokenExpires = newRefreshToken.Expired;
			user.LastLogIn=DateTime.Now;

			_context.Entry(user).State = EntityState.Modified;
			await _context.SaveChangesAsync();
		}
		private string CreateToken(User user)
		{
			List<Claim> claims = new List<Claim>
{
	new Claim(ClaimTypes.Name, user.Username),
	new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
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


