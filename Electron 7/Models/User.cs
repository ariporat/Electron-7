namespace Electron_7.Models
{
	public class User
	{
		public int Id { get; set; }
		public string Username { get; set; } = string.Empty;
		public string PasswordHash { get; set; } = string.Empty;
		public bool IsAdmin { get; set; }

		public string? RefreshToken { get; set; }
		public DateTime? TokenCreated { get; set; }
		public DateTime? TokenExpires { get; set; }
		public DateTime? LastLogIn { get; set; }
	}
}
