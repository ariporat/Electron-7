using Microsoft.EntityFrameworkCore;

namespace Electron_7.Models
{
	public class ApplicationDbContext : DbContext
	{
		public DbSet<User> Users { get; set; }

		public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
			: base(options)
		{
		}
	}
}
