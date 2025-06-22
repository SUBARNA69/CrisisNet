using CrisisNet.Models;
using Microsoft.EntityFrameworkCore;

namespace CrisisNet.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions options) : base(options)
        {
        }
       
        protected ApplicationDbContext()
        {
        }
        public DbSet<User> Users { get; set; }
    }
}
