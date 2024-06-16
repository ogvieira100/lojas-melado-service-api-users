using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace UserServiceApi.Data
{
    public class ApplicationUserContext : IdentityDbContext
    {

        public ApplicationUserContext(DbContextOptions<ApplicationUserContext> options) : base(options) { }



    }
}
