using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace csharp_webapp_auth_example;

public class ExampleIdentityDbContext : IdentityDbContext<IdentityUser, IdentityRole, string>
{
    public ExampleIdentityDbContext(DbContextOptions<ExampleIdentityDbContext> options)
        : base(options)
    {
    }
}
