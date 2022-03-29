using System.Text;
using System.Text.Json;
using csharp_webapp_auth_example;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Identity Entity Framework
builder.Services.AddDbContext<ExampleIdentityDbContext>(options =>
{
    options.UseInMemoryDatabase("IdentityDb");
});

// ASP NET Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddRoleManager<RoleManager<IdentityRole>>()
    .AddEntityFrameworkStores<ExampleIdentityDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = IdentityConstants.ApplicationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = false,
            ValidAudience = builder.Configuration["JWT:ValidAudience"],
            ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
        };

        options.Events = new JwtBearerEvents()
        {
            OnChallenge = context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";

                // Ensure we always have an error and error description.
                if (string.IsNullOrEmpty(context.Error))
                    context.Error = "invalid_token";
                if (string.IsNullOrEmpty(context.ErrorDescription))
                    context.ErrorDescription =
                        "This request requires a valid JWT access token to be provided";

                // Add some extra context for expired tokens.
                if (context.AuthenticateFailure != null && context.AuthenticateFailure.GetType() ==
                    typeof(SecurityTokenExpiredException))
                {
                    if (context.AuthenticateFailure is SecurityTokenExpiredException authenticationException)
                    {
                        context.Response.Headers.Add("x-token-expired",
                            authenticationException.Expires.ToString("o"));
                        context.ErrorDescription =
                            $"The token expired on {authenticationException.Expires.ToString("o")}";
                    }
                }

                return context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    error = context.Error,
                    error_description = context.ErrorDescription
                }));
            }
        };
    });

builder.Services.ConfigureApplicationCookie(options =>
{
    // Cookie settings
    options.Cookie.Name = "ExampleIdentity";
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.Cookie.SameSite = SameSiteMode.None;
    // If the LoginPath isn't set, ASP.NET Core defaults
    // the path to /Account/Login.
    options.LoginPath = "/Account/Login";
    // If the AccessDeniedPath isn't set, ASP.NET Core defaults
    // the path to /Account/AccessDenied.
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
    options.Events.OnRedirectToAccessDenied =
        options.Events.OnRedirectToLogin = context =>
        {
            if (context.Request.Path.ToString().StartsWith("/api/"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.FromResult<object>(null);
            }
            context.Response.Redirect(context.RedirectUri);
            return Task.FromResult<object>(null);
        };
});

builder.Services.AddAuthorization(options =>
{
    // options.AddPolicy("Policy", policy =>
    // {
    //     policy.AuthenticationSchemes.Add(IdentityConstants.ApplicationScheme);
    //     policy.RequireAuthenticatedUser();
    // });
    // options.AddPolicy("ApiPolicy", policy =>
    // {
    //     policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
    //     policy.RequireAuthenticatedUser();
    // });
    var defaultAuthorizationPolicyBuilder = new AuthorizationPolicyBuilder(IdentityConstants.ApplicationScheme, JwtBearerDefaults.AuthenticationScheme);
    defaultAuthorizationPolicyBuilder = defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();
    options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();
});

// Identity settings
builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings
    options.Password.RequireDigit = false;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    options.Password.RequiredUniqueChars = 3;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
