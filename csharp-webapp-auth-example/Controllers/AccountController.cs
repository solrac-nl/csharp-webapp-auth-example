using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using csharp_webapp_auth_example.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace csharp_webapp_auth_example.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IConfiguration _configuration;

    public AccountController(UserManager<IdentityUser> userManager, IConfiguration configuration, SignInManager<IdentityUser> signInManager)
    {
        _userManager = userManager;
        _configuration = configuration;
        _signInManager = signInManager;
    }

    [HttpPost("Register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register(LoginViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return Ok();
            }
        }

        return BadRequest();
    }

    [HttpPost("Login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email,
                model.Password, model.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                return Ok();
            }
        }
        return BadRequest("Invalid login attempt.");
    }

    [HttpPost("LoginJwt")]
    [AllowAnonymous]
    public async Task<IActionResult> LoginJwt(LoginViewModel model)
    {
        if (!ModelState.IsValid) return NotFound();

        var user = await _userManager.FindByNameAsync(model.Email);
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var userRoles = await _userManager.GetRolesAsync(user);
            var token = GenerateJwtToken(user, userRoles);
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }
        return Unauthorized();
    }

    private JwtSecurityToken GenerateJwtToken(IdentityUser user, IList<string> userRoles)
    {
        var authClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        foreach (var userRole in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
        }

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes( _configuration["JWT:Secret"] ));

        var expires = DateTime.Now.AddMinutes(25); // 5 minutes are added in the library

        return new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: expires,
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );
    }
}
