using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Emit;
using System.Security.Claims;
using AuthTest.Factories;
using AuthTest.FormModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthTest.Controllers;

[ApiController]
[Route("auth")]
public class AuthController(IAccessTokenFactory accessFactory) : Controller
{
    private readonly Random _random = new();

    [HttpGet("getValue")]
    [Authorize]
    public IActionResult GetRandomValue()
    {
        return Ok(_random.Next(20));
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromForm] RegisterForm form)
    {
        Guid guid = Guid.NewGuid();
        var token = accessFactory.GenerateAccessTokenForUser(guid.ToString());
        await System.IO.File.AppendAllTextAsync("amerika.txt", $"GUID: {guid}\n\rTOKEN: Bearer {token}\n\r\n\r");
        return Ok(new
        {
            Guid = guid,
            Token = token
        });
    }

    [HttpGet("by/{provider}")]
    public IActionResult ExternalToken(string provider, string returnUrl = "/")
    {
        var redirectUrl = Url.Action(nameof(AuthController.GetCode), new { Provider=provider, ReturnUrl = returnUrl });
        var properties = new AuthenticationProperties()
        {
            RedirectUri = redirectUrl,
            Items =
            {
                { "LoginProvider", provider }
            },
            AllowRefresh = true
        };
        return Challenge(properties, provider);
    }

    [HttpGet("vk")]
    public async Task<IActionResult> GetCode(string provider, string redirectUri = "/")
    {
        AuthenticateResult externalAuthResult = await HttpContext.AuthenticateAsync(provider);

        ClaimsPrincipal? principal = externalAuthResult.Principal;

        if (principal == null) return NoContent();

        foreach (Claim claim in principal.Claims)
        {
            Console.WriteLine(claim.Value + " " + claim.Type);
        }

        return RedirectToAction(nameof(GetRandomValue));
    }
}