using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Emit;
using System.Security.Claims;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Linq;
using AuthTest.Extensions;
using AuthTest.Factories;
using AuthTest.FormModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
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
            RedirectUri = redirectUrl
        };
        
        return Challenge(properties, provider);
    }

    [HttpGet("logined")]
    public async Task<IActionResult> GetCode(string provider, string redirectUri = "/")
    {
        AuthenticateResult externalAuthResult = await HttpContext.AuthenticateAsync(provider);

        ClaimsPrincipal? principal = externalAuthResult.Principal;

        if (principal == null) return NoContent();
        
        if (!principal.TryGetClaimValue<string>(ClaimTypes.NameIdentifier, out var oAuthId))
            return BadRequest("External authentication error. Unknown userid");

        foreach (Claim claim in principal.Claims)
        {
            Console.WriteLine(claim.Value + " " + claim.Type);
        }
        
        var token = accessFactory.GenerateTokenForExternalUser(oAuthId, "haha lol useless parameter");
        return base.Content($"<h1>Bearer {token}</h1><button onclick='navigator.clipboard.writeText(\"{token}\")'>copy</button>", "text/html");
    }

    [HttpGet("xmltest")]
    public async Task<IActionResult> XmlTest(string requestXML)
    {
        var xml = HttpUtility.UrlDecode(requestXML);
        
        Console.WriteLine(xml);
        XDocument document = XDocument.Parse(xml);

        var info = document.Root.Element("Info");
        
        var clientLogin = info.Element("ClientLogin").Value;
        var clientPassword = info.Element("ClientPassword").Value;

        if (clientLogin != "max" || clientPassword != "123")
            return Unauthorized();


        XElement status = new XElement("UserId");
        XElement resultInfo = new XElement("Info");
        XElement request = new XElement("WebResponse");

        status.Value = "amerikanec";
        resultInfo.Add(status);
        request.Add(resultInfo);
        XDeclaration declaration = new XDeclaration("1.0", "utf-8", "yes");
        XDocument result = new XDocument(declaration, request);
        
        return Ok(HttpUtility.UrlEncode(result.ToString()));
    }

    [HttpGet("supertest")]
    public async Task<IActionResult> XmlTest()
    {
        var redirectUrl = Url.Action(nameof(AuthController.GetCode), new { Provider=OpenIdConnectDefaults.AuthenticationScheme });
        var properties = new AuthenticationProperties()
        {
            RedirectUri = redirectUrl
        };

        return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
    }
}