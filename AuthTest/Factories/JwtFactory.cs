using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthTest.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthTest.Factories;

public class JwtFactory(IOptions<JwtOptions> options) : IAccessTokenFactory
{
    private const string AuthenticationType = "Token";
    
    public string GenerateAccessTokenForUser(string userId)
    {
        List<Claim> claims = [new Claim(ClaimTypes.NameIdentifier, userId)];
        return GenerateToken(claims);
    }

    public string GenerateTokenForExternalUser(string oAuthId, string externalProvider)
    {
        List<Claim> claims = [new Claim(ClaimTypes.NameIdentifier, oAuthId)];
        var token = GenerateToken(claims);
        
        var jwt = new JwtSecurityToken(
            issuer: options.Value.JwtIssuer,
            audience: options.Value.JwtAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddDays(options.Value.LifeTime),
            signingCredentials: new SigningCredentials(options.Value.SymmetricSecurityKey, SecurityAlgorithms.HmacSha256));
            
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private string GenerateToken(IEnumerable<Claim> claims)
    {
        // создаем JWT-токен
        var jwt = new JwtSecurityToken(
            issuer: options.Value.JwtIssuer,
            audience: options.Value.JwtAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddDays(options.Value.LifeTime),
            signingCredentials: new SigningCredentials(options.Value.SymmetricSecurityKey, SecurityAlgorithms.HmacSha256));
            
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
}