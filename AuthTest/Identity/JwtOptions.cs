using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthTest.Identity;

public class JwtOptions
{
    public const string JwtSection = "JwtConfig";

    public string JwtIssuer { get; set; }

    public string JwtAudience { get; set; }

    public string JwtSecret { get; set; }

    public int LifeTime { get; set; }

    public SymmetricSecurityKey SymmetricSecurityKey =>
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSecret));
}