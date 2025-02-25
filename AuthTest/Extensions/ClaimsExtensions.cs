using System.Security.Claims;

namespace AuthTest.Extensions;

public static class ClaimsExtensions
{
    public static bool TryGetClaimValue<T>(this ClaimsPrincipal principal, string type, out T value)
    {
        var claimValue = principal.Claims.Where(x => x.Type == type).Select(x => x.Value).FirstOrDefault();
        if (claimValue == null)
        {
            value = default(T);
            return false;
        }

        try
        {
            value = claimValue.ChangeType<T>();
            return true;
        }
        catch
        {
            value = default(T);
            return false;
        }
    }
    
    public static T ChangeType<T>(this object source)
    {
        var type = typeof(T);
        if (type.IsEnum)
        {
            return source switch
            {
                string x => (T)Enum.Parse(type, x),
                int x => (T)Enum.ToObject(type, x),
                _ => throw new InvalidCastException()
            };
        }

        return (T)Convert.ChangeType(source, typeof(T));
    }
}