using System.Security.Claims;

namespace Foundation.AuthenticationHelper;
public interface ITokenService
{
    string GenerateAccessToken(string userId, string role, string ipAddress, string userAgent);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token, out bool isExpired);
}
