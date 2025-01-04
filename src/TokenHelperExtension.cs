
using Microsoft.Extensions.DependencyInjection;
using System.Net.Sockets;

namespace Foundation.AuthenticationHelper;
public static class TokenHelperExtension
{

    public static IServiceCollection AddTokenService(this IServiceCollection services, string key)
    {
        if (services == null)
            throw new ArgumentNullException(nameof(services));

        services.AddSingleton<ITokenService>(c =>
        {
            var secret = Environment.GetEnvironmentVariable(key);
            if (string.IsNullOrWhiteSpace(secret))
                secret = Environment.GetEnvironmentVariable(key, EnvironmentVariableTarget.User);
            
            if (secret == null) 
                throw new ArgumentNullException(nameof(services));
            
            return new TokenService(secret);
        });

        return services;
    }
}
