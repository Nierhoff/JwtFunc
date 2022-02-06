using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Reflection;
using System.Resources;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

/**
 * using Microsoft.Extensions.Options;
 * https://jwt.io/
 */
namespace JwtFunc
{
    public class Function1
    {
        private readonly ILogger _logger;

        private static readonly Claim[] claims = new Claim[]
            {
                new Claim("role", "clerk")
            };

        private static readonly Claim issuer = new Claim("iss", "my-local.issuer.dk");
        private static readonly Claim audience = new Claim("aud", "my-local-audience");

        public Function1(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<Function1>();
        }

        [Function("Function1")]
        public HttpResponseData Run([HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequestData req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");

            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");

            string token = Generete();

            response.WriteString(token);

            return response;
        }

        public X509Certificate2 loadCert()
        {
            string ResourcePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            var certPem = File.ReadAllText(Path.Combine(ResourcePath, @"Resources\cert.pem.txt"));
            var keyPem = File.ReadAllText(Path.Combine(ResourcePath, @"Resources\key.pem.txt"));
            X509Certificate2 cert = X509Certificate2.CreateFromPem(
                keyPem: keyPem.ToCharArray(),
                certPem: certPem.ToCharArray()
                );
            return cert;
        }
        public SecurityKey loadSecurityKey()
        {
            X509Certificate2 cert = loadCert();
            return new RsaSecurityKey(cert.GetRSAPrivateKey());
        }

        public SigningCredentials loadSigningCredentials()
        {
            return new SigningCredentials(loadSecurityKey(), "RS256");
        }

        public string Generete()
        {
            X509Certificate2 certificate = loadCert();
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            JwtHeader header = new JwtHeader(signingCredentials: loadSigningCredentials());

            JwtPayload paykload = new JwtPayload(
                issuer: issuer.Value,
                audience: audience.Value,
                expires: DateTime.UtcNow.AddHours(24),
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                claims: claims
                );

            JwtSecurityToken JWToken = new JwtSecurityToken(header, paykload);

            string token = handler.WriteToken(JWToken);
            _logger.LogInformation(token);
            return token;
        }

        public ClaimsPrincipal Validate(string token)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = issuer.Value,
                ValidAudience = audience.Value,
                IssuerSigningKey = loadSecurityKey(),
                CryptoProviderFactory = new CryptoProviderFactory()
                {
                    CacheSignatureProviders = false
                }
            };

            ClaimsPrincipal claimsPrincipal = handler.ValidateToken(token, validationParameters, out var validatedSecurityToken);
            _logger.LogInformation(claimsPrincipal.ToString());
            return claimsPrincipal;
        }
    }
}
