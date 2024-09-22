using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorApp2.Auth;

public class CustomAuth : AuthenticationStateProvider
{
    private readonly ILocalStorageService _service;

    public CustomAuth(ILocalStorageService service)
    {
        _service = service;
    }
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var (userid, username, role) = await ReadJwtToken();
        var claimsprincipal = await GetClaims(username, role, userid);
        NotifyAuthenticationStateChanged(
            Task.FromResult<AuthenticationState>(new AuthenticationState(claimsprincipal)));
        return await Task.FromResult(new AuthenticationState(claimsprincipal));
    }

    public async Task<ClaimsPrincipal>  GetClaims(string? name, string? role, string? id)
    {
        var check = name is null || role is null || id is null;
        if (check) return new ClaimsPrincipal();
        var claims = new ClaimsPrincipal(new ClaimsIdentity(
            new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, id),
                new Claim(ClaimTypes.Name, name),
                new Claim(ClaimTypes.Role, role)
            }, authenticationType:"Jwt"
            ));
        return claims;
    }

    public async Task<Tuple<string?, string?, string?>> ReadJwtToken()
    {
        var token = await _service.GetItemAsStringAsync("token");
        if (token is null) return new(null, null, null);
        var security = new JwtSecurityTokenHandler();
        var claims = security.ReadJwtToken(token);
        var userid = claims.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)!.Value;
        var username = claims.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)!.Value;
        var role = claims.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)!.Value;
        return new (userid, username, role);

    }
}