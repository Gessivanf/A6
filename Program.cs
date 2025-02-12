using Exo.WebApi.Contexts;
using Exo.WebApi.Repositories;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<ExoContext, ExoContext>();
builder.Services.AddControllers();
// Forma de autenticação
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "JwtBearer";
    options.DefaultChallengeScheme = "JwtBearer";
})
// Paramento de validade do token
.AddJwtBearer("JwtBearer", options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // Valida quem está solicitando
        ValidateIssuer = true,
        // Valida quem está sabendo
        ValidateAudience = true,
        // Define se o tempo de expiração será validado
        ValidateLifetime = true,
        // Criptogarfia e validação da chave de autenticação
        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chave-autenticacao")),
        // Valida o tempo de expiração do token
        ClockSkew = TimeSpan.FromMinutes(30),
        // Nome dp issuer, da origem
        ValidIssuer = "exoapi.webapi",
        // Nome do audience, para o destino
        ValidAudience = "exoapi.webapi"

    };
});

builder.Services.AddTransient<ProjetoRepository, ProjetoRepository>();
builder.Services.AddTransient<UsuarioRepository, UsuarioRepository>();

var app = builder.Build();

app.UseRouting();
// Habilita autenticação
app.UseAuthentication();
// Habilita a autorização
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
