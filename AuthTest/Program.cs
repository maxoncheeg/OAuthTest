using System.Security.Claims;
using AuthTest.Factories;
using AuthTest.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition(name: "Bearer", securityScheme: new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "Enter the Bearer Authorization string as following: `Bearer Generated-JWT-Token`",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Name = "Bearer",
                In = ParameterLocation.Header,
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            new List<string>()
        }
    });
});

builder.Services.AddControllers();


builder.Services.AddAuthentication()
    .AddVkontakte("vk", opt =>
    {
        var googleAuth = builder.Configuration.GetSection("OAuth:VK");
        opt.ClientId = googleAuth["AppId"];
        opt.ClientSecret = googleAuth["AppSecret"];
        opt.CallbackPath = new PathString("/auth/vk");
        opt.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;


        opt.CorrelationCookie = new CookieBuilder()
        {
            HttpOnly = true, Expiration = TimeSpan.FromSeconds(30), MaxAge = TimeSpan.FromSeconds(30), SecurePolicy = CookieSecurePolicy.Always
        };
        
        opt.Fields.Add("uid");

         opt.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "uid");
        opt.SaveTokens = true;
    })
    .AddCookie()    
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = builder.Configuration["OAuth:Keycloak:Authority"];
        options.ClientId = builder.Configuration["OAuth:Keycloak:ClientId"];
        options.ClientSecret = builder.Configuration["OAuth:Keycloak:ClientSecret"];
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = false;
        options.CallbackPath = new PathString("/signin-oidc");
        options.RequireHttpsMetadata = false;
        //options.Configuration = new OpenIdConnectConfiguration();
    });

var jwtOptions = builder.Configuration.GetSection(JwtOptions.JwtSection).Get<JwtOptions>();
builder.Services.Configure<JwtOptions>(options => 
    builder.Configuration.GetSection(JwtOptions.JwtSection).Bind(options));

builder.Services.AddScoped<IAccessTokenFactory, JwtFactory>();

//  Microsoft.AspNetCore.Authentication.JwtBearer nuget
builder.Services.AddAuthentication(opt =>
    {
        opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        opt.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })  // схема аутентификации - с помощью jwt-токенов
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.JwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.JwtAudience,
            ValidateLifetime = true,
            IssuerSigningKey = jwtOptions.SymmetricSecurityKey,
            ValidateIssuerSigningKey = true,
        };
    });   

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseCookiePolicy();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
app.Urls.Add("http://localhost:80");
app.Run();