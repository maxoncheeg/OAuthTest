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
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

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
    .AddVkontakte("VK", opt =>
    {
        var googleAuth = builder.Configuration.GetSection("OAuth:VK");
        opt.ClientId = googleAuth["AppId"];
        opt.ClientSecret = googleAuth["AppSecret"];
        //opt.CallbackPath = new PathString("/auth/vk");
        opt.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        
        opt.Fields.Add("uid");
        // opt.Fields.Add("first_name");
        // opt.Fields.Add("last_name");
        //
        // // In this case email will return in OAuthTokenResponse, 
        // // but all scope values will be merged with user response
        // // so we can claim it as field
         opt.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "uid");
        // opt.ClaimActions.MapJsonKey(ClaimTypes.GivenName, "first_name");
        // opt.ClaimActions.MapJsonKey(ClaimTypes.Surname, "last_name");
        //
        opt.SaveTokens = true;
        // opt.Events = new OAuthEvents
        // {
        //     OnCreatingTicket = context =>
        //     {
        //         context.RunClaimActions(context.TokenResponse.Response.RootElement);
        //         return Task.CompletedTask;
        //     },
        // };
    })
    .AddCookie();

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