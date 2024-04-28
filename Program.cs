using AngularApp2.Controllers;
using AngularApp2.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using System.Text;

namespace AngularApp2
{
    public class Program
    {
        private static String _MyDefaultPolicy = "_myAllowSpecificOrigins";

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            //Jwt configuration starts here => takes the configuration from appsetttings.json
            var jwtKey = builder.Configuration.GetSection("Jwt:Key").Get<string>();
            var jwtIssuer = builder.Configuration.GetSection("Jwt:Issuer").Get<string>();
            var jwtAudience = builder.Configuration.GetSection("Jwt:Audience").Get<string>();

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
             .AddJwtBearer(options =>
             {
                 options.TokenValidationParameters = new TokenValidationParameters
                 {
                     ValidateIssuer = true,
                     ValidateAudience = true,
                     ValidateLifetime = true,
                     ValidateIssuerSigningKey = true,
                     ValidIssuer = jwtIssuer,
                     ValidAudience = jwtAudience,
                     IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
                 };
             });
            //Jwt configuration ends here

            builder.Services.AddMvc(config =>
            {
                // forces all calls to the API to be authenticated
                var policy = new AuthorizationPolicyBuilder()
                                 .RequireAuthenticatedUser()
                                 .Build();
                config.Filters.Add(new AuthorizeFilter(policy));
            });
            // Add signalR for websockets after MVC
            builder.Services.AddSignalR();


            builder.Services.AddControllersWithViews();


            builder.Services.AddCors(options =>
            {
                options.AddPolicy(name: _MyDefaultPolicy,
                                  policy =>
                                  {
                                      policy.AllowAnyMethod();
                                      policy.AllowAnyHeader();
                                      policy.AllowAnyOrigin();
                                  });
            });

            var app = builder.Build();
            
            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
            }

            app.UseStaticFiles();
            app.UseRouting();

            app.UseCors(_MyDefaultPolicy);

            // adds the middleware 
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapHub<NotificationHub>("/api/notificationHub"); // SignalR and configure signalR hub
            app.MapControllerRoute(
                name: "default",
                pattern: "{controller}/{action=Index}/{id?}");

            app.MapFallbackToFile("index.html");

            // create a thread to send messages every second
            Task.Factory.StartNew(async () => { 
                while (true)
                {
                    await Task.Delay(1000);
                    // notify signal R hubs that there's a new message
                    // within a debounce function here, so that we don't notify watchers ALL the time
                    var hub = app.Services?.GetService<IHubContext<NotificationHub>>();

                    NotificationHub.SendMessage(hub, "Message at " + DateTime.Now.ToString());
                }
            
            }, TaskCreationOptions.LongRunning);

            app.Run();
        }
    }
}