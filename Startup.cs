using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Identity.IdentityPolicy;
using Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Identity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddTransient<IPasswordValidator<AppUser>, CustomPasswordPolicy>();
            services.AddTransient<IUserValidator<AppUser>, CustomUsernameEmailPolicy>();
            services.AddDbContext<AppIdentityDbContext>(options => options.UseSqlServer(Configuration["ConnectionStrings:DefaultConnection"]));

            //Claims policy implementation
            // User should be in ‘Manager’ Role. 
            // User should have the claim type as ‘Coding-Skill’ and its value should be ‘ASP.NET Core MVC’.
            services.AddAuthorization(opts => {
                opts.AddPolicy("AspManager", policy => {
                    policy.RequireRole("Manager");
                    policy.RequireClaim("Coding-Skill", "ASP.NET Core MVC");
                });
            });

            //registered the authorization handler class with the service provider as an implementation
            services.AddTransient<IAuthorizationHandler, AllowUsersHandler>();
            services.AddAuthorization(opts => {
                opts.AddPolicy("AllowAppa", policy => {
                    policy.AddRequirements(new AllowUserPolicy("appa"));
                });
            });


            //Different way of implementing policy using IAuthorizationService
            services.AddTransient<IAuthorizationHandler, AllowPrivateHandler>();
            services.AddAuthorization(opts => {
                opts.AddPolicy("PrivateAccess", policy =>
                {
                    policy.AddRequirements(new AllowPrivatePolicy());
                });
            });

                //User and Password policy configuration
                services.AddIdentity<AppUser, IdentityRole>(options =>
            {
                //Password Policy in Identity
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = true;
                options.Password.RequireDigit = true;
                //Username and Email Policy in Identity
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyz";
            })
            .AddEntityFrameworkStores<AppIdentityDbContext>()
            .AddDefaultTokenProviders();


            services.AddAuthentication().AddGoogle(opts =>
            {
                var googleAuth = Configuration.GetSection("Authentication:Google");

                opts.ClientId = googleAuth["ClientId"];
                opts.ClientSecret = googleAuth["ClientSecret"];
                opts.SignInScheme = IdentityConstants.ExternalScheme;
            });


            services.AddMvc();

            //we can configure the login redirction path, if user access a url without login
            //By default it is /Account/Login with the url we trying to access
            //services.ConfigureApplicationCookie(opts => opts.LoginPath = "/Authenticate/Login");
            // ‘/ Account/AccessDenied’ URL is the default URL set by Identity - when particular role has permission
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseStatusCodePages();
            app.UseDeveloperExceptionPage();
            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseRouting();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}");
            });
        }
    }
}
