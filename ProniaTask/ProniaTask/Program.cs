using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ProniaTask.Abstractions.Services;
using ProniaTask.DAL;
using ProniaTask.Hubs;
using ProniaTask.Models;
using ProniaTask.Services;

namespace ProniaTask
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddControllersWithViews().AddNewtonsoftJson(options =>
        options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore
    );
            builder.Services.AddDbContext<AppDbContext>(opt =>
            {
                opt.UseSqlServer(builder.Configuration.GetConnectionString("MSSQL"));
            });
            builder.Services.AddScoped<LayoutService>();
            builder.Services.AddSession(opt =>
            {
                opt.IdleTimeout = TimeSpan.FromSeconds(100);
            });
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddIdentity<AppUser, IdentityRole>(opt =>
            {
                opt.Password.RequireDigit = true;
                opt.Password.RequireNonAlphanumeric = false;
                opt.Password.RequiredLength = 5;
                opt.Lockout.AllowedForNewUsers = true;
                opt.SignIn.RequireConfirmedEmail = true;
                opt.User.RequireUniqueEmail = true;
            }).AddDefaultTokenProviders().AddEntityFrameworkStores<AppDbContext>();
            builder.Services.AddScoped<IEmailService, EmailService>();
            builder.Services.AddSignalR();
            //builder.Services.ConfigureApplicationCookie(option =>
            //{
            //    option.LoginPath = "/Account/Register";
            //    option.LogoutPath = "/Account/Logout";
            //    option.AccessDeniedPath = "/Identity/Account/Login";
            //});
            var app = builder.Build();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllerRoute("areas", "{area:exists}/{controller=Dashboard}/{action=Index}/{id?}");
            app.MapHub<ChatHub>("/chatHub");
            app.MapControllerRoute("default", "{controller=Home}/{action=index}/{id?}");
            app.Run();
        }
    }
}