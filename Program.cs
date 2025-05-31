using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureDataSharing.Data;
using SecureDataSharing.Models;
using SecureDataSharing.Services;
using SecureDataSharing.Helpers;

namespace SecureDataSharing
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            // Налаштування Kestrel для максимального розміру тіла запиту
            // Визначаємо ліміти тут:
            const long appDeclaredMaxFileSize = 2L * 1024 * 1024 * 1024; // 2 GB
            long serverRequestLimit = appDeclaredMaxFileSize + (100L * 1024 * 1024); // ~2.1 GB, невеликий буфер

            builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = serverRequestLimit;
            });

            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.Limits.MaxRequestBodySize = serverRequestLimit;
            });

            // Add services to the container.
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));
            builder.Services.AddDefaultIdentity<ApplicationUser>(options => options.SignIn.RequireConfirmedAccount = false) // Встановіть true, якщо потрібне підтвердження email
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
            builder.Services.AddTransient<IEmailSender<ApplicationUser>, EmailSender>();

            builder.Services.AddDatabaseDeveloperPageExceptionFilter();


            builder.Services.AddControllersWithViews();
            builder.Services.AddScoped<ICryptographyService, CryptographyService>();


            builder.Services.AddHttpContextAccessor();
            builder.Services.AddScoped<IAuditService, AuditService>();


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");
            app.MapRazorPages();

            app.Run();
        }
    }
}
