using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using OpenIdDictMvcContext.Data;
using OpenIdDictMvcLib.Dto;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIdDictDbMigrator
{
    internal class InteractiveService : BackgroundService
    {

        private readonly IHostApplicationLifetime _lifetime;
        private readonly IServiceProvider _serviceProvider;
        public InteractiveService(
            IHostApplicationLifetime lifetime,
            IServiceProvider serviceProvider)
        {
            _lifetime = lifetime;
            _serviceProvider = serviceProvider;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var source = new TaskCompletionSource<bool>();
            using (_lifetime.ApplicationStarted.Register(static state => ((TaskCompletionSource<bool>)state!).SetResult(true), source))
            {
                await source.Task;
            }

            await using var scope = _serviceProvider.CreateAsyncScope();
            var Configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
            var connectionString = Configuration.GetConnectionString("DefaultConnection");
            if (string.IsNullOrEmpty(connectionString)) return;

            // create database
            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Creating a database if it doesn't exist: execution EnsureCreatedAsync().");
            Console.Write("Would you like to proceed (y/n):");
            Console.BackgroundColor = ConsoleColor.Black;
            ConsoleKeyInfo kinf = Console.ReadKey();
            if (kinf.KeyChar != 'y' && kinf.KeyChar != 'Y') { Console.WriteLine(); Console.WriteLine("OpenIdDict DbMigrator stops..."); return; } else Console.WriteLine();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync(stoppingToken);

            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"Creating predefined roles \"{OidcIdentityConsts.AdminRoleName}\" and \"{OidcIdentityConsts.ManagerRoleName}\".");
            Console.Write("Would you like to proceed (y/n):");
            Console.BackgroundColor = ConsoleColor.Black;
            kinf = Console.ReadKey();
            if (kinf.KeyChar != 'y' && kinf.KeyChar != 'Y') { Console.WriteLine(); Console.WriteLine("OpenIdDict DbMigrator stops..."); return; } else Console.WriteLine();
            await RegisterRolesAsync(scope.ServiceProvider, OidcIdentityConsts.AdminRoleName, stoppingToken);
            await RegisterRolesAsync(scope.ServiceProvider, OidcIdentityConsts.ManagerRoleName, stoppingToken);



            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"Creating predefined users \"{OidcIdentityConsts.AdminUserName}\" with an role \"{OidcIdentityConsts.AdminRoleName}\" and  \"{OidcIdentityConsts.ManagerUserName}\" with an role \"{OidcIdentityConsts.ManagerRoleName}\".");
            Console.WriteLine($"Both users have a password: \"{OidcIdentityConsts.Password}\"");
            Console.Write("Would you like to proceed (y/n):");
            Console.BackgroundColor = ConsoleColor.Black;
            kinf = Console.ReadKey();
            if (kinf.KeyChar != 'y' && kinf.KeyChar != 'Y') { Console.WriteLine(); Console.WriteLine("OpenIdDict DbMigrator stops..."); return; } else Console.WriteLine();
            await RegisterUsersAsync(scope.ServiceProvider, OidcIdentityConsts.AdminUserName, OidcIdentityConsts.Password, new string[] { OidcIdentityConsts.AdminRoleName }, null, null, stoppingToken);
            await RegisterUsersAsync(scope.ServiceProvider, OidcIdentityConsts.ManagerUserName, OidcIdentityConsts.Password, new string[] { OidcIdentityConsts.ManagerRoleName }, null, null, stoppingToken);

            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"Creating predefined scopes \"openid\", \"profile\", \"offline_access\"");
            Console.Write("Would you like to proceed (y/n):");
            Console.BackgroundColor = ConsoleColor.Black;
            kinf = Console.ReadKey();
            if (kinf.KeyChar != 'y' && kinf.KeyChar != 'Y') { Console.WriteLine(); Console.WriteLine("OpenIdDict DbMigrator stops..."); return; } else Console.WriteLine();
            OpenIddictScopeDescriptorJDto scp = new OpenIddictScopeDescriptorJDto()
            {
                Name = "openid",
                DisplayName = "openid: Mandatory Protocol Scope",
                DisplayNames = new List<DisplayNameDto> { new DisplayNameDto { Key = "ru-Ru", Value = "openid: Обязательная область протокола" } }
            };
            await RegisterScopes(scope.ServiceProvider, scp, stoppingToken);
            scp = new OpenIddictScopeDescriptorJDto()
            {
                Name = "profile",
                DisplayName = "profile: Mandatory Protocol Scope",
                DisplayNames = new List<DisplayNameDto> { new DisplayNameDto { Key = "ru-Ru", Value = "profile: Обязательная область протокола" } }
            };
            await RegisterScopes(scope.ServiceProvider, scp, stoppingToken);
            scp = new OpenIddictScopeDescriptorJDto()
            {
                Name = "offline_access",
                DisplayName = "offline_access: Mandatory Protocol Scope",
                DisplayNames = new List<DisplayNameDto> { new DisplayNameDto { Key = "ru-Ru", Value = "offline_access: Обязательная область протокола" } }
            };
            await RegisterScopes(scope.ServiceProvider, scp, stoppingToken);
            List<OpenIddictScopeDescriptorJDto> scopes = new();

            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"Creating user defined Scopes");
            Console.Write("Would you like to proceed (y/n):");
            Console.BackgroundColor = ConsoleColor.Black;
            kinf = Console.ReadKey();
            if (kinf.KeyChar != 'y' && kinf.KeyChar != 'Y') { Console.WriteLine(); Console.WriteLine("OpenIdDict DbMigrator stops..."); return; } else Console.WriteLine();

            Configuration.Bind("Scopes", scopes);
            foreach (var scps in scopes)
            {
                await RegisterScopes(scope.ServiceProvider, scps, stoppingToken);
            }

            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"Creating user defined Applications");
            Console.Write("Would you like to proceed (y/n):");
            Console.BackgroundColor = ConsoleColor.Black;
            kinf = Console.ReadKey();
            if (kinf.KeyChar != 'y' && kinf.KeyChar != 'Y') { Console.WriteLine(); Console.WriteLine("OpenIdDict DbMigrator stops..."); return; } else Console.WriteLine();
            List<OpenIddictApplicationDescriptorJDto> apps = new();
            Configuration.Bind("Applications", apps);
            foreach (var app in apps)
            {
                await RegisterApps(scope.ServiceProvider, app, stoppingToken);
            }

            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"Creating user defined Groups");
            Console.Write("Would you like to proceed (y/n):");
            Console.BackgroundColor = ConsoleColor.Black;
            kinf = Console.ReadKey();
            if (kinf.KeyChar != 'y' && kinf.KeyChar != 'Y') { Console.WriteLine(); Console.WriteLine("OpenIdDict DbMigrator stops..."); return; } else Console.WriteLine();
            List<OidcGroupJDto> groups = new();
            Configuration.Bind("Groups", groups);
            foreach (var grp in groups)
            {
                await RegisterGroups(scope.ServiceProvider, grp, stoppingToken);
            }

            Console.WriteLine();
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"Creating user defined Users");
            Console.Write("Would you like to proceed (y/n):");
            Console.BackgroundColor = ConsoleColor.Black;
            kinf = Console.ReadKey();
            if (kinf.KeyChar != 'y' && kinf.KeyChar != 'Y') { Console.WriteLine(); Console.WriteLine("OpenIdDict DbMigrator stops..."); return; } else Console.WriteLine();
            List<OidcUserJDto> users = new();
            Configuration.Bind("Users", users);
            foreach (var usr in users)
            {
                await RegisterUsersAsync(scope.ServiceProvider, usr.Email!, usr.Password!, usr.UserRoles, usr.UserScopes, usr.UserGroups, stoppingToken);
            }

            Console.WriteLine();
            Console.Write("OpenIdDict DbMigrator has completed its work. Please close the application window...");

            static async Task RegisterRolesAsync(IServiceProvider provider, string roleName, CancellationToken cancellationToken)
            {
                var roleManager = provider.GetRequiredService<RoleManager<OidcIdentityRole>>();
                if (!roleManager.Roles.Any(r => r.Name == roleName))
                {
                    OidcIdentityRole entityToAdd = new() { Name = roleName };
                    await roleManager.CreateAsync(entityToAdd);
                }
            }
            static async Task RegisterUsersAsync(IServiceProvider provider, string userEmail, string userPassword, string[]? roles, List<OidcScopeJDto>? scopes, string[]? UserGroups, CancellationToken cancellationToken)
            {
                var userManager = provider.GetRequiredService<UserManager<OidcIdentityUser>>();
                var userStore = provider.GetRequiredService<IUserStore<OidcIdentityUser>>();
                var emailStore = (IUserEmailStore<OidcIdentityUser>)userStore;
                var context = provider.GetRequiredService<ApplicationDbContext>();

                OidcIdentityUser? usr = await userManager.FindByNameAsync(userEmail);
                if (usr == null)
                {
                    usr = new();
                    await userStore.SetUserNameAsync(usr, userEmail, cancellationToken);
                    await emailStore.SetEmailAsync(usr, userEmail, cancellationToken);
                    var rslt = await userManager.CreateAsync(usr, userPassword);
                    if (rslt.Succeeded)
                    {
                        usr = await userManager.FindByNameAsync(userEmail);
                    }
                }
                if (usr != null)
                {
                    await emailStore.SetEmailConfirmedAsync(usr, true, cancellationToken);
                    await userManager.SetLockoutEnabledAsync(usr, false);
                    if (roles != null)
                    {
                        foreach (var role in roles)
                        {
                            await RegisterRolesAsync(provider, role, cancellationToken);
                            if (!(await userManager.IsInRoleAsync(usr, OidcIdentityConsts.AdminRoleName)))
                            {
                                var rslt = await userManager.AddToRoleAsync(usr, OidcIdentityConsts.AdminRoleName);
                            }
                        }
                    }

                    if (scopes != null)
                    {
                        foreach (var scp in scopes)
                        {
                            if (!(await context.OidcUserScopes.AnyAsync(s => s.OidcUserId == usr.Id && s.OidcAppName == scp.OidcAppName)))
                            {
                                OidcUserScope us = new()
                                {
                                    OidcUserId = usr.Id,
                                    OidcAppName = scp.OidcAppName,
                                    OidcScopes = scp.OidcScopes,
                                    OidcAudiences = scp.OidcAudiences
                                };
                                context.OidcUserScopes.Add(us);
                                try
                                {
                                    await context.SaveChangesAsync();
                                }
                                catch (Exception ex)
                                {
                                    Exception? wex = ex;
                                    if (wex != null)
                                    {
                                        StringBuilder sb = new();
                                        while (wex != null)
                                        {
                                            sb.Append(wex.Message);
                                            wex = wex.InnerException;
                                        }
                                        Console.WriteLine("Could not create new User Scope: " + sb.ToString());
                                    }
                                }

                            }

                        }
                    }

                    if(UserGroups != null)
                    {
                        foreach (var userGroup in UserGroups)
                        {
                            var ug = context.OidcGroups.Where(g => g.OidcGroupName == userGroup).FirstOrDefault();
                            if(ug == null)
                            {
                                Console.WriteLine("Could not assign Group "+ userGroup + " to User as no such group in the database.");
                                continue;
                            }
                            if(!(await context.OidcUserGroups.AnyAsync(i => i.OidcGroupId == ug.OidcGroupId && i.OidcUserId == usr.Id)))
                            {
                                OidcUserGroup oug = new()
                                {
                                    OidcUserId = usr.Id,
                                    OidcGroupId = ug.OidcGroupId
                                };
                                context.OidcUserGroups.Add(oug);
                                try
                                {
                                    await context.SaveChangesAsync();
                                }
                                catch (Exception ex)
                                {
                                    Exception? wex = ex;
                                    if (wex != null)
                                    {
                                        StringBuilder sb = new();
                                        while (wex != null)
                                        {
                                            sb.Append(wex.Message);
                                            wex = wex.InnerException;
                                        }
                                        Console.WriteLine("Could not assign Group to User: " + sb.ToString());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            static async Task RegisterScopes(IServiceProvider provider, OpenIddictScopeDescriptorJDto descriptorDto, CancellationToken cancellationToken)
            {
                var scopemanager = provider.GetRequiredService<IOpenIddictScopeManager>();
                if (await scopemanager.FindByNameAsync(descriptorDto.Name!, cancellationToken) is null)
                {
                    var descriptor = new OpenIddictScopeDescriptor
                    {
                        DisplayName = descriptorDto.DisplayName,
                        Name = descriptorDto.Name,
                        Description = descriptorDto.Description
                    };
                    if (descriptorDto.Resources != null)
                    {
                        foreach (var resource in descriptorDto.Resources)
                        {
                            descriptor.Resources.Add(resource);
                        }
                    }
                    if (descriptorDto.DisplayNames != null)
                    {
                        foreach (var dispNm in descriptorDto.DisplayNames)
                        {
                            if (string.IsNullOrEmpty(dispNm.Key) || string.IsNullOrEmpty(dispNm.Value))
                            {
                                continue;
                            }
                            else
                            {
                                try
                                {
                                    CultureInfo ci = new(dispNm.Key);
                                    descriptor.DisplayNames.Add(ci, dispNm.Value);
                                }
                                catch
                                {
                                    continue;
                                }
                            }
                        }
                    }
                    await scopemanager.CreateAsync(descriptor, cancellationToken);
                }
            }
            static async Task RegisterApps(IServiceProvider provider, OpenIddictApplicationDescriptorJDto descriptorDto, CancellationToken cancellationToken)
            {
                var applicationManager = provider.GetRequiredService<IOpenIddictApplicationManager>();
                OpenIddictApplicationDescriptor descriptor = new()
                {
                    ClientId = descriptorDto.ClientId,
                    ClientSecret = descriptorDto.ClientSecret,
                    DisplayName = descriptorDto.DisplayName,
                    ConsentType = descriptorDto.ConsentType,
                    Type = descriptorDto.ClientType
                };

                if (descriptorDto.Permissions != null)
                {
                    foreach (var permission in descriptorDto.Permissions)
                    {
                        descriptor.Permissions.Add(permission);
                    }
                }
                if (descriptorDto.PostLogoutRedirectUris != null)
                {
                    foreach (var postLogoutRedirectUri in descriptorDto.PostLogoutRedirectUris)
                    {
                        if (Uri.TryCreate(postLogoutRedirectUri, UriKind.RelativeOrAbsolute, out Uri? luri))
                        {
                            if (luri != null) descriptor.PostLogoutRedirectUris.Add(luri);
                        }
                        else
                        {
                            Console.WriteLine("For " + descriptorDto.ClientId + "Not all Post Logout Redirect Uri UIs are populated with correct data.");
                        }
                    }
                }
                if (descriptorDto.RedirectUris != null)
                {
                    foreach (var redirectUri in descriptorDto.RedirectUris)
                    {
                        if (Uri.TryCreate(redirectUri, UriKind.RelativeOrAbsolute, out Uri? luri))
                        {
                            if (luri != null) descriptor.RedirectUris.Add(luri);
                        }
                        else
                        {
                            Console.WriteLine("For " + descriptorDto.ClientId + "Not all Redirect Uri UIs are populated with correct data.");
                        }
                    }
                }
                if (descriptorDto.Requirements != null)
                {
                    foreach (var requirement in descriptorDto.Requirements)
                    {
                        descriptor.Requirements.Add(requirement);
                    }
                }
                if (descriptorDto.DisplayNames != null)
                {
                    foreach (var dispNm in descriptorDto.DisplayNames)
                    {
                        if (string.IsNullOrEmpty(dispNm.Key) || string.IsNullOrEmpty(dispNm.Value))
                        {
                            Console.WriteLine("For " + descriptorDto.ClientId + "Not all Display Names are populated with correct data.");
                        }
                        else
                        {
                            try
                            {
                                CultureInfo ci = new CultureInfo(dispNm.Key);
                                descriptor.DisplayNames.Add(ci, dispNm.Value);
                            }
                            catch
                            {
                                Console.WriteLine("For " + descriptorDto.ClientId + "Not all Display Names are populated with correct data.");
                            }
                        }
                    }
                }
                try
                {
                    var rslt = await applicationManager.CreateAsync(descriptor);
                }
                catch (Exception ex)
                {
                    Exception? wex = ex;
                    if (wex != null)
                    {
                        StringBuilder sb = new();
                        while (wex != null)
                        {
                            sb.Append(wex.Message);
                            wex = wex.InnerException;
                        }
                        Console.WriteLine("Could not create new Application: " + sb.ToString());
                    }
                }
            }
            static async Task RegisterGroups(IServiceProvider provider, OidcGroupJDto descriptorDto, CancellationToken cancellationToken)
            {
                var context = provider.GetRequiredService<ApplicationDbContext>();

                OidcGroup? grp = context.OidcGroups.Where(g => g.OidcGroupName == descriptorDto.OidcGroupName).FirstOrDefault();
                if (grp == null)
                {
                    grp = new OidcGroup() { OidcGroupName = descriptorDto.OidcGroupName, OidcGroupDisplayName = descriptorDto.OidcGroupDisplayName };
                    context.OidcGroups.Add(grp);
                    try
                    {
                        await context.SaveChangesAsync();
                    } catch (Exception ex)
                    {
                        grp = null;
                        Exception ? wex = ex;
                        if (wex != null)
                        {
                            StringBuilder sb = new();
                            while (wex != null)
                            {
                                sb.Append(wex.Message);
                                wex = wex.InnerException;
                            }
                            Console.WriteLine("Could not create new Group: " + sb.ToString());
                        }
                    }
                }
                if ((grp == null) || (descriptorDto.OidcScopes == null)) return;
                foreach(var scp in descriptorDto.OidcScopes)
                {
                    if (!(await context.OidcGroupScopes.AnyAsync(s => s.OidcGroupId == grp!.OidcGroupId && s.OidcAppName == scp.OidcAppName)))   
                    {
                        OidcGroupScope gs = new()
                        {
                            OidcGroupId = grp!.OidcGroupId,
                            OidcAppName = scp.OidcAppName,
                            OidcScopes = scp.OidcScopes,
                            OidcAudiences = scp.OidcAudiences
                        };
                        context.OidcGroupScopes.Add(gs);
                        try
                        {
                            await context.SaveChangesAsync();
                        }
                        catch (Exception ex)
                        {
                            grp = null;
                            Exception? wex = ex;
                            if (wex != null)
                            {
                                StringBuilder sb = new();
                                while (wex != null)
                                {
                                    sb.Append(wex.Message);
                                    wex = wex.InnerException;
                                }
                                Console.WriteLine("Could not create new Group Scope: " + sb.ToString());
                            }
                        }
                    }
                }
            }


        }
    }
}
