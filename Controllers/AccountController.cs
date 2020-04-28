using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private UserManager<AppUser> userManager;
        private SignInManager<AppUser> signInManager;

        public AccountController(UserManager<AppUser> userMgr, SignInManager<AppUser> signinMgr)
        {
            this.userManager = userMgr;
            this.signInManager = signinMgr;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult AccessDenied() => View();

        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            //Here client/browser requesting Auth provider to Allow this app to get user details from provider

            //Generate a url with absolute path for action
            string redirectUrl = Url.Action("GoogleResponse", "Account");

            //configures the redirect URL (to the redirectUrl value) and user identifier for the Google Authentication
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", redirectUrl);

            //redirecting user to the Google Auth URL
            return new ChallengeResult("Google", properties);

            //then directly user authenticate himself in auth provider and when successful, 
            //oAuthpriver send a call to redirectedUrl with claims
        }

        [AllowAnonymous]
        public async Task<IActionResult> GoogleResponse()
        {
            //After authenticating user, Google will redirect them to the GoogleResponse Action.

            /*
             * ExternalLoginInfo class defines an ExternalPrincipal property that returns a ClaimsPrincipal
             * object, which contains the claims provided for the user by Google.
            */
            
            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
                return RedirectToAction(nameof(Login));

            //user to Application using these claims
            var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
            string[] userInfo = { info.Principal.FindFirst(ClaimTypes.Name).Value, info.Principal.FindFirst(ClaimTypes.Email).Value };

            //If the sign-in fails, 
            //then it is due to the fact that there is no user in the database that represents the Google user.
            if (result.Succeeded)
                return View(userInfo); //Name and Email of the user is returned to the View
            else
            {
                //If already existing user(registered using email) try login via External auth provider it fails
                //Here we neew to add ExternalLoginInfo to partcular user
                AppUser appUser = await userManager.FindByEmailAsync(info.Principal.FindFirst(ClaimTypes.Email).Value);
                if (appUser != null)
                {
                    IdentityResult identResult = await userManager.AddLoginAsync(appUser, info);
                    if (identResult.Succeeded)
                    {
                        await signInManager.SignInAsync(appUser, false);
                        return View(userInfo);
                    }
                    return AccessDenied();
                }
                else
                {
                    //Here we create creating the new user and associating the Google credentials with it.
                    AppUser user = new AppUser
                    {
                        Email = info.Principal.FindFirst(ClaimTypes.Email).Value,
                        UserName = info.Principal.FindFirst(ClaimTypes.Email).Value,
                        Salary = "200000"
                    };

                    IdentityResult identResult = await userManager.CreateAsync(user);
                    if (identResult.Succeeded)
                    {
                        identResult = await userManager.AddLoginAsync(user, info);
                        if (identResult.Succeeded)
                        {
                            await signInManager.SignInAsync(user, false);
                            return View(userInfo);
                        }
                    }
                    return AccessDenied();
                }
            }
        }

        [AllowAnonymous]
        public IActionResult Login(string returnUrl)
        {
            Login login = new Login();
            login.ReturnUrl = returnUrl;
            return View(login);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(Login login)
        {
            if (ModelState.IsValid)
            {
                AppUser appUser = await userManager.FindByEmailAsync(login.Email);
                if (appUser != null)
                {
                    await signInManager.SignOutAsync();
                    Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(appUser, login.Password, false, false);
                    if (result.Succeeded)
                        return Redirect(login.ReturnUrl ?? "/");
                }
                ModelState.AddModelError(nameof(login.Email), "Login Failed: Invalid Email or password");
            }
            return View(login);
        }

        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}