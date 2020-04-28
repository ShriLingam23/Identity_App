using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Identity.IdentityPolicy
{
    public class AllowPrivatePolicy : IAuthorizationRequirement
    {
    }

    public class AllowPrivateHandler : AuthorizationHandler<AllowPrivatePolicy>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AllowPrivatePolicy requirement)
        {
            //We pass the allowed user in the controller level
            //AuthorizationResult authorized = await authService.AuthorizeAsync(User, allowedUsers, "PrivateAccess");
            //This allow us to get the lis of user dynamically 

            //AllowPrivateHandler class gets the ‘allowedUsers’ value from its AuthorizationHandlerContext class ‘Resource’ property.
            string[] allowedUsers = context.Resource as string[];

            if (allowedUsers.Any(user => user.Equals(context.User.Identity.Name, StringComparison.OrdinalIgnoreCase)))
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
            return Task.CompletedTask;
        }
    }
}
