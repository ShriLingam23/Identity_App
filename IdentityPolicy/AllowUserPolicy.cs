using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Identity.IdentityPolicy
{
    /*
     * AllowUserPolicy class implements the IAuthorizationRequirement interface, 
    and takes all the allowed users through the constructor parameter in string array type.
    
     */
    public class AllowUserPolicy : IAuthorizationRequirement
    {
        public string[] AllowUsers { get; set; }

        public AllowUserPolicy(params string[] users)
        {
            AllowUsers = users;
        }
    }

    /*
     * ‘HandleRequirementAsync’ method is called when the authorization system needs to check access to a Action method.
     * 
     * I check if the Current Logged in user does come in the allowed user names. In that case I called the Succeed method, 
     * else fail method is called.
     * 
     * I get the logged in user name by – context.User.Identity.Name
    */
    public class AllowUsersHandler : AuthorizationHandler<AllowUserPolicy>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AllowUserPolicy requirement)
        {
            if (requirement.AllowUsers.Any(user => user.Equals(context.User.Identity.Name, StringComparison.OrdinalIgnoreCase)))
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
