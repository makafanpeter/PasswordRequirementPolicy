// See https://aka.ms/new-console-template for more information

using System.Text.RegularExpressions;

internal class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");

        var pRequirement = new PasswordRequirement(8, true, true, true, true);

        var strategies = new List<IPasswordRequirementStrategy>
        {
            new MinimumLengthRequirementStrategy(pRequirement.MinimumLength),
           
        };

        if (pRequirement.RequireUppercase)
        {
            strategies.Add(new UppercaseRequirementStrategy());
        }

        if (pRequirement.RequireDigit)
        {
            strategies.Add(new DigitRequirementStrategy());
           
        }

        if (pRequirement.RequireLowercase)
        {
            strategies.Add(new LowercaseRequirementStrategy());
        }

        if (pRequirement.RequireNonAlphanumeric)
        {
            strategies.Add(new NonAlphanumericRequirementStrategy());
        }


        var validationContext = new PasswordValidationContext(strategies);

        var testPassword = "SecureP@ssword123";
        var validationResults = validationContext.ValidatePassword(testPassword);

        Console.WriteLine(validationResults.ToString());

        validationResults = ValidatePasswordRequirement(pRequirement,testPassword);

        Console.WriteLine(validationResults.ToString());

        SecurityResult ValidatePasswordRequirement(PasswordRequirement passwordRequirement,string password)
        {
    
    
            var result = SecurityResult.Success;
            var errors = new List<string>();
            //1. checks the value
            if (string.IsNullOrEmpty(password))
            {
                result = SecurityResult.Failed("The password cannot be empty");
                return result;
            }

            //2. Validate minimum length
            if (password.Length < passwordRequirement.MinimumLength)
            {
                errors.Add($"The password must be over {passwordRequirement.MinimumLength} characters.");
            }

            //3. At least one lowercase character
            if (passwordRequirement.RequireLowercase)
            {
                Match lowercase = Regex.Match(password, @"^(?=.*[a-z])");
                if (!lowercase.Success)
                {
                    errors.Add("The password must contain at least one lowercase character.");
                }
            }

            //4.  At least one upper case character
            if (passwordRequirement.RequireUppercase)
            {
                Match uppercase = Regex.Match(password, @"^(?=.*[A-Z])");
                if (!uppercase.Success)
                {
                    errors.Add("The password must contain at least one uppercase character.");
                }
            }

            // 3. At least one digit
            if (passwordRequirement.RequireDigit)
            {
                Match digit = Regex.Match(password, @"^(?=.*\d)");
                if (!digit.Success)
                {
                    errors.Add("The password must contain at least one digit.");
                }
            }

            // 4. At least one special character
            if (passwordRequirement.RequireNonAlphanumeric)
            {
                Match specialCharacter = Regex.Match(password, @"^(?=.*[^\da-zA-Z])");
                if (!specialCharacter.Success)
                {
                    errors.Add("The password must contain at least one non-alphanumeric character.");
                }
            }


            if (errors.Any())
            {
                result = SecurityResult.Failed(errors.ToArray());
            }

            return result;
        }
    }
}

public record PasswordRequirement(
    int MinimumLength,
    bool RequireUppercase,
    bool RequireLowercase,
    bool RequireNonAlphanumeric,
    bool RequireDigit
);


public class SecurityResult
    {
        private static readonly SecurityResult _success = new SecurityResult { Succeeded = true };
        private readonly List<string> _errors = new List<string>();

        /// <summary>
        /// Flag indicating whether if the operation succeeded or not.
        /// </summary>
        /// <value>True if the operation succeeded, otherwise false.</value>
        public bool Succeeded { get; protected set; }

        /// <summary>
        /// An <see cref="IEnumerable{T}"/> of <see cref="SecurityResult"/>s containing an errors
        /// that occurred during the identity operation.
        /// </summary>
        /// <value>An <see cref="IEnumerable{T}"/> of <see cref="SecurityResult"/>s.</value>
        public IEnumerable<string> Errors => _errors;

        /// <summary>
        /// Returns an <see cref="SecurityResult"/> indicating a successful identity operation.
        /// </summary>
        /// <returns>An <see cref="SecurityResult"/> indicating a successful operation.</returns>
        public static SecurityResult Success => _success;

        /// <summary>
        /// Creates an <see cref="SecurityResult"/> indicating a failed identity operation, with a list of <paramref name="errors"/> if applicable.
        /// </summary>
        /// <param name="errors">An optional array of <see cref="SecurityResult"/>s which caused the operation to fail.</param>
        /// <returns>An <see cref="SecurityResult"/> indicating a failed identity operation, with a list of <paramref name="errors"/> if applicable.</returns>
        public static SecurityResult Failed(params string[] errors)
        {
            var result = new SecurityResult { Succeeded = false };
            if (errors != null)
            {
                result._errors.AddRange(errors);
            }
            return result;
        }


        public static SecurityResult Failed(string errors)
        {
            var result = new SecurityResult { Succeeded = false };
            if (errors != null)
            {
                result._errors.Add(errors);
            }
            return result;
        }

        /// <summary>
        /// Converts the value of the current <see cref="SecurityResult"/> object to its equivalent string representation.
        /// </summary>
        /// <returns>A string representation of the current <see cref="SecurityResult"/> object.</returns>
        /// <remarks>
        /// If the operation was successful the ToString() will return "Succeeded" otherwise it returned 
        /// "Failed : " followed by a comma delimited list of error codes from its <see cref="Errors"/> collection, if any.
        /// </remarks>
        public override string ToString()
        {
            return Succeeded ?  "Succeeded" : $"Failed : {string.Join(",", Errors.Select(x => x).ToList())}";
        }
    }
    
    
public interface IPasswordRequirementStrategy
{
    SecurityResult Validate(string password);
}

public class NonAlphanumericRequirementStrategy : IPasswordRequirementStrategy
{
    public SecurityResult Validate(string password)
    {
        Match specialCharacter = Regex.Match(password, @"^(?=.*[^\da-zA-Z])");
        if (!specialCharacter.Success)
        {
            return SecurityResult.Failed("The password must contain at least one non-alphanumeric character.");
        }
        
        return SecurityResult.Success;
    }
}
public class DigitRequirementStrategy : IPasswordRequirementStrategy
{
    public SecurityResult Validate(string password)
    {
        Match digit = Regex.Match(password, @"^(?=.*\d)");
        if (!digit.Success)
        {
            SecurityResult.Failed("The password must contain at least one digit.");
        }
        return SecurityResult.Success;
    }
}

public class LowercaseRequirementStrategy : IPasswordRequirementStrategy
{
    public SecurityResult Validate(string password)
    {
        Match lowercase = Regex.Match(password, @"^(?=.*[a-z])");
        return !lowercase.Success ? SecurityResult.Failed("The password must contain at least one lowercase character.") : SecurityResult.Success;
    }
}

public class UppercaseRequirementStrategy : IPasswordRequirementStrategy
{
    public SecurityResult Validate(string password)
    {
        Match uppercase = Regex.Match(password, @"^(?=.*[A-Z])");
        return !uppercase.Success ? SecurityResult.Failed("The password must contain at least one lowercase character.") : SecurityResult.Success;
    }
}
public class MinimumLengthRequirementStrategy(int minimumLength) : IPasswordRequirementStrategy
{
    public SecurityResult Validate(string password)
    {
        return password.Length >= minimumLength ? SecurityResult.Success : SecurityResult.Failed($"The password must be over {minimumLength} characters.");
    }
}



public class PasswordValidationContext
{
    private readonly IList<IPasswordRequirementStrategy> _strategies;

    public PasswordValidationContext(IList<IPasswordRequirementStrategy> strategies)
    {

        _strategies = strategies;
    }

    public SecurityResult ValidatePassword(string password)
    {
        SecurityResult result;
        if (string.IsNullOrEmpty(password))
        {
            result = SecurityResult.Failed("The password cannot be empty");
            return result;
        }
        
        foreach (var strategy in _strategies)
        {
            result = strategy.Validate(password);
            if (!result.Succeeded)
            {
                return result;
            }
        }

        return SecurityResult.Success;
    }
}
   