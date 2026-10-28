using System;
using System.Runtime.InteropServices;

// Checks the Windows password of the account that will run the dkclient
// service before installation continues. Used by the setup bootstrapper and by
// Install-DiskControl.ps1 (Add-Type). The password is never stored or logged.
public enum CredentialCheckResult
{
    Valid,
    WrongPassword,
    LockedOut,
    Disabled,
    PasswordExpired,
    AccountExpired,
    LogonRestricted,
    DomainUnavailable,
    Unknown
}

public static class CredentialCheck
{
    public const int MaximumWrongPasswordAttempts = 3;

    private const int Logon32LogonNetwork = 3;
    private const int Logon32ProviderDefault = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LogonUserW(string userName, string domain, string password,
        int logonType, int logonProvider, out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    // Returns the Win32 error of a network logon, 0 when the password is valid.
    public static int Validate(string account, string password)
    {
        string domain = null;
        string user = account ?? string.Empty;
        int slash = user.IndexOf('\\');
        if (slash > 0)
        {
            domain = user.Substring(0, slash);
            user = user.Substring(slash + 1);
        }
        else if (user.IndexOf('@') < 0)
        {
            domain = ".";
        }

        IntPtr token;
        if (LogonUserW(user, domain, password ?? string.Empty, Logon32LogonNetwork, Logon32ProviderDefault, out token))
        {
            CloseHandle(token);
            return 0;
        }
        return Marshal.GetLastWin32Error();
    }

    public static CredentialCheckResult Classify(int error)
    {
        switch (error)
        {
            case 0: return CredentialCheckResult.Valid;
            case 1326: return CredentialCheckResult.WrongPassword;          // ERROR_LOGON_FAILURE
            case 1909: return CredentialCheckResult.LockedOut;              // ERROR_ACCOUNT_LOCKED_OUT
            case 1331: return CredentialCheckResult.Disabled;               // ERROR_ACCOUNT_DISABLED
            case 1330:                                                      // ERROR_PASSWORD_EXPIRED
            case 1907: return CredentialCheckResult.PasswordExpired;        // ERROR_PASSWORD_MUST_CHANGE
            case 1793: return CredentialCheckResult.AccountExpired;         // ERROR_ACCOUNT_EXPIRED
            case 1327:                                                      // ERROR_ACCOUNT_RESTRICTION
            case 1328:                                                      // ERROR_INVALID_LOGON_HOURS
            case 1329:                                                      // ERROR_INVALID_WORKSTATION
            case 1385: return CredentialCheckResult.LogonRestricted;        // ERROR_LOGON_TYPE_NOT_GRANTED
            case 1311:                                                      // ERROR_NO_LOGON_SERVERS
            case 1355:                                                      // ERROR_NO_SUCH_DOMAIN
            case 1789: return CredentialCheckResult.DomainUnavailable;      // ERROR_TRUSTED_RELATIONSHIP_FAILURE
            default: return CredentialCheckResult.Unknown;
        }
    }

    // Only a wrong password counts towards the attempt limit; each such attempt
    // is also counted by the domain lockout policy.
    public static bool CountsAsWrongPassword(CredentialCheckResult result)
    {
        return result == CredentialCheckResult.WrongPassword;
    }

    // The password could not be checked, but the service may still start with it.
    public static bool MayContinueUnverified(CredentialCheckResult result)
    {
        return result == CredentialCheckResult.DomainUnavailable ||
            result == CredentialCheckResult.LogonRestricted ||
            result == CredentialCheckResult.Unknown;
    }

    public static string Message(CredentialCheckResult result, string account, int error)
    {
        switch (result)
        {
            case CredentialCheckResult.Valid:
                return "Пароль для " + account + " проверен.";
            case CredentialCheckResult.WrongPassword:
                return "Неверный пароль для " + account + ".";
            case CredentialCheckResult.LockedOut:
                return "Учетная запись " + account + " заблокирована. Обратитесь к администратору домена и повторите установку после разблокировки.";
            case CredentialCheckResult.Disabled:
                return "Учетная запись " + account + " отключена. Служба не сможет под ней работать.";
            case CredentialCheckResult.PasswordExpired:
                return "Срок действия пароля " + account + " истек или его нужно сменить. Смените пароль при входе в Windows и повторите установку.";
            case CredentialCheckResult.AccountExpired:
                return "Срок действия учетной записи " + account + " истек.";
            case CredentialCheckResult.LogonRestricted:
                return "Пароль для " + account + " нельзя проверить: политика запрещает такой тип входа. " +
                    "Право «Вход в качестве службы» установщик выдаст сам.";
            case CredentialCheckResult.DomainUnavailable:
                return "Контроллер домена недоступен, пароль для " + account + " сейчас проверить нельзя.";
            default:
                return "Пароль для " + account + " проверить не удалось (код Windows " + error + ").";
        }
    }
}
