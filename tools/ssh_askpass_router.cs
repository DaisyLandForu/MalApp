using System;

public static class MalAppSshAskPassRouter
{
    public static void Main(string[] args)
    {
        var prompt = string.Join(" ", args ?? Array.Empty<string>());
        var jumpPassword = Environment.GetEnvironmentVariable("MALAPP_JUMP_SSH_PASSWORD") ?? "";
        var targetPassword = Environment.GetEnvironmentVariable("MALAPP_TARGET_SSH_PASSWORD") ?? "";

        if (prompt.IndexOf("10.0.11.82", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            Console.WriteLine(jumpPassword);
            return;
        }

        Console.WriteLine(targetPassword);
    }
}
