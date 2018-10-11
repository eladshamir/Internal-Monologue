using System;

namespace InternalMonologue
{
    public class Class1
    {
        public static void Main(bool impersonate = true, bool threads = false, bool downgrade = true, bool restore = true, string challenge = "1122334455667788", bool verbose = false)
        {
            var monologue = new InternalMonologue(impersonate, threads, downgrade, restore, challenge, verbose);
            var monologueConsole = monologue.Go();
            Console.WriteLine(monologueConsole.Output());
        }
    }
}
