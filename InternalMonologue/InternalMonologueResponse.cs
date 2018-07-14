namespace InternalMonologue
{
    public class InternalMonologueResponse
    {
        public bool FromElevated = false;
        public bool NtlmDowngrade = false;
        public string ProcessName = "";
        public int PID = 0;
        public string SID = "";
        public string ImpersonatedIdentity = "";
        public string UserName = "";
        public string Domain = "";
        public string Resp1 = ""; //LM if NtlmDowngrade = true
        public string Resp2 = "";
        public string Challenge = "";

        public override string ToString()
        {
            if (FromElevated)
            {
                return string.Format("{0}::{1}:{2}:{3}:{4}", UserName, Domain, Resp1, Resp2, Challenge);
            }
            return string.Format("{0}::{1}:{2}:{3}:{4}", UserName, Domain, Challenge, Resp1, Resp2);
        }
    }
}
