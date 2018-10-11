# Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS

## Introduction
Mimikatz, developed by Benjamin Delpy (@gentilkiwi), is a well-regarded post-exploitation tool, which allows adversaries to extract plain text passwords, NTLM hashes and Kerberos tickets from memory, as well as perform attacks such as pass-the-hash, pass-the-ticket or build a golden ticket. Arguably, the primary use of Mimikatz is retrieving user credentials from LSASS process memory for use in post exploitation lateral movement.

Recently, Microsoft has introduced Credential Guard in Windows 10 Enterprise and Windows Server 2016, which uses virtualization-based security to isolate secrets, and it is very effective in preventing Mimikatz from retrieving hashes directly from memory.
Also, Mimikatz has become a prime target of most endpoint protection solutions, and they are very aggressive in their efforts to detect and prevent it. Although these efforts are bound to fail, they are increasingly becoming a nuisance.

## NetNTLM
NetNTLM is Windows’ challenge-response protocol that is mainly used where Kerberos is not supported. In NetNTLM, the server sends to the client a random 8-byte nonce as a challenge, and the client calculates a response that processes the challenge with the NTLM hash as the key, which is the MD4 hash of the user’s password. There are two versions of the NetNTLM authentication protocol, and both are vulnerable to certain attacks. Naturally, version 1 is significantly weaker than version 2, and therefore as of Windows Vista/2008 NetNTLM version 1 is disabled by default.


## Pass the Hash
Because the NTLM hash is the key to calculating the response, an adversary does not necessarily need to obtain the victim’s plain text password to authenticate, hence retrieving the hash from LSASS memory using Mimikatz is almost equivalent to stealing a plain text password. 
Chris Hummel has published an article describing this technique in 2009 and named it “Pass the Hash” [https://www.sans.org/reading-room/whitepapers/testing/crack-pass-hash-33219].

## Divide and Conquer
At Defcon 2012, Moxie Marlinspike and David Hulton presented a “Divide and Conquer” attack against NetNTLMv1 [https://www.youtube.com/watch?v=sIidzPntdCM]. In NetNTLMv1, the client receives the 8-byte challenge and calculates the response by encrypting it three times using DES with the different parts of the NTLM hash as the key. The key length for DES is effectively 56 bits, which is 7 bytes, while the NTLM hash is 16 bytes. NetNTLMv1 first encrypts the challenge using the first 7 bytes of the NTLM hash as the key, then encrypts the challenge using the next 7 bytes of the NTLM hash as the key, and finally encrypts the challenge using the last 2 bytes of the NTLM hash padded with null-bytes as the key. Effectively, this means that to retrieve the NTLM hash given a NetNTLMv1 challenge and response, an adversary must crack two 56-bit DES keys, which is exponentially easier than cracking a single 128-bit key.
Moxie and Hulton developed custom hardware for this task and were able to brute-force the entire DES keyspace in less than 24 hours, which guarantees the successful retrieval of the NTLM hash within a reasonable time.
Note that unlike dictionary or brute force attacks against the password, which may not be fruitful, this attack guarantees the successful retrieval of the NTLM hash.


## Rainbow Tables
As demonstrated by ToorCon at https://crack.sh, it is feasible to create a complete rainbow table for all the possible NetNTLMv1 responses to a chosen challenge, such as 0x1122334455667788, which allows cracking the NTLM hash for a given response within minutes. The implication is that capturing a NetNTLMv1 response for the chosen challenge can be translated to the corresponding NTLM hash almost instantly, which is almost the equivalent to obtaining the password due to Pass the Hash.

## NetNTLM Downgrade Attack
Mimikatz is commonly executed after the adversary has gained elevated access to the target host. At this point, the adversary can also change registry keys, such as LMCompatibilityLevel, which specifies whether the host should negotiate NetNTLMv1 or NetNTLMv2. The adversary can change the value to 0, 1 or 2, which enable NetNTLMv1 as a client, and then try to authenticate to a rogue SMB server that will capture the client’s response, as described in Optiv’s blog post [https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks].

## Extended NetNTLM Downgrade Attack
Two more settings may stop the victim from negotiating a NetNTLMv1 response:
1. NTLMMinClientSec - if configured to "Require NTLMv2 session security", the connection will fail if NTLMv2 protocol is not negotiated.
2. RestrictSendingNTLMTraffic - if configured to "Deny all," the client computer cannot authenticate to a remote server with NetNTLM of any version.
Similarly to the NetNTLM Downgrade attack, these settings can be changed if necessary. Note that unlike LMCompatibilityLevel, these settings are not configured by default to block NetNTLMv1 authentication.

## Internal Monologue Attack
In secure environments, where Mimikatz should not be executed, an adversary can perform an Internal Monologue Attack, in which they invoke a local procedure call to the NTLM authentication package (MSV1_0) from a user-mode application through SSPI to calculate a NetNTLM response in the context of the logged on user, after performing an extended NetNTLM downgrade.

The Internal Monologue Attack flow is described below:
1. Disable NetNTLMv1 preventive controls by changing LMCompatibilityLevel, NTLMMinClientSec and RestrictSendingNTLMTraffic to appropriate values, as described above.
2. Retrieve all non-network logon tokens from currently running processes and impersonate the associated users.
3. For each impersonated user, interact with NTLM SSP locally to elicit a NetNTLMv1 response to the chosen challenge in the security context of the impersonated user.
4. Restore the original values of LMCompatibilityLevel, NTLMMinClientSec and RestrictSendingNTLMTraffic.
5. Crack the NTLM hash of the captured responses using rainbow tables.
6. Pass the Hash.

## Update: Credential Guard Compatibility
I have recently retested Internal Monologue in environments with Credential Guard enabled and got negative results. I am not sure whether Credential Guard was not working properly in my test environment during the initial tests, or perhaps something changed since then.
I updated the implementation to acquire a server token from AcceptSecurityContext dynamically and tamper with it to avoid the local authentication trap, so that if NetNTLMv1 without Extended Session Security fails, at least a NetNTLMv2 challenge-response can be captured.

## Audit Trail
The Internal Monologue Attack is arguably stealthier than running Mimikatz because there is no need to inject code or dump memory to/from a protected process.
Because the NetNTLMv1 response is elicited by interacting with NTLM SSP locally, no network traffic is generated, and the chosen challenge is not easily visible.
No successful NTLM authentication event is recorded in the logs.
The registry changes for the NetNTLM downgrade and stealing tokens/impersonating other users may trip indicators.

## Proof of Concept
This tool is a proof of concept that implements the Internal Monologue Attack in C#. Porting the code to PowerShell may substitute certain event logs in the audit trail with others.
The PoC code is far from perfect. Positive contributions and improvements are welcome.

## Author
Elad Shamir from The Missing Link Security

## Acknowledgements
* Matthew Bush (3xocyte) from The Missing Link Security and Shaun Williamson (AusJock) from Beyond Binary for helping bounce off ideas and put this together
* Moxie Marlinspike and David Hulton for their talk “Defeating PPTP VPNs and WPA2 Enterprise with MS-CHAPv2” at Defcon 20
* Optiv for the NetNTLM Downgrade Attack
* Bialek Joseph (clymb3r) for Invoke-TokenManupilation 
* MWR Labs for Incognito
* Anton Sapozhnikov (snowytoxa) for Selfhash
* Tim Malcom Vetter (malcomvetter) for multiple improvements
* Marcello Salvati (byt3bl33d3r) for the DLL library addition
