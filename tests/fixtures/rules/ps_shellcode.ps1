Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
"@ -Name Win32 -Namespace N
