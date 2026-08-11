#Requires -Version 5.1
<##
    Hush.WindowProbe.ps1

    Runs inside an interactive user's session. It reports process IDs that own
    visible top-level windows to the SYSTEM enforcer. The enforcer starts this
    helper with the user's token because window stations are isolated per
    session; a user32 call from SYSTEM/session 0 cannot see the user's desktop.
##>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class HushWindowProbe {
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    public static int[] GetVisibleWindowProcessIds() {
        var ids = new HashSet<int>();
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
            if (!IsWindowVisible(hWnd)) return true;
            uint processId;
            GetWindowThreadProcessId(hWnd, out processId);
            if (processId != 0) ids.Add((int)processId);
            return true;
        }, IntPtr.Zero);
        var result = new int[ids.Count];
        ids.CopyTo(result);
        return result;
    }
}
'@

try {
    $ids = [HushWindowProbe]::GetVisibleWindowProcessIds()
    [System.IO.File]::WriteAllLines($OutputPath, [string[]]@($ids))
    exit 0
} catch {
    exit 1
}
