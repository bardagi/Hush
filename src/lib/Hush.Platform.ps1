#Requires -Version 5.1
<#
    Hush.Platform.ps1
    Windows process, session, and target discovery helpers.

    This file is dot-sourced by the Hush compatibility loaders.
#>

#  ACTION HELPERS  — each returns one or more New-HushResult objects.
#  $Context = @{ Preview = [bool]; Exclusions = <obj>; Config = <obj> }
# =============================================================================

function Get-HushDescendantPids {
    param([Parameter(Mandatory)][int]$ParentId, [Parameter(Mandatory)]$AllProcs)
    $kids = $AllProcs | Where-Object { $_.ParentProcessId -eq $ParentId }
    foreach ($k in $kids) {
        $k.ProcessId
        Get-HushDescendantPids -ParentId $k.ProcessId -AllProcs $AllProcs
    }
}

function Initialize-HushSessionProbeType {
    if ('HushSessionProbe' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class HushSessionProbe {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(
        IntPtr token,
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    public static string GetUserTempPath(int sessionId) {
        IntPtr token = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        try {
            if (!WTSQueryUserToken((uint)sessionId, out token)) return null;
            if (!CreateEnvironmentBlock(out environment, token, false)) return null;
            IntPtr cursor = environment;
            while (Marshal.ReadInt16(cursor) != 0) {
                string entry = Marshal.PtrToStringUni(cursor);
                if (entry.StartsWith("TEMP=", StringComparison.OrdinalIgnoreCase)) return entry.Substring(5);
                cursor = IntPtr.Add(cursor, (entry.Length + 1) * 2);
            }
            return null;
        } finally {
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    public static bool RunProbe(int sessionId, string executable, string arguments, int timeoutMilliseconds) {
        IntPtr token = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try {
            if (!WTSQueryUserToken((uint)sessionId, out token)) return false;
            if (!CreateEnvironmentBlock(out environment, token, false)) return false;

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.lpDesktop = "winsta0\\default";
            string command = "\"" + executable.Replace("\"", "\\\"") + "\" " + arguments;
            StringBuilder commandLine = new StringBuilder(command);
            const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            const uint CREATE_NO_WINDOW = 0x08000000;
            if (!CreateProcessAsUser(token, executable, commandLine, IntPtr.Zero, IntPtr.Zero,
                    false, CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, environment, null, ref si, out pi)) return false;

            uint waitResult = WaitForSingleObject(pi.hProcess, (uint)timeoutMilliseconds);
            if (waitResult != 0) return false;
            uint exitCode;
            return GetExitCodeProcess(pi.hProcess, out exitCode) && exitCode == 0;
        } finally {
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }
}
'@
}

function Get-HushVisibleWindowPids {
    param([Parameter(Mandatory)][int[]]$SessionIds)
    $empty = [pscustomobject]@{ Available = $false; VisiblePids = @() }
    $paths = Get-HushPaths
    $probePath = Join-Path $paths.Bin 'Hush.WindowProbe.ps1'
    if (-not (Test-Path -LiteralPath $probePath)) { return $empty }

    $powershell = Get-Command 'powershell.exe' -ErrorAction SilentlyContinue
    if (-not $powershell) { return $empty }
    Initialize-HushSessionProbeType

    $currentSessionId = -1
    $currentIsSystem = $false
    try {
        $currentSessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $currentIsSystem = ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
    } catch { }

    $visible = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($sessionId in @($SessionIds | Where-Object { $_ -ge 0 } | Select-Object -Unique)) {
        $sameInteractiveSession = ([int]$sessionId -eq $currentSessionId) -and -not $currentIsSystem
        $userTemp = if ($sameInteractiveSession) {
            [System.IO.Path]::GetTempPath()
        } else {
            [HushSessionProbe]::GetUserTempPath([int]$sessionId)
        }
        if ([string]::IsNullOrWhiteSpace($userTemp) -or -not (Test-Path -LiteralPath $userTemp)) { return $empty }
        $outputPath = Join-Path $userTemp ('Hush-window-' + [guid]::NewGuid().ToString('N') + '.txt')
        try {
            $probeArguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $probePath, '-OutputPath', $outputPath)
            $probeCommandArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -OutputPath "{1}"' -f $probePath, $outputPath
            $probeOk = if ($sameInteractiveSession) {
                & $powershell.Source @probeArguments | Out-Null
                ($LASTEXITCODE -eq 0)
            } else {
                [HushSessionProbe]::RunProbe([int]$sessionId, $powershell.Source, $probeCommandArgs, 15000)
            }
            if (-not $probeOk) { return $empty }
            if (-not (Test-Path -LiteralPath $outputPath)) { return $empty }
            foreach ($line in @(Get-Content -LiteralPath $outputPath -Encoding ASCII)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $visibleProcessId = 0
                if (-not [int]::TryParse($line, [ref]$visibleProcessId) -or $visibleProcessId -le 0) { return $empty }
                [void]$visible.Add($visibleProcessId)
            }
        } catch {
            return $empty
        } finally {
            if (Test-Path -LiteralPath $outputPath) {
                Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    return [pscustomobject]@{ Available = $true; VisiblePids = @($visible) }
}

