<#
GOALS
  1) Pull AD computer objects from multiple domains where whenChanged is older than $StaleCutoffDays
  2) Compare to Entra and EXCLUDE devices that are active (ApproximateLastSignInDateTime newer than cutoff)
     - FAST MODE (Option A): prefetch all ACTIVE Entra devices since cutoff once, then local lookups.
  3) Export the parsed list to CSV
#>

# ============================
# BOOTSTRAP
# ============================
$ErrorActionPreference = "Stop"
# Graph module setting to avoid function-count limits.
$MaximumFunctionCount = 20000

# Ensure required Graph modules exist.
$graphModules = @(
  "Microsoft.Graph.Authentication",
  "Microsoft.Graph.Identity.DirectoryManagement"
)
foreach ($m in $graphModules) {
  if (-not (Get-Module -ListAvailable -Name $m)) {
    Write-Host "Installing missing module: $m" -ForegroundColor Cyan
    Install-Module $m -Scope CurrentUser -Force -AllowClobber
  }
}


# ============================
# CONFIG
# ============================
# The variables in this script is the $StaleCutoffDays & $TenantId & $Domains - Cutoff defines the minimum time window for Objects to be "Stale"
$StaleCutoffDays   = 90
$Cutoff            = (Get-Date).AddDays(-$StaleCutoffDays)

$OutParsed         = "C:\Temp\AD_Stale_NotActiveInEntra.csv"
$OutDebugEnriched  = "C:\Temp\AD_Stale_All_With_Entra.csv"  # set to $null to disable

$SearchBase        = $null

# Optional: exclude by OU name fragments (set to $null to disable)
$ExcludeOUPatterns = $null
# Optional: Add Example:
# $ExcludeOUPatterns = @(
#   "OU=Domain Controllers",
#   "OU=Servers"
# )

$Domains = @(
  "site.org",
  "site2.com",
  "site3.com"
)

$EntraActiveCutoff = $Cutoff

# ============================
# MODULES
# ============================
Import-Module ActiveDirectory -ErrorAction Stop

# Import only what we need from Graph to avoid function-count blowups
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

# ============================ (This Was PAINFUL......)
# GRAPH AUTH (Reliable for enterprise Windows: Device Code + Process scope)
# ============================
$TenantId = "add Entra TenantID keep quotes"
$Scopes   = @("Directory.Read.All","Device.Read.All","User.Read.All")

try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
try { Clear-MgContext   -ErrorAction SilentlyContinue } catch {}

Write-Host "Authenticating to Microsoft Graph using DEVICE CODE (most reliable in locked-down environments)..." -ForegroundColor Cyan
Connect-MgGraph `
  -TenantId $TenantId `
  -UseDeviceCode `
  -Scopes $Scopes `
  -ContextScope Process `
  -NoWelcome

$ctx = Get-MgContext
if (-not $ctx -or -not $ctx.Account) {
  throw "Graph auth failed: no valid MgContext/Account after Connect-MgGraph."
}


# ============================
# 1) AD Discovery (server-side LDAP filter)
# ============================
$swTotal = [System.Diagnostics.Stopwatch]::StartNew()
$swAD    = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "Cutoff date: $Cutoff" -ForegroundColor Cyan
Write-Host "Querying AD computers across domains where whenChanged <= cutoff (server-side LDAP filter)..." -ForegroundColor Cyan

$cutoffLdap = $Cutoff.ToUniversalTime().ToString("yyyyMMddHHmmss.0Z")
$ldapFilter = "(&(objectCategory=computer)(whenChanged<=$cutoffLdap))"

$adCandidates = @()

foreach ($domain in $Domains) {

    Write-Host "AD Query Domain: $domain" -ForegroundColor Cyan

    $adQueryParams = @{
      Server         = $domain
      LDAPFilter     = $ldapFilter
      Properties     = @("whenChanged","DistinguishedName","sAMAccountName")
      ResultPageSize = 2000
      ResultSetSize  = $null
      ErrorAction    = "Stop"
    }
    if ($SearchBase) { $adQueryParams.SearchBase = $SearchBase }

    try {
        $adAll = Get-ADComputer @adQueryParams
    } catch {
        Write-Warning "Failed querying $domain : $($_.Exception.Message)"
        continue
    }

    $adDomainResults = $adAll | Where-Object {
        $dn = $_.DistinguishedName

        # If exclusions not set, keep everything
        if (-not $ExcludeOUPatterns) { return $true }

        # Otherwise exclude if DN contains any pattern
        -not ($ExcludeOUPatterns | Where-Object { $dn -like "*$_*" })
    } | ForEach-Object {
        [pscustomobject]@{
            DomainOrDC     = $domain
            ComputerName   = $_.Name
            SamAccountName = $_.sAMAccountName
            AD_whenChanged = $_.whenChanged
            AD_DN          = $_.DistinguishedName
        }
    }

    $adCandidates += $adDomainResults
    Write-Host ("  -> AD stale candidates from {0}: {1}" -f $domain, $adDomainResults.Count) -ForegroundColor Yellow
}

$swAD.Stop()
Write-Host ("TOTAL AD stale candidates (all domains): {0}" -f $adCandidates.Count) -ForegroundColor Yellow
Write-Host ("AD discovery time: {0:n1}s" -f $swAD.Elapsed.TotalSeconds) -ForegroundColor DarkGray

if (-not $adCandidates -or $adCandidates.Count -eq 0) {
    Write-Warning "No AD candidates found. Exiting."
    return
}

# Deduplicate names for reporting + sanity
$uniqueNames = $adCandidates.ComputerName | Sort-Object -Unique
Write-Host ("Unique computer names (post-AD): {0}" -f $uniqueNames.Count) -ForegroundColor Yellow


# ============================
# 2) ENTRA FAST MODE (Option A)
#    Prefetch ALL ACTIVE devices since cutoff ONCE, then local lookup.
# ============================
$swEntra = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "Prefetching Entra devices and applying client-side activity filter..." -ForegroundColor Cyan

$allDevices = Get-MgDevice -All `
  -Property "id,displayName,approximateLastSignInDateTime" `
  -ErrorAction Stop

$activeDevices = $allDevices | Where-Object {
    $_.ApproximateLastSignInDateTime -and
    ([datetime]$_.ApproximateLastSignInDateTime -ge $EntraActiveCutoff)
}


# Build a map: DISPLAYNAME -> best (most recent) device
$ActiveMap = @{}

foreach ($d in $activeDevices) {
    if (-not $d.DisplayName) { continue }

    $key = $d.DisplayName.ToUpperInvariant()
    $dt  = if ($d.ApproximateLastSignInDateTime) { [datetime]$d.ApproximateLastSignInDateTime } else { [datetime]"1900-01-01" }

    if (-not $ActiveMap.ContainsKey($key)) {
        $ActiveMap[$key] = $d
        continue
    }

    $existing = $ActiveMap[$key]
    $existingDt = if ($existing.ApproximateLastSignInDateTime) { [datetime]$existing.ApproximateLastSignInDateTime } else { [datetime]"1900-01-01" }

    if ($dt -gt $existingDt) {
        $ActiveMap[$key] = $d
    }
}

$swEntra.Stop()
Write-Host ("Active Entra devices since cutoff: {0}" -f $activeDevices.Count) -ForegroundColor Yellow
Write-Host ("Unique active displayNames indexed: {0}" -f $ActiveMap.Count) -ForegroundColor Yellow
Write-Host ("Entra prefetch+index time: {0:n1}s" -f $swEntra.Elapsed.TotalSeconds) -ForegroundColor DarkGray


Write-Host "Comparing AD stale candidates against ACTIVE Entra map (local lookups)..." -ForegroundColor Cyan

$swJoin = [System.Diagnostics.Stopwatch]::StartNew()

$enriched = foreach ($c in $adCandidates) {
    $k = $c.ComputerName.ToUpperInvariant()

    $entra = $null
    if ($ActiveMap.ContainsKey($k)) { $entra = $ActiveMap[$k] }

    $entraLast = $null
    if ($entra -and $entra.ApproximateLastSignInDateTime) {
        $entraLast = [datetime]$entra.ApproximateLastSignInDateTime
    }

    $isActive = ($entraLast -and $entraLast -ge $EntraActiveCutoff)

    # FAST MODE status:
    # - If in ActiveMap, it is active by definition
    # - If not in ActiveMap, it might be NotFound OR Inactive OR NoSignInDate (we didn't query those)
    $entraStatus = if ($entra) { "Active" } else { "NotActiveOrNotFound" }

    [pscustomobject]@{
        DomainOrDC            = $c.DomainOrDC
        ComputerName          = $c.ComputerName
        SamAccountName        = $c.SamAccountName
        AD_whenChanged        = $c.AD_whenChanged
        AD_DN                 = $c.AD_DN

        EntraDeviceId         = $entra.Id
        EntraApproxLastSignIn = $entraLast
        ActiveInEntra         = $isActive
        EntraStatus           = $entraStatus
    }
}

$parsed = $enriched | Where-Object { $_.ActiveInEntra -ne $true }

$swJoin.Stop()

Write-Host ""
Write-Host ("Enriched stale candidates (AD stale + Entra map lookup): {0}" -f $enriched.Count) -ForegroundColor Yellow
Write-Host ("Parsed list (AD stale AND NOT active in Entra):        {0}" -f $parsed.Count) -ForegroundColor Yellow
Write-Host ("Local compare time: {0:n1}s" -f $swJoin.Elapsed.TotalSeconds) -ForegroundColor DarkGray


# ============================
# 3) OUTPUT
# ============================
$outDir = Split-Path $OutParsed -Parent
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

$parsed | Sort-Object AD_whenChanged |
    Export-Csv $OutParsed -NoTypeInformation

if ($OutDebugEnriched) {
    $enriched | Sort-Object ActiveInEntra, EntraApproxLastSignIn |
      Export-Csv $OutDebugEnriched -NoTypeInformation
}

$swTotal.Stop()

Write-Host ""
Write-Host "Saved:" -ForegroundColor Green
Write-Host " - Parsed: $OutParsed"
if ($OutDebugEnriched) { Write-Host " - Debug : $OutDebugEnriched" }
Write-Host ("Total runtime: {0:n1}s" -f $swTotal.Elapsed.TotalSeconds) -ForegroundColor Green
