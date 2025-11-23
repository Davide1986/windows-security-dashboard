<#
 Security Dashboard Windows v3.1 – Production Blue Edition (improved)
 Target: Windows Server in produzione

 ITA:
   Script PowerShell in sola lettura che analizza i principali Event Log di sicurezza
   (Security, System, Defender, PowerShell) degli ultimi N giorni e costruisce una
   vista strutturata in memoria. Questo frammento si occupa della raccolta e
   normalizzazione dei dati, non della generazione dell'output HTML.

 ENG:
   Read-only PowerShell script that inspects key Windows security-related Event Logs
   (Security, System, Defender, PowerShell) for the last N days and builds an
   in-memory view. This section focuses on data collection and normalization,
   not on HTML report generation.
#>

# --- Parametri base / Basic parameters ---
# ITA: Numero di giorni da analizzare all'indietro rispetto ad oggi.
# ENG: Number of days to look back from current date.
$DaysBack  = 90

# ITA: Data/ora di inizio finestra di analisi.
# ENG: Start time for the analysis time window.
$startTime = (Get-Date).AddDays(-$DaysBack)

# ITA: Timestamp corrente (fine finestra di analisi).
# ENG: Current timestamp (end of analysis window).
$now       = Get-Date

# ITA: Nome della macchina su cui gira lo script (hostname).
# ENG: Local machine name (hostname) where the script is executed.
$computer  = $env:COMPUTERNAME

# ITA: Timestamp in formato compatibile con nomi file (yyyyMMdd_HHmmss).
# ENG: Timestamp formatted for filename usage (yyyyMMdd_HHmmss).
$timestamp = $now.ToString('yyyyMMdd_HHmmss')

# ITA: Percorso completo del report che verrà generato sul Desktop dell'utente.
# ENG: Full output path for the report that will be generated on user's Desktop.
$outputPath = Join-Path $env:USERPROFILE "Desktop\SecurityDashboard_${computer}_$timestamp.html"

Write-Host "== Security Dashboard v3.1 – Production Blue Edition ==" -ForegroundColor Cyan
Write-Host "Analisi degli ultimi $DaysBack giorni: da $startTime a $now`n" -ForegroundColor Cyan

# --- Funzioni di supporto / Helper functions ---

function Get-XmlData {
    <#
      ITA:
        Estrae un singolo campo dai dati XML di un evento (EventRecord) in base
        al nome del campo (FieldName). Se il campo non esiste, restituisce $null.

      ENG:
        Extracts a single field from the XML representation of an event
        (EventRecord) by its name (FieldName). Returns $null if the field
        is not present.
    #>
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,
        [string]$FieldName
    )
    try {
        $xml = [xml]$Event.ToXml()
        ($xml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }).'#text'
    } catch {
        $null
    }
}

function Get-LogonTypeName {
    <#
      ITA:
        Restituisce una descrizione leggibile del tipo di logon (LogonType)
        basandosi sul valore numerico registrato nell'evento di sicurezza.

      ENG:
        Returns a human-readable description for a given logon type (LogonType),
        based on the numeric value stored in the security event.
    #>
    param($Type)
    switch ($Type) {
        '2'  { 'Console locale' }                      # ITA/ENG: Local interactive logon
        '3'  { 'Accesso da rete (condivisioni/servizi)' } # Network logon (shares/services)
        '7'  { 'RDP – sessione già aperta / sblocco' } # RDP reconnect / unlock
        '10' { 'RDP – nuova sessione remota' }         # New Remote Desktop session
        '11' { 'Credenziali cache (offline)' }         # Cached credentials logon
        default { "Altro ($Type)" }                    # Other/unknown logon type
    }
}

# --- Controllo impostazioni command line processi (solo verifica) ---
# --- Process command line logging check (read-only, no changes) ---

Write-Host "[INFO] Controllo logging command line dei processi (4688)..." -ForegroundColor Yellow

try {
    # ITA: Recupera dal Registro la chiave che indica se la CommandLine dei processi
    #      è inclusa negli eventi 4688. Non modifica nulla.
    # ENG: Reads from the Registry whether process CommandLine is included
    #      in 4688 events. Does not modify anything.
    $cmdLineReg = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction Stop
    $cmdLineEnabled = ($cmdLineReg.ProcessCreationIncludeCmdLine_Enabled -eq 1)
} catch {
    $cmdLineEnabled = $false
}

if (-not $cmdLineEnabled) {
    # ITA: Avviso all'operatore: logging CommandLine non attivo, fornisce comandi
    #      da eseguire manualmente (se approvato) per abilitarlo.
    # ENG: Warns operator: CommandLine logging is not enabled, suggests manual
    #      commands (if approved) to turn it on.
    Write-Host "[AVVISO] Il logging della command line dei processi NON risulta attivo." -ForegroundColor Red
    Write-Host "         Per abilitare manualmente (da valutare in produzione):" -ForegroundColor Yellow
    Write-Host '         New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null' -ForegroundColor DarkYellow
    Write-Host '         New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force' -ForegroundColor DarkYellow
} else {
    Write-Host "[OK] Il logging della command line dei processi è attivo.`n" -ForegroundColor Green
}

Write-Host "[INFO] Lettura Event Log (Security/System/Defender/PowerShell)..." -ForegroundColor Yellow

# --- Raccolta Event Log principali / Main Event Log collection ---

# ITA: Filtro per il registro Security: include solo gli ID evento critici per
#      autenticazione, account, privilegi, processi, servizi, scheduled tasks.
# ENG: Filter for the Security log: includes only the most relevant event IDs
#      for authentication, accounts, privileges, processes, services, tasks.
$securityFilter = @{
    LogName   = 'Security'
    StartTime = $startTime
    Id        = 4624,4625,4672,4688,4697,4720,4723,4724,
                4728,4732,4756,4729,4733,4757,4740,4648,4698,4702
}

# ITA: Filtro per il registro System: qui in particolare i nuovi servizi (7045).
# ENG: Filter for the System log: here mainly interested in new services (7045).
$systemFilter = @{
    LogName   = 'System'
    StartTime = $startTime
    Id        = 7045
}

try {
    # ITA: Lettura eventi dal log Security usando il filtro definito.
    # ENG: Read events from the Security log using the defined filter.
    $secEvents = Get-WinEvent -FilterHashtable $securityFilter -ErrorAction Stop
} catch {
    Write-Host "[ERRORE] Impossibile leggere il log Security: $_" -ForegroundColor Red
    $secEvents = @()
}

try {
    # ITA: Lettura eventi dal log System (principalmente nuovi servizi).
    # ENG: Read events from the System log (mainly new services).
    $sysEvents = Get-WinEvent -FilterHashtable $systemFilter -ErrorAction Stop
} catch {
    $sysEvents = @()
}

# Defender (se disponibile) / Windows Defender events (if available)
try {
    # ITA: Recupera gli eventi operativi di Windows Defender nel periodo analizzato.
    # ENG: Retrieves Windows Defender Operational log events within the analysis window.
    $defenderEvents = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction Stop |
                      Where-Object { $_.TimeCreated -ge $startTime }
} catch {
    $defenderEvents = @()
}

# PowerShell Operational (4103/4104 – se logging abilitato) / if enabled
try {
    # ITA: Recupera eventi PowerShell (script block logging) 4103/4104 se il log è attivo.
    # ENG: Retrieves PowerShell Operational events (4103/4104) if logging is enabled.
    $psEvents = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop |
                Where-Object { $_.TimeCreated -ge $startTime -and $_.Id -in 4103,4104 }
} catch {
    $psEvents = @()
}

# --- Info log Security (dimensione e retention) ---
# --- Security log info (size and retention) ---

try {
    # ITA: Ottiene metadati sul log Security: dimensione massima e dimensione attuale.
    # ENG: Obtains metadata about the Security log: max size and current file size.
    $secLogInfo = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
    $secMaxMB   = [math]::Round($secLogInfo.MaximumSizeInBytes / 1MB, 1)
    $secSizeMB  = [math]::Round($secLogInfo.FileSize / 1MB, 1)
} catch {
    $secLogInfo = $null
    $secMaxMB   = 'N/D'   # ITA: Non disponibile / ENG: Not available
    $secSizeMB  = 'N/D'
}

if ($secEvents.Count -gt 0) {
    # ITA: Primo evento disponibile nel periodo: serve per stimare la copertura reale in giorni.
    # ENG: First available event in the range: used to estimate effective coverage in days.
    $firstEventTime = ($secEvents | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
    $coverageDays   = [math]::Round( ($now - $firstEventTime).TotalDays, 1 )
} else {
    $firstEventTime = $null
    $coverageDays   = 0
}

# --- Login (4624/4625) ---
# --- Logon events (4624 = success, 4625 = failure) ---

$logonEvents = $secEvents | Where-Object { $_.Id -in 4624,4625 } | Sort-Object TimeCreated

$logonsParsed = $logonEvents | ForEach-Object {
    # ITA: Estrazione utente, IP e tipo di logon dall'evento grezzo.
    # ENG: Extract user, IP and logon type from raw event.

    $user = Get-XmlData -Event $_ -FieldName 'TargetUserName'
    if (-not $user) { $user = Get-XmlData -Event $_ -FieldName 'SubjectUserName' }

    $ip   = Get-XmlData -Event $_ -FieldName 'IpAddress'
    $lt   = Get-XmlData -Event $_ -FieldName 'LogonType'
    $ltName = Get-LogonTypeName $lt

    $stato = switch ($lt) {
        '10' { 'RDP – nuova sessione' }
        '7'  { 'RDP – sessione già aperta / sblocco' }
        '2'  { 'Console locale' }
        '3'  { 'Accesso da rete' }
        default { "Altro ($lt)" }
    }

    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated                      # ITA/ENG: Timestamp of the event
        Esito        = if ($_.Id -eq 4624) { 'Successo' } else { 'Fallito' }  # Result: success/failure
        Utente       = $user
        IpAddress    = $ip
        LogonType    = $lt
        TipoLogon    = $ltName
        StatoAccesso = $stato
    }
}

# ITA: Suddividiamo login falliti/riusciti e in particolare i logon RDP.
# ENG: Split failed/successful logons and specifically RDP-related logons.
$failedLogons  = $logonsParsed | Where-Object { $_.Esito -eq 'Fallito' } | Sort-Object TimeCreated -Descending
$successLogons = $logonsParsed | Where-Object { $_.Esito -eq 'Successo' } | Sort-Object TimeCreated -Descending
$rdpFailed     = $failedLogons  | Where-Object { $_.LogonType -in @('7','10') }
$rdpSuccess    = $successLogons | Where-Object { $_.LogonType -in @('7','10') }

# --- Eventi account & privilegi / Account & privilege events ---

# ITA: Accessi con privilegi elevati (es. SeDebugPrivilege, SeBackupPrivilege, ecc.).
# ENG: Logons with elevated privileges (e.g., SeDebugPrivilege, SeBackupPrivilege, etc.).
$privEvents       = $secEvents | Where-Object { $_.Id -eq 4672 }

# ITA: Creazione nuovi account utente.
# ENG: New user accounts created.
$newUserEvents    = $secEvents | Where-Object { $_.Id -eq 4720 }

# ITA: Modifica/cambio password account.
# ENG: Password change/reset events.
$pwdChangeEvents  = $secEvents | Where-Object { $_.Id -in 4723,4724 }

# ITA: Account bloccati (lockout), spesso associato a brute force.
# ENG: Account lockout events, often mapped to brute-force activity.
$lockoutEvents    = $secEvents | Where-Object { $_.Id -eq 4740 }

# ITA: Uso di credenziali esplicite (ID 4648), indicativo di tool come PSExec o
#      accessi con account diversi.
# ENG: Explicit credential usage (ID 4648), typical for tools like PSExec
#      or when using different accounts.
$explicitCreds    = $secEvents | Where-Object { $_.Id -eq 4648 }

# --- Gruppi (aggiunte e rimozioni) / Group membership changes ---

$groupEvents = $secEvents | Where-Object { $_.Id -in 4728,4732,4756,4729,4733,4757 } | ForEach-Object {
    # ITA/ENG: Map event IDs to human-readable group action description.
    $desc = switch ($_.Id) {
        4728 { 'Agg. a gruppo Global / Added to Global group' }
        4732 { 'Agg. a gruppo Local / Added to Local group' }
        4756 { 'Agg. a gruppo Universal / Added to Universal group' }
        4729 { 'Rimozione da gruppo Global / Removed from Global group' }
        4733 { 'Rimozione da gruppo Local / Removed from Local group' }
        4757 { 'Rimozione da gruppo Universal / Removed from Universal group' }
        default { "Evento $($_.Id)" }
    }
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Azione      = $desc
        Gruppo      = Get-XmlData $_ 'TargetUserName'
        Membro      = Get-XmlData $_ 'MemberName'
        EseguitoDa  = Get-XmlData $_ 'SubjectUserName'
    }
}

# --- Nuovi servizi (4697 Security + 7045 System) / New service installation ---

$newServiceSec = $secEvents | Where-Object { $_.Id -eq 4697 } | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        OrigineLog  = 'Security (4697)'                 # Source log
        ServiceName = Get-XmlData $_ 'ServiceName'
        Path        = Get-XmlData $_ 'ServiceFileName'
        CreatoDa    = Get-XmlData $_ 'SubjectUserName'  # Created by which account
    }
}

$newServiceSys = $sysEvents | Where-Object { $_.Id -eq 7045 } | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        OrigineLog  = 'System (7045)'
        ServiceName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
        Path        = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
        CreatoDa    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'AccountName' }).'#text'
    }
}

# ITA/ENG: Unione dei servizi rilevati da Security e System, ordinati per data.
$newServices = ($newServiceSec + $newServiceSys) | Sort-Object TimeCreated -Descending

# --- Scheduled Tasks (4698/4702) / Scheduled tasks creation & changes ---

$scheduledTasks = $secEvents | Where-Object { $_.Id -in 4698,4702 } | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        IdEvento    = $_.Id
        Dettagli    = $_.Message    # Full message for later inspection
    }
}

# --- Processi (4688) con euristica sospetta ---
# --- Process events (4688) with heuristic-based suspicious detection ---

$procEventsRaw = $secEvents | Where-Object { $_.Id -eq 4688 }

# ITA: Nomi di processi noti come LOLBins o spesso abusati dai malware.
# ENG: Process names known as LOLBins or often abused by malware.
$suspiciousNames = @(
    'cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe',
    'rundll32.exe','regsvr32.exe','mshta.exe','schtasks.exe',
    'bitsadmin.exe','psexec.exe','wmic.exe','wmiprvse.exe',
    'msbuild.exe','installutil.exe','reg.exe','certutil.exe'
)

# ITA: Pattern tipici di command line malevole (obfuscation, base64, bypass policy, recon).
# ENG: Typical malicious command-line patterns (obfuscation, base64, policy bypass, recon).
$suspiciousCmdPatterns = @(
    '-enc','-encodedcommand','frombase64string',' -nop',' -noni',
    '-w hidden','-windowstyle hidden','invoke-expression','iex ',
    'downloadstring','webclient','mimikatz','sekurlsa',
    'invoke-mimikatz','/c whoami','/c net user','/c net group','/c net localgroup'
)

$procEvents = $procEventsRaw | ForEach-Object {
    $pName   = Get-XmlData $_ 'NewProcessName'
    $cmdLine = Get-XmlData $_ 'CommandLine'
    $parent  = Get-XmlData $_ 'ParentProcessName'
    $user    = Get-XmlData $_ 'SubjectUserName'

    $pLower = ($pName   | ForEach-Object { $_.ToLower() })
    $cLower = ($cmdLine | ForEach-Object { $_.ToLower() })

    $isSuspName = $false
    foreach ($n in $suspiciousNames) {
        if ($pLower -like "*$n") { $isSuspName = $true; break }
    }

    $isSuspCmd  = $false
    foreach ($pat in $suspiciousCmdPatterns) {
        if ($cLower -like "*$pat*") { $isSuspCmd = $true; break }
    }

    # ITA: Classificazione di rischio per il processo in base al nome e alla command line.
    # ENG: Risk classification for the process based on its name and command line.
    $level = if ($isSuspName -and $isSuspCmd) {
        'Nome + CommandLine sospette / Suspicious name + command line'
    } elseif ($isSuspName) {
        'Nome processo sospetto / Suspicious process name'
    } elseif ($isSuspCmd) {
        'CommandLine sospetta / Suspicious command line'
    } else {
        'Normale / Normal'
    }

    [PSCustomObject]@{
        TimeCreated     = $_.TimeCreated
        Utente          = $user
        Processo        = $pName
        ProcessoPadre   = $parent
        CommandLine     = $cmdLine
        SuspicionLevel  = $level
    }
}

# ITA/ENG: Solo i processi classificati come non “Normale” vengono marcati come sospetti.
$suspiciousProc = $procEvents | Where-Object { $_.SuspicionLevel -notlike 'Normale*' } |
                  Sort-Object TimeCreated -Descending

# --- Eventi Defender / Defender events ---

$defenderParsed = $defenderEvents | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $threatName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Threat Name' }).'#text'
    if (-not $threatName) {
        $threatName = ($xml.Event.EventData.Data | Select-Object -First 1).'#text'
    }
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventId     = $_.Id
        Threat      = $threatName
        Message     = $_.Message
    }
}

# --- PowerShell Operational (4103/4104) analisi base ---
# --- PowerShell Operational events (4103/4104) basic analysis ---

$psSuspPatterns = @(
    'invoke-webrequest','downloadstring','frombase64string',
    'iex ','invoke-expression','add-type','reflection.assembly',
    'mimikatz','invoke-mimikatz','invoke-shellcode'
)

$psParsed = $psEvents | ForEach-Object {
    $msg = $_.Message
    $msgShort = if ($msg.Length -gt 200) { $msg.Substring(0,200) + ' ...' } else { $msg }
    $msgLower = $msg.ToLower()
    $isSusp   = $false
    foreach ($pat in $psSuspPatterns) {
        if ($msgLower -like "*$pat*") { $isSusp = $true; break }
    }

    [PSCustomObject]@{
        TimeCreated  = $_.TimeCreated
        EventId      = $_.Id
        Sospetto     = if ($isSusp) { 'Sì / Yes' } else { 'No' }
        Dettaglio    = $msgShort
    }
}

# --- A questo punto hai tutti i dati strutturati in memoria ---
# --- At this point you have all key data structured in memory ---

# Da qui in poi, in un altro file o nella parte successiva,
# puoi generare l'HTML, fare grafici, esportare JSON, ecc.
# From here on, in another file or in the next section,
# you can generate HTML, charts, export JSON, etc.
