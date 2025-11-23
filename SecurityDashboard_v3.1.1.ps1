<#
 Security Dashboard Windows v3.1.1 – Production Blue Edition (migliorata)
 Target: Windows Server in produzione
 Modalità: sola lettura (non cancella log, non riavvia servizi, non cambia configurazioni)
 Output: report HTML sul Desktop con nome macchina + data
#>

# --- Parametri base ---
$DaysBack  = 90
$startTime = (Get-Date).AddDays(-$DaysBack)
$now       = Get-Date
$computer  = $env:COMPUTERNAME
$timestamp = $now.ToString('yyyyMMdd_HHmmss')
$outputPath = Join-Path $env:USERPROFILE "Desktop\SecurityDashboard_${computer}_$timestamp.html"

Write-Host "== Security Dashboard v3.1 – Production Blue Edition ==" -ForegroundColor Cyan
Write-Host "Analisi degli ultimi $DaysBack giorni: da $startTime a $now`n" -ForegroundColor Cyan

# --- Funzioni di supporto ---
function Get-XmlData {
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
    param($Type)
    switch ($Type) {
        '2'  { 'Console locale' }
        '3'  { 'Accesso da rete (condivisioni/servizi)' }
        '7'  { 'RDP – sessione già aperta / sblocco' }
        '10' { 'RDP – nuova sessione remota' }
        '11' { 'Credenziali cache (offline)' }
        default { "Altro ($Type)" }
    }
}

# --- Controllo (NON modifica) impostazioni command line processi ---
Write-Host "[INFO] Controllo logging command line dei processi (4688)..." -ForegroundColor Yellow
try {
    $cmdLineReg = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction Stop
    $cmdLineEnabled = ($cmdLineReg.ProcessCreationIncludeCmdLine_Enabled -eq 1)
} catch {
    $cmdLineEnabled = $false
}

if (-not $cmdLineEnabled) {
    Write-Host "[AVVISO] Il logging della command line dei processi NON risulta attivo." -ForegroundColor Red
    Write-Host "         Per abilitare manualmente (da valutare in produzione):" -ForegroundColor Yellow
    Write-Host '         New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null' -ForegroundColor DarkYellow
    Write-Host '         New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force' -ForegroundColor DarkYellow
} else {
    Write-Host "[OK] Il logging della command line dei processi è attivo.`n" -ForegroundColor Green
}

Write-Host "[INFO] Lettura Event Log (Security/System/Defender/PowerShell)..." -ForegroundColor Yellow

# --- Raccolta Event Log principali ---
$securityFilter = @{
    LogName   = 'Security'
    StartTime = $startTime
    Id        = 4624,4625,4672,4688,4697,4720,4723,4724,
                4728,4732,4756,4729,4733,4757,4740,4648,4698,4702
}
$systemFilter = @{
    LogName   = 'System'
    StartTime = $startTime
    Id        = 7045
}

try {
    $secEvents = Get-WinEvent -FilterHashtable $securityFilter -ErrorAction Stop
} catch {
    Write-Host "[ERRORE] Impossibile leggere il log Security: $_" -ForegroundColor Red
    $secEvents = @()
}

try {
    $sysEvents = Get-WinEvent -FilterHashtable $systemFilter -ErrorAction Stop
} catch {
    $sysEvents = @()
}

# Defender (se disponibile)
try {
    $defenderEvents = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction Stop |
                      Where-Object { $_.TimeCreated -ge $startTime }
} catch {
    $defenderEvents = @()
}

# PowerShell Operational (4103/4104 – se logging abilitato)
try {
    $psEvents = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop |
                Where-Object { $_.TimeCreated -ge $startTime -and $_.Id -in 4103,4104 }
} catch {
    $psEvents = @()
}

# --- Info log Security (size, retention) ---
try {
    $secLogInfo = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
    $secMaxMB   = [math]::Round($secLogInfo.MaximumSizeInBytes / 1MB, 1)
    $secSizeMB  = [math]::Round($secLogInfo.FileSize / 1MB, 1)
} catch {
    $secLogInfo = $null
    $secMaxMB   = 'N/D'
    $secSizeMB  = 'N/D'
}

if ($secEvents.Count -gt 0) {
    $firstEventTime = ($secEvents | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
    $coverageDays   = [math]::Round( ($now - $firstEventTime).TotalDays, 1 )
} else {
    $firstEventTime = $null
    $coverageDays   = 0
}

# --- Login (4624/4625) ---
$logonEvents = $secEvents | Where-Object { $_.Id -in 4624,4625 } | Sort-Object TimeCreated

$logonsParsed = $logonEvents | ForEach-Object {
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
        TimeCreated  = $_.TimeCreated
        Esito        = if ($_.Id -eq 4624) { 'Successo' } else { 'Fallito' }
        Utente       = $user
        IpAddress    = $ip
        LogonType    = $lt
        TipoLogon    = $ltName
        StatoAccesso = $stato
    }
}

$failedLogons  = $logonsParsed | Where-Object { $_.Esito -eq 'Fallito' } | Sort-Object TimeCreated -Descending
$successLogons = $logonsParsed | Where-Object { $_.Esito -eq 'Successo' } | Sort-Object TimeCreated -Descending
$rdpFailed     = $failedLogons  | Where-Object { $_.LogonType -in @('7','10') }
$rdpSuccess    = $successLogons | Where-Object { $_.LogonType -in @('7','10') }

# --- Eventi account & privilegi ---
$privEvents       = $secEvents | Where-Object { $_.Id -eq 4672 }
$newUserEvents    = $secEvents | Where-Object { $_.Id -eq 4720 }
$pwdChangeEvents  = $secEvents | Where-Object { $_.Id -in 4723,4724 }
$lockoutEvents    = $secEvents | Where-Object { $_.Id -eq 4740 }
$explicitCreds    = $secEvents | Where-Object { $_.Id -eq 4648 }

# --- Gruppi (aggiunte e rimozioni: 4728,4732,4756,4729,4733,4757) ---
$groupEvents = $secEvents | Where-Object { $_.Id -in 4728,4732,4756,4729,4733,4757 } | ForEach-Object {
    $desc = switch ($_.Id) {
        4728 { 'Agg. a gruppo Global' }
        4732 { 'Agg. a gruppo Local' }
        4756 { 'Agg. a gruppo Universal' }
        4729 { 'Rimozione da gruppo Global' }
        4733 { 'Rimozione da gruppo Local' }
        4757 { 'Rimozione da gruppo Universal' }
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

# --- Nuovi servizi (4697 Security + 7045 System) ---
$newServiceSec = $secEvents | Where-Object { $_.Id -eq 4697 } | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        OrigineLog  = 'Security (4697)'
        ServiceName = Get-XmlData $_ 'ServiceName'
        Path        = Get-XmlData $_ 'ServiceFileName'
        CreatoDa    = Get-XmlData $_ 'SubjectUserName'
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

$newServices = ($newServiceSec + $newServiceSys) | Sort-Object TimeCreated -Descending

# --- Scheduled Tasks (Security: 4698/4702) ---
$scheduledTasks = $secEvents | Where-Object { $_.Id -in 4698,4702 } | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        IdEvento    = $_.Id
        Dettagli    = $_.Message
    }
}

# --- Processi (4688) con euristica sospetta ---
$procEventsRaw = $secEvents | Where-Object { $_.Id -eq 4688 }

$suspiciousNames = @(
    'cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe',
    'rundll32.exe','regsvr32.exe','mshta.exe','schtasks.exe',
    'bitsadmin.exe','psexec.exe','wmic.exe','wmiprvse.exe',
    'msbuild.exe','installutil.exe','reg.exe','certutil.exe'
)

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

    $level = if ($isSuspName -and $isSuspCmd) {
        'Nome + CommandLine sospette'
    } elseif ($isSuspName) {
        'Nome processo sospetto'
    } elseif ($isSuspCmd) {
        'CommandLine sospetta'
    } else {
        'Normale'
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

$suspiciousProc = $procEvents | Where-Object { $_.SuspicionLevel -ne 'Normale' } |
                  Sort-Object TimeCreated -Descending

# --- Eventi Defender ---
$defenderParsed = $defenderEvents | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $threatName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Threat Name' }).'#text'
    if (-not $threatName) { $threatName = ($xml.Event.EventData.Data | Select-Object -First 1).'#text' }
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventId     = $_.Id
        Threat      = $threatName
        Message     = $_.Message
    }
}

# --- PowerShell Operational (4103/4104) analisi base ---
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
        Sospetto     = if ($isSusp) { 'Sì' } else { 'No' }
        Dettaglio    = $msgShort
    }
}

# --- Riepilogo numerico ---
$summary = [PSCustomObject]@{
    'Login RDP falliti'               = $rdpFailed.Count
    'Login RDP riusciti'              = $rdpSuccess.Count
    'Login falliti totali'            = $failedLogons.Count
    'Login riusciti totali'           = $successLogons.Count
    'Nuovi utenti creati'             = $newUserEvents.Count
    'Account bloccati (4740)'         = $lockoutEvents.Count
    'Password modificate (4723/4724)' = $pwdChangeEvents.Count
    'Accessi privilegiati (4672)'     = $privEvents.Count
    'Modifiche gruppi (agg.+rimozioni)' = $groupEvents.Count
    'Nuovi servizi (4697/7045)'       = $newServices.Count
    'Scheduled tasks (4698/4702)'     = $scheduledTasks.Count
    'Processi registrati (4688)'      = $procEvents.Count
    'Processi sospetti'               = $suspiciousProc.Count
    'Eventi Defender'                 = $defenderParsed.Count
    'Eventi PowerShell (4103/4104)'   = $psParsed.Count
}

# --- Semaforo ---
function Get-BadgeClass {
    param([int]$value, [int]$warn, [int]$crit)
    if ($value -ge $crit) { 'crit' }
    elseif ($value -ge $warn) { 'warn' }
    else { 'ok' }
}

$rdpFailClass   = Get-BadgeClass $rdpFailed.Count 5 20
$loginFailClass = Get-BadgeClass $failedLogons.Count 10 50
$newUserClass   = Get-BadgeClass $newUserEvents.Count 1 3
$lockoutClass   = Get-BadgeClass $lockoutEvents.Count 2 5
$newServClass   = Get-BadgeClass $newServices.Count 1 5
$suspProcClass  = Get-BadgeClass $suspiciousProc.Count 1 10
$defenderClass  = Get-BadgeClass $defenderParsed.Count 1 5

# --- HTML HEAD (ATTENZIONE: "@" e "@ devono stare a colonna 1) ---
$head = @"
<meta charset="utf-8" />
<title>Security Dashboard - $computer</title>
<link rel='preconnect' href='https://cdn.jsdelivr.net'>
<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
<style>
body { font-family:Segoe UI,Arial,sans-serif; background:#f5f7fb; margin:20px; }
h1,h2,h3 { color:#153E75; }
.card { background:#ffffff; border-radius:8px; padding:15px 20px; margin-bottom:18px; box-shadow:0 1px 4px rgba(0,0,0,0.1); }
.badge { display:inline-block; padding:3px 9px; border-radius:10px; color:#fff; font-size:11px; font-weight:bold; }
.ok { background:#2e7d32; }
.warn { background:#ffa000; }
.crit { background:#c62828; }
.small { font-size:12px; color:#555; }
table { width:100%; border-collapse:collapse; margin-top:8px; font-size:12px; }
th,td { border:1px solid #ddd; padding:4px 6px; text-align:left; }
th { background:#e3eaf5; }
pre { background:#f0f2f7; padding:8px; border-radius:5px; overflow:auto; }
</style>
"@

# --- Riepilogo HTML ---
$summaryHtml = @"
<div class='card'>
  <h1>Security Dashboard – $computer</h1>
  <p class='small'>Periodo analizzato: $startTime → $now<br/>
  Questo report mostra gli eventi principali di sicurezza per aiutare a capire se ci sono stati attacchi o movimenti laterali.</p>
  <p class='small'>
    <b>Legenda:</b>
    <span class='badge ok'>OK</span>
    <span class='badge warn'>Attenzione</span>
    <span class='badge crit'>Allarme</span>
  </p>
  <ul>
    <li>Login RDP falliti: <span class='badge $rdpFailClass'>$($rdpFailed.Count)</span></li>
    <li>Login falliti totali: <span class='badge $loginFailClass'>$($failedLogons.Count)</span></li>
    <li>Nuovi utenti creati: <span class='badge $newUserClass'>$($newUserEvents.Count)</span></li>
    <li>Account bloccati: <span class='badge $lockoutClass'>$($lockoutEvents.Count)</span></li>
    <li>Nuovi servizi: <span class='badge $newServClass'>$($newServices.Count)</span></li>
    <li>Processi sospetti: <span class='badge $suspProcClass'>$($suspiciousProc.Count)</span></li>
    <li>Eventi Windows Defender: <span class='badge $defenderClass'>$($defenderParsed.Count)</span></li>
  </ul>
</div>
"@

# --- Tabelle dettagli ---
$failedTable = $failedLogons |
    Select-Object -First 50 TimeCreated,Utente,IpAddress,StatoAccesso,TipoLogon |
    ConvertTo-Html -Fragment -PreContent "<h3>Ultimi 50 login falliti</h3><p class='small'>Molti login falliti da stessi IP o verso lo stesso utente possono indicare attacchi brute force.</p>"

$rdpTable = ($rdpFailed | Select-Object -First 20) + ($rdpSuccess | Select-Object -First 20) |
    Sort-Object TimeCreated -Descending |
    ConvertTo-Html -Fragment -PreContent "<h3>Login RDP (falliti e riusciti)</h3><p class='small'>Controlla se gli IP sono attesi (VPN aziendale, amministratori) o sconosciuti.</p>"

$privTable = $privEvents |
    Select-Object -First 30 @{n='TimeCreated';e={$_.TimeCreated}},
                          @{n='Utente';e={Get-XmlData $_ 'SubjectUserName'}} |
    ConvertTo-Html -Fragment -PreContent "<h3>Accessi con privilegi elevati (4672)</h3><p class='small'>Qui appaiono gli account che hanno avuto diritti molto elevati. Devono essere solo amministratori autorizzati.</p>"

$newUserTable = $newUserEvents |
    Select-Object -First 30 @{n='TimeCreated';e={$_.TimeCreated}},
                          @{n='NuovoUtente';e={Get-XmlData $_ 'TargetUserName'}},
                          @{n='CreatoDa';e={Get-XmlData $_ 'SubjectUserName'}} |
    ConvertTo-Html -Fragment -PreContent "<h3>Nuovi account creati (4720)</h3><p class='small'>Nuovi utenti inattesi sono un forte indicatore di compromissione o movimento laterale.</p>"

$groupTable = $groupEvents |
    Select-Object -First 40 TimeCreated,Azione,Gruppo,Membro,EseguitoDa |
    ConvertTo-Html -Fragment -PreContent "<h3>Modifiche a gruppi (aggiunte/rimozioni)</h3><p class='small'>Controlla in particolare gruppi come Administrators, Remote Desktop Users, Domain Admins.</p>"

$serviceTable = $newServices |
    Select-Object -First 30 TimeCreated,OrigineLog,ServiceName,Path,CreatoDa |
    ConvertTo-Html -Fragment -PreContent "<h3>Nuovi servizi installati (4697/7045)</h3><p class='small'>I malware spesso si installano come servizio per avviarsi automaticamente ad ogni riavvio.</p>"

$taskTable = $scheduledTasks |
    Select-Object -First 30 TimeCreated,IdEvento,Dettagli |
    ConvertTo-Html -Fragment -PreContent "<h3>Scheduled tasks (4698/4702)</h3><p class='small'>Le attività pianificate possono essere usate per persistenza o esecuzione ritardata di malware.</p>"

$suspProcTable = $suspiciousProc |
    Select-Object -First 50 TimeCreated,Utente,Processo,ProcessoPadre,CommandLine,SuspicionLevel |
    ConvertTo-Html -Fragment -PreContent "<h3>Processi sospetti (4688 + euristica)</h3><p class='small'>Processi con nomi o command line sospette (PowerShell obfuscato, base64, LOLBins). Verifica attentamente questi elementi.</p>"

if ($defenderParsed.Count -gt 0) {
    $defTable = $defenderParsed |
        Select-Object -First 30 TimeCreated,EventId,Threat |
        ConvertTo-Html -Fragment -PreContent "<h3>Eventi Windows Defender</h3><p class='small'>Questi eventi indicano rilevamenti o azioni dell'antivirus di Windows.</p>"
} else {
    $defTable = "<p class='small'><b>Eventi Windows Defender:</b> nessun evento rilevante nel periodo analizzato oppure log non disponibile.</p>"
}

if ($psParsed.Count -gt 0) {
    $psTable = $psParsed |
        Select-Object -First 40 TimeCreated,EventId,Sospetto,Dettaglio |
        ConvertTo-Html -Fragment -PreContent "<h3>Eventi PowerShell (4103/4104)</h3><p class='small'>Script PowerShell registrati dal log operativo. Se 'Sospetto' = Sì, potrebbero indicare attività malevole o amministrazione avanzata.</p>"
} else {
    $psTable = "<h3>Eventi PowerShell (4103/4104)</h3><p class='small'>Nessun evento PowerShell operativo rilevato nel periodo o log non abilitato.</p>"
}

# --- Info log Security in HTML ---
if ($secLogInfo -ne $null -and $firstEventTime -ne $null) {
    $covMsg = if ($coverageDays -lt $DaysBack) {
        "Attenzione: il log di sicurezza copre solo circa $coverageDays giorni (target $DaysBack). Valuta di aumentare la dimensione massima del log Security per avere più storico."
    } else {
        "Il log di sicurezza copre tutto il periodo richiesto (circa $coverageDays giorni)."
    }

    $logInfoHtml = @"
<div class='card'>
  <h2>Informazioni sul log Security</h2>
  <p class='small'>
    Dimensione attuale file Security: $secSizeMB MB su massimo configurato $secMaxMB MB.<br/>
    Primo evento disponibile nel periodo: $firstEventTime<br/>
    Copertura temporale effettiva: circa $coverageDays giorni.<br/>
    $covMsg
  </p>
</div>
"@
} else {
    $logInfoHtml = @"
<div class='card'>
  <h2>Informazioni sul log Security</h2>
  <p class='small'>Impossibile determinare dimensione o copertura del log Security (permessi o configurazione). Verifica manualmente da Visualizzatore eventi.</p>
</div>
"@
}

# --- Grafico login falliti ---
$chartSection = @"
<div class='card'>
  <h2>Grafico login falliti</h2>
  <p class='small'>Confronto rapido tra login RDP falliti e tutti i login falliti nel periodo.</p>
  <canvas id='logonsChart'></canvas>
</div>
<script>
const ctx = document.getElementById('logonsChart').getContext('2d');
new Chart(ctx,{
  type:'bar',
  data:{
    labels:['RDP falliti','Login falliti totali'],
    datasets:[{
      label:'Numero eventi',
      data:[$($rdpFailed.Count),$($failedLogons.Count)],
      backgroundColor:['#c62828','#ffa000']
    }]
  },
  options:{
    responsive:true,
    plugins:{legend:{display:true}}
  }
});
</script>
"@

# --- BODY HTML ---
$body = @"
$summaryHtml

<div class='card'>
  <h2>Accessi e autenticazioni</h2>
  $chartSection
  $failedTable
  $rdpTable
</div>

<div class='card'>
  <h2>Account, privilegi e gruppi</h2>
  $privTable
  $newUserTable
  $groupTable
</div>

<div class='card'>
  <h2>Persistenza (servizi e scheduled tasks)</h2>
  $serviceTable
  $taskTable
</div>

<div class='card'>
  <h2>Processi e possibili malware fileless</h2>
  $suspProcTable
</div>

<div class='card'>
  <h2>Antivirus (Windows Defender)</h2>
  $defTable
</div>

<div class='card'>
  <h2>PowerShell Operational</h2>
  $psTable
</div>

$logInfoHtml

<div class='card'>
  <h2>Note per chi non è esperto di cybersecurity</h2>
  <p class='small'>
    - Se vedi molti login falliti o tentativi RDP da IP sconosciuti, potrebbe essere un attacco di forza bruta.<br/>
    - Nuovi account o modifiche ai gruppi admin non previste sono segnali seri di compromissione o movimento laterale.<br/>
    - Nuovi servizi o scheduled tasks inattesi possono indicare malware che cerca di rimanere persistente nel sistema.<br/>
    - Processi come <b>powershell.exe</b>, <b>cmd.exe</b>, <b>rundll32.exe</b> con command line strane (base64, -enc, -nop, download da Internet) sono spesso indizi di attacco avanzato.<br/>
    - Gli eventi di Windows Defender indicano ciò che l'antivirus ha rilevato o bloccato.<br/>
    - In caso di dubbi:
      <br/> &nbsp;&nbsp;• non spegnere subito il server ma isolarlo dalla rete, se possibile;
      <br/> &nbsp;&nbsp;• contatta il team di sicurezza o un consulente specializzato;
      <br/> &nbsp;&nbsp;• conserva i log e il report generato per eventuali analisi forensi.<br/>
    - Per approfondire IP o hash sospetti, puoi usare strumenti esterni come portali di threat intelligence (es. VirusTotal, AbuseIPDB) da una macchina di analisi separata.
  </p>
</div>
"@

# --- Generazione file HTML ---
ConvertTo-Html -Head $head -Body $body -Title "Security Dashboard - $computer" |
    Out-File -Encoding UTF8 $outputPath

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host " Security Dashboard generata con successo " -ForegroundColor Green
Write-Host " File: $outputPath" -ForegroundColor Yellow
Write-Host " Aprilo con il browser per analizzare gli eventi." -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
