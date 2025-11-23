# 🛡️ Security Dashboard Windows v3.1  
### Production Blue Edition — Davide De Rubeis

> Licenza: CC BY-NC 4.0 — **Uso consentito solo per scopi non commerciali**, con obbligo di attribuzione.

## 🇮🇹 Descrizione (Italiano)

**Security Dashboard Windows v3.1** è uno strumento di analisi difensiva per Windows Server >= 2019 e Windows 10+, sviluppato per supportare:
- Blue Team
- SOC / Incident Response
- Audit e Digital Forensics

Lo script PowerShell analizza i log di sicurezza degli ultimi 90 giorni (configurabile) e genera un **report HTML professionale interattivo**.

### 🔍 Cosa monitora

| Categoria | Detections |
|----------|------------|
| Login | Falliti/Riusciti, RDP, brute-force |
| Account | Creazione nuovi utenti |
| Privilegi | Eventi con privilegi elevati (4672) |
| Gruppi | Aggiunte/rimozioni gruppi sensibili |
| Persistenza | Nuovi servizi (4697/7045), Scheduled Tasks |
| Processi | LOLBins, comandi offuscati, fileless payload |
| Antivirus | Detezioni Windows Defender |
| PowerShell | Script sospetti (4103/4104) |

---

### ✨ Caratteristiche principali

- Modalità **Read-Only** → nessuna modifica al sistema
- Dashboard HTML con semafori minaccia (OK / Attenzione / Allarme)
- Grafici interattivi (chart.js)
- Analisi euristica tattiche di attacco (MITRE ATT&CK oriented)
- Indicazioni per personale non tecnico
- Utile come **strumento di primo triage** in caso di compromissione

---

## ⚙️ Come usarlo

1️⃣ Aprire PowerShell come **Amministratore**

2️⃣ Se necessario:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
```
3️⃣ Eseguire lo script:
```
.\SecurityDashboard_v3.1.ps1
```


📌 Report generato sul Desktop:

SecurityDashboard_HOST_yyyymmdd_hhmmss.html
```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
