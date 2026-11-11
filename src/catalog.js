// BlueShift — static catalog: the building blocks the generator draws from.
// Fully simulated. MITRE ATT&CK tactic/technique labels are used as plain
// taxonomy for realism; no live feeds. Each detection ARCHETYPE carries a
// ground-truth verdict distribution (real SOCs are mostly noise) so a learner's
// triage can be scored against what the alert "really" was.

const FIRST = ['ava', 'liam', 'noah', 'mia', 'eli', 'zoe', 'omar', 'ines', 'raj', 'nina', 'theo', 'sara', 'kofi', 'lena', 'jun', 'amir', 'cora', 'dev', 'ida', 'yuki'];
const LAST = ['patel', 'nguyen', 'okafor', 'santos', 'khan', 'rossi', 'mwangi', 'cohen', 'garcia', 'owusu', 'haddad', 'novak', 'silva', 'adeyemi', 'brandt', 'costa'];
const DEPTS = ['Finance', 'Engineering', 'Sales', 'HR', 'IT Operations', 'Legal', 'Marketing', 'Executive'];

// Asset roles and their typical OS + base criticality.
const ROLES = [
  { role: 'workstation', os: ['Windows 11', 'macOS 14', 'Windows 10'], crit: 'low', weight: 10 },
  { role: 'laptop', os: ['Windows 11', 'macOS 14'], crit: 'low', weight: 8 },
  { role: 'file-server', os: ['Windows Server 2022', 'Ubuntu 22.04'], crit: 'high', weight: 3 },
  { role: 'web-server', os: ['Ubuntu 22.04', 'RHEL 9'], crit: 'high', weight: 3 },
  { role: 'domain-controller', os: ['Windows Server 2022'], crit: 'critical', weight: 1 },
  { role: 'database', os: ['RHEL 9', 'Ubuntu 22.04'], crit: 'critical', weight: 2 },
  { role: 'firewall', os: ['PAN-OS 11', 'FortiOS 7'], crit: 'high', weight: 1 },
  { role: 'vpn-gateway', os: ['PAN-OS 11'], crit: 'high', weight: 1 }
];

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const VERDICTS = ['true-positive', 'false-positive', 'benign'];

// The detection archetypes. ev() returns raw log lines (newest last). The hidden
// `verdicts` weighting is the ground truth a learner's disposition is graded on.
const ARCHETYPES = [
  {
    key: 'ssh-brute-force', severity: 'high', category: 'Credential Access',
    tactic: 'Credential Access', techniqueId: 'T1110', technique: 'Brute Force',
    rule: 'Auth · repeated SSH failures from single source',
    title: c => `SSH brute-force against ${c.asset.hostname} from ${c.srcIp}`,
    verdicts: [['true-positive', 6], ['false-positive', 3], ['benign', 1]],
    ev: c => [
      ...Array.from({ length: 5 }, (_, i) => `sshd[${1200 + i}]: Failed password for ${c.user} from ${c.srcIp} port ${40000 + i * 7} ssh2`),
      `sshd: ${c.failCount} failed login attempts for ${c.user} from ${c.srcIp} in 90s`,
      c.truth === 'true-positive' ? `sshd: Accepted password for ${c.user} from ${c.srcIp}  <-- successful login after failures` : `sshd: connection closed by ${c.srcIp} [preauth]`
    ],
    reco: c => `Confirm whether the source ${c.srcIp} is expected. If not, block it at the firewall, force a password reset for ${c.user}, and check for a successful login after the failures.`
  },
  {
    key: 'rdp-brute-force', severity: 'high', category: 'Credential Access',
    tactic: 'Credential Access', techniqueId: 'T1110.001', technique: 'Password Guessing',
    rule: 'Auth · RDP account lockout threshold exceeded',
    title: c => `Repeated RDP logon failures on ${c.asset.hostname}`,
    verdicts: [['true-positive', 5], ['false-positive', 4], ['benign', 1]],
    ev: c => [
      `Security 4625: An account failed to log on. Account: ${c.user}. Source: ${c.srcIp}. Type: 10 (RemoteInteractive)`,
      `Security 4625: ${c.failCount} failures in 2 minutes for ${c.user}`,
      c.truth === 'false-positive' ? `Service account ${c.user} mapped to a scheduled task with a stale password` : `Security 4740: User account ${c.user} was locked out`
    ],
    reco: c => `Check if ${c.user} is a service/automation account with a stale credential (common false positive). Otherwise treat as targeted guessing: isolate the source and review lateral movement.`
  },
  {
    key: 'port-scan', severity: 'medium', category: 'Discovery',
    tactic: 'Discovery', techniqueId: 'T1046', technique: 'Network Service Discovery',
    rule: 'Network · horizontal port scan detected',
    title: c => `Port scan from ${c.srcIp} across the ${c.subnet} subnet`,
    verdicts: [['true-positive', 3], ['false-positive', 5], ['benign', 2]],
    ev: c => [
      `firewall: ${c.srcIp} probed ${c.hostCount} hosts on ports 22,80,443,445,3389 in 30s`,
      `IDS: SCAN TCP SYN sweep from ${c.srcIp}`,
      c.truth === 'benign' ? `asset-mgmt: ${c.srcIp} is the authorized vulnerability scanner (Nessus) per CMDB` : `firewall: ${c.srcIp} not found in asset inventory`
    ],
    reco: c => `Correlate ${c.srcIp} against the CMDB — authorized vulnerability scanners trip this rule constantly (benign). If unknown, it is reconnaissance: contain the source and watch for follow-on exploitation.`
  },
  {
    key: 'c2-beacon', severity: 'critical', category: 'Command and Control',
    tactic: 'Command and Control', techniqueId: 'T1071', technique: 'Application Layer Protocol',
    rule: 'Network · periodic beacon to low-reputation host',
    title: c => `Possible C2 beacon from ${c.asset.hostname} to ${c.extIp}`,
    verdicts: [['true-positive', 8], ['false-positive', 1], ['benign', 1]],
    ev: c => [
      `proxy: ${c.asset.ip} -> ${c.extIp} GET /${c.beaconPath} every 60s (+/- 3s jitter)`,
      `threat-intel: ${c.extIp} flagged newly-registered domain, low reputation`,
      `edr: beaconing process ${c.proc} with no signed publisher on ${c.asset.hostname}`
    ],
    reco: c => `Strong C2 indicator: regular low-jitter beaconing to a low-reputation host. Isolate ${c.asset.hostname} from the network, capture the process ${c.proc}, and block ${c.extIp} at the proxy/firewall.`
  },
  {
    key: 'phishing-click', severity: 'high', category: 'Initial Access',
    tactic: 'Initial Access', techniqueId: 'T1566', technique: 'Phishing',
    rule: 'Email · user clicked a flagged phishing link',
    title: c => `${c.user} clicked a phishing link on ${c.asset.hostname}`,
    verdicts: [['true-positive', 6], ['false-positive', 2], ['benign', 2]],
    ev: c => [
      `email-gw: message to ${c.user} from ${c.extUser} matched phishing signature "invoice-credential-harvest"`,
      `proxy: ${c.user} visited hxxps://${c.phishDomain}/login (credential form)`,
      c.truth === 'true-positive' ? `idp: successful auth for ${c.user} from new ASN minutes later` : `proxy: page blocked by web filter before submission`
    ],
    reco: c => `Determine whether credentials were submitted. If the filter blocked the page it may be contained; if a login from a new location followed, reset ${c.user}'s password, revoke sessions, and enable step-up MFA.`
  },
  {
    key: 'suspicious-powershell', severity: 'high', category: 'Execution',
    tactic: 'Execution', techniqueId: 'T1059.001', technique: 'PowerShell',
    rule: 'Endpoint · encoded PowerShell execution',
    title: c => `Encoded PowerShell executed on ${c.asset.hostname}`,
    verdicts: [['true-positive', 4], ['false-positive', 5], ['benign', 1]],
    ev: c => [
      `edr: powershell.exe -nop -w hidden -enc ${c.b64}... launched by ${c.user}`,
      `edr: parent process ${c.truth === 'true-positive' ? 'winword.exe (macro)' : 'ConfigMgr agent'}`,
      c.truth === 'false-positive' ? `cmdb: host is managed by SCCM; encoded commands are routine for software deployment` : `edr: child process reached out to ${c.extIp}`
    ],
    reco: c => `Decode the command and check the parent process. Spawned from Office/macro with network egress = malicious; spawned from a management agent (SCCM/Intune) is a common false positive.`
  },
  {
    key: 'priv-esc', severity: 'critical', category: 'Privilege Escalation',
    tactic: 'Privilege Escalation', techniqueId: 'T1068', technique: 'Exploitation for Privilege Escalation',
    rule: 'Endpoint · unexpected local admin elevation',
    title: c => `${c.user} elevated to local admin on ${c.asset.hostname}`,
    verdicts: [['true-positive', 6], ['false-positive', 3], ['benign', 1]],
    ev: c => [
      `Security 4672: Special privileges assigned to ${c.user} on ${c.asset.hostname}`,
      `Security 4732: ${c.user} added to the local Administrators group`,
      c.truth === 'false-positive' ? `change-mgmt: approved change CR-${c.cr} grants temporary admin for software install` : `no approved change record for this elevation`
    ],
    reco: c => `Cross-reference against change management. An approved change (CR) makes this benign; with no record, revoke the privilege, investigate how it was obtained, and hunt for a local exploit.`
  },
  {
    key: 'data-exfil', severity: 'critical', category: 'Exfiltration',
    tactic: 'Exfiltration', techniqueId: 'T1048', technique: 'Exfiltration Over Alternative Protocol',
    rule: 'DLP · large outbound transfer to external host',
    title: c => `Large outbound transfer from ${c.asset.hostname} (${c.mb} MB)`,
    verdicts: [['true-positive', 6], ['false-positive', 3], ['benign', 1]],
    ev: c => [
      `dlp: ${c.asset.ip} uploaded ${c.mb} MB to ${c.extIp} over ${c.proto} in 4 min`,
      `dlp: ${c.docCount} documents matched classification "Confidential"`,
      c.truth === 'benign' ? `cmdb: ${c.extIp} is the sanctioned backup provider endpoint` : `threat-intel: ${c.extIp} is an anonymous file-sharing service`
    ],
    reco: c => `Identify the destination ${c.extIp}: a sanctioned backup/SaaS endpoint is benign, an anonymous file-share is exfiltration. If unsanctioned, block egress, preserve the host, and scope what left.`
  },
  {
    key: 'impossible-travel', severity: 'high', category: 'Credential Access',
    tactic: 'Initial Access', techniqueId: 'T1078', technique: 'Valid Accounts',
    rule: 'Identity · impossible travel between logins',
    title: c => `Impossible travel for ${c.user} (${c.geoA} -> ${c.geoB})`,
    verdicts: [['true-positive', 4], ['false-positive', 5], ['benign', 1]],
    ev: c => [
      `idp: ${c.user} signed in from ${c.geoA} at 09:02`,
      `idp: ${c.user} signed in from ${c.geoB} at 09:41 (1,100 km apart)`,
      c.truth === 'false-positive' ? `idp: second login sourced from the corporate VPN egress in ${c.geoB}` : `idp: second login from residential ASN, new device`
    ],
    reco: c => `Check whether the second login came through a corporate VPN egress (common false positive) or a new device/ASN. If genuinely impossible, treat the account as compromised: revoke sessions and reset.`
  },
  {
    key: 'mfa-fatigue', severity: 'high', category: 'Credential Access',
    tactic: 'Credential Access', techniqueId: 'T1621', technique: 'Multi-Factor Authentication Request Generation',
    rule: 'Identity · repeated MFA push requests',
    title: c => `MFA push flood targeting ${c.user}`,
    verdicts: [['true-positive', 6], ['false-positive', 2], ['benign', 2]],
    ev: c => [
      `idp: ${c.pushCount} MFA push requests for ${c.user} in 10 minutes, all denied`,
      `idp: password for ${c.user} was valid on each attempt (attacker has the password)`,
      c.truth === 'true-positive' ? `idp: one push eventually APPROVED from ${c.srcIp}` : `idp: all pushes denied; user reported the prompts`
    ],
    reco: c => `The password is already known to the attacker. If any push was approved, the account is compromised — reset and revoke now. Either way, move ${c.user} to number-matching/phishing-resistant MFA.`
  },
  {
    key: 'av-detection', severity: 'medium', category: 'Execution',
    tactic: 'Execution', techniqueId: 'T1204', technique: 'User Execution',
    rule: 'Endpoint · antivirus detection',
    title: c => `Malware detected on ${c.asset.hostname} (${c.malware})`,
    verdicts: [['true-positive', 5], ['false-positive', 3], ['benign', 2]],
    ev: c => [
      `av: ${c.malware} detected in C:\\Users\\${c.user}\\Downloads\\${c.file}`,
      c.truth === 'benign' ? `av: file is the EICAR test string (harmless AV test)` : `av: quarantine FAILED — file was already executed`,
      `edr: ${c.truth === 'true-positive' ? 'process spawned before quarantine' : 'no child processes observed'}`
    ],
    reco: c => `Confirm the detection quarantined successfully and whether the file executed. EICAR test files are benign; a real sample that ran before quarantine needs host isolation and a full investigation.`
  },
  {
    key: 'new-admin-account', severity: 'high', category: 'Persistence',
    tactic: 'Persistence', techniqueId: 'T1136.001', technique: 'Create Account: Local Account',
    rule: 'Identity · new privileged account created',
    title: c => `New admin account "${c.newAcct}" created on ${c.asset.hostname}`,
    verdicts: [['true-positive', 4], ['false-positive', 4], ['benign', 2]],
    ev: c => [
      `Security 4720: user account ${c.newAcct} was created by ${c.user}`,
      `Security 4728: ${c.newAcct} added to Domain Admins`,
      c.truth === 'false-positive' ? `hr/onboarding ticket HR-${c.cr} requests admin for new IT hire` : `account created outside business hours, no ticket`
    ],
    reco: c => `Verify against onboarding/change tickets. A legitimate IT hire is benign; an account created off-hours with no ticket and immediate Domain Admin rights is persistence — disable it and investigate the creator ${c.user}.`
  }
];

module.exports = { FIRST, LAST, DEPTS, ROLES, SEVERITIES, SEV_RANK, VERDICTS, ARCHETYPES };
