# What type of user signs in from a specific IP address?

<h1 id="bkmrk-what-type-of-user-si"><em>What type of user signs in from a specific IP address?</em></h1>
<h2 id="bkmrk-query-information">Query Information</h2>
<h4 id="bkmrk-mitre-att%26ck-techniq">MITRE ATT&amp;CK Technique(s)</h4>
<table id="bkmrk-technique-id-title-l">
<thead>
<tr>
<th>Technique ID</th>
<th>Title</th>
<th>Link</th>
</tr>
</thead>
<tbody>
<tr>
<td></td>
<td></td>
<td></td>
</tr>
</tbody>
</table>
<h4 id="bkmrk-description">Description</h4>
<p id="bkmrk-helps-to-build-knowl">Helps to build knowledge of IP utilisation within an organisation. Useful for confirming VPN IP addresses or understanding IP context</p>
<h4 id="bkmrk-author-%3Coptional%3E">Author &lt;Optional&gt;</h4>
<ul id="bkmrk-name%3A-callum-duncan-">
<li><strong>Name:</strong> Callum Duncan</li>
<li><strong>Github:</strong> c-dunc</li>
<li><strong>LinkedIn:</strong> callumsduncan</li>
<li><strong>Website:</strong> callumduncan.dev</li>
</ul>
<h2 id="bkmrk-defender-xdr">Defender XDR</h2>
<pre id="bkmrk-let-lookback-%3D-30d%3B-"><code class="language-kql">let lookback = 30d;
let ip = "1.1.1.1";

let suspiciousUPNs =
    SigninLogs
    | where TimeGenerated &gt;= ago(lookback)
    | where IPAddress == ip
    | where isnotempty(UserPrincipalName)
    | extend NormalizedUPN = tolower(trim(" ", UserPrincipalName))
    | distinct NormalizedUPN;
    
IdentityInfo
| where TimeGenerated &gt;= ago(lookback)
| where isnotempty(AccountUPN)
| extend NormalizedUPN = tolower(trim(" ", AccountUPN))
| summarize arg_max(TimeGenerated, *) by NormalizedUPN
| join kind=inner suspiciousUPNs on NormalizedUPN
| project AccountUPN, JobTitle, GroupMembership
</code></pre>
<h2 id="bkmrk-sentinel">Sentinel</h2>
<pre id="bkmrk-let-lookback-%3D-30d%3B--1"><code class="language-KQL">let lookback = 30d;
let ip = "1.1.1.1";

let suspiciousUPNs =
    SigninLogs
    | where TimeGenerated &gt;= ago(lookback)
    | where IPAddress == ip
    | where isnotempty(UserPrincipalName)
    | extend NormalizedUPN = tolower(trim(" ", UserPrincipalName))
    | distinct NormalizedUPN;
    
IdentityInfo
| where TimeGenerated &gt;= ago(lookback)
| where isnotempty(AccountUPN)
| extend NormalizedUPN = tolower(trim(" ", AccountUPN))
| summarize arg_max(TimeGenerated, *) by NormalizedUPN
| join kind=inner suspiciousUPNs on NormalizedUPN
| project AccountUPN, JobTitle, GroupMembership
</code></pre>
