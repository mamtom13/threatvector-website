/* ================================================================
   legal-pages.js — Privacy Policy, Responsible Use, Disclaimer
================================================================ */
'use strict';

const LEGAL_PAGES = {

  'privacy': {
    title: 'Privacy Policy',
    tag:   'LEGAL',
    updated: 'March 2024',
    sections: [
      {
        heading: 'Overview',
        body: `ThreatVector Intelligence ("we", "us", "our") is committed to protecting 
the privacy of individuals who interact with our platform. This Privacy Policy explains 
what information we collect, how we use it, and your rights regarding that information. 
By using this website, you agree to the practices described in this policy.`
      },
      {
        heading: 'Information We Collect',
        body: `<strong style="color:var(--bright)">Information you provide voluntarily:</strong><br>
When you submit an abuse report through our contact form, we collect the information 
you choose to provide — including your name, organization, email address, domain names, 
IP addresses, and any evidence or notes you include. This information is submitted 
voluntarily and is used solely to process and investigate the reported abuse.<br><br>
<strong style="color:var(--bright)">Technical tool usage:</strong><br>
When you use our URL Check or Hash Lookup tools, the URL or hash you submit is sent 
to VirusTotal via our Cloudflare Worker proxy for analysis. We do not log, store, 
or retain the URLs or hashes you submit. VirusTotal's own 
<a href="https://www.virustotal.com/gui/help/privacy-policy" target="_blank" rel="noopener" style="color:var(--accent)">Privacy Policy</a> 
applies to that interaction.<br><br>
When you use our WHOIS Lookup tool, the domain you query is sent to third-party 
WHOIS/RDAP services for resolution. We do not log these queries.<br><br>
<strong style="color:var(--bright)">Automatically collected information:</strong><br>
Like most websites, our hosting infrastructure may collect standard server logs 
including IP addresses, browser type, referring URLs, and page visit timestamps. 
This data is used solely for security and operational purposes and is not shared 
with third parties.`
      },
      {
        heading: 'How We Use Your Information',
        body: `Information collected through abuse report submissions is used to:
<br>• Investigate and validate reported DNS abuse
<br>• Prepare and submit evidence packages to registrars, registries, and abuse desks
<br>• Follow up with reporters if additional information is required
<br>• Maintain records of abuse investigations for quality control purposes
<br><br>
We do not sell, rent, or trade personal information to any third party. 
We do not use your information for advertising or marketing purposes.`
      },
      {
        heading: 'Information Sharing',
        body: `In the course of processing abuse reports, information you provide may be 
shared with relevant registrars, registries, CERT/CSIRT teams, or law enforcement 
agencies as necessary to address the reported abuse. We share only the minimum 
information required for abuse mitigation purposes.<br><br>
Reporter identity is treated with discretion. Where operationally possible, 
we will honor requests for anonymous reporting.`
      },
      {
        heading: 'Data Retention',
        body: `Abuse report submissions are retained for a period necessary to complete 
the investigation and maintain accountability records. Technical lookup queries 
(URLs, hashes, domain names) are not stored by us beyond the duration of the 
immediate lookup request.`
      },
      {
        heading: 'Cookies',
        body: `This website does not use tracking cookies, advertising cookies, or 
third-party analytics. We do not track your behavior across websites.`
      },
      {
        heading: 'Third-Party Services',
        body: `This website integrates with the following third-party services:
<br>• <strong style="color:var(--bright)">VirusTotal</strong> — for URL and file hash analysis
<br>• <strong style="color:var(--bright)">RDAP/WHOIS services</strong> — for domain registration data
<br>• <strong style="color:var(--bright)">Google Fonts</strong> — for typography (font files loaded from Google servers)
<br>• <strong style="color:var(--bright)">Cloudflare</strong> — for hosting and Worker proxy services
<br><br>
Each of these services operates under its own privacy policy.`
      },
      {
        heading: 'Contact',
        body: `For privacy-related inquiries, contact us at 
<a href="mailto:&#105;&#110;&#102;&#111;&#64;&#116;&#104;&#114;&#101;&#97;&#116;&#118;&#101;&#99;&#116;&#111;&#114;&#105;&#110;&#116;&#101;&#108;&#108;&#105;&#103;&#101;&#110;&#99;&#101;&#46;&#99;&#111;&#109;" style="color:var(--accent)">info&#64;threatvectorintelligence&#46;com</a>`
      },
    ]
  },

  'responsible': {
    title: 'Responsible Use Policy',
    tag:   'LEGAL',
    updated: 'March 2024',
    sections: [
      {
        heading: 'Purpose',
        body: `ThreatVector Intelligence operates as a DNS abuse investigation and reporting 
platform. This policy establishes the standards of responsible use that apply to all 
individuals who submit abuse reports, use our lookup tools, or otherwise interact 
with our platform.`
      },
      {
        heading: 'Permitted Use',
        body: `This platform is provided for legitimate DNS abuse investigation and reporting purposes. 
Permitted uses include:
<br>• Submitting good-faith abuse reports for malware C2, botnet infrastructure, phishing, pharming, and spam-enabling domains
<br>• Using URL Check and Hash Lookup tools to investigate potentially malicious content
<br>• Using WHOIS Lookup to research domain registration information for abuse investigation
<br>• Accessing case studies and methodology documentation for educational purposes`
      },
      {
        heading: 'Prohibited Use',
        body: `The following uses of this platform are strictly prohibited:
<br>• Submitting false, misleading, or fabricated abuse reports
<br>• Using our tools to harass, target, or investigate individuals without legitimate cause
<br>• Submitting reports intended to cause unjustified domain suspensions (reverse abuse)
<br>• Automated scraping or bulk querying of our tools beyond reasonable research use
<br>• Attempting to probe, attack, or compromise our infrastructure
<br>• Using submitted information for commercial purposes without authorization
<br>• Submitting content dispute claims, copyright complaints, or general grievances outside our DNS abuse scope`
      },
      {
        heading: 'Good-Faith Reporting Standard',
        body: `All abuse reports must be submitted in good faith with a reasonable belief 
that the reported domain is engaged in DNS abuse as defined by ICANN. Reports must be 
accompanied by verifiable technical evidence. Submitting reports with the intent to 
harm a legitimate domain operator is a misuse of this platform and may be reported 
to relevant authorities.`
      },
      {
        heading: 'Evidence Requirements',
        body: `We require that all abuse reports include supporting evidence. 
Accepted evidence types include:
<br>• Sandbox analysis reports (e.g. Any.run, Hybrid Analysis, VirusTotal)
<br>• Network packet captures (PCAP files or summaries)
<br>• Passive DNS records showing malicious resolution patterns
<br>• Malware sample hashes with analysis results
<br>• Screenshots with timestamps
<br>• URLScan.io reports
<br><br>
Reports without supporting evidence will not be processed.`
      },
      {
        heading: 'Reporter Accountability',
        body: `By submitting a report, you represent that the information provided 
is accurate to the best of your knowledge and that you are acting in good faith. 
ThreatVector Intelligence reserves the right to decline, discard, or flag any 
report that does not meet our evidence and good-faith standards.`
      },
      {
        heading: 'Enforcement',
        body: `Violations of this Responsible Use Policy may result in:
<br>• Rejection of current and future abuse report submissions
<br>• Notification to relevant authorities in cases of deliberate abuse
<br><br>
We reserve the right to update this policy at any time. Continued use of this 
platform constitutes acceptance of the current policy.`
      },
    ]
  },

  'disclaimer': {
    title: 'Disclaimer',
    tag:   'LEGAL',
    updated: 'March 2024',
    sections: [
      {
        heading: 'General Disclaimer',
        body: `The information provided on ThreatVector Intelligence is for general 
informational and DNS abuse investigation purposes only. While we strive to maintain 
accurate and up-to-date information, we make no warranties or representations of 
any kind — express or implied — regarding the completeness, accuracy, reliability, 
or suitability of the information or tools provided.`
      },
      {
        heading: 'Tool Results Disclaimer',
        body: `<strong style="color:var(--bright)">URL Check and Hash Lookup:</strong><br>
Results from our URL Check and Hash Lookup tools are sourced from VirusTotal and 
reflect the aggregated verdicts of third-party security vendors at the time of the 
query. Results may include cached data and do not constitute a definitive security 
assessment. A clean result does not guarantee that a URL or file is safe; a flagged 
result does not guarantee that it is malicious. Always validate findings with 
additional sources before taking action.<br><br>
<strong style="color:var(--bright)">WHOIS Lookup:</strong><br>
WHOIS and RDAP data is retrieved from third-party registration data services. 
This data may be incomplete, redacted under GDPR/privacy policies, or outdated. 
We do not guarantee the accuracy of registration data returned.`
      },
      {
        heading: 'No Legal Advice',
        body: `Nothing on this platform constitutes legal advice. ThreatVector Intelligence 
is not a law firm and does not provide legal services. If you require legal guidance 
regarding domain abuse, intellectual property, or cybercrime matters, please consult 
a qualified legal professional.`
      },
      {
        heading: 'No Takedown Authority',
        body: `ThreatVector Intelligence is an independent DNS abuse investigation and 
reporting organization. We are not a domain registrar, registry, or ICANN-accredited 
body. We do not have the authority to suspend, delete, or modify domain registrations. 
Our role is to investigate, document, and report abuse to the appropriate parties — 
registrars, registries, and abuse desks — who hold the authority to act.`
      },
      {
        heading: 'Third-Party Links and Services',
        body: `This platform links to and integrates with third-party services including 
VirusTotal, RDAP/WHOIS providers, and others. We are not responsible for the content, 
availability, or privacy practices of these third-party services. Links to external 
sites do not constitute endorsement.`
      },
      {
        heading: 'Limitation of Liability',
        body: `To the fullest extent permitted by applicable law, ThreatVector Intelligence 
shall not be liable for any direct, indirect, incidental, consequential, or punitive 
damages arising from your use of this platform, reliance on information provided here, 
or actions taken based on our abuse reports or tool results.`
      },
      {
        heading: 'Changes',
        body: `We reserve the right to modify or update this Disclaimer at any time without 
prior notice. Your continued use of this platform following any changes constitutes 
acceptance of the updated Disclaimer.`
      },
    ]
  },
};

/* ── Show legal page ─────────────────────────────────────────── */
function showLegal(pageId) {
  const d = LEGAL_PAGES[pageId];
  if (!d) return;

  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-menu a').forEach(a => a.classList.remove('active'));

  const page = document.getElementById('legal-detail');
  if (!page) return;
  page.classList.add('active');
  window.scrollTo({ top: 0, behavior: 'smooth' });

  page.innerHTML = `
<div class="wrap">
  <div style="margin-bottom:40px">
    <button class="btn btn-g" onclick="history.back()" style="font-size:10px;padding:8px 18px">
      ← BACK
    </button>
  </div>

  <div class="sec-head">
    <div class="sec-tag">// ${d.tag}</div>
    <h2 class="sec-title">${d.title.toUpperCase()}</h2>
    <div class="sec-rule"></div>
    <div style="font-family:var(--mono);font-size:10px;color:var(--dim);margin-top:12px;letter-spacing:.1em">
      Last updated: ${d.updated}
    </div>
  </div>

  ${d.sections.map(s => `
  <div class="abuse-section">
    <div class="abuse-section-title">${s.heading}</div>
    <p class="abuse-body">${s.body.trim()}</p>
  </div>`).join('')}

</div>`;
}

/* ── Wire up footer legal links ──────────────────────────────── */
window.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.footer-legal a').forEach(a => {
    const txt = a.textContent.trim();
    let pageId = null;
    if (txt === 'Privacy Policy')   pageId = 'privacy';
    if (txt === 'Responsible Use')  pageId = 'responsible';
    if (txt === 'Disclaimer')       pageId = 'disclaimer';
    if (pageId) {
      a.style.cursor = 'pointer';
      a.onclick = (e) => { e.preventDefault(); showLegal(pageId); };
    }
  });
});
