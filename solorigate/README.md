# Tracking UNC2452-Related Reporting

MITRE's ATT&CK team - with the assistance of contributors - has been mapping techniques related to a recent intrusion campaign, referred to as NOBELIUM by Microsoft, by a threat group referred to as UNC2452/Dark Halo by FireEye and Volexity respectively, and more recently attributed to the existing APT29/Cozy Bear/The Dukes threat group by NSA, CISA, and FBI.

It's been difficult keeping up with all the reporting and updates while trying to track down descriptions of adversary behavior, particularly as we're looking for direct analysis of intrusion data rather than derivative reporting. To that end, we're sharing a list of the reports and alerts we've been following to date. This list doesn't include everything that has been said about this intrusion, but rather those reports directly analyzing intrusion data, with a focus on describing adversary behavior. If you're interested in what ATT&CK techniques we've spotted so far from UNC2452 and the SUNBURST/TEARDROP malware, you can see our current [ATT&CK Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fcenter-for-threat-informed-defense%2Fpublic-resources%2Fmaster%2Fsolorigate%2FUNC2452%2Bmalware.json), or [download it directly](UNC2452+malware.json). We've been updating what's new and being updated in ATT&CK [in our blog](https://medium.com/mitre-attack/identifying-unc2452-related-techniques-9f7b6c7f3714).

If you see a report you think we're missing that matches the above, we'd be interested in hearing about it through email at attack@mitre.org, Twitter DM to @mitreattack, or directly through this repo.

<!--ts-->
   * [Tracking UNC2452-Related Reporting](#tracking-unc2452-related-reporting)
      * [Checkpoint](#checkpoint)
      * [CrowdStrike](#crowdstrike)
      * [Department of Homeland Security/Cybersecurity and Infrastructure Security Agency (DHS/CISA)](#department-of-homeland-securitycybersecurity-and-infrastructure-security-agency-dhscisa)
      * [DomainTools](#domaintools)
      * [FireEye](#fireeye)
      * [Kaspersky](#kaspersky)
      * [McAfee](#mcafee)
      * [Microsoft](#microsoft)
      * [National Security Agency (NSA)](#national-security-agencynsa)
      * [Netresec](#netresec)
      * [Palo Alto](#palo-alto)
      * [ReversingLabs](#reversinglabs)
      * [SolarWinds](#solarwinds)
      * [Symantec](#symantec)
      * [UK National Cyber Security Centre (NCSC)](#uk-national-cyber-security-centre-ncsc)
      * [US Senate Select Committe on Intelligence (SSCI)](#us-senate-select-committe-on-intelligence-ssci)
      * [US White House](#us-white-house)
      * [Volexity](#volexity)
      * [Yahoo](#yahoo)

<!-- Added by: adamp, at: Thu Apr 15 19:14:52 EDT 2021 -->

<!--te-->

---

## Checkpoint
- Analysis of the SUNBURST backdoor and its TEARDROP payload with a focus on their obfuscation and control flow.
    - Released 22 December 2020
    - https://research.checkpoint.com/2020/sunburst-teardrop-and-the-netsec-new-normal/

## CrowdStrike
- CrowdStrike, through its work with SolarWinds, identified what it refers to as the SUNSPOT implant, which was used to inject the SUNBURST backdoor into software builds of the SolarWinds Orion IT management product. CrowdStrike is tracking this intrusion under the "StellarParticle" activity cluster.
    - Released 11 January 2021
    - https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/

## Department of Homeland Security/Cybersecurity and Infrastructure Security Agency (DHS/CISA)
- CISA released a Malware Analysis Report for SOLARFLARE/GoldFinder and SUNSHUTTLE/GoldMax malware.
    - Released 15 April 2021
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-105a  
- CISA created a central page related to the Russian Foreign Intelligence Service's (SVR) targeting of US and Allied networks; the page includes a summary of CVEs SVR actors are exploiting, related alerts, Malware Analysis Reports for SUNBURST and TEARDROP, and remediation guidance for networks affected by this campaign.
    - Released 15 April 2021
    - https://us-cert.cisa.gov/ncas/current-activity/2021/04/15/nsa-cisa-fbi-joint-advisory-russian-svr-targeting-us-and-allied   
- CISA released a table of tactics, techniques, and procedures (TTPs) used by UNC2452 in the SolarWinds and Active Directory/M365 compromise. The table is desiged to help network defenders detect and remediate this activity by pairing tactics and techniques with corresponding detection recommendations.
    - Released 17 March 2021
    - https://us-cert.cisa.gov/sites/default/files/publications/SolarWinds_and_AD-M365_Compromise-Detecting_APT_Activity_from_Known_TTPs.pdf  
- CISA created a centralized guidance page for conducting a risk/impact assessment, with corresponding remediation recommendations, for federal agencies, critical infrastructure operators, and private organizations. In the "Threat Actor Activity" section, CISA confirmed the attackers also gained initial access via password guessing (T1110.001) and password spraying (T1110.003), in addition to the supply chain compromise.
    - Released 9 March 2021
    - https://us-cert.cisa.gov/ncas/current-activity/2021/03/09/guidance-remediating-networks-affected-solarwinds-and-active
    - https://us-cert.cisa.gov/remediating-apt-compromised-networks  
- CISA released two Malware Analysis Reports (MAR) for SUNBURST and TEARDROP respectively.
    - Released 8 February 2021
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-039a
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-039b
- CISA issued an accompanying Alert to AA20-352a that addresses additional TTPs attributed to the same actor. The Alert notes techniques unrelated to compromised SolarWinds Orion products the APT actor may have used to obtain initial access, and provides a list of detection tools and methods.
    - Released 8 January 2021 (**Updated 4 February 2021**)
    - https://us-cert.cisa.gov/ncas/alerts/aa21-008a
- On 5 January 2021, CISA, FBI, NSA, and ODNI issued a joint statement that noted the SolarWinds intrusion was "likely Russian in origin" and to date fewer then 10 US government organizations had been compromised, however the investigation is ongoing.
    - Released 5 January 2021
    - https://www.cisa.gov/news/2021/01/05/joint-statement-federal-bureau-investigation-fbi-cybersecurity-and-infrastructure
- On 23 December, CISA announced its creation of a new Supply Chain Compromise website related to what CISA describes as an ongoing intrusion.
    - Released 23 December 2020
    - https://us-cert.cisa.gov/ncas/current-activity/2020/12/23/cisa-releases-cisa-insights-and-creates-webpage-ongoing-apt-cyber
- CISA is periodically updating this alert regarding observed TTPs and mitigation recommendations; as of 19 December 2020 CISA noted evidence of initial access vectors other than the SolarWinds Orion platform.
    - Released 17 December 2020 (**Updated 8 February 2021**)
    - https://us-cert.cisa.gov/ncas/alerts/aa20-352a
- CISA is also updating Emergency Directive 21–01, including corresponding guidance, as more information about the attack becomes available.
    - Released 13 December 2020 (**Updated 6 January 2021**)
    - https://cyber.dhs.gov/ed/21-01/#supplemental-guidance

## DomainTools
- An analysis of the network C2 infrastructure used by the SUNBURST malware along with timeline information gathered from DomainTools' passive DNS.
    - Released 14 December 2020
    - https://www.domaintools.com/resources/blog/unraveling-network-infrastructure-linked-to-the-solarwinds-hack

## FireEye
- SUNSHUTTLE malware analysis report describing a newly-reported second-stage backdoor with links to UNC2452. SUNSHUTTLE is a Go-based backdoor that can generate fake traffic and responds to a number of commands from a C2 over HTTPS. This report was released in parallel with Microsoft's NOBELIUM report, which refers to this malware as GoldMax.
  - Released 4 March 2021
  - https://www.fireeye.com/blog/threat-research/2021/03/sunshuttle-second-stage-backdoor-targeting-us-based-entity.html    

- Blog post describing a number of adversary tactics, techniques, and procedures observed from UNC2452. The March 18th update added information about a new behavior, the threat actors modifying the permissions of mailbox folders.
  - Released 19 January 2021 (**Updated 18 March 2021***)
  - https://www.fireeye.com/blog/threat-research/2021/01/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452.html

- An in-depth analysis of the SUNBURST backdoor with a focus on anti-analysis environment checks and blocklists, domain generation algorithm and variations, command and Control (C2) behaviors for DNS A and CNAME records, and malware modes of operation.
    - Released 24 December 2020
    - https://www.fireeye.com/blog/threat-research/2020/12/sunburst-additional-technical-details.html
- FireEye's initial report on UNC2452, SUNBURST malware, and TEARDROP malware, containing observed TTPs, detection opportunities, and mitigation recommendations.
    - Released 13 December 2020
    - https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- A repository of countermeasures against malware related to the UNC2452 Solarwinds compromise. Note: this repository contains signatures and indicators for the COSMICGALE and SUPERNOVA malware, which was originally combined with information from the UNC2452 Solarwinds compromise but was separated out as an unrelated intrusion on 16 December 2020.
    - Released 13 December 2020 (**Updated 21 December 2020**)
    - https://github.com/fireeye/sunburst_countermeasures
- In a broader context, it's also worth bearing in mind the theft of FireEye's Red Team tools, as disclosed in early December. This theft was later linked to UNC2452 in Kevin Mandia's SSCI testimony.
    - Released 8 December 2020
    - https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html

## Kaspersky
- Malware analysis identifying potential overlaps between the Sunburst backdoor and a previously identified .NET backdoor known as Kazuar. Kazuar was first reported by Palo Alto in 2017 and was tentatively linked to the Turla APT group, although no solid attribution link has been made. 
    - Released 11 January 2021
    - https://securelist.com/sunburst-backdoor-kazuar/99981/

## McAfee
- McAfee Labs' analysis of SUNBURST malware.
    - Released 17 December 2020
    - https://www.mcafee.com/blogs/other-blogs/mcafee-labs/additional-analysis-into-the-sunburst-backdoor/

## Microsoft
- Introduction of NOBELIUM as the threat actor group name and includes analysis of three recently discovered pieces of malware: GoldMax - a RAT written in Go that can generate decoy network traffic (named by FireEye as SUNSHUTTLE), Silbot - malware that maintains persistence and can download and execute arbitrary payloads from a C2 server, and GoldFinder - another Go-based tool that can map out hops and proxies to a given C2 server.
    - Released 4 March 2021
    - https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/ 
- In-depth analysis of how the actors moved from SUNBURST/Solorigate to TEARDROP and RAINDROP to Cobalt Strike, and measures taken to reduce chances of detection.
    - Released 20 January 2021
    - https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
- Updated information on the known extent of Solorigate activity within Microsoft with some new details on actor behavior.
    - Released 31 December 2020
    - https://msrc-blog.microsoft.com/2020/12/31/microsoft-internal-solorigate-investigation-update/
- An overview of the "Solorigate" cyber intrusion targeted at users of Microsoft 365 Defender containing some new details of post-compromise activity.
    - Released 28 December 2020
    - https://www.microsoft.com/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/
- A central list of Microsoft’s posts/reports/other hunting resources related to the “NOBELIUM” intrusion.
    - Released 21 December 2020 (**Updated 4 March 2021**)
    -  https://aka.ms/nobelium
- Detailed descriptions of attack patterns against identity mechanisms and visible indications of compromise to identity vendors and consumers.
    - Released 21 December 2020
    - https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610
    - https://twitter.com/JohnLaTwC/status/1341116928350277632
- Detailed analysis of Solorigate (SUNBURST) malware, including a reference at the end of this report regarding a separate DLL (SUPERNOVA) Microsoft concludes was not part of this intrusion.
    - Released 18 December 2020
    - https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
- New hunting and detection queries for Azure Sentinel.
    - Released 16 December 2020 (**Updated 15 January 2021**)
    - https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095
- An overview of the “solorigate” cyber intrusion and a frequently updated list of most of the public Microsoft posts/reports related to it targeted at customers.
    - Released 13 December 2020 (**Updated 21 December 2020**)
    - https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
- Microsoft’s initial report describing key early activities in the intrusion at a high level.
    - Released 13 December 2020
    - https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/

## National Security Agency (NSA)
- NSA issued a joint cybersecurity advisory, along with DHS/CISA and the FBI, regarding recent Russian SVR cyber activities, including the SolarWinds compromise. The advisory cites CVEs exploited as well as observed techniques, and provides mitigation guidance.
    - Released 15 April 2021
    - https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF
- NSA issued a related cybersecurity advisory regarding detecting abuse of authentication mechanisms, including TTPs for gaining access to a victim network's cloud resources.
    - Released 17 December 2020
    - https://twitter.com/NSACyber/status/1339759778923474944
    - https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF

## Netresec
- Additional details of the DNS-based C2 protocol used by the SUNBURST malware, with a focus on the "stage 2" CNAME-based protocol.
    - Released 18 February 2021 
    - https://www.netresec.com/?page=Blog&month=2021-02&post=Targeting-Process-for-the-SolarWinds-Backdoor
- Technical details of SUNBURST DNS queries with information about a bit set by the malware to indicate that it is ready for a new C2 domain. This bit may be usable from passive DNS queries to determine what stage of intrusion a system progessed to.
    - Released 4 January 2021
    - https://www.netresec.com/?page=Blog&month=2021-01&post=Finding-Targeted-SUNBURST-Victims-with-pDNS

## Palo Alto
- A timeline summary of this intrusion based on publicly-available information as well as Palo Alto's internal data.
    - Released 23 December 2020
    - https://unit42.paloaltonetworks.com/solarstorm-supply-chain-attack-timeline/

## ReversingLabs
- ReversingLabs' analysis of how the attackers compromised the SolarWinds Orion software release process by blending in with the affected code base, mimicking the developer's coding style and naming standards.
    - Released 16 December 2020
    - https://blog.reversinglabs.com/blog/sunburst-the-next-level-of-stealth

## SolarWinds
- SolarWinds provided an update on its investigation that included an attack timeline and initial references to the SUNSPOT implant.
    - Released 11 January 2021
    - https://orangematter.solarwinds.com/2021/01/11/new-findings-from-our-investigation-of-sunburst/
- SolarWinds 8-K filings related to their security incident that include unique details on how their Orion Platform products were modified.
    - Released 17 December 2020
    - https://www.sec.gov/ix?doc=/Archives/edgar/data/1739942/000162828020017451/swi-20201214.htm
    - https://www.sec.gov/ix?doc=/Archives/edgar/data/1739942/000162828020017620/swi-20201217.htm
- SolarWinds is updating its security advisory as new information becomes available, including which products are and are not known to be affected.
    - Released 13 December 2020 (**Updated 29 January 2021**)
    - https://www.solarwinds.com/securityadvisory

## Symantec
- The fourth and final report on SUNBURST's command and control, focusing on how the malware sends data back to the attackers through HTTP(S) POST requests.
    - Released 22 January 2021
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-sunburst-sending-data
- Analysis of a new piece of malware, Raindrop, which was deployed laterally in intrusions and used for loading Cobalt Strike. Also describes a credential dumper designed specifically for SolarWinds Orion databases similar to the open source "solarflare" tool.
    - Released 19 January 2021
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-raindrop-malware
    - https://twitter.com/ChristiaanBeek/status/1351515962768502786
- Describes the control flow via DNS for the Sunburst backdoor's command and control.
    - Released 15 January 2021
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-sunburst-command-control
- Analysis of how the Sunburst backdoor's domain generation algorithm (DGA) was used to initiate contact with the attackers’ command and control servers.
    - Released 7 January 2021
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-unique-dga
- Describes a number of defense evasion techniques used by the Sunburst backdoor.
    - Released 21 December 2020
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-attacks-stealthy-attackers-attempted-evade-detection
- Analysis of the Sunburst backdoor and its Teardrop payload along with a description of some post-compromise behaviors from analysis of a victim computer.
    - Released 14 December 2020 (**Updated 16 December 2020**)
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/sunburst-supply-chain-attack-solarwinds

## UK National Cyber Security Centre (NCSC)
- The UK NCSC published an alert stating Russia's SVR was responsible for the SolarWinds compromise, in addition to other cyber intrusions. The alert included links to NCSC guidance, including "Dealing with the SolarWinds Orion compromise" and "Identifying suspicious credential usage".
  - Released 15 April 2021
  - https://www.ncsc.gov.uk/news/uk-and-us-call-out-russia-for-solarwinds-compromise

## US Senate Select Committe on Intelligence (SSCI)
- Opening statements from FireEye CEO Kevin Mandia, Microsoft President Brad Smith, CrowdStrike CEO George Kurtz, and SolarWinds CEO Sudhakar Ramakrishna during the SSCI open hearing, "Hearing on the Hack of U.S. Networks by a Foreign Adversary".
   - Released 23 February 2021
   - https://www.intelligence.senate.gov/sites/default/files/documents/os-kmandia-022321.pdf
   - https://www.intelligence.senate.gov/sites/default/files/documents/os-bsmith-022321.pdf
   - https://www.intelligence.senate.gov/sites/default/files/documents/os-gkurtz-022321.pdf
   - https://www.intelligence.senate.gov/sites/default/files/documents/os-sramakrishna-022321.pdf   

## US White House
- The US White House released a fact sheet titled, "Imposing Costs for Harmful Foreign Activities by the Russian Government", that included the formal attribution of the SolarWinds Orion software compromise to Russia's SVR. The announcement also mentioned financial sanctions against six Russian technology companies that provide support to Russian intelligence cyber operations.
    - Released 15 April 2021
    - https://www.whitehouse.gov/briefing-room/statements-releases/2021/04/15/fact-sheet-imposing-costs-for-harmful-foreign-activities-by-the-russian-government/

## Volexity
- Volexity tied the SolarWinds Orion software compromise to a threat group it tracks as "Dark Halo"; this report focuses on command-line actions taken post-compromise at a US-based think tank over the course of three Dark Halo intrusions, starting in late 2019.
    - Released 14 December 2020
    - https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/


## Yahoo
- Reporting by Kim Zetter that incudes details on UNC2452 enrolling a mobile device into FireEye's multi-factor authentication system in order to authenticate to the FireEye VPN.
    - Released 18 December 2020
    - https://news.yahoo.com/hackers-last-year-conducted-a-dry-run-of-solar-winds-breach-215232815.html

---
©2021 The MITRE Corporation. ALL RIGHTS RESERVED Approved for public release. Distribution unlimited 20-00841-19.
