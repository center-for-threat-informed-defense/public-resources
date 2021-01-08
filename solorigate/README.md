# Tracking UNC2452-Related Reporting

MITRE's ATT&CK team - with the assistance of contributors - has been mapping techniques related to a recent intrusion campaign, referred to as Solorigate by Microsoft, by a threat group referred to as UNC2452/Dark Halo by FireEye and Volexity respectively.

It's been difficult keeping up with all the reporting and updates while trying to track down descriptions of adversary behavior, particularly as we're looking for direct analysis of intrusion data rather than derivative reporting. To that end, we're sharing a list of the reports and alerts we've been following to date. This list doesn't include everything that has been said about this intrusion, but rather those reports directly analyzing intrusion data, with a focus on describing adversary behavior. If you're interested in what ATT&CK techniques we've spotted so far from UNC2452 and the SUNBURST/TEARDROP malware, you can see our current [ATT&CK Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fcenter-for-threat-informed-defense%2Fpublic-resources%2Fmaster%2Fsolorigate%2FUNC2452%2Bmalware.json), or [download it directly](UNC2452+malware.json). We've been updating what's new and being updated in ATT&CK [in our blog](https://medium.com/mitre-attack/identifying-unc2452-related-techniques-9f7b6c7f3714).

If you see a report you think we're missing that matches the above, we'd be interested in hearing about it through email at attack@mitre.org, Twitter DM to @mitreattack, or directly through this repo.

<!--ts-->
   * [Tracking UNC2452-Related Reporting](#tracking-unc2452-related-reporting)
      * [Checkpoint](#checkpoint)
      * [Department of Homeland Security/Cybersecurity and Infrastructure Security Agency (DHS/CISA)](#department-of-homeland-securitycybersecurity-and-infrastructure-security-agency-dhscisa)
      * [DomainTools](#domaintools)
      * [FireEye](#fireeye)
      * [McAfee](#mcafee)
      * [Microsoft](#microsoft)
      * [National Security Agency (NSA)](#national-security-agencynsa)
      * [Netresec](#netresec)
      * [Palo Alto](#palo-alto)
      * [ReversingLabs](#reversinglabs)
      * [SolarWinds](#solarwinds)
      * [Symantec](#symantec)
      * [Volexity](#volexity)

<!-- Added by: adamp, at: Thu Jan  7 19:31:51 EST 2021 -->

<!--te-->

---

## Checkpoint
- Analysis of the SUNBURST backdoor and its TEARDROP payload with a focus on their obfuscation and control flow.
    - Released 22 December 2020
    - https://research.checkpoint.com/2020/sunburst-teardrop-and-the-netsec-new-normal/

## Department of Homeland Security/Cybersecurity and Infrastructure Security Agency (DHS/CISA)
- CISA issued an accompanying Alert to AA20-352a that addresses additional TTPs attributed to the same actor. The Alert notes techniques unrelated to compromised SolarWinds Orion products the APT actor may have used to obtain initial access, and provides a list of detection tools and methods.
    - Released 8 January 2021
    - https://us-cert.cisa.gov/ncas/alerts/aa21-008a

- On 5 January 2021, CISA, FBI, NSA, and ODNI issued a joint statement that noted the SolarWinds intrusion was "likely Russian in origin" and to date fewer then 10 US government organizations had been compromised, however the investigation is ongoing.
    - Released 5 January 2021
    - https://www.cisa.gov/news/2021/01/05/joint-statement-federal-bureau-investigation-fbi-cybersecurity-and-infrastructure

- On 23 December, CISA announced its creation of a new Supply Chain Compromise website related to what CISA describes as an ongoing intrusion.
    - Released 23 December 2020
    - https://us-cert.cisa.gov/ncas/current-activity/2020/12/23/cisa-releases-cisa-insights-and-creates-webpage-ongoing-apt-cyber

- CISA is periodically updating this alert regarding observed TTPs and mitigation recommendations; as of 19 December 2020 CISA noted evidence of initial access vectors other than the SolarWinds Orion platform.
    - Released 17 December 2020 (**Updated 6 January 2021**)
    - https://us-cert.cisa.gov/ncas/alerts/aa20-352a

- CISA is also updating Emergency Directive 21–01, including corresponding guidance, as more information about the attack becomes available.
    - Released 13 December 2020 (**Updated 6 January 2021**)
    - https://cyber.dhs.gov/ed/21-01/#supplemental-guidance

## DomainTools
- An analysis of the network C2 infrastructure used by the SUNBURST malware along with timeline information gathered from DomainTools' passive DNS.
    - Released 14 December 2020
    - https://www.domaintools.com/resources/blog/unraveling-network-infrastructure-linked-to-the-solarwinds-hack

## FireEye
- An in-depth analysis of the SUNBURST backdoor with a focus on anti-analysis environment checks and blocklists, domain generation algorithm and variations, command and Control (C2) behaviors for DNS A and CNAME records, and malware modes of operation.
    - Released 24 December 2020
    - https://www.fireeye.com/blog/threat-research/2020/12/sunburst-additional-technical-details.html

- FireEye's initial report on UNC2452, SUNBURST malware, and TEARDROP malware, containing observed TTPs, detection opportunities, and mitigation recommendations.
    - Released 13 December 2020
    - https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

- A repository of countermeasures against malware related to the UNC2452 Solarwinds compromise. Note: this repository contains signatures and indicators for the COSMICGALE and SUPERNOVA malware, which was originally combined with information from the UNC2452 Solarwinds compromise but was separated out as an unrelated intrusion on 16 December 2020.
    - Released 13 December 2020 (**Updated 21 December 2020**)
    - https://github.com/fireeye/sunburst_countermeasures

- In a broader context, it's also worth bearing in mind the theft of FireEye's Red Team tools, as disclosed in early December.
    - Released 8 December 2020
    - https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html

## McAfee
- McAfee Labs' analysis of SUNBURST malware.
    - Released 17 December 2020
    - https://www.mcafee.com/blogs/other-blogs/mcafee-labs/additional-analysis-into-the-sunburst-backdoor/

## Microsoft
- Updated information on the known extent of Solorigate activity within Microsoft with some new details on actor behavior.
    - Released 31 December 2020
    - https://msrc-blog.microsoft.com/2020/12/31/microsoft-internal-solorigate-investigation-update/
- An overview of the "Solorigate" cyber intrusion targeted at users of Microsoft 365 Defender containing some new details of post-compromise activity.
    - Released 28 December 2020
    - https://www.microsoft.com/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/
- A central list of Microsoft’s posts/reports/other hunting resources related to the “solorigate” intrusion.
    - Released 21 December 2020 (**Updated 31 December 2020**)
    - https://aka.ms/solorigate
- Detailed descriptions of attack patterns against identity mechanisms and visible indications of compromise to identity vendors and consumers.
    - Released 21 December 2020
    - https://techcommunity.microsoft.com/t5/azure-active-directory-identity/understanding-quot-solorigate-quot-s-identity-iocs-for-identity/ba-p/2007610
    - https://twitter.com/JohnLaTwC/status/1341116928350277632
- Detailed analysis of Solorigate (SUNBURST) malware, including a reference at the end of this report regarding a separate DLL (SUPERNOVA) Microsoft concludes was not part of this intrusion.
    - Released 18 December 2020
    - https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
- New hunting and detection queries for Azure Sentinel.
    - Released 16 December 2020 (**Updated 28 December 2020**)
    - https://techcommunity.microsoft.com/t5/azure-sentinel/solarwinds-post-compromise-hunting-with-azure-sentinel/ba-p/1995095
- An overview of the “solorigate” cyber intrusion and a frequently updated list of most of the public Microsoft posts/reports related to it targeted at customers.
    - Released 13 December 2020 (**Updated 21 December 2020**)
    - https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
- Microsoft’s initial report describing key early activities in the intrusion at a high level.
    - Released 13 December 2020
    - https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/

## National Security Agency (NSA)
- NSA issued a related cybersecurity advisory regarding detecting abuse of authentication mechanisms, including TTPs for gaining access to a victim network's cloud resources.
    - Released 17 December 2020
    - https://twitter.com/NSACyber/status/1339759778923474944
    - https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF

## Netresec
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
- SolarWinds 8-K filings related to their security incident that include unique details on how their Orion Platform products were modified.
    - Released 17 December 2020
    - https://www.sec.gov/ix?doc=/Archives/edgar/data/1739942/000162828020017451/swi-20201214.htm
    - https://www.sec.gov/ix?doc=/Archives/edgar/data/1739942/000162828020017620/swi-20201217.htm

- SolarWinds is updating its security advisory as new information becomes available, including which products are and are not known to be affected.
    - Released 13 December 2020 (**Updated 31 December 2020**)
    - https://www.solarwinds.com/securityadvisory

## Symantec
- Describes a number of defense evasion techniques used by the Sunburst backdoor.
    - Released 21 December 2020
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-attacks-stealthy-attackers-attempted-evade-detection
- Analysis of the Sunburst backdoor and its Teardrop payload along with a description of some post-compromise behaviors from analysis of a victim computer.
    - Released 14 December 2020 (**Updated 16 December 2020**)
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/sunburst-supply-chain-attack-solarwinds


## Volexity
- Volexity tied the SolarWinds Orion software compromise to a threat group it tracks as "Dark Halo"; this report focuses on command-line actions taken post-compromise at a US-based think tank over the course of three Dark Halo intrusions, starting in late 2019.
    - Released 14 December 2020
    - https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/



---
©2020 The MITRE Corporation. ALL RIGHTS RESERVED Approved for public release. Distribution unlimited 20-00841-19.
