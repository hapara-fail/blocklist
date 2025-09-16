# hapara.fail DNS Blocklist

**A DNS blocklist for neutralizing surveillance and content filtering systems in managed network environments.**

This repository contains a universal blocklist designed for seamless integration with modern DNS filtering solutions. Its purpose is to inhibit the function of software commonly used for student monitoring, web censorship, and other forms of network-level restriction.

### Core Features

* **Focused Scope:** The list is curated to target domains directly associated with surveillance and filtering software, minimizing the potential for unintended service disruption.
* **Adblock Plus Syntax:** Formatted using the `||domain.com^` syntax for compatibility with specific ad-blocking software, ensuring precise domain and subdomain blocking.
* **Community-Maintained:** The blocklist is actively updated based on community-submitted intelligence and research to adapt to the changing domain infrastructure of targeted services.
* **Privacy-Oriented:** Designed to restore user autonomy and enhance digital privacy by disabling intrusive network monitoring.

## Objective

The primary objective of this blocklist is to provide network administrators and users with a tool to disable the functionality of specific third-party services. It operates by blocking DNS resolution for domains essential to the operation of:

* **Student Monitoring & Surveillance:** Applications that monitor user activity, capture screen content, and report on browsing habits.
* **Web Censorship & Filtering:** Cloud-based and on-premise solutions that restrict access to websites and online resources.
* **Restrictive Network Technologies:** Various other services that limit user control and compromise privacy within a managed network.

## Format & Compatibility

This blocklist uses the **Adblock Plus (ABP) syntax** (`||domain.com^`). Due to this specific formatting, it is only compatible with software that can correctly parse this syntax.

#### ✅ Supported Software
This list should only be used with the following software:
* Pi-hole
* AdGuard
* AdGuard Home
* eBlocker
* uBlock Origin
* Brave (with Shields set to Aggressive)
* AdNauseam
* Little Snitch Mini

#### ❌ Incompatible Software
The list is **not formatted for** the following software and is therefore incompatible:
* AdAway
* adblock-lean
* Bind
* Blocky
* Diversion
* DNS66
* DNSCloak / DNSCrypt
* DNSMasq
* Hostfile-based blockers (Linux, etc.)
* InviZible Pro
* Knot
* Nebulo
* NetDuma
* NetGuard
* NextDNS
* OPNsense / pfBlockerNG
* OpenSnitch
* PersonalBlocklist
* PersonalDNSfilter
* PowerDNS
* Response Policy Zone (RPZ)
* Technitium DNS
* uMatrix
* Unbound
* YogaDNS

## Implementation Guide

Integration of the blocklist is a straightforward process for supported software.

1.  **Copy the Raw Blocklist URL:**
    > ```
    > [https://raw.githubusercontent.com/hapara-fail/blocklist/main/blocklist.txt](https://raw.githubusercontent.com/hapara-fail/blocklist/main/blocklist.txt)
    > ```

2.  **Add the URL to your DNS Filtering Solution:**
    * **Pi-hole:** Navigate to `Group Management` > `Adlists` and add the URL as a new list source.
    * **AdGuard Home:** Go to `Filters` > `DNS blocklists` and select "Add blocklist" to import the URL.
    * **uBlock Origin / AdNauseam:** Open the dashboard, go to the "Filter lists" tab, scroll down to the "Custom" section, and paste the URL into the "Import" field. Then, click "Apply changes."
    * **Other Systems:** Consult the official documentation for your software, ensuring it supports the Adblock Plus syntax for custom remote lists.

## Services Targeted

The blocklist is organized by service category for transparency. It currently includes domains related to the following platforms, among others:

#### Monitoring & Classroom Management
* Bark
* DyKnow
* Gaggle
* GoGuardian
* Gopher
* Hapara
* LanSchool
* Senso

#### Content Filtering & Security
* Blocksi
* Content Keeper
* Fortinet / FortiGuard
* Iboss
* Lightspeed Systems
* Linewize / Qoria / FamilyZone
* Netsweeper
* Securly
* Smoothwall

#### Platform & Infrastructure
* Anthology / Blackboard
* Deledao
* LFGL (London Grid for Learning)
* Pulse / EducatorImpact

#### Common Dependencies
* Ably
* Pusher
* Domains for CDNs and other backend services required by the above platforms.

## Disclaimer and Important Considerations

* **Potential for Overblocking:** While the list is curated for precision, the use of wildcard domains or the blocking of shared infrastructure could disrupt legitimate services. **Thorough testing is strongly recommended** in a controlled environment before widespread deployment.
* **Effectiveness is Not Guaranteed:** The efficacy of this blocklist is contingent on the specific network architecture and filtering methods in place. It may not bypass all restrictive measures.
* **Service Infrastructure:** Targeted services frequently update their domains and hosting infrastructure. Continuous maintenance of this list is required for it to remain effective.
* **Responsible Use:** This blocklist is provided for informational purposes. Users are solely responsible for ensuring their use of this tool complies with all applicable acceptable use policies and local regulations.

## Contributions

Contributions are welcome to maintain the efficacy and accuracy of this list. If you identify missing domains, incorrect entries, or domains that are no longer relevant, please assist by:

1.  **Opening an Issue** in this repository to report your findings.
2.  **Submitting a Pull Request** with your proposed changes.

Please include supporting documentation or context for any proposed modifications.

---
*This blocklist is an open-source initiative maintained by [hapara.fail](https://hapara.fail).*
