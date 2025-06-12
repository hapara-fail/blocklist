# hapara.fail DNS Blocklist

**A DNS blocklist for neutralizing surveillance and content filtering systems in managed network environments.**

This repository contains a universal blocklist designed for seamless integration with modern DNS filtering solutions. Its purpose is to inhibit the function of software commonly used for student monitoring, web censorship, and other forms of network-level restriction.

### Core Features

* **Focused Scope:** The list is curated to target domains directly associated with surveillance and filtering software, minimizing the potential for unintended service disruption.
* **Standard Format:** Provided as a raw text file, the list is compatible with a wide range of DNS filtering applications, including NextDNS, Pi-hole, and AdGuard Home.
* **Community-Maintained:** The blocklist is actively updated based on community-submitted intelligence and research to adapt to the changing domain infrastructure of targeted services.
* **Privacy-Oriented:** Designed to restore user autonomy and enhance digital privacy by disabling intrusive network monitoring.

## Objective

The primary objective of this blocklist is to provide network administrators and users with a tool to disable the functionality of specific third-party services. It operates by blocking DNS resolution for domains essential to the operation of:

* **Student Monitoring & Surveillance:** Applications that monitor user activity, capture screen content, and report on Browse habits.
* **Web Censorship & Filtering:** Cloud-based and on-premise solutions that restrict access to websites and online resources.
* **Restrictive Network Technologies:** Various other services that limit user control and compromise privacy within a managed network.

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

## Implementation Guide

Integration of the blocklist is a straightforward process.

1.  **Copy the Raw Blocklist URL:**
    > ```
    > [https://raw.githubusercontent.com/hapara-fail/blocklist/main/blocklist.txt](https://raw.githubusercontent.com/hapara-fail/blocklist/main/blocklist.txt)
    > ```

2.  **Add the URL to your DNS Filtering Solution:**
    * **NextDNS:** In the `Denylist` tab, paste the URL into the provided input field.
    * **Pi-hole:** Navigate to `Group Management` > `Adlists` and add the URL as a new list source.
    * **AdGuard Home:** Go to `Filters` > `DNS blocklists` and select "Add blocklist" to import the URL.
    * **Other Systems:** Consult the official documentation for your software. Most systems support adding custom blocklists from a remote URL.

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
