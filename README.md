# hapara.fail Blocklist

[![jsDelivr](https://data.jsdelivr.com/v1/package/gh/hapara-fail/blocklist/badge)](https://www.jsdelivr.com/package/gh/hapara-fail/blocklist)

**A unified blocklist for neutralizing surveillance and content filtering systems in managed network environments.**

This repository contains a comprehensive blocklist designed for seamless integration with modern network filtering and ad-blocking solutions. Its purpose is to inhibit the function of software commonly used for student monitoring, web censorship, and other forms of network-level restriction.

**DNS with Blocklist:** **[www.hapara.fail/services/dns](https://www.hapara.fail/services/dns)**

---

## 🛡️ Objective

The primary objective of this blocklist is to provide network administrators and users with a tool to disable the functionality of specific third-party services. It operates by blocking connections to domains essential to the operation of:

* **Student Monitoring & Surveillance:** Applications that monitor user activity, capture screen content, and report on browsing habits.
* **Web Censorship & Filtering:** Cloud-based and on-premise solutions that restrict access to websites and online resources.
* **Device Management (MDM):** Infrastructure used to force-install applications and enforce restrictions on managed devices.
* **Location Tracking:** Services used to track the physical location of users and devices.

---

## ✨ Core Features

* **Focused Scope:** The list is curated to target domains directly associated with surveillance and filtering software, minimizing the potential for unintended service disruption.
* **Adblock Plus Syntax:** Formatted using the `||domain.com^` syntax for compatibility with specific ad-blocking software, ensuring precise domain and subdomain blocking.
* **Community-Maintained:** The blocklist is actively updated based on community-submitted intelligence and research to adapt to the changing domain infrastructure of targeted services.
* **Privacy-Oriented:** Designed to restore user autonomy and enhance digital privacy by disabling intrusive network monitoring and location tracking.

---

## ⚙️ Format & Compatibility

This blocklist uses the **Adblock Plus (ABP) syntax** (`||domain.com^`). Due to this specific formatting, it is only compatible with software that can correctly parse this syntax.

#### ✅ Supported Software
This list should only be used with the following software:
* Pi-hole
* AdGuard / AdGuard Home
* eBlocker
* uBlock Origin / AdNauseam
* Brave (with Shields set to Aggressive)
* Little Snitch Mini

#### ❌ Incompatible Software
The list is **not formatted for** the following software and is therefore incompatible:
* AdAway / adblock-lean
* Bind / Blocky / Knot
* Diversion
* DNS66 / DNSCloak / DNSCrypt / DNSMasq / NextDNS
* Hostfile-based blockers
* InviZible Pro / Nebulo / PersonalDNSfilter
* NetDuma / NetGuard / OPNsense / pfBlockerNG
* OpenSnitch / PersonalBlocklist
* PowerDNS / Technitium DNS / Unbound / YogaDNS
* Response Policy Zone (RPZ)
* uMatrix

---

## 📥 Implementation Guide

Integration of the blocklist is a straightforward process for supported software.

1.  **Copy the Raw Blocklist URL:**
    ```
    https://cdn.jsdelivr.net/gh/hapara-fail/blocklist@main/blocklist.txt
    ```

2.  **Add the URL to your Blocking Solution:**
    * **Pi-hole:** Navigate to `Group Management` > `Adlists` and add the URL as a new list source.
    * **AdGuard Home:** Go to `Filters` > `DNS blocklists` and select "Add blocklist" to import the URL.
    * **uBlock Origin / AdNauseam:** Open the dashboard, go to the "Filter lists" tab, scroll down to the "Custom" section, and paste the URL into the "Import" field. Then, click "Apply changes."
    * **Other Systems:** Consult the official documentation for your software, ensuring it supports the Adblock Plus syntax for custom remote lists.

---

## 👁️ Services Targeted

The blocklist is organized by service category for transparency. It currently includes domains related to the following platforms:

#### Monitoring & Classroom Management
* Hapara
* GoGuardian
* LanSchool
* Bark
* Gaggle
* Blocksi
* NetSupport
* DyKnow
* Impero
* Senso
* Pulse / EducatorImpact

#### Content Filtering & Security
* Lightspeed Systems
* Securly
* iboss
* Fortinet / FortiGuard
* Zscaler
* Linewize / Qoria / FamilyZone
* Content Keeper
* Smoothwall
* Sophos
* Netsweeper
* Deledao

#### Device Management (MDM) & Infrastructure
* Jamf
* Mosyle
* Gopher
* LFGL (London Grid for Learning)
* Mobile Guardian

#### Parental Control & Location Tracking
* Life360
* Qustodio
* Kiddoware

#### Common Dependencies
* Vendor-specific cloud infrastructure (AWS/Azure endpoints).
* Specific realtime communication fallbacks used by filtering agents.

---

## ⚠️ Disclaimer

* **Potential for Overblocking:** While the list is curated for precision, the use of wildcard domains or the blocking of shared infrastructure could disrupt legitimate services. **Thorough testing is strongly recommended** in a controlled environment before widespread deployment.
* **Effectiveness is Not Guaranteed:** The efficacy of this blocklist is contingent on the specific network architecture and filtering methods in place. It may not bypass all restrictive measures.
* **Service Infrastructure:** Targeted services frequently update their domains and hosting infrastructure. Continuous maintenance of this list is required for it to remain effective.
* **Responsible Use:** This blocklist is provided for informational purposes. Users are solely responsible for ensuring their use of this tool complies with all applicable acceptable use policies and local regulations.

-----

## 🤝 Contributing

Contributions are welcome! To ensure changes are processed quickly and correctly, please review our **[Contributing Guidelines](https://github.com/hapara-fail/blocklist/blob/main/CONTRIBUTING.md)** before submitting.

If you have ideas for improvements, new tools, bug fixes, or blog post topics, please feel free to:

* **Open an Issue** on GitHub using our standardized templates.
* **Submit a Pull Request** with your proposed changes.
* Join our [Discord server](https://discord.gg/KA66dHUF4P) to discuss.

You can also find donation options [here](https://hapara.fail/contribute).

-----

## 📄 License

This project is licensed under the terms specified at [license.hapara.fail](https://license.hapara.fail/).
