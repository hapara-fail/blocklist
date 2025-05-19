# hapara.fail DNS Blocklist

This repository contains a curated DNS blocklist primarily aimed at enhancing internet freedom on restricted networks, particularly in educational environments using services like Hapara, Linewize, Smoothwall, and others.

The list is provided in a raw format suitable for use with various DNS filtering solutions such as NextDNS, Pi-hole, AdGuard Home, or other DNS servers that support domain-based blocking.

## Purpose

The primary goal of this blocklist is to help users regain control over their internet access by blocking domains associated with:

* Student monitoring and surveillance software (e.g., Hapara, Gaggle)
* Content filtering and web censorship services (e.g., Linewize/Qoria, Smoothwall, FamilyZone)
* Other potentially restrictive or privacy-invasive services often found in managed network environments.

## Blocklist Format

The blocklist (`blocklist.txt`) is a simple text file where each line represents a domain to be blocked.

* Lines starting with `*.` are wildcard domains, blocking the domain and all its subdomains.
* Lines starting with `#` are comments and are ignored by DNS filtering systems. They are used here to categorize services.

## Services Targeted

This list currently includes domains related to the following services (among others):

* Hapara
* Linewize / Qoria / FamilyZone / Sphirewall
* Smoothwall
* Classwize (and related services like Ably, Xirsys, Stream)
* Gaggle
* Blackboard / Anthology
* Pulse (and related services like EducatorImpact, Zendesk)

## How to Use

1.  **Obtain the Raw List:** You can find this [here](https://raw.githubusercontent.com/hapara-fail/blocklist/refs/heads/main/blocklist.txt).
2.  **Add to Your DNS Filter:**
    * **NextDNS:** Add the URLs to your "Denylist."
    * **Pi-hole:** Add the URL to your "Adlists" under "Group Management."
    * **AdGuard Home:** Add the URL under "Filters" > "DNS blocklists."
    * **Other Systems:** Consult the documentation for your specific DNS filtering software. Most allow adding custom blocklists from a URL or by pasting the content.

## Important Considerations & Disclaimer

* **Overblocking:** While efforts are made to target specific services, some domains (especially wildcards or those related to CDNs/shared infrastructure) might inadvertently block legitimate or desired content. **Always test thoroughly after applying this blocklist.**
* **Maintenance:** This list is maintained based on available information. Services frequently change their domains and infrastructure.
* **Effectiveness:** The effectiveness of this blocklist can vary depending on how network restrictions are implemented in a specific environment. It is not a guaranteed solution for all scenarios.
* **Use Responsibly:** This blocklist is provided for informational and educational purposes. Users are responsible for complying with any applicable acceptable use policies in their respective environments.

## Contributing

If you find domains that are missing, incorrectly blocked, or no longer relevant, please feel free to:

1.  Open an Issue in this repository.
2.  Fork the repository, make your changes, and submit a Pull Request.

Please provide context or evidence for any proposed changes.

---

*This blocklist is maintained by the hapara.fail project.*
