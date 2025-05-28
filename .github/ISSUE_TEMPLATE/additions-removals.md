---
name: Additions/removals
about: Used to request domans be added or removed from the blocklist.
title: "[A/R] "
labels: ''
assignees: nota9x

---

# Domain Addition/Removal Request for hapara.fail DNS Bypass Blocklist

Please use this template to request that domain(s) be **ADDED** to the blocklist (to block a new filtering/monitoring service or unwanted domain) OR **REMOVED** from the blocklist (e.g., if a service is no longer relevant, over-blocked, or its non-blocking is desired for specific reasons not constituting a critical false positive).

---

**Type of Request:** *(Please check one)*
- [ ] **ADD Domain(s) to Blocklist**
- [ ] **REMOVE Domain(s) from Blocklist**

---

**1. Domain(s) in Question:**
*List each domain on a new line.*

[https://www.google.com/search?q=exampledomain1.com]
[subdomain.exampledomain2.net]


**2. Service or Application Associated with Domain(s):**
*What service, application, or type of content are these domains primarily associated with? (e.g., Hapara, Securly, a specific ad network, a known tracker, a parental control system, etc.)*

> _Your answer here_

**3. Justification for Request:**

* **If ADDING domain(s):**
    *Why should these domains be added to the blocklist? What specific filtering, tracking, monitoring, or other unwanted behavior are they responsible for or contribute to? How does blocking them improve the user experience, privacy, or bypass effectiveness on managed devices?*
    > _Your explanation here_

* **If REMOVING domain(s):**
    *Why should these domains be removed from the blocklist? For example:*
        * *Is the service they relate to no longer active or relevant for blocking?*
        * *Do they block a non-essential but desired service whose functionality is preferred by some users over its potential for tracking/filtering (and it's not breaking critical web functions like a false positive would)?*
        * *Were they part of a broader block that could be more targeted?*
    > _Your explanation here_

**4. Evidence & Supporting Information:**
*Please provide evidence to support your request. This helps in evaluating the necessity and impact of the change.*

* **How were these domains identified and linked to the specified service or behavior?** *(e.g., Analysis of network logs, DNS query patterns when the service is active, browser developer tools, public documentation or reports about the service, etc.).*
    > _Your answer here_

* **For Additions: What is the observed impact of *not* blocking these domains?** *(e.g., "Allows `agent.example.com` to report Browse activity," "Enables `filter.cdn.example.net` to enforce restrictions," "Serves intrusive advertisements from `ads.example.org` on educational sites").*
    > _Your answer here_

* **For Removals: What is the anticipated positive impact of removing these domains?** *(e.g., "Will allow users to access `optional-service.com` which is currently blocked by its association with `cdn.example.net`," "The service `old-filter.com` is defunct, so its domains are no longer necessary to block.")*
    > _Your answer here_

* **Link to Supporting Documentation, Screenshots, Logs (Optional but helpful):** *(e.g., Link to a report about the tracking service, screenshot of network requests, snippet from DNS logs. Upload to Imgur, Pastebin, GitHub Gist, etc., and paste the link(s) here).*
    > _Link(s) here_

**5. Additional Context (Optional):**
*Is there anything else relevant to this request? For example:*
* *Known aliases or related domains.*
* *If adding, are there specific paths or subdomains that are most critical to block?*
* *If removing, are there any potential negative consequences to consider?*
> _Your additional context here_

---

**Confirmation:** *(Please check the box by replacing `[ ]` with `[x]`)*
- [ ] I have searched existing blocklist issues (open and closed) on `[Link to your issues page, e.g., GitHub issues]` to ensure this request is not a duplicate or already discussed.
- [ ] I understand that all blocklist modification requests are subject to review, testing, and community feedback to ensure the overall goals and effectiveness of the hapara.fail DNS bypass are maintained.
