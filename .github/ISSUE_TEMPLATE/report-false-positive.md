---
name: Report false positive
about: For domain's incorrectly blocked by our blocklist
title: "[FP] "
labels: ''
assignees: nota9x

---

# False Positive Report for hapara.fail DNS Bypass Blocklist

Please use this template if you believe a domain is **incorrectly blocked** by our blocklist, causing legitimate and intended website or application functionality to break.

---

**1. Incorrectly Blocked Domain(s):**
*List each domain on a new line that you believe is a false positive.*

[https://www.google.com/search?q=exampledomain1.com]
[subdomain.exampledomain2.net]


**2. Legitimate Service or Website Affected:**
*What legitimate service, application, or website is being negatively impacted or broken by these domains being blocked? Please be specific.*
*(e.g., "Google Classroom," "Our school's official student portal," "Accessing assignments on Khan Academy," "A specific educational research site.").*

> _Your answer here_

**3. Description of the Issue (What is Broken?):**
*Describe the exact problem you are experiencing due to the domain(s) being blocked. What were you trying to do, and what happened instead?*
*(e.g., "When the listed domain is blocked, I cannot log in to myschoolportal.com; the login button does nothing," or "Google Docs fails to load or save embedded images, showing a broken image icon," or "The main content of news.legitimatesite.org does not load, only the header and footer.")*

> _Your explanation here_

**4. Steps to Reproduce the Broken Functionality:**
*Please provide clear, step-by-step instructions that would allow us to observe this false positive in action.*
1. Ensure `[domain.com]` is blocked (e.g., by using NextDNS with the hapara.fail blocklist).
2. Go to: `https://www.servicenow.com/community/developer-forum/what-are-affected-services-here/td-p/2927602`
3. Attempt to: `[e.g., Click the login button, load a page with images, submit a form]`
4. Observed result: `[e.g., Error message X appears, images are broken, page hangs indefinitely]`

> _Your steps here_

**5. Evidence of False Positive (Crucial):**

* **How did you determine the listed domain(s) are responsible for the breakage?** *(e.g., Temporarily unblocking only this domain resolved the issue, browser developer tools network tab shows requests to this domain failing, DNS query logs show it being blocked when the issue occurs).*
    > _Your answer here_

* **Specific Impact / Error Messages:** *(e.g., "Error: Could not connect to server," "Page timed out." Please provide exact error messages. Screenshots are highly encouraged.)*
    > _Your answer here_

* **Link to Screenshots, GIFs, or Videos Showing the Issue (Highly Recommended):** *(Upload to a service like Imgur, Streamable, GitHub Gist, etc., and paste the link(s) here).*
    > _Link(s) here_

**6. Additional Context (Optional):**
*Is there anything else we should know? This might include:*
* *The type of device you observed this on (e.g., School-issued Chromebook, personal device using NextDNS with this blocklist).*
* *Specific ChromeOS version or Browser version (if the behavior seems specific).*
* *Any observed patterns (e.g., "This only happens when trying to access X feature of Y service").*
> _Your additional context here_

---

**Confirmation:** *(Please check the box by replacing `[ ]` with `[x]`)*
- [ ] I have searched existing blocklist issues (open and closed) on `[Link to your issues page, e.g., GitHub issues]` to ensure this false positive has not already been reported.
- [ ] I understand that this report will be reviewed, and the domain(s) may be removed or re-categorized if confirmed as a false positive impacting essential/legitimate functionality.
