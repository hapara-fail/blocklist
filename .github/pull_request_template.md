# Pull Request (Blocklist)

**1. Type of Change:**
*What does this PR do? (Check one)*
- [ ] **Add** new domains to the blocklist
- [ ] **Remove** domains (False Positive fix)
- [ ] **Documentation** / Maintenance update

**2. Related Issue:**
*Does this fix an existing issue? Please link it here (e.g., "Closes #12").*

> 

**3. Summary of Changes:**
*Briefly explain what you changed and why. (e.g., "Added 10 new telemetry domains for GoGuardian," "Removed canvas.instructure.com because it broke logins")*

> 

**4. Verification & Testing:**
*How did you verify these changes?*
- [ ] I have verified that these domains belong to the target service.
- [ ] I have checked that the Adblock Plus syntax (`||domain.com^`) is correct.
- [ ] (If removing) I confirmed that unblocking this restores the broken functionality.

**5. Placement:**
*Where did you put the new domains?*
- [ ] Under the correct Vendor Header (e.g., `### Lightspeed`).
- [ ] Created a new header for a new service.

---
**Final Checklist:**
- [ ] I have read the [Contributing Guidelines](https://github.com/hapara-fail/blocklist/blob/main/CONTRIBUTING.md).
- [ ] There are no trailing spaces or inline comments in the blocklist file.
