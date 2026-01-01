# Contributing Guidelines

First off, thank you for considering contributing to the **hapara.fail blocklist**. This project relies on community intelligence to stay ahead of the constantly shifting infrastructure of surveillance and filtering companies.

Whether you are identifying new tracking domains, fixing false positives, or simply requesting that a new service be targeted, your help is vital to maintaining digital autonomy for students.

## 🐛 Reporting Issues

We have simplified our reporting process. Please use the direct links below to **open an issue** using the correct template.

### 1. Requesting Blocks (Services or Domains)
If you want to block a new monitoring service, filter, or tracker:
* **[Click here to open a Service / Domain Addition Issue](https://github.com/hapara-fail/blocklist/issues/new?template=service---domain-addition.md)**
* **You do NOT need to know the specific domains.** You can simply request that we investigate a specific service (e.g., "Please add Impero Classroom").
* If you *do* know the domains, please list them to speed up the process.

### 2. Reporting False Positives (Broken Sites)
If a legitimate educational resource, school portal, or essential website is broken because of this blocklist:
* **[Click here to open a False Positive / Removal Issue](https://github.com/hapara-fail/blocklist/issues/new?template=false-positive---removal.md)**
* **Crucial:** Please provide as much detail as possible about *what* is broken and *which* domain is causing it (if you know).
* Screenshots of error messages or network logs are extremely helpful.

---

## 🛠️ Submitting Changes (Pull Requests)

We welcome direct contributions to the blocklist. If you are comfortable editing the file directly, please follow these guidelines to ensure your Pull Request (PR) is accepted.

### 1. Blocklist Format
The `blocklist.txt` file uses **Adblock Plus (ABP) syntax**. All entries must strictly follow this format to ensure compatibility with Pi-hole, AdGuard, and uBlock Origin.

* **Correct Syntax:** `||domain.com^`
* **Incorrect:** `domain.com`, `0.0.0.0 domain.com`, `http://domain.com`

**Rules for Entries:**
* **One domain per line.**
* **No comments** inline with domains (unless absolutely necessary for section headers).
* **Categorization:** Please place new domains under the correct Vendor Header (e.g., `### GoGuardian`, `### Lightspeed`). If adding a new vendor, create a new header using `! ### Vendor Name`.

### 2. How to Contribute
1.  **Fork** the repository to your own GitHub account.
2.  **Create a Branch** for your specific change (e.g., `add-impero-domains` or `fix-canvas-login`).
3.  **Add/Remove Domains** in `blocklist.txt` using the syntax above.
4.  **Verify** your changes:
    * Ensure there are no trailing spaces.
    * Ensure you haven't accidentally deleted unrelated domains.
5.  **Commit** your changes with a clear message:
    * *Good:* "Add telemetry endpoints for Lightspeed Filter"
    * *Bad:* "update list"
6.  **Push** to your branch and open a **Pull Request**.

---

## 🔍 Tips for Identifying Domains
Finding the right domain to block can be tricky. Here are a few tips:

* **Browser Developer Tools:** Press `F12` > `Network` tab. Look for requests that fail (blocked) or suspicious background requests (telemetry) when the service is running.
* **DNS Logs:** If you run Pi-hole or AdGuard Home, check your query logs when the surveillance software is active.
* **Wildcards:** Be careful with broad blocking. Blocking `||google.com^` will break the internet. Blocking `||cros-omahaproxy.googleusercontent.com^` is precise.

## 🤝 Code of Conduct
We value accuracy, privacy, and collaboration. Please ensure your interactions—whether in issues, pull requests, or Discord—are respectful and constructive. By participating, you are expected to uphold our **[Code of Conduct](https://github.com/hapara-fail/blocklist/blob/main/CODE_OF_CONDUCT.md)**.

## 📜 License
By contributing to hapara.fail, you agree that your contributions will be licensed under the same **GNU General Public License v3.0 (GPLv3)** that covers the project. Details can be found at [www.hapara.fail/license](https://www.hapara.fail/license).