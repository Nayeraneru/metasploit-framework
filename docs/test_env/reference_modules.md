# Reference Modules for test_env

## Selection Criteria
- Cover different service types: Java message broker (ActiveMQ), web application (WordPress)
- Have clear, single-port (or well-defined multi-port) mappings
- Have existing Docker images with known vulnerable versions
- Demonstrate different health check patterns (API endpoint, login page, root page)
- Include both authenticated and unauthenticated exploit scenarios

---

## Module 1: Apache ActiveMQ Jolokia RCE (Mentor Suggested)
- **Path:** `exploit/multi/http/apache_activemq_jolokia_rce`
- **Type:** Java web application (JMX-over-HTTP)
- **Ports:** 8161 (web console / Jolokia API), 61616 (OpenWire broker)
- **Health Check:** HTTP GET `/api/jolokia/` expecting 200, or GET `/` expecting 200
- **Why:** h00die suggested PR #21497. Has a verified Docker one-liner. Real-world CVE-2026-34197.
- **VulnerableEnvironment Definition:** `activemq`
- **Docker Image:** `apache/activemq-classic:5.18.6`
- **Docker Run:** `docker run -d --name activemq -p 8161:8161 -p 61616:61616 apache/activemq-classic:5.18.6`
- **Credentials:** admin / admin
- **Exploit Context:** Requires authenticated Jolokia access; `TARGETURI` typically `/api/jolokia/`

---

## Module 2: WordPress Admin Shell Upload
- **Path:** `exploit/unix/webapp/wp_admin_shell_upload`
- **Type:** Web application / CMS
- **Port:** 80
- **Health Check:** Two-stage — see **Provisioning** below. Base `health_check` is HTTP GET `/` expecting **[200, 302]** (the container returns `302` to `/wp-admin/install.php` on first boot; this is a valid "server is up" signal, not a failure). A separate `verify` check confirms the app is actually usable after provisioning: HTTP GET `/wp-login.php` expecting `200` and containing `user_login`.
- **Why:** Pre-built vulnerable image exists (`eystsen/vulnerablewordpress`), widely used in security testing, self-contained (bundles its own MySQL, no external DB link required).
- **VulnerableEnvironment Definition:** `wordpress`
- **Docker Image:** `eystsen/vulnerablewordpress`
- **Credentials:** admin / admin
- **Exploit Context:** Authenticated admin access; uploads PHP shell via theme/plugin editor
- **Provisioning:** This image does **not** start ready-to-use. The Dockerfile configures `wp-config.php` to point at a `wordpress` database but never creates the schema or an admin account — WordPress boots straight into the install wizard (`/wp-admin/install.php`), and stays there indefinitely with no admin/admin login until the wizard is submitted. `wordpress.yml` now defines a `provision` step (`type: http_post`, submits `install.php?step=2` with the credentials from `credentials.default`) that runs once the base health check passes, followed by the `verify` check above before the environment is registered as ready. See `04-environment-schema.md` for the general `provision`/`verify` schema this relies on.

---

## Module 3: Apache ActiveMQ OpenWire RCE (CVE-2023-46604)
- **Path:** `exploit/multi/misc/apache_activemq_rce_cve_2023_46604`
- **Type:** Java message broker (raw OpenWire protocol, not HTTP)
- **Port:** 61616 (broker) — 
- **Health Check:** Overrides `activemq.yml`'s shared HTTP check with a `tcp` check on this module's own RPORT-mapped port (61616). The shared HTTP check (against the Jetty web console) fails against this variant's image with `EOFError` - not a broken image, but **AMQ-8018**: since ActiveMQ 5.16.0, the web console binds to `127.0.0.1` *inside* the container by default and is unreachable externally unless an image explicitly patches it (confirmed: Module 1's official `apache/activemq-classic` image doesn't have this problem, so it's specific to how this community image leaves the stock config). Since this module never touches the web console anyway (pure OpenWire on 61616, which binds `0.0.0.0` by default), a TCP check on its own port is both accurate and sidesteps the issue entirely - a real example of the schema's "Module override" case (different health check type, same profile).
- **Why this module specifically:** it's the first real proof that `activemq.yml` works as a genuine shared definition across independent modules, not just independent files that happen to use the same schema. Two unrelated CVEs, two different attack surfaces (HTTP/Jolokia vs. raw OpenWire), one definition file.
- **VulnerableEnvironment Definition:** `activemq` (same file as Module 1 — nothing duplicated: image family, credentials, health check, and `ci.exploit`'s recommended payload are all inherited unchanged)
- **Docker Image:** `dinifarb/activemq:5.18.2`
- **Credentials:** none required — this CVE is unauthenticated
- **Exploit Context:** Unauthenticated; sends crafted OpenWire packet that loads attacker-hosted Spring XML config. Requires TARGET => 1 (Linux) override — default target is Windows.

