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