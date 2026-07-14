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
- **Health Check:** HTTP GET `/` expecting 200
- **Why:** Pre-built vulnerable image exists (`eystsen/vulnerablewordpress`), starts immediately without setup wizard, widely used in security testing
- **VulnerableEnvironment Definition:** `wordpress`
- **Docker Image:** `eystsen/vulnerablewordpress`
- **Credentials:** admin / admin
- **Exploit Context:** Authenticated admin access; uploads PHP shell via theme/plugin editor