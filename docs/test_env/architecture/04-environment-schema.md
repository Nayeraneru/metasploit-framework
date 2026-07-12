# Environment Definition YAML Schema

## What I Verified

I created `data/vuln_envs/jenkins.yml` and validated it with Ruby:

```bash
ruby -e "
require 'yaml'
data = YAML.safe_load(File.read('data/vuln_envs/jenkins.yml'), permitted_classes: [Symbol])
puts 'Name: ' + data['name']
puts 'Versions: ' + data['versions'].keys.inspect
puts 'Ports: ' + data['shared']['ports'].inspect
puts 'Health check type: ' + data['shared']['health_check']['type']
"
```

Output:
```
Name: jenkins
Versions: ["2.361", "2.375"]
Ports: {"http"=>8080}
Health check type: http
```

## Directory Structure

```
data/
  vuln_envs/
    README.md          # Schema documentation
    jenkins.yml        # Jenkins with multiple profiles
```

## File Location
`data/vuln_envs/{name}.yml`

The `{name}` must match the `name` field inside the file.

## Design Principle: Profiles Over Files

A **single environment definition** represents one vulnerable service. It contains **one set of software versions** and **multiple configuration profiles** that describe different runtime states of that service.

**Why profiles instead of separate files?**
- **DRY**: Software versions are defined once, not duplicated across files
- **Discoverability**: All variants of a service live in one file
- **Relationship clarity**: `http-stopped` is explicitly a profile of `jenkins`, not a separate service
- **Maintainability**: Adding a new version requires editing one file, not N files

**Version strings represent actual software versions.** They are never suffixed to indicate configuration variants. The `profile` key selects the runtime configuration.

## Three-Level Configuration Hierarchy

When `test_env build` resolves an environment, it merges configuration in this order:

```
Level 1: Base shared (all profiles inherit)
    ↓
Level 2: Profile-specific overrides
    ↓
Level 3: Module-level overrides (minor tweaks)
```

This gives maximum reusability while allowing precise per-module customization.

## Decision Matrix: Profile vs. Module Override

| Scenario | Approach | Example |
|----------|----------|---------|
| Different runtime state (services on/off, different health check type) | **New profile** | `default` (HTTP on) vs `http-stopped` (HTTP off) |
| Different health check endpoint or expected status | **Module override** | Same profile, module overrides `health_check.path` |
| Different datastore default | **Module override** | Same profile, module overrides `datastore_defaults.TARGETURI` |
| Different credentials | **Module override** | Same profile, module overrides `credentials.default` |

## Schema

### Top-Level Keys

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Machine-friendly identifier (matches filename) |
| `description` | String | Yes | Human-readable description |
| `variants` | Array | Yes | List of variant configurations |
| `shared` | Hash | Yes | Base configuration inherited by all profiles |
| `profiles` | Hash | Yes | Map of profile names to profile-specific overrides |

### variants Section

A list of configuration variants for this service. Each variant is a distinct
runnable configuration — typically a software version, but may also represent
different backends, plugins, or build options for the same version.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | String | Yes | Unique identifier for this variant. Used in `test_env build VARIANT=...` |
| `version` | String | Yes | The actual software version. For information and future validation (e.g., Rapid7#21583) |
| `image` | String | Yes | OCI image reference |
| `build_args` | Hash | No | Docker build arguments |
| `default` | Boolean | No | If `true`, this variant is selected when no `VARIANT` is specified. Only one variant may be `default` |

Example:
```yaml
variants:
  - name: "2.361"
    version: "2.361"
    image: vulnhub/jenkins:2.361
    build_args:
      JENKINS_VERSION: "2.361"
    default: true

  - name: "2.361-postgres"
    version: "2.361"
    image: vulnhub/jenkins:2.361-pg
    build_args:
      JENKINS_VERSION: "2.361"
      DB_BACKEND: "postgresql"

  - name: "2.375"
    version: "2.375"
    image: vulnhub/jenkins:2.375
    build_args:
      JENKINS_VERSION: "2.375"
```
### shared Section

Base configuration inherited by all profiles. Any field here can be overridden by a profile or by module-level metadata.

#### ports (Required)
```yaml
shared:
  ports:
    http: 8080
```

#### health_check (Required in base or profile)
```yaml
shared:
  health_check:
    type: http
    path: /login
    expected_status: 200
    interval: 5
    timeout: 2
    retries: 12
```

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `type` | String | Yes | `http`, `tcp`, or `command` |
| `path` | String | If type=http | HTTP path to check |
| `expected_status` | Integer | No | Default: 200 |
| `command` | String | If type=command | Command to execute |
| `expected_output` | String | If type=command | Substring to match |
| `interval` | Integer | No | Seconds between checks. Default: 5 |
| `timeout` | Integer | No | Seconds to wait. Default: 2 |
| `retries` | Integer | No | Max attempts. Default: 12 |

#### credentials (Optional)
```yaml
shared:
  credentials:
    default:
      username: admin
      password: admin
```

#### datastore_defaults (Optional)
```yaml
shared:
  datastore_defaults:
    TARGETURI: /script
```

#### volumes (Optional)
```yaml
shared:
  volumes:
    jenkins_home:
      container_path: /var/jenkins_home
      persist: false
```

#### ci (Optional)
```yaml
shared:
  ci:
    exploit:
      payload: java/meterpreter/reverse_tcp
      options:
        LHOST: 127.0.0.1
        LPORT: 4444
    validation:
      expected_session: true
      session_type: meterpreter
      expected_output: "uid="
      timeout: 120
```

### profiles Section

Each profile is a key-value pair:
- **Key**: Profile name (e.g., `default`, `http-stopped`)
- **Value**: Hash that overrides or extends `shared`

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `description` | String | Yes | What this profile represents |
| `health_check` | Hash | No | Overrides base `shared.health_check` |
| `datastore_defaults` | Hash | No | Overrides base `shared.datastore_defaults` |
| `credentials` | Hash | No | Overrides base `shared.credentials` |
| `volumes` | Hash | No | Overrides base `shared.volumes` |
| `ci` | Hash | No | Overrides base `shared.ci` |

**Profile names** must match `[a-z0-9-]+`.

## Validation Rules

1. `name` must match filename (without `.yml`)
2. `variants` must be a non-empty list
3. Each variant must have a `name` and `image`
4. Variant `name` must be unique across all variants
5. At most one variant may have `default: true`
6. `shared.ports` must have at least one entry
7. `profiles` must have at least one entry
8. `profiles` must contain a `default` profile
9. Profile names must match `[a-z0-9-]+`
10. `health_check` must be defined in `shared` or in every profile
11. Module-level `overrides` are deep-merged into the final profile config

## Resolution & Merge Logic

When `test_env build` resolves an environment definition, the loader performs a **three-level deep merge**:

### Merge Order

| Level | Source | What It Contains |
|-------|--------|------------------|
| 1 | `shared` | Base configuration inherited by all profiles |
| 2 | `profiles[profile_name]` | Profile-specific overrides (minus `description`) |
| 3 | `VulnerableEnvironment['overrides']` | Module-level tweaks |

### Merge Rules

- **Hash fields** (e.g., `health_check`, `datastore_defaults`) are deep-merged: nested keys are combined, not replaced wholesale.
- **Scalar fields** (e.g., `image`, `build_args`) are replaced by the higher level.
- **The `description` key** in a profile is informational only and is excluded from the merge.

### Resolution Steps

1. Load the YAML definition file by `name`.
2. Validate that `variants` contains the requested `variant`.
3. Validate that `profiles` contains the requested `profile` (default: `'default'`).
4. Start with a copy of `shared`.
5. Deep-merge the selected profile's configuration into it.
6. Deep-merge the module's `VulnerableEnvironment['overrides']` (if any).
7. Attach the variant-specific `image`, `version`, and `build_args` from the matching variant in the `variants` list.

### Error Cases

| Condition | Error |
|-----------|-------|
| Definition file not found | `"Definition not found: data/vuln_envs/{name}.yml"` |
| Variant not in `variants` | `"Variant '{variant}' not defined for '{name}'"` |
| Profile not in `profiles` | `"Profile '{profile}' not defined for '{name}'"` |
| No `default` profile exists | Validation fails at load time |

### Loader Interface (Week 3)

The `EnvironmentDefinitionLoader` exposes:

- `load(name)` — Parse and validate a definition file.
- `resolve(name, variant, profile, overrides)` — Return the fully merged configuration for a specific environment instance.
- `available_definitions` — List all `.yml` files in `data/vuln_envs/`.
## Module Metadata Integration

Modules reference a definition and optionally a profile. See [02-module-metadata.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/02-module-metadata.md) for the full `VulnerableEnvironment` schema.

```ruby
# Standard module — uses default variant and profile
'VulnerableEnvironment' => {
  'definition'      => 'jenkins',
  'default_variant' => '2.361',
  'port_mapping'    => { 8080 => 'RPORT' }
}

# Variant module — uses postgres variant
'VulnerableEnvironment' => {
  'definition'      => 'jenkins',
  'default_variant' => '2.361-postgres',
  'port_mapping'    => { 8080 => 'RPORT' }
}

# Module with profile override
'VulnerableEnvironment' => {
  'definition'      => 'jenkins',
  'default_variant' => '2.361',
  'profile'         => 'http-stopped',
  'port_mapping'    => { 8080 => 'RPORT' }
}

# Module with minor override — same profile, different health check
'VulnerableEnvironment' => {
  'definition'      => 'jenkins',
  'default_variant' => '2.361',
  'port_mapping'    => { 8080 => 'RPORT' },
  'overrides'       => {
    'health_check' => {
      'path' => '/script',
      'expected_status' => 403
    },
    'datastore_defaults' => {
      'TARGETURI' => '/script'
    }
  }
}
```


## Integration With Registry

Environment definitions are loaded by the plugin and used to:
1. Build/pull container images
2. Map container ports to host ports
3. Configure health checks
4. Set module datastore defaults
5. Apply profile-specific overrides
6. Apply module-level overrides (if any)

See [03-database-schema.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/03-database-schema.md) for registry design.


