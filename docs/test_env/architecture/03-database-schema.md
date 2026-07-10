# Database Schema & Persistence

## What I Learned From Metasploit Source

I investigated the database architecture and found:

### Migration System
- `db/migrate/` exists but is **empty** in the framework repo
- Migrations are gathered from **Rails engines** via `gather_engine_migration_paths`
- `lib/msf/core/db_manager/migration.rb` uses `ActiveRecord::MigrationContext`
- `schema.rb` is auto-generated, not edited directly

### Key Code From `lib/msf/core/db_manager/migration.rb`

```ruby
def gather_engine_migration_paths
  paths = ActiveRecord::Migrator.migrations_paths
  ::Rails::Engine.subclasses.map(&:instance).each do |engine|
    migrations_paths = engine.paths['db/migrate'].existent_directories
    migrations_paths.each do |migrations_path|
      unless paths.include? migrations_path
        paths << migrations_path
      end
    end
  end
  paths
end
```

### Database Configuration
- `config/database.yml` does not exist in the framework
- Database config is passed via `DatabaseYAML` option
- `framework.db.active` checks if database is connected

## Phase 1: Plugin-Only (Weeks 1-6) — In-Memory Registry

**Decision:** For the initial plugin implementation, use **in-memory storage only**.
No database migrations, no schema changes.

### Why In-Memory First?
1. No framework modifications required
2. Plugin loads/unloads cleanly
3. Container labels provide cross-session identification
4. Database integration is Phase 2 (Week 6)

### In-Memory Registry Design

```ruby
class BuiltEnvironmentRegistry
  attr_reader :environments, :framework
  
  def initialize(framework)
    @framework = framework
    @environments = {}  # local_id => Hash
    @next_id = 1
  end
  
  def register(container_id:, module_fullname:, rhost:, rport:,
               version: nil, runtime: 'docker', image_ref:,
               exploit_command:, datastore: {})
    id = @next_id
    @next_id += 1
    
    @environments[id] = {
      local_id: id,
      container_id: container_id,
      module_fullname: module_fullname,
      env_version: version,
      rhost: rhost,
      rport: rport,
      runtime: runtime,
      image_ref: image_ref,
      status: 'running',
      exploit_command: exploit_command,
      datastore: datastore,
      created_at: Time.now,
      started_at: Time.now
    }
    
    id
  end
  
  def get(id)
    @environments[id]
  end
  
  def list
    @environments.values.sort_by { |e| e[:local_id] }
  end
  
  def update_status(id, status)
    return unless @environments[id]
    @environments[id][:status] = status
    @environments[id][:updated_at] = Time.now
    @environments[id][:stopped_at] = Time.now if status == 'stopped'
    @environments[id][:started_at] = Time.now if status == 'running'
  end
  
  def remove(id)
    return unless @environments[id]
    @environments[id][:status] = 'removed'
    @environments[id][:removed_at] = Time.now
    @environments.delete(id)
  end
  
  def remove_all
    @environments.each_value do |env|
      env[:status] = 'removed'
      env[:removed_at] = Time.now
    end
    @environments.clear
    @next_id = 1
  end
  
  def find_by_container(container_id)
    @environments.values.find { |e| e[:container_id] == container_id }
  end
  
  def find_by_module(module_fullname)
    @environments.values.select { |e| e[:module_fullname] == module_fullname }
  end
  
  def used_ports
    @environments.values.map { |e| e[:rport] }
  end
  
  def running?
    @environments.values.any? { |e| e[:status] == 'running' }
  end
end
```

### Container Labels (Cross-Session Identification)

Since in-memory data is lost on msfconsole restart, use **OCI container labels**
to identify and reconstruct environments.

**Design Decision:** Use only lightweight individual labels for the minimal
dynamic data needed. All static metadata (credentials, datastore defaults,
health checks, exploit commands) is reconstructible from the module's
`VulnerableEnvironment` definition and the environment YAML file.

**Rationale:** The second mentor correctly observed that if we can identify
the container by `managed_by` + `instance_id` + `module` labels, we can look
up the module's `VulnerableEnvironment` definition from `module_info`. The
definition contains `port_mapping`, `datastore_defaults`, `credentials`, and
`health_check`. The only truly dynamic data that cannot be reconstructed is:

1. **Allocated port(s)** — dynamically assigned at runtime
2. **Environment version** — which image tag was provisioned
3. **Container runtime ID** — the actual Docker/Podman container ID

**Label Schema:**

| Label | Type | Value | Purpose |
|-------|------|-------|---------|
| `msf.vulnenv.managed_by` | String | `test_env` | Discovery filter — find all framework-managed containers |
| `msf.vulnenv.instance_id` | String | `msf-{hostname}-{pid}` | Session isolation — identify which msfconsole created it |
| `msf.vulnenv.module` | String | Module fullname | Module linkage — filter by target module |
| `msf.vulnenv.env_id` | String | `1` | Registry cross-reference — map to in-memory ID |
| `msf.vulnenv.version` | String | `2.361` | **Version used** — not reliably in image tag |
| `msf.vulnenv.ports` | String | `8081:8080` | **Allocated port mapping** — host:container, comma-separated |

**Example:**

```bash
docker run -d \
  --label "msf.vulnenv.managed_by=test_env" \
  --label "msf.vulnenv.instance_id=msf-hostname-12345" \
  --label "msf.vulnenv.module=exploit/multi/http/jenkins_script_console" \
  --label "msf.vulnenv.env_id=1" \
  --label "msf.vulnenv.version=2.361" \
  --label "msf.vulnenv.ports=8081:8080" \
  vulnhub/jenkins:2.361
```

**Why no Base64 JSON payload?**

| Concern | Resolution |
|---------|-----------|
| Docker label size limit (~2KB total) | Lightweight labels stay well under limit |
| Schema evolution | Adding a new label is simpler than versioning a JSON schema |
| No encoding/decoding complexity | No Base64, no JSON parsing errors |

### State Reconstruction From Labels (Future Enhancement)

```ruby
def reconstruct_from_labels(runtime)
  # Step 1: Discover all framework-managed containers via native filter
  containers = runtime.list(filters: { 'label' => 'msf.vulnenv.managed_by=test_env' })

  containers.each do |container|
    labels = container['Config']['Labels'] || {}

    # Step 2: Skip containers from other msfconsole instances
    instance_id = labels['msf.vulnenv.instance_id']
    next unless instance_id == current_instance_id

    # Step 3: Extract minimal dynamic data from labels
    module_fullname = labels['msf.vulnenv.module']
    env_id = labels['msf.vulnenv.env_id'].to_i
    version = labels['msf.vulnenv.version']

    # Parse port mapping: "8081:8080,9090:61616" -> {8080=>8081, 61616=>9090}
    ports = parse_port_label(labels['msf.vulnenv.ports'])

    # Step 4: Load module and resolve its VulnerableEnvironment definition
    mod = framework.modules.create(module_fullname)
    next unless mod

    vuln_env_meta = mod.send(:module_info)['VulnerableEnvironment']
    next unless vuln_env_meta

    definition_name = vuln_env_meta['definition']
    profile = vuln_env_meta['profile'] || 'default'
    overrides = vuln_env_meta['overrides'] || {}

    # Step 5: Resolve environment config from YAML
    loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
    config = loader.resolve(definition_name, version, profile, overrides)

    # Step 6: Build datastore from port_mapping + allocated ports
    datastore = { 'RHOSTS' => '127.0.0.1' }
    vuln_env_meta['port_mapping'].each do |container_port, ds_option|
      datastore[ds_option] = ports[container_port]
    end

    # Step 7: Reconstruct registry entry
    @environments[env_id] = {
      local_id: env_id,
      container_id: container['Id'],
      module_fullname: module_fullname,
      env_version: version,
      rhost: '127.0.0.1',
      rport: ports.values.first,
      runtime: runtime.name,
      image_ref: container['Config']['Image'],
      status: container['State']['Status'],
      exploit_command: build_exploit_command(datastore),
      datastore: datastore,
      created_at: Time.parse(container['Created']),
      started_at: Time.parse(container['State']['StartedAt'])
    }

    @next_id = [@next_id, env_id + 1].max
  end
end

# Parse "8081:8080,9090:61616" into {8080=>8081, 61616=>9090}
def parse_port_label(label_value)
  return {} unless label_value

  label_value.split(',').each_with_object({}) do |pair, hash|
    host_port, container_port = pair.split(':')
    hash[container_port.to_i] = host_port.to_i
  end
end

# Build exploit command from datastore
def build_exploit_command(datastore)
  cmds = datastore.map { |k, v| "set #{k} #{v}" }
  cmds.join('; ') + '; exploit'
end
```


## Phase 2: Database Integration (Week 6+)

When adding PostgreSQL persistence:

### Migration File
```ruby
# db/migrate/20240624000001_create_vuln_environments.rb
class CreateVulnEnvironments < ActiveRecord::Migration[8.0]
  def change
    create_table :vuln_environments, id: :serial do |t|
      t.string  :container_id,    null: false
      t.string  :image_ref,       null: false
      t.string  :module_fullname, null: false
      t.string  :env_version
      t.string  :rhost,           default: '127.0.0.1'
      t.integer :rport,           null: false
      t.text    :datastore
      t.string  :runtime,         default: 'docker', null: false
      t.string  :msf_instance_id
      t.string  :status,          null: false, default: 'running'
      t.text    :exploit_command
      t.timestamps
      t.datetime :started_at
      t.datetime :stopped_at
      t.datetime :removed_at
    end
    
    add_index :vuln_environments, :module_fullname
    add_index :vuln_environments, :status
    add_index :vuln_environments, :container_id, unique: true
    add_index :vuln_environments, :msf_instance_id
    add_index :vuln_environments, [:status, :module_fullname]
  end
end
```

### ActiveRecord Model
```ruby
class VulnEnvironment < ActiveRecord::Base
  self.table_name = 'vuln_environments'
  serialize :datastore, JSON
  
  scope :active, -> { where(status: ['running', 'stopped']) }
  scope :running, -> { where(status: 'running') }
  scope :by_module, ->(name) { where(module_fullname: name) }
  
  validates :container_id, presence: true, uniqueness: true
  validates :module_fullname, presence: true
  validates :rport, presence: true, numericality: { only_integer: true }
  validates :status, inclusion: { in: %w[running stopped removed orphaned error] }
end
```

### Integration With In-Memory Registry

```ruby
class BuiltEnvironmentRegistry
  def initialize(framework)
    @framework = framework
    @environments = {}
    @next_id = 1
    load_from_database if database_available?
  end
  
  private
  
  def database_available?
    framework.db.active && defined?(VulnEnvironment)
  end
  
  def load_from_database
    VulnEnvironment.active.each do |db_env|
      @environments[@next_id] = {
        local_id: @next_id,
        db_id: db_env.id,
        container_id: db_env.container_id,
        # ... map all fields ...
      }
      @next_id += 1
    end
  end
  
  def persist_to_database(record)
    VulnEnvironment.create!(...)
  end
end
```

## Reference: sessions Table Pattern

From `db/schema.rb`:
```ruby
create_table "sessions", id: :serial, force: :cascade do |t|
  t.integer "host_id"
  t.string "stype"
  t.string "via_exploit"      # Module association
  t.string "via_payload"
  t.string "desc"
  t.integer "port"
  t.string "platform"
  t.text "datastore"          # Serialized hash
  t.datetime "opened_at", precision: nil, null: false
  t.datetime "closed_at", precision: nil
  t.string "close_reason"
  t.integer "local_id"        # In-memory mapping
  t.datetime "last_seen", precision: nil
  t.integer "module_run_id"
  t.index ["module_run_id"], name: "index_sessions_on_module_run_id"
end
```

My `vuln_environments` table follows this exact pattern:
- `id: :serial` primary key
- `module_fullname` like `via_exploit`
- `datastore` serialized text
- `local_id` equivalent via `env_id` label
- Lifecycle timestamps (`created_at`, `started_at`, `stopped_at`, `removed_at`)


