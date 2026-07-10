require 'set'
require 'json'
require 'open3'
require 'shellwords'

module Msf
  class Plugin::TestEnv < Msf::Plugin
    # =====================================================================
    # VulnerableEnvironment Struct
    # =====================================================================

    # Encapsulates and validates VulnerableEnvironment metadata from a module.
    # Mirrors the framework pattern used by #name, #description, #notes, etc.
    # but adds validation and returns a typed object instead of a raw Hash.
    class VulnerableEnvironment
      attr_reader :definition, :default_variant, :profile, :port_mapping, :overrides

      # Required keys that must be present
      REQUIRED_KEYS = %w[definition default_variant port_mapping].freeze

      # Valid types for each key
      SCHEMA = {
        'definition'      => String,
        'default_variant' => String,
        'profile'         => String,
        'port_mapping'    => Hash,
        'overrides'       => Hash
      }.freeze

      def initialize(raw_hash)
        @raw = raw_hash || {}

        validate!

        @definition      = @raw['definition']
        @default_variant = @raw['default_variant']
        @profile         = @raw['profile'] || 'default'
        @port_mapping    = @raw['port_mapping'] || {}
        @overrides       = @raw['overrides'] || {}
      end

      def valid?
        errors.empty?
      end

      def errors
        errs = []

        REQUIRED_KEYS.each do |key|
          errs << "Missing required key: '#{key}'" unless @raw.key?(key)
        end

        SCHEMA.each do |key, expected_type|
          next unless @raw.key?(key)
          unless @raw[key].is_a?(expected_type)
            errs << "Key '#{key}' must be #{expected_type}, got #{@raw[key].class}"
          end
        end

        if @raw['port_mapping'].is_a?(Hash)
          @raw['port_mapping'].each do |k, v|
            unless k.is_a?(Integer) || k.to_s.match?(/\A\d+\z/)
              errs << "port_mapping key must be an integer port, got: #{k.inspect}"
            end
            unless v.is_a?(String)
              errs << "port_mapping value must be a String datastore option name, got: #{v.inspect}"
            end
          end
        end

        errs
      end

      private

      def validate!
        errs = errors
        raise ArgumentError, "Invalid VulnerableEnvironment: #{errs.join('; ')}" unless errs.empty?
      end
    end

    # =====================================================================
    # Runtime Abstraction Layer
    # =====================================================================

    class BaseRuntime
      def available?
        raise NotImplementedError, "#{self.class} must implement available?"
      end

      def name
        raise NotImplementedError, "#{self.class} must implement name"
      end

      def pull(image)
        raise NotImplementedError, "#{self.class} must implement pull"
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        raise NotImplementedError, "#{self.class} must implement run"
      end

      def inspect(container_id)
        raise NotImplementedError, "#{self.class} must implement inspect"
      end

      def stop(container_id)
        raise NotImplementedError, "#{self.class} must implement stop"
      end

      def start(container_id)
        raise NotImplementedError, "#{self.class} must implement start"
      end

      def remove(container_id)
        raise NotImplementedError, "#{self.class} must implement remove"
      end

      def exec(container_id, command)
        raise NotImplementedError, "#{self.class} must implement exec"
      end

      def list(filters: {})
        raise NotImplementedError, "#{self.class} must implement list"
      end

      # =====================================================================
      # Label Helpers (Shared Across Runtimes)
      # =====================================================================

      # Build container labels from environment metadata.
      # Stores only minimal dynamic data; static metadata is reconstructible
      # from the module's VulnerableEnvironment definition.
      def build_labels(instance_id:, module_fullname:, env_id:, version:, ports:)
        {
          'msf.vulnenv.managed_by' => 'test_env',
          'msf.vulnenv.instance_id' => instance_id,
          'msf.vulnenv.module' => module_fullname,
          'msf.vulnenv.env_id' => env_id.to_s,
          'msf.vulnenv.version' => version.to_s,
          'msf.vulnenv.ports' => encode_port_label(ports)
        }
      end

      # Encode port mapping hash {container_port => host_port} into label string
      # Format: "host:container,host:container" (e.g., "8081:8080,9090:61616")
      def encode_port_label(ports)
        ports.map { |container_port, host_port| "#{host_port}:#{container_port}" }.join(',')
      end

      # Decode port label string back into {container_port => host_port} hash
      def decode_port_label(label_value)
        return {} unless label_value

        label_value.split(',').each_with_object({}) do |pair, hash|
          host_port, container_port = pair.split(':')
          hash[container_port.to_i] = host_port.to_i
        end
      end

      VALID_IMAGE_NAME = /\A[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[a-zA-Z0-9._-]+)?\z/ unless defined?(VALID_IMAGE_NAME)

      private

      def validate_image_name!(image)
        unless image.to_s.match?(VALID_IMAGE_NAME)
          raise ArgumentError, "Invalid image name: #{image.inspect}"
        end
      end

      def parse_labels(labels_string)
        return {} if labels_string.nil? || labels_string.empty?

        labels_string.split(',').each_with_object({}) do |pair, hash|
          key, value = pair.split('=', 2)
          hash[key] = value || ''
        end
      end
    end

    # ============================================================
    # DOCKER RUNTIME
    # ============================================================
    class DockerRuntime < BaseRuntime
      def available?
        _out, _err, status = Open3.capture3('docker', 'version')
        status.success?
      rescue Errno::ENOENT
        false
      end

      def name
        'docker'
      end

      def pull(image)
        validate_image_name!(image)
        _out, err, status = Open3.capture3('docker', 'pull', image)
        if status.success?
          true
        else
          elog("Docker pull failed: #{err}")
          false
        end
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        validate_image_name!(image)
        cmd = ['docker', 'run', '-d']

        # ports: {container_port => host_port}
        ports.each do |container_port, host_port|
          cmd += ['-p', "127.0.0.1:#{host_port}:#{container_port}"]
        end

        labels.each do |key, value|
          cmd += ['--label', "#{key}=#{value}"]
        end

        volumes.each do |host_path, container_path|
          cmd += ['-v', "#{host_path}:#{container_path}"]
        end

        env.each do |key, value|
          cmd += ['-e', "#{key}=#{value}"]
        end

        cmd += ['--name', name] if name
        cmd << image

        out, err, status = Open3.capture3(*cmd)
        if status.success?
          out.strip
        else
          raise "Docker run failed: #{err}"
        end
      end

      def inspect(container_id)
        out, _err, status = Open3.capture3('docker', 'inspect', container_id)
        return nil unless status.success?
        return nil if out.empty?

        begin
          data = JSON.parse(out)
          data.first
        rescue JSON::ParserError => e
          elog("Docker inspect JSON parse error: #{e.message}")
          nil
        end
      end

      def stop(container_id)
        _out, _err, status = Open3.capture3('docker', 'stop', container_id)
        status.success?
      end

      def start(container_id)
        _out, _err, status = Open3.capture3('docker', 'start', container_id)
        status.success?
      end

      def remove(container_id)
        _out, _err, status = Open3.capture3('docker', 'rm', container_id)
        status.success?
      end

      def exec(container_id, command)
        return ["", 1] if command.nil? || command.empty?
        out, err, status = Open3.capture3('docker', 'exec', container_id, *Shellwords.split(command))
        [out + err, status.exitstatus]
      end

      def list(filters: {})
        cmd = ['docker', 'ps', '-a', '--format', '{{json .}}']

        filters.each do |key, value|
          cmd += ['--filter', "#{key}=#{value}"]
        end

        out, _err, status = Open3.capture3(*cmd)
        return [] unless status.success?
        return [] if out.empty?

        containers = out.lines.map do |line|
          begin
            JSON.parse(line.strip)
          rescue JSON::ParserError
            nil
          end
        end.compact

        containers.each do |c|
          c['Labels'] = parse_labels(c['Labels']) if c['Labels'].is_a?(String)
        end

        containers
      end
    end

    # ============================================================
    # PODMAN RUNTIME
    # ============================================================
    class PodmanRuntime < BaseRuntime
      def available?
        _out, _err, status = Open3.capture3('podman', 'version')
        status.success?
      rescue Errno::ENOENT
        false
      end

      def name
        'podman'
      end

      def pull(image)
        validate_image_name!(image)
        qualified = qualify_image(image)
        _out, err, status = Open3.capture3('podman', 'pull', qualified)
        if status.success?
          true
        else
          elog("Podman pull failed for #{qualified}: #{err}")
          false
        end
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        validate_image_name!(image)
        cmd = ['podman', 'run', '-d']

        # ports: {container_port => host_port}
        ports.each do |container_port, host_port|
          cmd += ['-p', "127.0.0.1:#{host_port}:#{container_port}"]
        end

        labels.each do |key, value|
          cmd += ['--label', "#{key}=#{value}"]
        end

        volumes.each do |host_path, container_path|
          cmd += ['-v', "#{host_path}:#{container_path}"]
        end

        env.each do |key, value|
          cmd += ['-e', "#{key}=#{value}"]
        end

        cmd += ['--name', name] if name
        cmd << qualify_image(image)

        out, err, status = Open3.capture3(*cmd)
        if status.success?
          out.strip
        else
          raise "Podman run failed: #{err}"
        end
      end

      def inspect(container_id)
        out, _err, status = Open3.capture3('podman', 'inspect', container_id)
        return nil unless status.success?
        return nil if out.empty?

        begin
          data = JSON.parse(out)
          data.first
        rescue JSON::ParserError => e
          elog("Podman inspect JSON parse error: #{e.message}")
          nil
        end
      end

      def stop(container_id)
        _out, _err, status = Open3.capture3('podman', 'stop', container_id)
        status.success?
      end

      def start(container_id)
        _out, _err, status = Open3.capture3('podman', 'start', container_id)
        status.success?
      end

      def remove(container_id)
        _out, _err, status = Open3.capture3('podman', 'rm', container_id)
        status.success?
      end

      def exec(container_id, command)
        return ["", 1] if command.nil? || command.empty?
        out, err, status = Open3.capture3('podman', 'exec', container_id, *Shellwords.split(command))
        [out + err, status.exitstatus]
      end

      def list(filters: {})
        cmd = ['podman', 'ps', '-a', '--format', '{{json .}}']

        filters.each do |key, value|
          cmd += ['--filter', "#{key}=#{value}"]
        end

        out, _err, status = Open3.capture3(*cmd)
        return [] unless status.success?
        return [] if out.empty?

        containers = out.lines.map do |line|
          begin
            JSON.parse(line.strip)
          rescue JSON::ParserError
            nil
          end
        end.compact

        containers.each do |c|
          c['Labels'] = parse_labels(c['Labels']) if c['Labels'].is_a?(String)
        end

        containers
      end

      private

      def qualify_image(image)
        return image if image.include?('/')
        "docker.io/library/#{image}"
      end
    end

    # ============================================================
    # RUNTIME ADAPTER
    # ============================================================
    class RuntimeAdapter
      def self.detect(datastore = {})
        runtime_pref = normalize_pref(datastore['TEST_ENV_RUNTIME'] || ENV['TEST_ENV_RUNTIME'])

        case runtime_pref
        when 'docker'  then detect_docker
        when 'podman'  then detect_podman
        else                detect_auto
        end
      end

      def self.normalize_pref(raw)
        pref = raw.to_s.downcase.strip
        return pref if %w[auto docker podman].include?(pref)
        elog("Invalid TEST_ENV_RUNTIME: #{raw.inspect}, falling back to auto")
        'auto'
      end

      def self.detect_docker
        docker = DockerRuntime.new
        return docker if docker.available?
        raise "Docker requested but not available"
      end

      def self.detect_podman
        podman = PodmanRuntime.new
        return podman if podman.available?
        raise "Podman requested but not available"
      end

      def self.detect_auto
        docker = DockerRuntime.new
        return docker if docker.available?
        podman = PodmanRuntime.new
        return podman if podman.available?
        nil
      end
    end

    # =====================================================================
    # Port Allocator
    # =====================================================================
    class PortAllocator
      EPHEMERAL_START = 49152 unless defined?(EPHEMERAL_START)
      EPHEMERAL_END   = 65535 unless defined?(EPHEMERAL_END)

      class NoPortsAvailable < RuntimeError; end

      def initialize(used_ports = [])
        @used_ports = Set.new(used_ports)
      end

      def allocate(preferred = nil)
        if preferred && available?(preferred)
          @used_ports.add(preferred)
          return preferred
        end

        (EPHEMERAL_START..EPHEMERAL_END).each do |port|
          next if @used_ports.include?(port)
          if available?(port)
            @used_ports.add(port)
            return port
          end
        end

        raise NoPortsAvailable, "No available ports in range #{EPHEMERAL_START}-#{EPHEMERAL_END}"
      end

      def release(port)
        @used_ports.delete(port)
      end

      private

      def available?(port)
        return false if @used_ports.include?(port)

        server = TCPServer.new('127.0.0.1', port)
        server.close
        true
      rescue Errno::EADDRINUSE
        false
      end
    end

    # =====================================================================
    # Environment Definition Loader
    # =====================================================================
    class EnvironmentDefinitionLoader
      def initialize(data_directory)
        @base_path = File.join(data_directory, 'vuln_envs')
      end

      def load(name)
        path = File.join(@base_path, "#{name}.yml")
        raise "Definition not found: #{path}" unless File.exist?(path)

        data = YAML.safe_load(File.read(path), permitted_classes: [Symbol])
        validate!(data, name)
        data
      end

      def resolve(name, variant, profile = 'default', overrides = {})
        data = load(name)

        unless data['variants'].key?(variant)
          available = data['variants'].keys.join(', ')
          raise "Variant '#{variant}' not defined for '#{name}'. Available: #{available}"
        end

        unless data['profiles'].key?(profile)
          available = data['profiles'].keys.join(', ')
          raise "Profile '#{profile}' not defined for '#{name}'. Available: #{available}"
        end

        config = deep_copy(data['shared'] || {})

        profile_data = data['profiles'][profile].dup
        profile_data.delete('description')
        config = deep_merge(config, profile_data)

        config = deep_merge(config, overrides) if overrides.is_a?(Hash) && !overrides.empty?

        variant_data = data['variants'][variant]
        config['image'] = variant_data['image']
        config['build_args'] = variant_data['build_args'] if variant_data['build_args']

        config
      end

      def available_definitions
        return [] unless Dir.exist?(@base_path)
        Dir.glob(File.join(@base_path, '*.yml')).map { |f| File.basename(f, '.yml') }
      end

      private

      def validate!(data, filename)
        unless data['name'] == filename
          raise "Validation failed: name '#{data['name']}' does not match filename '#{filename}'"
        end

        unless data['variants'].is_a?(Hash) && !data['variants'].empty?
          raise "Validation failed: 'variants' must have at least one entry"
        end

        data['variants'].each do |var, cfg|
          unless cfg.is_a?(Hash) && cfg['image'].is_a?(String) && !cfg['image'].empty?
            raise "Validation failed: variant '#{var}' missing valid 'image'"
          end
        end

        unless data['shared'].is_a?(Hash) && data['shared']['ports'].is_a?(Hash) && !data['shared']['ports'].empty?
          raise "Validation failed: 'shared.ports' must have at least one entry"
        end

        unless data['profiles'].is_a?(Hash) && !data['profiles'].empty?
          raise "Validation failed: 'profiles' must have at least one entry"
        end

        unless data['profiles'].key?('default')
          raise "Validation failed: 'profiles' must contain a 'default' profile"
        end

        data['profiles'].keys.each do |profile_name|
          unless profile_name.to_s.match?(/\A[a-z0-9-]+\z/)
            raise "Validation failed: profile name '#{profile_name}' must match [a-z0-9-]+"
          end
        end

        shared_has_health = data['shared'].is_a?(Hash) && data['shared']['health_check'].is_a?(Hash)
        unless shared_has_health
          data['profiles'].each do |name, cfg|
            unless cfg.is_a?(Hash) && cfg['health_check'].is_a?(Hash)
              raise "Validation failed: 'health_check' must be defined in 'shared' or in every profile (missing in '#{name}')"
            end
          end
        end
      end

      def deep_copy(obj)
        Marshal.load(Marshal.dump(obj))
      end

      def deep_merge(base, override)
        return base unless override.is_a?(Hash)
        base.merge(override) do |_key, old_val, new_val|
          if old_val.is_a?(Hash) && new_val.is_a?(Hash)
            deep_merge(old_val, new_val)
          else
            new_val
          end
        end
      end
    end

    # =====================================================================
    # Console Command Dispatcher
    # =====================================================================
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      @@runtime = nil

      def self.runtime=(runtime)
        @@runtime = runtime
      end

      def self.runtime
        @@runtime
      end

      def name
        'TestEnv'
      end

      def commands
        {
          'test_env' => 'Manage vulnerable test environments'
        }
      end

      def cmd_test_env(*args)
        if args.empty? || args.first == '-h' || args.first == '--help'
          cmd_test_env_help
          return
        end

        subcommand = args.shift

        case subcommand
        when 'build'
          cmd_test_env_build(args)
        when 'list'
          print_status("TODO: test_env list")
        when 'stop'
          print_status("TODO: test_env stop")
        when 'start'
          print_status("TODO: test_env start")
        when 'remove'
          print_status("TODO: test_env remove")
        when 'remove-all'
          print_status("TODO: test_env remove-all")
        when 'exec'
          print_status("TODO: test_env exec")
        when 'status'
          cmd_test_env_status(args)
        when 'help'
          cmd_test_env_help
        else
          print_error("Unknown subcommand: #{subcommand}")
          cmd_test_env_help
        end
      end

      def cmd_test_env_build(args)
        begin
          # 1. Preconditions
          mod = driver.active_module
          unless mod
            print_error("No active module. Use 'use <module>' first.")
            return
          end

          # 2. Read and validate module metadata
          env = vulnerable_environment(mod)
          return unless env  # nil means missing or invalid; error already printed

          # 3. Parse user arguments
          options = parse_build_args(args)

          # 4. Extract references from validated Struct
          definition_name = env.definition
          default_variant = env.default_variant
          port_mapping    = env.port_mapping

          # 5. Determine variant and profile
          variant = options['VERSION'] || default_variant
          profile = options['PROFILE'] || env.profile

          unless variant
            print_error("No variant specified and module has no default_variant.")
            return
          end

          # 6. Load and resolve environment definition
          loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
          config = loader.resolve(definition_name, variant, profile, env.overrides)

          # 7. Display resolved configuration (Week 3 proof of concept)
          print_status("Resolving environment for #{mod.fullname}...")
          print_status("Definition: #{definition_name} | Variant: #{variant} | Profile: #{profile}")
          print_status("Image: #{config['image']}")
          print_status("Ports: #{config['ports'].inspect}")
          print_status("Port mapping: #{port_mapping.inspect}")

          if config['health_check']
            print_status("Health check: #{config['health_check']['type']} #{config['health_check']['path']}")
          end

          if config['datastore_defaults']
            print_status("Datastore defaults: #{config['datastore_defaults'].inspect}")
          end

          if config['credentials']
            print_status("Credentials: #{config['credentials'].inspect}")
          end

          print_good("Environment definition resolved successfully.")
          print_status("Ready for container launch (Week 4).")

        rescue => e
          print_error("test_env build failed: #{e.message}")
          elog("test_env build error: #{e.class} - #{e.message}")
          elog(e.backtrace.join("\n"))
        end
      end

      def cmd_test_env_help
        print_line("Usage: test_env <command>")
        print_line
        print_line("Commands:")
        print_line("  build      Build and launch environment for active module")
        print_line("  list       List tracked environments")
        print_line("  stop <ID>  Stop a running environment")
        print_line("  start <ID> Restart a stopped environment")
        print_line("  remove <ID> Tear down an environment")
        print_line("  remove-all Tear down all environments")
        print_line("  exec <ID>  Execute exploit against environment")
        print_line("  status     Show runtime status")
        print_line("  help       Show this help")
        print_line
      end

      def cmd_test_env_status(args)
        runtime = self.class.runtime
        if runtime
          print_status("Runtime: #{runtime.name}")
        else
          print_error("No runtime configured.")
        end

        loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
        defs = loader.available_definitions

        valid_defs = []
        defs.each do |name|
          begin
            loader.load(name)
            valid_defs << name
          rescue => e
            print_error("Validation failed for '#{name}': #{e.message}")
          end
        end

        if valid_defs.any?
          print_status("Available definitions: #{valid_defs.join(', ')}")
        else
          print_error("No valid definitions found.")
        end
      rescue => e
        print_error("Status check failed: #{e.message}")
      end

      def cmd_test_env_tabs(str, words)
        if words.length == 1
          return %w[build list stop start remove remove-all exec status help]
        end

        if words.length == 2 && words[0] == 'build'
          return %w[VERSION= PROFILE=]
        end

        if words.length == 2
          case words[0]
          when 'stop', 'start', 'remove', 'exec'
            return []
          end
        end

        []
      end

      private

      # Reads and validates VulnerableEnvironment metadata from the active module.
      # Mirrors the framework pattern used by #name, #description, #notes, etc.
      # Returns a VulnerableEnvironment Struct, or nil if the module has none.
      def vulnerable_environment(mod)
        return nil unless mod

        raw = mod.send(:module_info)['VulnerableEnvironment']
        return nil unless raw

        VulnerableEnvironment.new(raw)
      rescue ArgumentError => e
        print_error("Module has invalid VulnerableEnvironment: #{e.message}")
        nil
      end

      # Parse build arguments. Only accepts known keys.
      def parse_build_args(args)
        options = {}
        args.each do |arg|
          if arg.include?('=')
            key, value = arg.split('=', 2)
            key = key.upcase
            if %w[VERSION PROFILE].include?(key)
              options[key] = value
            else
              print_warning("Unknown build option: #{key}. Expected: VERSION=, PROFILE=")
            end
          end
        end
        options
      end
    end

    # =====================================================================
    # Plugin Lifecycle
    # =====================================================================
    def initialize(framework, opts)
      super
      @runtime = RuntimeAdapter.detect
      ConsoleCommandDispatcher.runtime = @runtime
      if @runtime
        print_status("TestEnv plugin loaded. Runtime: #{@runtime.name}")
      else
        print_error("TestEnv plugin loaded, but no container runtime found.")
        print_error("Install Docker or Podman to use test_env.")
      end
      add_console_dispatcher(ConsoleCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher('TestEnv')
      ConsoleCommandDispatcher.runtime = nil
    end

    def name
      'test_env'
    end

    def desc
      'Automated vulnerable environment provisioning'
    end
  end
end