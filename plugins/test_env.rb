require 'set'
require 'json'
require 'open3'
require 'shellwords'

module Msf
  class Plugin::VulnEnv < Msf::Plugin
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
          _out2, err2, status2 = Open3.capture3('podman', 'pull', image)
          if status2.success?
            true
          else
            elog("Podman pull failed: #{err}")
            false
          end
        end
      end

      def run(image:, ports:, labels:, volumes: [], env: {}, name: nil)
        validate_image_name!(image)
        cmd = ['podman', 'run', '-d']

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

      def resolve(name, version, profile = 'default', overrides = {})
        data = load(name)

        # Verify version exists
        unless data['versions'].key?(version)
          available = data['versions'].keys.join(', ')
          raise "Version '#{version}' not defined for '#{name}'. Available: #{available}"
        end

        # Verify profile exists
        unless data['profiles'].key?(profile)
          available = data['profiles'].keys.join(', ')
          raise "Profile '#{profile}' not defined for '#{name}'. Available: #{available}"
        end

        # Start with a deep copy of shared
        config = deep_copy(data['shared'] || {})

        # Deep-merge profile-specific overrides (minus description)
        profile_data = data['profiles'][profile].dup
        profile_data.delete('description')
        config = deep_merge(config, profile_data)

        # Deep-merge module-level overrides
        config = deep_merge(config, overrides) if overrides.is_a?(Hash) && !overrides.empty?

        # Attach version-specific image and build args
        version_data = data['versions'][version]
        config['image'] = version_data['image']
        config['build_args'] = version_data['build_args'] if version_data['build_args']

        config
      end

      def available_definitions
        return [] unless Dir.exist?(@base_path)
        Dir.glob(File.join(@base_path, '*.yml')).map { |f| File.basename(f, '.yml') }
      end

      private

      def validate!(data, filename)
        # Rule 1: name must match filename
        unless data['name'] == filename
          raise "Validation failed: name '#{data['name']}' does not match filename '#{filename}'"
        end

        # Rule 2: versions must have at least one entry
        unless data['versions'].is_a?(Hash) && !data['versions'].empty?
          raise "Validation failed: 'versions' must have at least one entry"
        end

        # Rule 3: each version must have an image
        data['versions'].each do |ver, cfg|
          unless cfg.is_a?(Hash) && cfg['image'].is_a?(String) && !cfg['image'].empty?
            raise "Validation failed: version '#{ver}' missing valid 'image'"
          end
        end

        # Rule 4: shared.ports must have at least one entry
        unless data['shared'].is_a?(Hash) && data['shared']['ports'].is_a?(Hash) && !data['shared']['ports'].empty?
          raise "Validation failed: 'shared.ports' must have at least one entry"
        end

        # Rule 5: profiles must have at least one entry
        unless data['profiles'].is_a?(Hash) && !data['profiles'].empty?
          raise "Validation failed: 'profiles' must have at least one entry"
        end

        # Rule 6: profiles must contain a 'default' profile
        unless data['profiles'].key?('default')
          raise "Validation failed: 'profiles' must contain a 'default' profile"
        end

        # Rule 7: profile names must match [a-z0-9-]+
        data['profiles'].keys.each do |profile_name|
          unless profile_name.to_s.match?(/\A[a-z0-9-]+\z/)
            raise "Validation failed: profile name '#{profile_name}' must match [a-z0-9-]+"
          end
        end

        # Rule 8: health_check must be defined in shared or in every profile
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

      # Class-level storage for runtime reference
      @@runtime = nil

      def self.runtime=(runtime)
        @@runtime = runtime
      end

      def self.runtime
        @@runtime
      end

      def name
        'VulnEnv'
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

          # 2. Read module metadata
          vuln_env = get_module_vuln_env(mod)
          unless vuln_env
            print_error("Module does not define a vulnerable environment configuration.")
            return
          end

          # 3. Parse user arguments
          options = parse_build_args(args)

          # 4. Extract references
          definition_name = vuln_env['definition']
          default_version = vuln_env['default_version']
          port_mapping    = vuln_env['port_mapping'] || {}
          module_overrides = vuln_env['overrides'] || {}

          # 5. Determine version and profile
          version = options['VERSION'] || default_version
          profile = options['PROFILE'] || vuln_env['profile'] || 'default'

          unless version
            print_error("No version specified and module has no default_version.")
            return
          end

          # 6. Load and resolve
          loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
          config = loader.resolve(definition_name, version, profile, module_overrides)

          # 7. Display resolved configuration (Week 3 proof of concept)
          print_status("Resolving environment for #{mod.fullname}...")
          print_status("Definition: #{definition_name} | Version: #{version} | Profile: #{profile}")
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
          return %w[VERSION= PROFILE= RPORT=]
        end

        if words.length == 2
          case words[0]
          when 'stop', 'start', 'remove', 'exec'
            # TODO: Return IDs from registry in Week 6
            return []
          end
        end

        []
      end
      
      private

      def get_module_vuln_env(mod)
        return nil unless mod
        mod.send(:module_info)['VulnEnv']
      end

      def parse_build_args(args)
        options = {}
        args.each do |arg|
          if arg.include?('=')
            key, value = arg.split('=', 2)
            options[key.upcase] = value
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
        print_status("VulnEnv plugin loaded. Runtime: #{@runtime.name}")
      else
        print_error("VulnEnv plugin loaded, but no container runtime found.")
        print_error("Install Docker or Podman to use test_env.")
      end
      add_console_dispatcher(ConsoleCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher('VulnEnv')
      ConsoleCommandDispatcher.runtime = nil
    end

    def name
      'vulnenv'
    end

    def desc
      'Automated vulnerable environment provisioning'
    end
  end
end