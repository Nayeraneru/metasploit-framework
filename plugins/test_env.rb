require 'set'
require 'json'
require 'open3'
require 'shellwords'
require 'tmpdir'
require 'socket'
require 'fileutils'
require 'timeout'   
require 'net/http'

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

      # reject only dangerous shell characters
      VALID_IMAGE_NAME = /\A[^\s;|&`$(){}]+\z/ unless defined?(VALID_IMAGE_NAME)
      
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

      def verify_rootless
        # Verify Podman mode and networking backend.
        # Returns [ok, message] — ok is true if viable, message describes status.
        out, _, st = Open3.capture3('podman', 'info', '--format', '{{.Host.Security.Rootless}}')
        rootless = st.success? && out.strip.downcase == 'true'

        unless rootless
          return [true, 'Podman running in rootful mode.']
        end

        # Rootless: check for pasta (preferred) or slirp4netns (fallback) using Ruby's PATH search
        if executable_in_path?('pasta')
          [true, 'Rootless Podman verified — pasta networking available.']
        elsif executable_in_path?('slirp4netns')
          [true, 'Rootless Podman verified — slirp4netns networking available.']
        else
          [false, 'Rootless Podman detected but no networking backend (pasta or slirp4netns) found. ' \
                  'Port forwarding may fail. Install pasta or slirp4netns.']
        end
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

      def executable_in_path?(cmd)
        return false if ENV['PATH'].nil?
        ENV['PATH'].split(File::PATH_SEPARATOR).any? do |dir|
          File.executable?(File.join(dir, cmd))
        end
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
        return 'auto' if pref.empty?  # Unset env var is not an error
        return pref if %w[auto docker podman].include?(pref)
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
    # Allocates free host ports for container bindings.
    # Checks both the current registry AND actively bound Docker/Podman ports
    # to avoid collisions with orphaned containers from previous sessions.
    class PortAllocator
      EPHEMERAL_START = 49152 unless defined?(EPHEMERAL_START)
      EPHEMERAL_END   = 65535 unless defined?(EPHEMERAL_END)

      class NoPortsAvailable < RuntimeError; end

      # runtime: the runtime adapter (DockerRuntime or PodmanRuntime) used to
      # query already-bound ports from previous sessions.
      def initialize(runtime = nil, used_ports = [])
        @runtime = runtime
        @used_ports = Set.new(used_ports)

        # Seed the set with ports already bound by Docker/Podman containers.
        # This prevents collisions with orphaned containers from previous
        # msfconsole sessions whose registry state is lost.
        scan_runtime_ports if @runtime
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

      # Query the container runtime for ports already bound on the host.
      # This catches orphaned containers from previous sessions.
      def scan_runtime_ports
        return unless @runtime

        begin
          containers = @runtime.list
          containers.each do |c|
            next unless c['Ports'].is_a?(String)

            # Docker ps output format: "127.0.0.1:49153->8161/tcp, 127.0.0.1:49154->80/tcp"
            # Extract host ports from the binding string.
            c['Ports'].scan(/:(\d+)->\d+\//).each do |match|
              port = match[0].to_i
              @used_ports.add(port) if port.between?(EPHEMERAL_START, EPHEMERAL_END)
            end
          end
        rescue => e
          # If the runtime query fails, fall back to TCPServer-only checking
          # This is a graceful degradation, not a fatal error
          elog("PortAllocator: failed to scan runtime ports: #{e.message}")
        end
      end

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
    # Built Environment (Immutable Value Object)
    # =====================================================================
    class BuiltEnvironment
      attr_reader :local_id, :container_id, :module_fullname, :env_version,
                  :runtime, :image_ref, :status,:datastore, :allocated_ports, 
                  :created_at, :started_at, :stopped_at, :removed_at, :temp_dirs

      def initialize(local_id:, container_id:, module_fullname:, env_version: nil,
                     runtime:, image_ref:, datastore: {}, allocated_ports: {},
                     created_at: Time.now, started_at: Time.now, temp_dirs: [])
        @local_id        = local_id
        @container_id    = container_id
        @module_fullname = module_fullname
        @env_version     = env_version
        @runtime         = runtime
        @image_ref       = image_ref
        @status          = :running
        @datastore       = datastore.dup.freeze  # Prevent external mutation
        @created_at      = created_at
        @started_at      = started_at
        @stopped_at      = nil
        @removed_at      = nil
        @temp_dirs = temp_dirs.dup.freeze
        @allocated_ports = allocated_ports.dup.freeze
      end

      # Convenience accessors — derived from datastore, not stored redundantly
      def rhost
        datastore['RHOSTS'] || datastore['RHOST']
      end

      def rport
        datastore['RPORT']
      end

      # All host ports allocated for this environment (for collision detection)
      def all_host_ports
        allocated_ports.values
      end

      def running?
        status == :running
      end

      def stopped?
        status == :stopped
      end

      def removed?
        status == :removed
      end

      # State transitions with timestamp tracking
      def mark_running
        @status = :running
        @started_at = Time.now
      end

      def mark_stopped
        @status = :stopped
        @stopped_at = Time.now
      end

      def mark_removed
        @status = :removed
        @removed_at = Time.now
      end

      # construct exploit command dynamically from current datastore
      def exploit_command
        opts = datastore.map { |k, v| "#{k}=#{v}" }.join(' ')
        "exploit #{opts}"
      end

      # Convert to hash for serialization (DB Phase 2) or table output
      def to_h
        {
          local_id: local_id,
          container_id: container_id,
          module_fullname: module_fullname,
          env_version: env_version,
          runtime: runtime,
          image_ref: image_ref,
          status: status,
          exploit_command: exploit_command,
          datastore: datastore,
          allocated_ports: allocated_ports,
          all_host_ports: all_host_ports,
          rhost: rhost,
          rport: rport,
          created_at: created_at,
          started_at: started_at,
          stopped_at: stopped_at,
          removed_at: removed_at,
          temp_dirs: temp_dirs
        }
      end
    end

    # =====================================================================
    # Built Environment Registry (Phase 1: In-Memory Only)
    # =====================================================================
    class BuiltEnvironmentRegistry
      attr_reader :environments, :framework

      def initialize(framework)
        @framework = framework
        @environments = {}  # local_id => BuiltEnvironment
        @next_id = 1
        @mutex = Mutex.new
      end

      def reserve_id
        @mutex.synchronize do
          id = @next_id
          @next_id += 1
          id
        end
      end

      def register(container_id:, module_fullname:, env_version: nil,
                   runtime:, image_ref:, datastore: {}, allocated_ports: {}, temp_dirs: [])
        @mutex.synchronize do
          id = @next_id
          @next_id += 1

          env = BuiltEnvironment.new(
            local_id: id,
            container_id: container_id,
            module_fullname: module_fullname,
            env_version: env_version,
            runtime: runtime,
            image_ref: image_ref,
            datastore: datastore,
            allocated_ports: allocated_ports,
            temp_dirs: temp_dirs
          )

          @environments[id] = env
          id
        end
      end

      def register_with_id(env_id:, container_id:, module_fullname:, env_version: nil,
                           runtime:, image_ref:, datastore: {}, allocated_ports: {}, temp_dirs: [])
        @mutex.synchronize do
          env = BuiltEnvironment.new(
            local_id: env_id,
            container_id: container_id,
            module_fullname: module_fullname,
            env_version: env_version,
            runtime: runtime,
            image_ref: image_ref,
            datastore: datastore,
            allocated_ports: allocated_ports,
            temp_dirs: temp_dirs
          )

          @environments[env_id] = env
          env_id
        end
      end 

      def get(id)
        @environments[id]
      end

      def list
        @environments.values.sort_by(&:local_id)
      end

      def update_status(id, status)
        @mutex.synchronize do
          env = @environments[id]
          return unless env

          case status.to_sym
          when :running then env.mark_running
          when :stopped then env.mark_stopped
          when :removed then env.mark_removed
          end
        end
      end

      def remove(id)
        dirs_to_clean = []
        
        @mutex.synchronize do
          env = @environments[id]
          return unless env

          dirs_to_clean = env.temp_dirs.dup
          env.mark_removed
          @environments.delete(id)
        end
        
        # cleanup outside mutex
        dirs_to_clean.each do |dir|
          FileUtils.rm_rf(dir) if Dir.exist?(dir)
        end
      end

      def remove_all
        # this only clears registry records. It does NOT stop containers
        # the dispatcher must call runtime.stop / runtime.remove on each container first
        # collect temp directories and mark removed under mutex
        # but do the actual filesystem cleanup AFTER releasing the mutex
        envs_to_clean = []
        
        @mutex.synchronize do
          @environments.each_value do |env|
            envs_to_clean << env.temp_dirs
            env.mark_removed
          end
          @environments.clear
          @next_id = 1
        end
        
        # slow filesystem operations happen OUTSIDE the mutex
        # other threads can now use the registry freely
        envs_to_clean.each do |dirs|
          dirs.each do |dir|
            FileUtils.rm_rf(dir) if Dir.exist?(dir)
          end
        end
      end

      def find_by_container(container_id)
        @environments.values.find { |e| e.container_id == container_id }
      end

      def find_by_module(module_fullname)
        @environments.values.select { |e| e.module_fullname == module_fullname }
      end

      def used_ports
        @environments.values.flat_map(&:all_host_ports).compact
      end

      def running?
        @environments.values.any?(&:running?)
      end
    end

    # =====================================================================
    # Health Manager
    # =====================================================================
    # waits for a container to become ready using a configurable strategy
    # supports HTTP (status code), TCP (port open), and Command (exec inside container)
    class HealthManager
      def initialize(runtime, container_id, health_config, host_port, dispatcher = nil)
        @runtime = runtime
        @container_id = container_id
        @config = health_config || {}
        @host_port = host_port
        @dispatcher = dispatcher
      end

      # block until the health check passes or retries are exhausted
      # returns true on success. raises on failure so the caller decides cleanup
      def wait
        type = @config['type']
        interval = @config['interval'] || 5
        timeout = @config['timeout'] || 2
        retries = @config['retries'] || 12

        unless %w[http tcp command].include?(type)
          raise "Unknown health check type: #{type.inspect}"
        end

        print_status("Waiting for health check (#{type.upcase})...")

        retries.times do |i|
          print_status("  Attempt #{i + 1}/#{retries}...")

          result = false
          begin
            # Wrap each individual check in a timeout so a hanging TCP/HTTP
            # connection doesn't consume the entire retry budget.
            Timeout.timeout(timeout) do
              result = case type
                       when 'http'    then check_http
                       when 'tcp'     then check_tcp
                       when 'command' then check_command
                       end
            end
          rescue Timeout::Error
            result = false
          rescue => e
            # Log debug details but don't spam the console on every retry
            @dispatcher&.elog("Health check attempt #{i + 1} error: #{e.class} - #{e.message}") if @dispatcher&.respond_to?(:elog)
            result = false
          end

          if result
            print_good("Health check passed.")
            return true
          end

          sleep(interval)
        end

        total_seconds = retries * interval
        raise "Health check timed out after #{total_seconds} seconds"
      end

      def print_status(msg)
        @dispatcher&.print_status(msg)
      end

      def print_good(msg)
        @dispatcher&.print_good(msg)
      end

      def print_error(msg)
        @dispatcher&.print_error(msg)
      end

      private

      def check_http
        path = @config['path'] || '/'
        expected_status = @config['expected_status'] || 200

        uri = URI("http://127.0.0.1:#{@host_port}#{path}")

        # Explicit timeouts prevent hanging connections from consuming the retry budget.
        # Timeout.timeout is unreliable with Net::HTTP blocking I/O.
        http = Net::HTTP.new(uri.host, uri.port)
        http.open_timeout = 2   # Max seconds to establish TCP connection
        http.read_timeout = 2   # Max seconds to read response

        request = Net::HTTP::Get.new(uri)

        # If credentials are defined in the health_check config, add Basic Auth.
        # ActiveMQ's Jolokia endpoint requires this.
        if @config['credentials'] && @config['credentials']['username']
          request.basic_auth(
            @config['credentials']['username'],
            @config['credentials']['password']
          )
        end

        response = http.request(request)

        actual_status = response.code.to_i
        if actual_status == expected_status
          true
        else
          # Diagnostic output: tell the user what actually came back
          print_status("  Health check returned #{actual_status}, expected #{expected_status}")
          false
        end
      rescue Errno::ECONNRESET
        # TCP connection accepted but HTTP server not yet initialized.
        # This is a transient "not ready" signal — retry on next attempt.
        print_status("  Connection reset on port #{@host_port} (service still initializing)")
        false

      rescue Errno::ECONNREFUSED
        print_status("  Connection refused on port #{@host_port}")
        false

      rescue Net::OpenTimeout
        print_status("  Connection timeout on port #{@host_port}")
        false
      rescue => e
        print_status("  Health check error: #{e.class} - #{e.message}")
        false
      end

      def check_tcp
        # A successful connection + immediate close means the port is listening
        TCPSocket.new('127.0.0.1', @host_port).close
        true
      rescue => e
        false
      end

      def check_command
        command = @config['command']
        expected_output = @config['expected_output']

        output, exit_code = @runtime.exec(@container_id, command)
        return false unless exit_code == 0

        if expected_output
          output.include?(expected_output)
        else
          true
        end
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

        variant_cfg = data['variants'].find { |v| v['name'] == variant }
        unless variant_cfg
          available = data['variants'].map { |v| v['name'] }.join(', ')
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

        config['image'] = variant_cfg['image']
        config['build_args'] = variant_cfg['build_args'] if variant_cfg['build_args']

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

        unless data['variants'].is_a?(Array) && !data['variants'].empty?
          raise "Validation failed: 'variants' must be a non-empty list"
        end

        data['variants'].each do |cfg|
          unless cfg.is_a?(Hash) && cfg['name'].is_a?(String) && !cfg['name'].empty?
            raise "Validation failed: variant missing valid 'name'"
          end
          unless cfg['image'].is_a?(String) && !cfg['image'].empty?
            raise "Validation failed: variant '#{cfg['name']}' missing valid 'image'"
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

      def self.registry=(registry)
        @@registry = registry
      end

      def self.registry
        @@registry
      end

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
          container_id = nil   # Track for cleanup
          registered = false # Track whether registration succeeded
          
          # 1. Preconditions
          mod = driver.active_module
          unless mod
            print_error("No active module. Use 'use <module>' first.")
            return
          end

          # 2. Read and validate module metadata
          env = vulnerable_environment(mod)
          unless env
            print_error("Module does not define a vulnerable environment configuration.")
            return
          end

          # 3. Parse user arguments
          options = parse_build_args(args)

          # 4. Extract references from validated Struct
          definition_name = env.definition
          default_variant = env.default_variant
          port_mapping    = env.port_mapping

          # 5. Determine variant and profile
          variant = options['VARIANT'].to_s.empty? ? default_variant : options['VARIANT']
          profile = options['PROFILE'].to_s.empty? ? env.profile : options['PROFILE']

          unless variant
            print_error("No variant specified and module has no default_variant.")
            return
          end

          # 6. Check runtime availability
          runtime = self.class.runtime
          unless runtime
            print_error("No container runtime available. Install Docker or Podman.")
            return
          end

          # 7. Load and resolve environment definition
          loader = EnvironmentDefinitionLoader.new(Msf::Config.data_directory)
          config = loader.resolve(definition_name, variant, profile, env.overrides)

          # Validate: every port in module's port_mapping must exist in the environment's exposed ports
          resolved_ports = config.fetch('ports', {}).values.map(&:to_i)
          port_mapping.keys.each do |container_port|
            port_int = container_port.to_i
            unless resolved_ports.include?(port_int)
              available = resolved_ports.join(', ')
              raise "Port mapping mismatch: module maps port #{port_int} but environment '#{definition_name}' (variant '#{variant}', profile '#{profile}') only exposes ports: #{available}"
            end
          end

          print_status("Resolving environment for #{mod.fullname}...")
          print_status("Definition: #{definition_name} | Variant: #{variant} | Profile: #{profile}")
          print_status("Image: #{config['image']}")

          # 8. Pull the container image
          print_status("Pulling image #{config['image']}...")
          unless runtime.pull(config['image'])
            print_error("Failed to pull image: #{config['image']}")
            return
          end
          print_good("Image pulled successfully.")

          # 9. Allocate ports using PortAllocator
          # Pass the runtime so PortAllocator can scan Docker/Podman for
          # ports already bound by orphaned containers from previous sessions.
          allocator = PortAllocator.new(runtime, self.class.registry.used_ports)
          allocated_ports = {}  # {container_port => host_port}
          user_rport = options['RPORT'] ? options['RPORT'].to_i : nil
          # Resolve which container port the user actually wants to override.
          # this ensures RPORT=8081 always targets the port mapped to the
          # 'RPORT' datastore key, regardless of Ruby hash insertion order.
          target_container_port = user_rport ? port_mapping.key('RPORT') : nil

          port_mapping.each do |container_port, ds_option|
            preferred = (container_port == target_container_port) ? user_rport : nil
            host_port = allocator.allocate(preferred)

            if preferred && host_port != preferred
              print_status("Requested port #{preferred} unavailable. Using dynamically allocated port #{host_port}.")
            end

            allocated_ports[container_port] = host_port
          end

          # 10. Build container labels for cross-session identification
          instance_id = "msf-#{Socket.gethostname}-#{Process.pid}"
          # reserve the ID first, before starting the container
          env_id = self.class.registry.reserve_id

          # now build labels with the GUARANTEED ID
          labels = runtime.build_labels(
            instance_id: instance_id,
            module_fullname: mod.fullname,
            env_id: env_id,
            version: variant,
            ports: allocated_ports
          )

          # 11. Prepare port mappings for docker run
          # Format: {container_port => host_port} for runtime.run
          run_ports = {}
          allocated_ports.each do |container_port, host_port|
            run_ports[container_port] = host_port
          end

          # 12. Prepare volumes from config
          volumes = {}
          temp_dirs = []

          if config['volumes']
            config['volumes'].each do |name, vol_cfg|
              host_path = vol_cfg['host_path']
              unless host_path  # <-- CHANGED: split the || into two lines
                host_path = Dir.mktmpdir("test_env_#{name}_")
                temp_dirs << host_path  # <-- ADD THIS LINE
              end
              volumes[host_path] = vol_cfg['container_path']
            end
          end

          # 13. Launch the container
          print_status("Starting container...")
          container_name = "msf-vulnenv-#{definition_name}-#{variant}-#{Time.now.to_f.to_s.delete('.')}"  
          container_id = runtime.run(
            image: config['image'],
            ports: run_ports,
            labels: labels,
            volumes: volumes,
            name: container_name
          )

          # verify container actually started
          container_info = runtime.inspect(container_id)
          unless container_info
            print_error("Container started but inspect failed immediately.")
            runtime.remove(container_id)
            return
          end

          # check if running (Docker/Podman both use State.Status)
          status = container_info.dig('State', 'Status') || container_info.dig('State', 'Running')
          if status != 'running' && status != true
            # Try to get the error reason
            error_msg = container_info.dig('State', 'Error') || 'unknown'
            print_error("Container failed to start. Status: #{status.inspect}, Error: #{error_msg}")

            # clean up the dead container
            runtime.remove(container_id)
            return
          end

          print_good("Container started: #{container_id[0..11]}")

          # Determine the host port for health checks.
          # If the module maps a port to 'RPORT', use that. Otherwise fall back
          # to the first allocated port so health checks don't crash on modules
          # that use a different datastore key (e.g., auxiliary scanners).
          primary_container_port = port_mapping.key('RPORT')
          health_host_port = allocated_ports[primary_container_port] || allocated_ports.values.first

          # 14. wait for health check BEFORE registering the environment
          # If this fails, the container is cleaned up and the environment is NOT tracked
          health = config['health_check']
          begin
          HealthManager.new(runtime, container_id, health, health_host_port, self).wait
          rescue => e
            print_error("Health check failed: #{e.message}")

            # stop and remove the unhealthy container so it doesn't leak
            begin
              runtime.stop(container_id) rescue nil
              runtime.remove(container_id) rescue nil
            rescue => cleanup_err
              elog("Failed to cleanup unhealthy container: #{cleanup_err.message}")
            end
            return
          end

          # 15. Build datastore from allocated ports and config defaults
          datastore = { 'RHOSTS' => '127.0.0.1' }
          allocated_ports.each do |container_port, host_port|
            ds_option = port_mapping[container_port]
            datastore[ds_option] = host_port if ds_option
          end

          # Apply datastore_defaults from environment definition
          if config['datastore_defaults']
            config['datastore_defaults'].each do |key, value|
              datastore[key] = value unless datastore.key?(key)  # Don't override port mappings
            end
          end

          # TODO(Week 8): If module requires payload, auto-set PAYLOAD, LHOST, LPORT


          # 16. Pass the pre-reserved env_id
          self.class.registry.register_with_id(
            env_id: env_id,
            container_id: container_id,
            module_fullname: mod.fullname,
            env_version: variant,
            runtime: runtime.name,
            image_ref: config['image'],
            datastore: datastore,
            allocated_ports: allocated_ports,
            temp_dirs: temp_dirs
          )
          # Labels already contain correct env_id from reserve_id above

          registered = true

          # 17. Apply datastore to the active module
          datastore.each do |key, value|
            mod.datastore[key] = value
          end


          # 18. Display results to user
          print_good("Environment ready.")
          print_status("Environment ID: #{env_id}")
          datastore.each do |key, value|
            print_status("   #{key.ljust(12)} => #{value}")
          end

          if config['credentials'] && config['credentials']['default']
            creds = config['credentials']['default']
            print_status("   #{'USERNAME'.ljust(12)} => #{creds['username']}")
            print_status("   #{'PASSWORD'.ljust(12)} => #{creds['password']}")
          end

          env = self.class.registry.get(env_id)
          print_status("Suggested: #{env.exploit_command}")

        rescue PortAllocator::NoPortsAvailable => e
          print_error("No available ports: #{e.message}")
        rescue => e
          # Clean up orphaned container if we created one but failed to register it
          if container_id && !registered
            begin
              # A running container cannot be removed without -f
              # we stop first to ensure clean removal
              runtime.stop(container_id) rescue nil
              runtime.remove(container_id)
              print_status("Cleaned up orphaned container #{container_id[0..11]}")
            rescue => cleanup_err
              elog("Failed to cleanup orphaned container: #{cleanup_err.message}")
            end
          end

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
          if runtime.respond_to?(:verify_rootless)
            ok, msg = runtime.verify_rootless
            ok ? print_good(msg) : print_warning(msg)
          end

          # count framework-managed containers
          containers = runtime.list(filters: { 'label' => 'msf.vulnenv.managed_by=test_env' })
          running = containers.count { |c| c['State'] == 'running' }
          total = containers.length

          print_status("Managed containers: #{total} total, #{running} running")
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
          return %w[VARIANT= PROFILE= RPORT=]
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
            if %w[VARIANT PROFILE RPORT].include?(key)
              options[key] = value
            else
              print_warning("Unknown build option: #{key}. Expected: VARIANT=, PROFILE=, RPORT=")
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
      @registry = BuiltEnvironmentRegistry.new(framework)

      ConsoleCommandDispatcher.runtime = @runtime
      ConsoleCommandDispatcher.registry = @registry

      if @runtime
        print_status("TestEnv plugin loaded. Runtime: #{@runtime.name}")
        # Verify rootless Podman when applicable
        if @runtime.respond_to?(:verify_rootless)
          ok, msg = @runtime.verify_rootless
          ok ? print_status(msg) : print_warning(msg)
        end
      else
        print_error("TestEnv plugin loaded, but no container runtime found.")
        print_error("Install Docker or Podman to use test_env.")
      end
      add_console_dispatcher(ConsoleCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher('TestEnv')
      ConsoleCommandDispatcher.runtime = nil
      ConsoleCommandDispatcher.registry = nil
    end

    def name
      'test_env'
    end

    def desc
      'Automated vulnerable environment provisioning'
    end
  end
end
