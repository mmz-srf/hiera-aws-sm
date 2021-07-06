require 'logger'
require 'date'
require 'digest/md5'

Puppet::Functions.create_function(:hiera_aws_sm) do
  begin
    require 'json'
  rescue LoadError
    raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install json gem to use hiera-aws-sm backend'
  end
  begin
    require 'aws-sdk-core'
  rescue LoadError
    raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install aws-sdk-core gem to use hiera-aws-sm backend'
  end
  begin
    require 'aws-sdk-secretsmanager'
  rescue LoadError
    raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install aws-sdk-secretsmanager gem to use hiera-aws-sm backend'
  end

  dispatch :lookup_key do
    param 'Variant[String, Numeric]', :key
    param 'Hash', :options
    param 'Puppet::LookupContext', :context
  end

  ##
  # lookup_key
  #
  # Determine whether to lookup a given key in secretsmanager, and if so, return the result of the lookup
  #
  # @param key Key to lookup
  # @param options Options hash
  # @param context Puppet::LookupContext
  def lookup_key(key, options, context)
    log = Logger.new(STDOUT)
    case options['log_level']
    when 'info'
      log.level = Logger::INFO
    when 'warn'
      log.level = Logger::WARN    
    when 'debug'
      log.level = Logger::DEBUG
    else
      log.level = Logger::ERROR
    end
    # Filter out keys that do not match a regex in `confine_to_keys`, if it's specified
    if confine_keys = options['confine_to_keys']
      raise ArgumentError, '[hiera-aws-sm] confine_to_keys must be an array' unless confine_keys.is_a?(Array)

      begin
        confine_keys = confine_keys.map { |r| Regexp.new(r) }
      rescue StandardError => err
        raise Puppet::DataBinding::LookupError, "[hiera-aws-sm] Failed to create regexp with error #{err}"
      end
      re_match = Regexp.union(confine_keys)
      unless key[re_match] == key
        context.explain { "[hiera-aws-sm] Skipping secrets manager as #{key} doesn't match confine_to_keys" }
        context.not_found
      end
    end

    # Handle cache
    if options.key?('cache_ttl')
      cache_ttl = options['cache_ttl']
    else
      options['cache_ttl'] = 0
    end

    if options.key?('cache_file')
      log.info("Using cache #{options['cache_file']}")
    else
      create_md5 = options['prefixes'].join
      file_name = Digest::MD5.hexdigest(create_md5)
      options['cache_file'] = "/tmp/#{file_name}"
      log.info("Using cache #{options['cache_file']}")
    end

    # Handle prefixes if suplied
    if prefixes = options['prefixes']
      raise ArgumentError, '[hiera-aws-sm] prefixes must be an array' unless prefixes.is_a?(Array)
      if delimiter = options['delimiter']
        raise ArgumentError, '[hiera-aws-sm] delimiter must be a String' unless delimiter.is_a?(String)
      else
        delimiter = '/'
      end

      # Remove trailing delimters from prefixes
      prefixes = prefixes.map { |prefix| (prefix[prefix.length-1] == delimiter) ? prefix[0..prefix.length-2] : prefix }
      # Merge keys and prefixes
      keys = prefixes.map { |prefix| [prefix, key].join(delimiter) }
    else
      keys = [key]
    end

    # Query SecretsManager for the secret data, stopping once we find a match
    result = nil
    keys.each do |secret_key|
      result = get_secret(secret_key, options, context)
      unless result.nil?
        break
      end
    end

    continue_if_not_found = options['continue_if_not_found'] || false

    if result.nil? and continue_if_not_found
      context.not_found
    end
    result
  end

  ##
  # get_secret
  #
  # Lookup a given key in AWS Secrets Manager
  #
  # @param key Key to lookup
  # @param options Options hash
  # @param context Puppet::LookupContext
  #
  # @return One of Hash, String, (Binary?) depending on the value returned
  # by AWS Secrets Manager. If a secret_binary is present in the response,
  # it is returned directly. If secret_string is set, and can be co-erced
  # into a Hash, it is returned, otherwise a String is returned.
  def get_secret(key, options, context)
    client_opts = {}
    client_opts[:access_key_id] = options['aws_access_key'] if options.key?('aws_access_key')
    client_opts[:secret_access_key] = options['aws_secret_key'] if options.key?('aws_secret_key')
    client_opts[:region] = options['region'] if options.key?('region')
    
    log = Logger.new(STDOUT)
    case options['log_level']
    when 'info'
      log.level = Logger::INFO
    when 'warn'
      log.level = Logger::WARN    
    when 'debug'
      log.level = Logger::DEBUG
    else
      log.level = Logger::ERROR
    end
    secretsmanager = Aws::SecretsManager::Client.new(client_opts)
    response = nil
    secret = nil

    context.explain { "[hiera-aws-sm] Looking up #{key}" }
    begin
      secret_formatted = key.gsub('::', '/')
      # development/puppetserver/profile_puppetserver/puppetdb/aws_testpassword
      # production/puppetserver.loc.serv.development.srf.mpc/profile_puppetserver/puppetdb/aws_testpassword
      if (secret_in_cache(secret_formatted, options)) || (options['cache_ttl'] == 0)
        log.info("[hiera-aws-sm] secret #{key}  found in cache ")
        #response = secretsmanager.get_secret_value(secret_id: secret_formatted)
        #output = `export AWS_ACCESS_KEY_ID=XXXXXX && export AWS_SECRET_ACCESS_KEY=YYYYYY && export AWS_DEFAULT_REGION=eu-central-1 && aws secretsmanager get-secret-value --secret-id StefansTestSecretName`
        #response = JSON.parse(output)
        response = JSON.parse('{
                        "SecretString": "{\"StefansTestSecret\":\"xxxxx\",\"vvvvvvv\":\"Oh, man kann was hinzufügen\"}"
                    }')
        log.info("[hiera-aws-sm] secret #{key} provided by #{secret_formatted}")
      end
    rescue Aws::SecretsManager::Errors::ResourceNotFoundException
      context.explain { "[hiera-aws-sm] No data found for #{key}" }
      if key.include? "common"
        log.warn("[hiera-aws-sm] secret #{key} not found in SM")
      else
        log.info("[hiera-aws-sm] secret #{key} not found in SM")
      end
    rescue Aws::SecretsManager::Errors::UnrecognizedClientException
      raise Puppet::DataBinding::LookupError, "[hiera-aws-sm] Skipping backend. No permission to access #{key}"
    rescue Aws::SecretsManager::Errors::ServiceError => e
      if e.message == 'You can\'t perform this operation on the secret because it was marked for deletion.' then
        context.explain { "[hiera-aws-sm] #{key} found but scheduled for deletion" }
        log.info("[hiera-aws-sm] #{key} found but scheduled for deletion")
      else
        raise Puppet::DataBinding::LookupError, "[hiera-aws-sm] Skipping backend. Failed to lookup #{key} due to #{e.message}"
      end
    end

    unless response.nil?
      secret = process_secret_string(response['SecretString'], options, context)
      secret = secret_formatted
    end

    secret
  end

  ##
  # Get the secret name to lookup, applying a prefix if
  # one is set in the options
  def secret_key_name(key, options)
    if options.key?('prefix')
      [options.prefix, key].join('/')
    else
      key
    end
  end

  def secret_in_cache(key, options)
    if options['cache_ttl'] > 0
      file_cache_exist(options)
      secrets = File.readlines(options['cache_file']).map(&:chomp)
      value = key
      secrets.each do | secret|
        if(value == secret)
          return true
        end
      end
      return false
    else 
      return false
    end
  end

  def file_cache_exist(options)
    cache_expiration_time = DateTime.now - (options['cache_ttl']/24.0)

    if(File.exist?("#{options['cache_file']}"))
      if (cache_expiration_time.strftime( "%Y-%m-%d %H:%M:%S" ) > File.ctime("#{options['cache_file']}").strftime( "%Y-%m-%d %H:%M:%S" ))
         generate_cache(options['cache_file'], options['prefixes'], options['region'])
      end
    else
         generate_cache(options['cache_file'], options['prefixes'], options['region'])
    end
  end

  def generate_cache(path, prefixes, region)
    client = Aws::SecretsManager::Client.new(
      region: region,
    )
    resp = client.list_secrets({
      max_results: 100,
    })
    file = File.open(path, 'w')
    begin
      for i in resp.secret_list
        for prefix in prefixes
          if i.name.include? prefix 
            file.puts(i.name)
          end
        end
      end
      if not resp.key?('next_token')
        break
      end
      resp = client.list_secrets({
        max_results: 100,
        next_token: resp.next_token
      })
    end while true
    file.close()
    return true
  end



  ##
  # Process the response secret string by attempting to coerce it
  def process_secret_string(secret_string, _options, context)
    # Attempt to process this string as a JSON object
    begin
      result = JSON.parse(secret_string)
    rescue JSON::ParserError
      context.explain { '[hiera-aws-sm] Not a hashable result' }
      result = secret_string
    end

    result
  end
end
