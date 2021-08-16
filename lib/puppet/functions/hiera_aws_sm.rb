require 'logger'
require 'date'
require 'digest/md5'

Puppet::Functions.create_function(:hiera_aws_sm) do
  begin
    require 'json'
  rescue LoadError
    raise Puppet::DataBinding::LookupError, '[hiera-aws-sm] Must install json gem to use hiera-aws-sm backend'
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

    # Handle prefixes if suplied
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
    response = nil
    secret = nil
    credentials_file = options['credentials_file']

    context.explain { "[hiera-aws-sm] Looking up #{key}" }

    secret_f = key.gsub('::', options['delimiter'])
    secret_formatted = secret_f.sub('secretmanager.', '') #remove secrets prefix for cleaner secret names
    log.info("[hiera-aws-sm] secret #{key}  found in cache ")

    response = { 'SecretString' => "Secret key not found in AWS Secrets Manager #{secret_formatted}" }
    begin
      output = `export AWS_CONFIG_FILE=#{credentials_file} && aws secretsmanager get-secret-value --secret-id #{secret_formatted} 2>&1`
      response = JSON.parse(output)
    rescue
      log.info("[hiera-aws-sm] secret key not found in AWS Secrets Manager #{secret_formatted}")
    end
    log.info("[hiera-aws-sm] secret #{key} provided by #{secret_formatted}")

    unless response.nil?
      # TODO write result to "secret" variable
      secret = process_secret_string(response['SecretString'], options, context)
      #secret = output
      #secret = secret_formatted
    end

    #secret = secret_formatted
    secret
  end

  ##
  # Return JSON in case Secret is a Hash
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