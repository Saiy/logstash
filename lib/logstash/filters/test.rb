require "logstash/filters/base"
require "logstash/namespace"
require 'digest/md5';

# Just a test
class LogStash::Filters::Test < LogStash::Filters::Base
  config_name "test"
  milestone 2


  public
  def register
    # Nothing to do
  end #def register

  public
  def filter(event)
    return unless filter?(event)
      if event['type'] == 'nginx-access'
        security_infos = {};
        $posts = {} if $posts == nil
        if event['request']
          args = '';
          tmp = event['request'].split('?',2);
          filename = tmp[0];
          args = tmp[1] if event['request'].include?('?')

          security_infos['args'] = query_parse(args);

          hash = Digest::MD5.hexdigest(filename);

          security_infos['filename'] = filename;
          security_infos['hash']     = hash;
   
          if event['method'] == 'POST'
            if event['response'] == '200'
              if $posts.has_key?(hash)
                $posts[hash] = $posts[hash] + 1;
              else
                $posts[hash] = 1;
              end
            end
          security_infos['posts_count'] = $posts[hash] if $posts.has_key?(hash);
          end

        filter_matched(event)
        security_infos.each do |key,value|
          event[key] = value;
        end
      end
    end
  end

  private
  def _type(input)
    return '[%n]' if input.length == 0; 
    return '[%d]' if /^[0-9]+$/.match(input);
    return '[%f]' if /.*\.\.(\/|\\\\|\%((2f)|(5c)))\.\.(\/|\\\\).*|^(\/|\\\\|\%((2f)|(2F)|(5c)|(5C))).+(\/|\\\\|\%((2f)|(2F)|(5c)|(5C))).+(\/|\\\\|\%((2f)|(2F)|(5c)|(5C))).+/.match(input);
    return '[%e]' if /.*(\\\'|\\\"|\#|(\%(27|22|23)))|((\(|\%28).*?(\)|\%29))/.match(input);
    return '[%s]';
  end

  private
  def query_parse(query) 
    return ['%n',''] if query.length == 0;

    string = '';
    tmp = query.split('&');
    add = '';
    args_string = [];
    args_db = [];
    i = 0;
    tmp.each do |value|
      _value = '[%n]';
      _tmp = value.split('=',2);
      _value = _type(_tmp[1]) if _tmp[1];

      args_tmp = [_tmp[0] , _value];
      args_string[i] = args_tmp.join('=');
      args_db[i] = '';
      args_db[i] = _tmp[1] if _tmp[1];
      i = i+1;
    end


    string  = args_string.join('&');
    result = [string];
    result = result + args_db;
  end
end # class LogStash::Filters::Test
