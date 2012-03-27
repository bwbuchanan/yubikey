require 'base64'
require 'cgi'
require 'hmac-sha1'
require 'securerandom'

module Yubikey

  API_URL = 'https://api.yubico.com/wsapi/2.0'

  class OTP::Verify
    
    class << self
      attr_accessor :api_id, :api_key
    end

    # The raw status from the Yubico server
    attr_reader :status

    def initialize(otp)
      verify("id=#{self.class.api_id}&otp=#{CGI.escape(otp)}")
    end

    def valid?
      @status == 'OK'
    end

    def replayed?
      @status == 'REPLAYED_OTP'
    end

    private
    
    def self.sign(params)
      api_key = Base64.strict_decode64(self.api_key)
      
      pairs = params.map { |param| param.split('=', 2) }
      pairs.sort!
      sorted_query_string = pairs.find_all { |k, v| k != 'h' }.map { |k, v| "#{k}=#{v}" }.join('&')
      Base64.strict_encode64(HMAC::SHA1.digest(api_key, sorted_query_string))
    end

    def verify(query)
      nonce = SecureRandom.urlsafe_base64(30)
      
      uri = URI.parse(API_URL) + 'verify'
      uri.query = query + "&nonce=#{nonce}&timestamp=1"

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.ca_file = File.expand_path(File.join(File.dirname(__FILE__), "cacert.pem"))
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER

      req = Net::HTTP::Get.new(uri.request_uri)
      result = http.request(req).body
      p result
      sig = result[/^h=(.*)$/, 1].strip
      expected_sig = self.class.sign(result.strip.split("\r\n"))
      
      if sig != expected_sig
        raise OTP::BadSignatureError, "Response signature is not valid"
      end

      @status = result[/^status=(.*)$/, 1].strip

      if @status == 'BAD_OTP' || @status == 'BACKEND_ERROR'
        raise OTP::InvalidOTPError, "Received error: #{@status}"
      end
    end
  end # OTP::Verify
end # Yubikey
