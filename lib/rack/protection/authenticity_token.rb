require 'rack/protection'

module Rack
  module Protection
    ##
    # Prevented attack::   CSRF
    # Supported browsers:: all
    # More infos::         http://en.wikipedia.org/wiki/Cross-site_request_forgery
    #
    # Only accepts unsafe HTTP requests if a given access token matches the token
    # included in the session.
    #
    # Compatible with Rails and rack-csrf.
    class AuthenticityToken < Base
      def accepts?(env)
        return true if safe? env
        session = session env
        token   = session[:csrf] ||= session['_csrf_token'] || random_string
        secure_compare(env['HTTP_X_CSRF_TOKEN'], token) ||
          secure_compare(Request.new(env).params['authenticity_param'], token)
      end
    end
  end
end
