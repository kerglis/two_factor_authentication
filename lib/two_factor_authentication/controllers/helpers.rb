module TwoFactorAuthentication
  module Controllers
    module Helpers
      extend ActiveSupport::Concern

      included do

        @@otp_authentication = false

        before_filter :handle_two_factor_authentication

        def self.skip_two_factor_authentication
          @@otp_authentication = false
        end

        def self.require_two_factor_authentication
          @@otp_authentication = true
        end

      end

      def required_two_factor_authentication?
        @@otp_authentication == true
      end

      private

      def handle_two_factor_authentication
        if !devise_controller? and required_two_factor_authentication?
          Devise.mappings.keys.flatten.any? do |scope|
            if signed_in?(scope) and warden.session(scope)['need_two_factor_authentication']
              handle_failed_second_factor(scope)
            end
          end
        end
      end

      def handle_failed_second_factor(scope)
        if request.format.present? and request.format.html?
          session["#{scope}_return_to"] = request.path if request.get?
          redirect_to two_factor_authentication_path_for(scope)
        else
          render nothing: true, status: :unauthorized
        end
      end

      def two_factor_authentication_path_for(resource_or_scope = nil)
        scope = Devise::Mapping.find_scope!(resource_or_scope)
        change_path = "#{scope}_two_factor_authentication_path"
        send(change_path)
      end

    end
  end
end

module Devise
  module Controllers
    module Helpers
      def is_fully_authenticated?
        Devise.mappings.keys.flatten.any? do |scope|
          !session["warden.user.#{scope}.session"].try(:[], 'need_two_factor_authentication')
        end
      end
    end
  end
end
