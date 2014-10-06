module TwoFactorAuthentication
  module Controllers
    module Helpers
      extend ActiveSupport::Concern

      included do
        before_filter :handle_two_factor_authentication
      end

      private

      def skip_two_factor_authentication
        @@require_two_factor_authentication = false
      end

      def require_two_factor_authentication
        @@require_two_factor_authentication = true
      end

      def require_two_factor_authentication?
        @@require_two_factor_authentication == true
      end

      def handle_two_factor_authentication
        if !devise_controller? and require_two_factor_authentication?
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
      def is_fully_authenticated?(resource_or_scope = nil)
        scope = Devise::Mapping.find_scope!(resource_or_scope)
        !session["warden.user.#{scope}.session"].try(:[], 'need_two_factor_authentication')
      end
    end
  end
end
