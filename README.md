# Devise와 Ommiauth를 이용하여 SNS 아이디로 로그인

Devise gem과 omniauth gem을 활용하여 facebook, google, naver, kakao, instagram 아이디로 로그인할 수 있도록 해주는 기능입니다.

## Getting Started

다음의 gem을 설치합니다.

### Gemfile

```
gem 'devise'
gem 'omniauth'
gem 'omniauth-facebook'
gem 'omniauth-naver'
gem "omniauth-google-oauth2"
gem 'omniauth-kakao', :git => 'git://github.com/hcn1519/omniauth-kakao'
gem 'omniauth-instagram'
```
```
bundle install
```

### 필요한 MVC 설정

```
rails generate devise:install
rails generate devise user
rails generate devise:views user
rails generate devise:controllers user
rails g migration add_name_to_users name:string
rails g model identity user:references provider:string uid:string
```

### config/initializers/devise.rb

```
config.omniauth :facebook, "key", "secret"
config.omniauth :naver, "key", "secret"
config.omniauth :google_oauth2, "key", "secret"
config.omniauth :kakao, "key", :redirect_path => "/users/auth/kakao/callback"  
config.omniauth :instagram, "key", "secret"
```

### config/routes.rb

```
devise_for :users, :controllers => { omniauth_callbacks: 'user/omniauth_callbacks' }
```

### app/models/identity.rb

```
class Identity < ActiveRecord::Base
  belongs_to :user
  validates_presence_of :uid, :provider
  validates_uniqueness_of :uid, :scope => :provider

  def self.find_for_oauth(auth)
    find_or_create_by(uid: auth.uid, provider: auth.provider)
  end
end
```

### app/models/user.rb

```
class User < ActiveRecord::Base
  
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable, :omniauthable
  
  def self.find_for_oauth(auth, signed_in_resource = nil)

    # user와 identity가 nil이 아니라면 받는다
    identity = Identity.find_for_oauth(auth)
    user = signed_in_resource ? signed_in_resource : identity.user
    
    # user가 nil이라면 새로 만든다.
    if user.nil?
      
      # 이미 있는 이메일인지 확인한다.
      email = auth.info.email
      user = User.where(:email => email).first  
      unless self.where(email: auth.info.email).exists?
        
        # 없다면 새로운 데이터를 생성한다.
        if user.nil?
          if auth.provider == "naver"
            user = User.new(
              name: auth.info.name,
              email: auth.info.email,
              password: Devise.friendly_token[0,20]
            )
          else
            user = User.new(
              name: auth.extra.raw_info.name,
              email: auth.info.email,
              password: Devise.friendly_token[0,20]
            )
          end  
            
            user.save!
        end
        
      end
    
    end
    
    if identity.user != user
      identity.user = user
      identity.save!
    end
    user
    
  end
  
end
```

### app/controllers/user/omniauth_callbacks_controller.rb
 
```
class User::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  
  def self.provides_callback_for(provider)
    class_eval %Q{
      def #{provider}
        @user = User.find_for_oauth(env["omniauth.auth"], current_user)

        if @user.persisted?
          sign_in_and_redirect @user, event: :authentication
          set_flash_message(:notice, :success, kind: "#{provider}".capitalize) if is_navigational_format?
        else
          session["devise.#{provider}_data"] = env["omniauth.auth"]
          redirect_to new_user_registration_url
        end
      end
    }
  end

  [:instagram, :kakao, :naver, :facebook, :google_oauth2].each do |provider|
    provides_callback_for provider
  end

  def after_sign_in_path_for(resource)
      root_path
  end
end
```