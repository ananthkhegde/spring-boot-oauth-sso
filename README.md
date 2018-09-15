# spring-boot-oauth2-SSO (Single sign on)
Oauth based single sign on using spring boot

This is a spring boot demo project to illustrate Single Sign On with various Oauth2 identity providers such as GOOGLE/FACEBOOK/GITHUB etc
Project allow us to configure multiple Oauth providers in application.yml file present in resource folder.

Basic details of the projects are explained so that it is easy to tweak as per your requirement.

## Maven dependencies

```
	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-security</artifactId>
	</dependency>

	<dependency>
		<groupId>org.springframework.security.oauth.boot</groupId>
		<artifactId>spring-security-oauth2-autoconfigure</artifactId>
		<version>2.0.4.RELEASE</version>
	</dependency>
```

## Key details of the project

Before configuring the new providers, Application has to registered as web application with Oauth2 providers by 
providing domain url and call back url. Post registering the application we get Client Id and client secret.
Authorization url and Access token url can be found in respective Outh vendors site
More details about oauth2 google api can be found here.
https://developers.google.com/identity/protocols/OAuth2

### Steps to configure

New auth provider can be configured by adding required endpoints in application.yml file 
```
google:
  client:
    clientId: 64984947785-lfq7ud2qd5rdrm5e57b156fdgkosjrh8.apps.googleusercontent.com
    clientSecret: w3p1zXrp4CYkzf8PHfPigvws
    accessTokenUri: https://www.googleapis.com/oauth2/v4/token
    userAuthorizationUri: https://accounts.google.com/o/oauth2/v2/auth
    clientAuthenticationScheme: form
    scope: email
  resource:
    userInfoUri: https://www.googleapis.com/oauth2/v3/userinfo
    preferTokenInfo: true
```
Add Single SignOn Filter (SSO Filter) for each vendors in WebSecurityConfig class file

```
 private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(facebook(), "/login/facebook"));
        filters.add(ssoFilter(github(), "/login/github"));
        filters.add(ssoFilter(microsoft(), "/login/microsoft"));
        filters.add(ssoFilter(google(), "/login/google"));
        filter.setFilters(filters);
        return filter;
    }

    private Filter ssoFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
        filter.setRestTemplate(template);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId());
        tokenServices.setRestTemplate(template);
        filter.setTokenServices(tokenServices);
        //
       tokenServices.setPrincipalExtractor(client.getPrincipalExtractor());
        filter.setAllowSessionCreation(false);
        filter.setSessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());
        return filter;
    }

 @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS).and()
                .logout().logoutSuccessUrl("/").and()
                .authorizeRequests()
                .antMatchers(
                        "/index.html",
                        "/",
                        "/login**",               ,
                        "/logout**").permitAll()
                .anyRequest().authenticated();
        // Custom JWT based security filter
        httpSecurity.addFilterBefore(ssoFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```
Index.html has link to all providers

```
<h1>Login</h1>
<div class="container" ng-show="!home.authenticated">
    <div>
        With Facebook: <a href="/login/facebook">click here</a>
    </div>
    <div>
        With Google: <a href="/login/google">click here</a>
    </div>
    <div>
        With GitHub: <a href="/login/github">click here</a>
    </div>
</div>
```

### Steps to Run the project

* import this project to any IDE like eclipse,IntelliJ etc 
* click on run button Project will run inside embedded tomcat.
* user will be presented with index.html page on http://localhost:8080 with options to select Oauth2 providers for Oauth2 login
* select any one and provider and page wil be redirected to respective oauth2 providers login page
* enter the required credentials and upon successful login user will be redirected back to index.html









