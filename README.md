# spring-boot-oauth2-SSO (Single sign on)
Oauth based single sign on using spring boot

This is a spring boot demo project to illustrate Single Sign On with various Oauth2 identity providers such as GOOGLE/FACEBOOK/GITHUB etc
Project allow us to configure multiple Oauth providers in application.yml file present in resource folder

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

Before configuring the new providers, Application has to registered as web application with Oauth providers by 
providing domain url and call back url. Post registering the application we get Client Id and client secret.
Authorization url and Access token url can be found in respective Outh vendors site
More details about google api can be fount here.
https://developers.google.com/identity/protocols/OAuth2
New auth provisers can be configured by adding required endpoints in application.yml file 
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






