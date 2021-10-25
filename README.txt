= Tangram Authentication Hook =

== Intro ==
This hook:
 - Protects pages by URL pattern with authentication
 - The authentication is not a Liferay authentication.
   Authenticated user will still be "anonymous" for Liferay.
 - If user is not authenticated she'll be redirected to a configured
   URL (/tgauth/login by default) used to initiate the authentication process.
 - SSO and certificate auth are supported:
   * SSO: A simple SSO protocol is implemented:
     - /delegate/tgauth?authType=sso -> will redirect to SSO provider specified
       in portlet properties
     - /delegate/tgauth?timestamp=<seconds since epoch>&uid=<user id>&auth=<auth token>
       auth token calculated this way:
         sha1(timestamp + uid + sso_shared_secret).hexdigest()
     - additional user attributes may be send
 - Certificate:
   * Processes a HTTP Header which specifies certificate or other data send
     by a web server in front of Liferay.
   * The header text (if exists) is sent to an external command for
     validation through stdout
   * The result is read from stdin in lines of format "variable=value"
     and the values are available to be set as session variables.
 - Some URLs (regex) can be configured to be protected, so a valid
   userid has to be present, otherwise requests are redirected.
 - The session variables are available for other Liferay plugins
   
   

== How it works ==
The basic logic is:
 - Is the page protected?
   - Yes: Is the user already authenticated?
     - No: See if we have data in header
       - No: Don't let her in into restricted area
       - Yes: Use external command to verify data
         - Run command
         - Extract data, set as session variables
         - If extraction successful, let her proceed, otherwise error
     - Yes: if it's a valid user -> proceed, otherwise error    
 


== Configure ==
Change "portlet.properties" to fit your needs before deploying.
 * sessionvariable.prefix: which prefix to add to all following 
   session variables
 * http.header.authdata: which http header has the data to validate
 * cmd: the command to execute to validate the header data
 * auth.info1.outputvariable: ouput "variable" to extract from cmd response
 * auth.info1.sessionvariable: session variable to be stored
 * auth.info2.outputvariable: next output "variable" to be read from cmd resp.
 * auth.info2.sessionvariable: session variable to be stored
 * ...   (up to 20)
 * restricted_path_regex: which URLs should be protected
 
Create a page with url /tgauth/login with two links on it:
 - Digital certificate: /c/portal/sso-login
 - SSO: /c/portal/cert-login

Make your SSO software point to /c/portal/sso-login
