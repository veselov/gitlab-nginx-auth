# gitlab-nginx-auth
OAuth2 authenticator service for Gitlab

This service can be used as NginX authenticator service, used against GitLab as an authentication and authorization 
provider.
The service can additionally provide trusted authentication information to the resource server.

Its use requires [ngx_http_js_module][1].

License: GPL-3.0-or-later

## Set-up

Consider that NginX is used to serve some content on a 
`http://resource.com`. This service will need to be running on resource.com, 
serving some requests from a specific context `<auth_context>`,
i.e. must be accessible at `http://resource.com/<auth_context>`.
The default authentication context is _gitlab (can be configured)

Consider that GitLab is serving users at `http://gitlab.com`

Choose the port the authenticator will be running on, `<auth_port>`

### Register GitLab application

The entire protected resource on `http://resource.com` shall be configured into GitLab
as an application. It is highly recommended to use global application entry
(this service was not tested with user applications)

Registering the application will provide application ID (also known as client ID) and
application secret (also known as client secret)

The callback URL specified in the application shall be `http://resource.com/<auth_context>/finish_login`
The application needs to be neither trusted nor confidential. The scopes shall be `read_user` and `read_api`.

### Configure NginX

NginX server needs to be configured to:
* Have a function that url-encodes the URI (hence the .js requirement)
* Define the authenticator context to be routed to the service
* Mark all protected resources as requiring authentication

Sample NginX configuration file (only relevant sections are provided):

```
load_module modules/ngx_http_js_module.so;
http {

# <auth_context> value is assumed to be _gitlab in this case,
# if it shall be different in your case, modify the configuration
# accordingly
# <auth_port> is assumed to be 8970, change if needed

js_import http.js;
js_set $e_uri http.encoded_request_uri;

    server {
        location /oauth_test {
            # if a location is protected, specify both auth_request
            # and error_page statements. This needs to be done for
            # all protected locations.
            auth_request /_gitlab/check;
            error_page 401 @401;
            // comment the next line out if you don't need a 403
            // page explaining access restrictions control.
            error_page 403 @403;

            # sample for an up stream server that can take advantage
            # of using user identity information
            proxy_pass http://hidden.server.com/server;
            auth_request_set $signed_auth $upstream_http_x_signed_auth;
            # the resource server will receive x-authed header that will
            # contained signed authentication data
            proxy_set_header x-authed $signed_auth;
        }

        location /resource_service

        // comment this out if you don't want a custom 403 page
        location @403 {
            // you can use 302, but this will rewrite the URL in the browser,
            // which may not be desirable
            # return 302 /_gitlab/refused_login?from=$e_uri;
            proxy_pass http://127.0.0.1:8970/_gitlab/refused_login?from=$e_uri;
        }

        location @401 {
            return 302 /_gitlab/init_login?from=$e_uri;
        }

        location /_gitlab {
            proxy_pass http://127.0.0.1:8970;
            proxy_set_header x-original-uri $request_uri;
        }
    }
}
```

The http.js file only contains code to be able to URL encode the
original path:

```javascript
function encoded_request_uri(r) {
    return encodeURIComponent(r.variables['request_uri']);
}
export default { encoded_request_uri }
``` 

### Configure the service

The service runs off of a single YAML configuration file. The service will look for 
`gitlab-nginx-auth` from the current directory by default. Configuration
file can be specified by a `-c` command line argument.

Below is a sample configuration file, with explanation of what each
property is for:

```yaml
# port that the service will run on, <auth_port> 
port: 8970
# client ID value, as was assigned by GitLab during application creation
client-id: CLIENT-ID
# client secret value, as was assigned by GitLab during application creation
client-secret: CLIENT-SECRET
# The context path the authenticator can be accessed at, <auth_context>
root-path: /_gitlab
# the top-level URL of the GitLab server
gitlab-url: https://gitlab.com/
# the top-level URL of the resource server, used to generate
# callback URLs. The <callback-url>/<auth_context>/finish_login
# must match the Callback URL configured in GitLab for the
# corresponding application
callback-url: http://resource.com
# the name of the cookie that is used by the authenticator to
# cache the credentials provided by GitLab. 
cookie-name: _this_auth
# the path the cookie should apply to. This, generally, must cover
# all protected resources, and in most cases will be "/", unless
# all protected resources stem from a specific context path.
cookie-path: /oauth_test
# whether mark cookie as secure. This should be set to true if
# the resource URL is secure.
secure-cookie: false
# To support accepting personal access tokens, specify header
# where such token should be found. If the token is found in
# the request, then the cookie is not checked.
# pat-header: x-gitlab-access

# the access control section controls which users have access
# to which resources. Access control can only be done by means of
# groups. A user must be part of a specific GitLab group, with at
# least level of 10 (Guest) to be able to access the resource.
# There can be as many access control statements as necessary,
# and they must be arranged into an array.
access-control:
-
# each array element of an access control statement defines which
# group(s) are required to access a URL with the specified pattern.
# Elements are tested in the same order they are specified in this
# configuration file. The evaluation finishes if, and only if: 
# - evaluation ran out of elements to consider, in which case
#   access is denied
# - evaluation found a pattern that match the request URI, and 
#   the user was found to be part of at least one listed group,
#   in which case the access is granted. The pattern is evaluated
#   according to perlre (https://perldoc.perl.org/perlre.html)
  pattern: ^/oauth-test[/].*
  groups: [ "x", "babies" ]
-
  pattern: ^/nothing[/].*
  groups: [ "au" ]

# Specify file where the service should store its logs. This property
# can be unset, in which case the log is printed to stdout. 
log: gitlab-nginx.log

# Specify the page size used for making requests to GitLab (to get the users'
# group list). Default is 40. Too large of a page size may strain the request,
# and too small will lead to large number of requests needed to verify the 
# identity 
# page-size: 40

# To enable caching of the responses from Gitlab (which can be quite slow)
# specify the amount of seconds the responses should be cached for.
# Cache is reloaded after expiration, or if the user does not have any
# of the groups required by the resource (so if the user is added to a 
# missing group, it's not necessary to wait until the cache expires
# until the effects are registered)
# data-cache-sec: 3600

# If enabled, then a ./refused_login endpoint will use this template
# to display a page explaining why access has been refused. The template
# receives a structure with "User" string property "Url" string property 
# and "Groups" string array.
# "User" is the username of the logged in Gitlab user, and is queried from Gitlab
# unless a cached value is found.
# "Url" is populated from the "from" URL parameter of the request, and
# "Groups" is populated with all the groups, membership to any of which would
# have allowed access to the resource.
# The template must comply to https://golang.org/pkg/text/template/
# refused-template: refused.gohtml

# the presence of this object configures and enables service providing
# signed object containing basic user information and list of the groups
# the user is a member of.
sign-user-info:
  # either private-key or shared-key property must be specified.
  # private-key must point to a PKCS#1 PEM encoded file containing private
  # key that will be used to sign the authentication data. The key must
  # either an elliptic key or an RSA key, depending on the algorithm used.  
  private-key: key.pem
  # if algorithm uses a symmetric key, that symmetric key must be provided
  # here in the hexadecimal format.
  shared-key: 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
  # algorithm to use for signing. The following algorithms are supported:
  # ECDSA, ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512
  # HS256, HS384, HS512 
  # See https://tools.ietf.org/html/rfc7515 for more information on the
  # algorithms.
  algorithm: ES256
  # the name of the header (default x-signed_auth) that the signed authentication
  # data is returned in. The data is the compact serialization of the
  # JWS object containing the JSON serialized object of user information.
  header-name: x-signed_auth
```

## Authentication Process Overview

Once a client requests a protected resource, NginX will invoke the authentication 
service URL (sub-path /check). The response can be:
- 204, authentication successful
- 401, authentication needed
- 403, access denied (authentication successful, but no access granted)

The authenticator service will first look for the previously issued authentication cookie.
If the cookie is found, it will extract the OAuth access information from the cookie, and 
make a request to GitLab to get user access information (group list). If the group list
was returned, it will evaluate the URI against the access control instructions and either issue
a 204, or 403. Additionally, if configured so, the service will set a header field containing signed
authentication information that can be accessed by the final resource destination.
In all other cases (cookie not found, access control cannot be extracted, GitLab
rejects the groups list request), the service will return 401.

The group values specified in the configurtion file are matched against `group.full_path` field of the
GitLab group object returned by GitLab API. This corresponds to "full path" property statement available
in the group description screen on GitLab UI.

Once 401 is returned, NginX will redirect the user to <auth_context>/init_login, preserving
the resource URL that was being accessed in the redirected URL. This will
again invoke the authentication service. Authentication service will redirect
the user to GitLab to both authenticate the user and have the user grant
(if not granted before) the access to its APIs (so authenticator can access GitLab
to retrieve user information)

GitLab, after performing necessary authentication procedures, will redirect
the user back to `http://resource.com/<auth_context>/finish_login`. The intended
resource URL will still be saved in the redirected URL. The `finish_login`
endpoint is again processed by the authenticator service. That invocation contains
a code that allows the authenticator to request an access token to GitLab. 
Once the access token is received, that access token is immediately used
to check its validity. Then, it's encrypted, and packaged into a cookie
that is set for the caller. The encryption key is chosen randomly each
time authenticator service starts up. The user is then redirected back
to the original URL that was intended to be accessed in the first place.

Note that this will result in `<auth_context>/check` path to be invoked again,
however this time the user will have the valid cookie, and their groups
should match the resource (or 403 will be issued).

### Signed Authentication data

The signed authentication object contains the following properties:
* user (object)
  * id (integer) user ID
  * username (string) user name
  * name (string) user display name
* groups (string[]) list of group the user is a member of
* issued (int) unix timestamp (seconds since Epoch) of when the 
data was issued. It's up to the resource server to determine how long
should the data be considered valid for.

The data is serialized as a JSON object, signed using JWS specification, and
serialized using compact serialization. See [JWS Standard][2]

[1]: http://nginx.org/en/docs/http/ngx_http_js_module.html
[2]: https://tools.ietf.org/html/rfc7515
