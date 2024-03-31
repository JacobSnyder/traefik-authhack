# Overview

This is a [Traefik plugin](https://doc.traefik.io/traefik/plugins/) that adds the ability to populate HTTP Basic Authorization headers from URL Query Parameters. Credentials can be provided either as a username and password (via the `username` and `password` query parameters, for example: `https://example.com/?username=username&password=password`) or as an encoded username and password (via the `authorization` query parameter, for example: `https://example.com/?authorization=...`).

This is intended to work similarly to browser authorization like `https://username:password@example.com/` except that 1) it isn't deprecated in Chrome (and probably Firefox eventually) and 2) it works in iFrames. My use case for this is to save credentials into bookmarks and [Organizr](https://docs.organizr.app/). This works well with [Traefik's BasicAuth Middleware](https://doc.traefik.io/traefik/middlewares/http/basicauth/).

This plugin operates in the following manner:

1. The client sends a request, specifying credentials via URL Query Parameters.
2. The plugin detects credentials in the URL Query Parameters. It intercepts the request, sending a HTTP 307 (Temporary Redirect) response to the client, redirecting it to the same URL but with the credentials removed and with a `Set-Cookie` header that stores the encoded credentials.
3. The client sets the authentication cookie and sends a new request to the redirected URL, providing the credentials in the cookie.
4. The plugin detects credentials in the cookie. It adds an `Authorization` header to the request with the credentials and removes the cookie and then sends it along.
5. Profit! The downstream service receives the request with authentication provided via the `Authorization` header.

# Disclaimer!

It probably isn't wise to use this in a sensitive production environment, particularly because the encoded username and password are saved in a cookie. For this reason, I've chosen not to publish this plugin in the [Traefik Plugin Catalog](https://plugins.traefik.io/plugins), which creates some amount of friction in using this plugin.

# Usage

Since this should only be used with caution, this isn't published to the catalog (see previous section). Therefore, to use this plugin, you'll need to clone the plugin locally. This is documented by Traefik [in their docs](https://plugins.traefik.io/install) and [in their example plugin](https://github.com/traefik/plugindemo?tab=readme-ov-file#local-mode), but the tl;dr is as follows:

1. Clone the repo locally. Assuming your Traefik configs are configured as a Docker volume like `./traefik/data:/etc/traefik`, clone into `./traefik/plugins-local/src/github.com/JacobSnyder/traefik_authhack` and add a volume `./traefik/plugins-local:/plugins-local`
2. In the static `traefik.yaml`, add:
```yaml
experimental:
  localPlugins:
    authhack:
      moduleName: github.com/JacobSnyder/traefik_authhack
```
3. Declare middleware using the plugin. For example, in your `dyanamic.yaml` file (see "Configuration" section below).
```yaml
authhack-example:
  plugin:
    authhack:
      logLevel: 2 # Warning = 2, All = 6
```
4. Configure endpoint(s) to use the middleware.
5. Restart Traefik: `docker restart traefik`.
6. Monitor logs for errors: `docker logs --tail 1000 --follow  traefik`.

# Configuration

- `LogLevel` - Describes the level of logging from the plugin. Note that to use this, the static `traefik.yaml` must be configured to use debug logging (`log: level: debug`). The levels are as follows:
  - 0: None
  - 1: Error
  - 2: Warning (default)
  - 3: Info
  - 4: Verbose
  - 5: Debug (caution, this will log credentials!)
  - 6: All
- `UsernameQueryParam` - Configures the username query parameter name (default: "username").
- `PasswordQueryParam` - Configures the password query parameter name (default: "password").
- `AuthorizationQueryParam` - Configures the authorization query parameter name (default: "authorization").
- `CookieName` - Configures the name of the cookie (default: "traefik-authhack").
- `CookieDomian` - Configures the domain of the cookie (default: ""). For more information, see the "Domain Attribute" section of [MDN's Using HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent).
- `CookiePath` - Configures the path of the cookie (default: "/"). For more information, see the "Path Attribute" section of [MDN's Using HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent).