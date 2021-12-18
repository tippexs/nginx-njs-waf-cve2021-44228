# NGINX njs Request Inspection for CVE2021-44228

As the <b>Log4Shell</b> Vulnerability is still hard to mitigate and a couple of users have asked us if NGINX will be able to have
something that will prevent requests from coming through the proxy layer we have just created a small njs script / configuration that will scan the `URI`, all incoming `headers` as well as the POST body for know strings.

## Disclaimer
This configuration is not officially supported by NGINX and F5. Please track issues in this repository.

## Prerequisite
NGINX njs module (> 0.4.0)
Download and Installation Instructions <a href="http://nginx.org/en/docs/njs/install.html" target="_blank">here</a>

## Installation

Download the `cve.js` file and place it into your NGINX Configuration directory (`/etc/nginx/conf.d/`, `/etc/nginx/`) and load it using `js_import`.

```shell
js_import cve from /etc/nginx/conf.d/cve.js
```

Enabling the Header / URI request scanning in for all locations in your server block.
```shell
    if ( $isJNDI = "1" ) {  return 404 "Not Found!\n"; }
```

## Example Configuration
### Header and URI Variables
```shell
js_import cve from conf.d/cve.js;
js_set $isJNDI cve.inspect;

server {
    listen 8090;
    ...
    if ( $isJNDI = "1" ) {  return 404 "Not Found!\n"; }

    location / {
	return 200 "OK\n";
	...
    }
}
```

### Post-Body Scanning
The configuration to scan the POST-Body data are a little bit more complex.

First, NGINX needs an `mirror` location to be able to inspect the whole post body.
<a href="https://www.nginx.com/blog/deploying-nginx-plus-as-an-api-gateway-part-2-protecting-backend-services/#request-bodies" target="_blank">More Information</a>.
Create a location and add it to the server block. Please note, POST body scanning works only on `location` level.

```shell
    location /_scannBodyJNDI {
        internal;
        return 204;
    }
```

Second, we can hook into the scanning process.
Add a new `js_set` directive to the configuration
```shell
js_import cve from cve202144228/cve.js;
js_set $isJNDI cve.inspect;
#add this
js_set $bodyScanned cve.postBodyInspect;
```

Reconfigure your already existing `location` block
```shell
   location /your-location/ {
       set $upstream "http://127.0.0.1:8099";  # Your Upstream-Definition. This can be a host OR an `upstream` defition.
       mirror /_scannBodyJNDI;
       client_body_in_single_buffer on;        # Minimize memory copy operations on request body
       client_body_buffer_size      128k;      # Largest body to keep in memory (before writing to file)
       client_max_body_size         128k;
    
       proxy_pass $bodyScanned; #Your new upstraem has to be set to this variable!
   }
```

Last add a error-proxy server configuration for all bad requests

```shell
server {
    listen 8999;

    location / {
        return 404 "Not Found!\n";
    }
}
```

If the Port `8999` is not available on your instance choose another one and change that in the server configuration in the `cve.js` file

```javascript
function postBodyInspect(r) {;
    if (r.method === "POST") {
        try {
            if (checkIOCStrings(r, r.variables.request_body)) {
	        return "http://127.0.0.1:CHANGEME/";
	    } else {
	        return r.variables.upstream;
	    }
        } catch(e) {
            r.error(`POST Body inspection failed!`);
        }
    }
}
```
