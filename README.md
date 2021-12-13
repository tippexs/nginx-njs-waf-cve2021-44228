# NGINX njs Request Inspection for CVE2021-44228

As the <b>Log4Shell</b> Vulnerability is still hard to mitigate and a couple of users have asked us if NGINX will be able to have
something that will prevent requests from comming trough the proxy layer we have just created a small njs script / configuration that will scan the `URI` as well as all incomming `headers` for know strings.

`POST Body` Inspection will be added soon.

## Prerequisite
NGINX njs module (> 0.4.0)
Download and Installation Instructions <a href="http://nginx.org/en/docs/njs/install.html" target="_blank">here</a>

## Installation

Download the `cve.js` file and place it into your NGINX Configuration directory (`/etc/nginx/conf.d/`, `/etc/nginx/`) and load it using `js_import`.

```shell
js_import cve from /etc/nginx/cve.js
```

Enabling the request scanning in your server-blocks.
```shell
  if ( $isJNDI = "1" ) {  return 400 "Not Found!\n"; }
```



## Example Configuration

```shell

js_import cve from cve202144228/cve.js;
js_set $isJNDI cve.inspect;

server {

  listen 8090;
  ...
  if ( $isJNDI = "1" ) {  return 400 "Not Found!\n"; }

  location / {
	 return 200 "OK\n";
	 ...
  }

}


```





