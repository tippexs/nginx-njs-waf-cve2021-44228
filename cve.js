/**
 * (c) Timo Stark F5 Inc. Dec. 2021
 *
 */

/**
 * Validates an incoming request and checks all Headers as well as the URI for IOCs of CVE2021-44228
 *
 * @param {Object} r NGINX njs Request Object.
 * @return {string} `1` if IOC was found `` if nothing was found.
 */
function inspect(r) {
	let allHeaders = "";
	r.rawHeadersIn.forEach(header => allHeaders += `${(header.join('--'))}`);
	return checkIOCStrings(r, `${r.variables.request_uri}${allHeaders}`);
}

/**
 * Validates an incoming request body and checks it for IOCs of CVE2021-44228
 *
 * @param {Object} r NGINX njs Request Object.
 * @return {string} `1` if IOC was found `` if nothing was found.
 */
function postBodyInspect(r) {
	if (r.method === "POST") {
		try {
			if (checkIOCStrings(r, r.variables.request_body)) {return "http://127.0.0.1:8999/"} else {return r.variables.upstream};
		} catch(e) {
			r.error(`POST Body inspection failed!`);
		}
	}
}

/**
 * Internal function to handle the check of strings against the List of IOC Strings
 *
 * @param {Object} r  NGINX njs Request Object.
 * @param {string} input String that could contain IOC Strings.
 * @return {string} `1` if IOC was found `` if nothing was found.
 */
function checkIOCStrings(r, input) {
	let found = "";
	const iocList = [
		'${jndi:ldap:/',
		'${jndi:rmi:/',
		'${jndi:ldaps:/',
		'${jndi:dns:/',
		'/$%7bjndi:',
		'%24%7bjndi:',
		'$%7Bjndi:',
		'%2524%257Bjndi',
		'%2F%252524%25257Bjndi%3A',
		'${jndi:${lower:',
		'${::-j}${',
		'${jndi:nis',
		'${jndi:nds',
		'${jndi:corba',
		'${jndi:iiop',
		'${::-l}${::-d}${::-a}${::-p}',
		'${base64:JHtqbmRp',
		'/Basic/Command/Base64/',
		new RegExp(/\$\{\s*(j|\$?\{.+?\})/)
	]

	iocList.forEach(element => {
		if (typeof element === 'object' && found !== "1") {
			if (input.match(element)) {
				r.error(`Found CVE2021-44228 IOC: ${element}. Request was blocked! From ${r.remoteAddress}`)
				found = "1";
			}
		} else {
			if (input.includes(element)) {
				r.error(`Found CVE2021-44228 IOC: ${element}. Request was blocked! From ${r.remoteAddress}`)
				found = "1";
			}
		}
	});
	return found;
}

export default {inspect, postBodyInspect};
