export default {inspect};



/**
 * Validates an incomming request and checks all Headers as well as the URI for IOCs of CVE2021-44228
 *
 * @param {r} r NGINX njs Request Object.
 * @return {string} `1` if IOC was found `` if nothing was found.
 */
function inspect(r) {
	let string = undefined;
	let allHeaders = "";
	let found = "";
	r.rawHeadersIn.forEach(header => allHeaders += `${(header.join('--'))}`);
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
		'${${env:BARFOO:-j}',
		'${::-l}${::-d}${::-a}${::-p}',
		'${base64:JHtqbmRp',
		'/Basic/Command/Base64/',
	]
	string = `${r.uri}${allHeaders}`;
	iocList.forEach(element => {
		if (string.includes(element)) {
			r.error(`Found CVE2021-44228 IOC: ${element}. Request was blocked! From ${r.remoteAddress}`)
			found = "1";
		}
	});
	
	return found;
}