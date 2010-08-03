#!/bin/env python
#
# Script to get internal IPs of all your Rackspace Cloud Servers
# and output iptables commands to restrict access to the internal
# interfaces to your servers (so other Rackspace customers can't
# scan/discover/see/exploit your internal services) 
#
# Note that this script will wipe anything you have configured
# in iptables and will leave the public Internet-facing interface
# wide open. You will need to apply this script on each of your
# virtual servers. Also remember to save the rules so they are
# applied at system startup.
#
# usage:
# ./rackspace-private-iptables.py jdoe a86850deb2742ec3cb41518e26aa2d89 | sh
#                                      ^- API key
#                                 ^- username
#
# if you omit username or key, these defaults will be used
# (you should obviously edit them):
DEFAULT_AUTH_USER = "jdoe"
DEFAULT_AUTH_KEY = "a86850deb2742ec3cb41518e26aa2d89"

# you shouldn't need to change anything below this line
# unless you want to customize things

IFACE_PUBLIC="eth0"
IFACE_PRIVATE="eth1"
IFACE_LOCAL="lo"

IPTABLES_EXTRA = """
# use this if you need additional rules (e.g. to restrict the public interface)
"""

IPTABLES_MAIN = """
iptables -A INPUT -i %(local)s -j ACCEPT
iptables -A OUTPUT -o %(local)s -j ACCEPT
iptables -A INPUT -i %(public)s -j ACCEPT
iptables -A OUTPUT -o %(public)s -j ACCEPT
iptables -A OUTPUT -o %(private)s -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i %(private)s -m state --state ESTABLISHED,RELATED -j ACCEPT
""" % {
	"local": IFACE_LOCAL,
	"public": IFACE_PUBLIC,
	"private": IFACE_PRIVATE,
}
IPTABLES_PRIVATE = """
iptables -A INPUT -i %s --source %%s -j ACCEPT
""" % IFACE_PRIVATE

from gzip import GzipFile
import httplib
import json
from StringIO import StringIO
from sys import exit, argv

AUTH_HOST = "auth.api.rackspacecloud.com"
AUTH_PATH = "/v1.0"

IPTABLES_CLEAR = """
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -t filter -F
iptables -t filter -X
iptables -t filter -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z
"""

def die(msg):
	print msg
	exit(1)

def get_auth_token_and_url(auth_host, auth_path, auth_user, auth_key):
	auth_conn = httplib.HTTPSConnection(auth_host)
	auth_headers = {
		"X-Auth-User": auth_user,
		"X-Auth-Key": auth_key,
	}
	auth_conn.request("GET", auth_path, headers = auth_headers)
	auth_response = auth_conn.getresponse()
	auth_conn.close()
	if auth_response.status != 204:
		die("authentication failed (HTTP " + str(auth_response.status) + ")")
	auth_token = auth_response.getheader("x-auth-token")
	if auth_token is None:
		die("invalid authentication response (missing x-auth-token header)")
	api_base_url = auth_response.getheader("x-server-management-url")
	if api_base_url is None:
		die("invalid authentication response (missing x-server-management-url header)")
	return auth_token, api_base_url

def get_server_dict(auth_token, api_base_url):
	QUERY_HOST = api_base_url.split("/")[2]
	QUERY_BASE_PATH = "/" + "/".join(api_base_url.split("/")[3:])
	QUERY_PATH = "/servers/detail"
	query_conn = httplib.HTTPSConnection(QUERY_HOST)
	query_headers = {
		"X-Auth-Token": auth_token,
		"Accept-Encoding": "gzip",
	}
	query_conn.request("GET", QUERY_BASE_PATH + QUERY_PATH, headers = query_headers)
	query_response = query_conn.getresponse()
	query_response_body_raw = query_response.read()
	query_conn.close()
	if query_response.status not in (200, 203):
		die("query failed (HTTP " + str(query_response.status) + ")")
	query_response_body_filelike = StringIO(query_response_body_raw)
	query_response_body_json = GzipFile(fileobj = query_response_body_filelike).read()
	return json.loads(query_response_body_json)

if __name__ == "__main__":
	if len(argv) == 3:
		auth_user = argv[1]
		auth_key = argv[2]
	else:
		auth_user = DEFAULT_AUTH_USER
		auth_key = DEFAULT_AUTH_KEY
	auth_token, api_base_url = get_auth_token_and_url(AUTH_HOST, AUTH_PATH, auth_user, auth_key)
	server_dict = get_server_dict(auth_token, api_base_url)
	
	private_ips = []
	public_ips = []
	for server in server_dict["servers"]:
		for private_ip in server["addresses"]["private"]:
			private_ips.append(private_ip)
		for public_ip in server["addresses"]["public"]:
			public_ips.append(public_ip)

	print IPTABLES_CLEAR
	print IPTABLES_MAIN
	for ip in private_ips:
		print IPTABLES_PRIVATE % ip
	print IPTABLES_EXTRA