# Caddyfile.ha: two FeatherAuth instances behind Caddy, for compose.ha.yaml.
# Caddy checks /readyz of each instance every 2 seconds and sends requests only
# to an instance that answers 200. A request that meets an instance which is
# being replaced is tried on the other one, and a request that finds no
# instance ready is held, for up to 30 seconds in both cases. The hold is set
# by lb_try_duration alone: do not add lb_retries, which would end it after a
# few tries (about a second) when no instance is ready.
#
# Plain HTTP on port 8080, for a test on the host. For a host name, replace the
# address with the host name (Caddy then gets the certificate itself) and keep
# the rest; Caddy writes no access log unless a log directive is added, and such
# a directive must drop the query string.
:8080 {
	reverse_proxy app1:8080 app2:8080 {
		health_uri /readyz
		health_interval 2s
		health_timeout 2s
		lb_policy round_robin
		lb_try_duration 30s
		lb_try_interval 250ms
		# A new connection to an instance for every request, none kept idle:
		# a request never meets a connection that an instance being replaced
		# is closing, which Caddy would answer 502 for a POST instead of
		# trying it on the other instance.
		transport http {
			keepalive off
		}
	}
}
