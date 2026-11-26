package deploy_test

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type composeFile struct {
	Services map[string]struct {
		Image   string   `yaml:"image"`
		Ports   []string `yaml:"ports"`
		Volumes []string `yaml:"volumes"`
	} `yaml:"services"`
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readCompose(t *testing.T, name string) composeFile {
	t.Helper()
	var c composeFile
	if err := yaml.Unmarshal([]byte(readFile(t, name)), &c); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

// The image's health check runs every 10 seconds and allows 6 failed checks in
// a row before the container is reported unhealthy. The running container's
// settings are checked by TestOpsCheckImage.
//
// Proves OPS-12 (health check tolerance): see the pass conditions of the row; OPS ids are not traced.
// Acceptance: Health check tolerance (part)
func TestDockerfileHealthCheckTolerance(t *testing.T) {
	d := readFile(t, "Dockerfile")
	want := "HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=6 \\\n  CMD [\"/featherauth\", \"healthcheck\"]"
	if !strings.Contains(d, want) {
		t.Errorf("Dockerfile lacks the health check %q", want)
	}
}

// Covers: SEC-11 (part)
// Acceptance: Client IP (part)
func TestDockerfileIsStaticDistrolessNonRootWithHealthcheck(t *testing.T) {
	d := readFile(t, "Dockerfile")
	for _, want := range []string{
		"CGO_ENABLED=0",
		"FROM gcr.io/distroless/static-debian12:nonroot",
		"USER 65532:65532",
		`HEALTHCHECK `,
		`"healthcheck"`,
		`ENTRYPOINT ["/featherauth"]`,
		`CMD ["serve"]`,
	} {
		if !strings.Contains(d, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
	if strings.Count(d, "FROM ") < 2 {
		t.Error("Dockerfile is not multi-stage")
	}
}

// Covers: SEC-11 (part)
// Acceptance: Client IP (part)
func TestComposePublishesOnLoopbackOnly(t *testing.T) {
	c := readCompose(t, "compose.yaml")
	svc, ok := c.Services["featherauth"]
	if !ok {
		t.Fatal("compose.yaml has no featherauth service")
	}
	if len(c.Services) != 1 {
		t.Errorf("compose.yaml runs %d services, want featherauth alone", len(c.Services))
	}
	if len(svc.Ports) == 0 {
		t.Fatal("no published port")
	}
	// Ports are decoded as strings, so the long syntax (a mapping with
	// host_ip) fails to decode above and the test fails loudly; keep the short
	// syntax so that this check stays simple.
	for _, p := range svc.Ports {
		if !strings.HasPrefix(p, "127.0.0.1:") {
			t.Errorf("port %q is not bound to 127.0.0.1", p)
		}
	}
	mounted := false
	for _, v := range svc.Volumes {
		if strings.Contains(v, ":/etc/featherauth") {
			mounted = true
			if !strings.HasSuffix(v, ":/etc/featherauth:ro") {
				t.Errorf("config mount %q is not read-only", v)
			}
		}
	}
	if !mounted {
		t.Error("compose.yaml does not mount the config directory at /etc/featherauth")
	}
}

// The Postgres overlay adds one database container that no port publishes, with
// a pinned image, its own volume and the password file read-only, and makes the
// service wait for its health check.
//
// Covers: FR-35 (part)
// Acceptance: Postgres service (part)
func TestComposePostgresKeepsTheDatabasePrivate(t *testing.T) {
	var c struct {
		Services map[string]struct {
			Image     string   `yaml:"image"`
			Ports     []string `yaml:"ports"`
			Volumes   []string `yaml:"volumes"`
			DependsOn map[string]struct {
				Condition string `yaml:"condition"`
			} `yaml:"depends_on"`
		} `yaml:"services"`
		Volumes map[string]any `yaml:"volumes"`
	}
	if err := yaml.Unmarshal([]byte(readFile(t, "compose.postgres.yaml")), &c); err != nil {
		t.Fatal(err)
	}
	pg, ok := c.Services["postgres"]
	if !ok {
		t.Fatal("compose.postgres.yaml has no postgres service")
	}
	if len(pg.Ports) != 0 {
		t.Errorf("postgres publishes %v; the database must not be reachable from the host", pg.Ports)
	}
	if !strings.Contains(pg.Image, "postgres:") || !strings.Contains(pg.Image, "@sha256:") {
		t.Errorf("postgres image %q is not pinned by version and digest", pg.Image)
	}
	if !slices.Contains(pg.Volumes, "postgres-data:/var/lib/postgresql") {
		t.Errorf("postgres volumes %v do not hold its data in the named volume postgres-data", pg.Volumes)
	}
	if _, ok := c.Volumes["postgres-data"]; !ok {
		t.Error("the volume postgres-data is not declared")
	}
	mounted := false
	for _, v := range pg.Volumes {
		if strings.HasSuffix(v, ":/run/secrets/postgres_password:ro") && strings.Contains(v, "secrets/postgres_password:") {
			mounted = true
		}
	}
	if !mounted {
		t.Errorf("postgres volumes %v do not mount the password file read-only", pg.Volumes)
	}
	if fa := c.Services["featherauth"]; fa.DependsOn["postgres"].Condition != "service_healthy" {
		t.Errorf("featherauth does not wait for postgres to be healthy: %+v", fa.DependsOn)
	}
}

// Covers: SEC-11 (part)
func TestComposeCaddyAddsCaddyAndNeverWidensFeatherAuth(t *testing.T) {
	c := readCompose(t, "compose.caddy.yaml")
	caddy, ok := c.Services["caddy"]
	if !ok {
		t.Fatal("compose.caddy.yaml has no caddy service")
	}
	if len(caddy.Ports) == 0 {
		t.Error("caddy publishes no ports")
	}
	if fa, ok := c.Services["featherauth"]; ok {
		for _, p := range fa.Ports {
			if !strings.HasPrefix(p, "127.0.0.1:") {
				t.Errorf("featherauth port %q is not bound to 127.0.0.1", p)
			}
		}
	}
}

// Covers: SEC-13 (part)
// Acceptance: Secrets and logs (part)
func TestNginxExampleLogsPathNotQuery(t *testing.T) {
	n := readFile(t, "nginx.example.conf")
	var format string
	for _, line := range strings.Split(n, "\n") {
		if strings.HasPrefix(line, "log_format featherauth ") || strings.HasPrefix(strings.TrimSpace(line), "'$") {
			format += line
		}
	}
	if !strings.Contains(format, "$uri") {
		t.Errorf("log_format does not record $uri: %q", format)
	}
	for _, bad := range []string{"$request ", "$request\"", "$request'", "$request_uri", "$args", "$query_string", "$http_referer"} {
		if strings.Contains(format, bad) {
			t.Errorf("log_format records %s", bad)
		}
	}
	if got := strings.Count(n, "access_log /var/log/nginx/featherauth.access.log featherauth;"); got != 2 {
		t.Errorf("%d server blocks use the safe access log format, want 2", got)
	}
	if got := strings.Count(n, "error_log /var/log/nginx/featherauth.error.log crit;"); got != 2 {
		t.Errorf("%d server blocks set the error log to crit, want 2", got)
	}
}

// The `http2 on;` directive exists only from nginx 1.25.1; Ubuntu 24.04 ships
// 1.24, which rejects it ("unknown directive"). The listen parameter works on
// both (newer nginx only warns that it is deprecated).
// Covers: SEC-12 (part)
// Acceptance: TLS examples (part)
func TestNginxExampleRunsOnNginx124(t *testing.T) {
	n := readFile(t, "nginx.example.conf")
	if strings.Contains(n, "http2 on;") {
		t.Error("nginx.example.conf uses `http2 on;`, which nginx before 1.25.1 rejects")
	}
}

// Covers: SEC-12 (part)
// Acceptance: TLS examples (part)
func TestNginxExampleRedirectsAndForwardsHeaders(t *testing.T) {
	n := readFile(t, "nginx.example.conf")
	for _, want := range []string{
		"listen 80;",
		"return 301 https://$host$request_uri;",
		"listen 443 ssl http2;",
		"listen [::]:443 ssl http2;",
		"proxy_pass http://127.0.0.1:8080;",
		"proxy_set_header Host $host;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Proto $scheme;",
		"ssl_certificate ",
		"ssl_certificate_key ",
		"certbot certonly --webroot -w /var/www -d auth.example.com",
		`--deploy-hook "nginx -s reload"`,
	} {
		if !strings.Contains(n, want) {
			t.Errorf("nginx.example.conf lacks %q", want)
		}
	}
	// The proxy opens a new connection to the service for every request
	// (Restart specification, Proxy connections): nginx does so unless an
	// upstream block keeps idle connections with keepalive.
	for _, l := range activeLines(n) {
		if f := strings.Fields(l); len(f) > 0 && strings.TrimSuffix(f[0], ";") == "keepalive" {
			t.Errorf("nginx.example.conf has an active keepalive directive: %q", l)
		}
	}
}

// activeLines returns the lines of a proxy configuration that are not
// comments, trimmed.
func activeLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// requireKeepaliveOff fails unless the Caddyfile c sets keepalive off in an
// active transport http block, so Caddy opens a new upstream connection for
// every request (Restart specification, Proxy connections).
func requireKeepaliveOff(t *testing.T, name, c string) {
	t.Helper()
	lines := activeLines(c)
	i := slices.Index(lines, "transport http {")
	if i < 0 || i+1 >= len(lines) || lines[i+1] != "keepalive off" {
		t.Errorf("%s does not set keepalive off in an active transport http block", name)
	}
}

// Covers: SEC-12 (part)
// Acceptance: TLS examples (part)
func TestCaddyExampleHoldsRequestsAndKeepsAdminAPI(t *testing.T) {
	c := readFile(t, "Caddyfile.example")
	for _, want := range []string{
		"reverse_proxy 127.0.0.1:8080 {",
		"lb_try_duration 10s",
		"lb_try_interval 250ms",
		"# tls /etc/ssl/auth/fullchain.pem /etc/ssl/auth/privkey.pem",
		"featherauth:8080",
		"trusted_proxies",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("Caddyfile.example lacks %q", want)
		}
	}
	// The compose healthcheck needs the admin API, and a log directive would
	// record the query string (SEC-13): neither may be active.
	for _, line := range strings.Split(c, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "admin ") || strings.HasPrefix(l, "log ") || l == "log {" {
			t.Errorf("Caddyfile.example has an active %q line", l)
		}
	}
	requireKeepaliveOff(t, "Caddyfile.example", c)
}

// Covers: FR-24 (part)
// Acceptance: Encrypted copy (part)
//
// The behaviour (the copy is unreadable, it decrypts, the restore serves) is
// proved by deploy/ops/check-offsite.sh in CI; this checks what the script
// must and must not contain.
func TestBackupOffsiteScriptEncryptsWithPublicKeyOnly(t *testing.T) {
	const name = "ops/backup-offsite.sh"
	s := readFile(t, name)
	for _, want := range []string{"age -r ", "rclone", "rsync", "CONFIG_DIR"} {
		if !strings.Contains(s, want) {
			t.Errorf("%s lacks %q", name, want)
		}
	}
	// Never needs the private key: no decrypt, no identity file, no secret key.
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		for _, bad := range []string{"age -d", "age --decrypt", "age -i", "--identity", "AGE-SECRET-KEY", "age-keygen"} {
			if strings.Contains(l, bad) {
				t.Errorf("%s has %q in %q", name, bad, l)
			}
		}
	}
	if out, err := exec.Command("sh", "-n", name).CombinedOutput(); err != nil {
		t.Errorf("sh -n %s: %v: %s", name, err, out)
	}
}

// No secret is in the repository: no tracked key or secrets file, and no
// tracked file holds a PEM private key (the marker alone on a line).
//
// Covers: SEC-09 (part)
func TestRepositoryHoldsNoSecretFiles(t *testing.T) {
	out, err := exec.Command("git", "-C", "..", "ls-files").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	files := strings.Fields(string(out))
	if len(files) < 100 {
		t.Fatalf("only %d tracked files listed", len(files))
	}
	for _, f := range files {
		for _, ext := range []string{".pem", ".p8", ".key", ".db"} {
			if strings.HasSuffix(f, ext) {
				t.Errorf("tracked secret-like file %s", f)
			}
		}
		if strings.Contains("/"+f, "/secrets/") {
			t.Errorf("tracked file in a secrets directory: %s", f)
		}
	}
	if b, err := exec.Command("git", "-C", "..", "grep", "-lE", `^-----BEGIN [ABCDEFGHIJKLMNOPQRSTUVWXYZ ]*PRIVATE KEY-----$`).Output(); err == nil {
		t.Errorf("a tracked file holds a private key:\n%s", b)
	}
}

// composeStop is the part of a compose file that TestComposeGivesTheDrainItsTime
// reads; yaml.v3 resolves the << merge of compose.ha.yaml's x-featherauth.
type composeStop struct {
	Services map[string]struct {
		Image           string  `yaml:"image"`
		StopGracePeriod *string `yaml:"stop_grace_period"`
	} `yaml:"services"`
}

// Docker kills a container 10 seconds after SIGTERM unless told otherwise,
// which would cut the 30-second drain short. Every shipped compose file that
// runs the service gives it stop_grace_period: 35s, compose.postgres.yaml
// inherits the value of compose.yaml, and the deploy scripts stop the service
// only through docker compose up -d, with no timeout of their own (Restart
// specification, Stop timeout).
//
// Acceptance: Restart (part)
// Proves OPS-13 (stop timeout)
func TestComposeGivesTheDrainItsTime(t *testing.T) {
	const image = "ghcr.io/yyudhistira/featherauth:"
	for file, names := range map[string][]string{
		"compose.yaml":     {"featherauth"},
		"compose.tls.yaml": {"featherauth"},
		"compose.ha.yaml":  {"app1", "app2"},
	} {
		var c composeStop
		if err := yaml.Unmarshal([]byte(readFile(t, file)), &c); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		var runs []string
		for name, svc := range c.Services {
			if strings.HasPrefix(svc.Image, image) {
				runs = append(runs, name)
			}
		}
		slices.Sort(runs)
		if !slices.Equal(runs, names) {
			t.Errorf("%s runs FeatherAuth in %v, want %v", file, runs, names)
		}
		for _, name := range runs {
			if g := c.Services[name].StopGracePeriod; g == nil || *g != "35s" {
				t.Errorf("%s: service %s has no stop_grace_period: 35s", file, name)
			}
		}
	}
	var pg composeStop
	if err := yaml.Unmarshal([]byte(readFile(t, "compose.postgres.yaml")), &pg); err != nil {
		t.Fatal(err)
	}
	for name, svc := range pg.Services {
		if svc.StopGracePeriod != nil {
			t.Errorf("compose.postgres.yaml sets stop_grace_period %q on %s; the featherauth service inherits compose.yaml's", *svc.StopGracePeriod, name)
		}
	}
	for _, script := range []string{"ops/deploy-remote.sh", "ops/rolling-deploy.sh"} {
		for _, l := range activeLines(readFile(t, script)) {
			for _, bad := range []string{"docker stop", "compose stop", "compose down", "--timeout", " -t "} {
				if strings.Contains(l, bad) {
					t.Errorf("%s has %q in %q: it stops the service only through docker compose up -d, with the compose file's timeout", script, bad, l)
				}
			}
		}
	}
}
