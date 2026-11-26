package web

import (
	"embed"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/yyudhistira/featherauth/internal/config"
)

//go:embed assets
var assetFS embed.FS

// defaultAccent is the documented default of login_page.accent_color, used
// only if a realm somehow carries a value that is not a hex colour.
const defaultAccent = "#2563eb"

var hexColour = regexp.MustCompile(`^#[0-9a-fA-F]{3,8}$`)

// logos are the built-in provider logos, by file name under logos/.
var logos = map[string]bool{"google.png": true, "apple.svg": true, "github.svg": true, "facebook.png": true}

// stylesheet is the realm's style.css: the accent colour as a custom property
// followed by the built-in rules.
func stylesheet(realm *config.Realm) ([]byte, error) {
	accent := realm.LoginPage.AccentColor
	if !hexColour.MatchString(accent) {
		accent = defaultAccent
	}
	rules, err := assetFS.ReadFile("assets/style.css")
	if err != nil {
		return nil, err
	}
	return append([]byte(":root { --accent: "+accent+"; }\n"), rules...), nil
}

// Assets serves the stylesheet and the provider logos under the realm's assets
// path. Anything else is 404.
func Assets(w http.ResponseWriter, r *http.Request, realm *config.Realm) {
	base := realm.EndpointPath(config.EndpointAssets, "") + "/"
	name, ok := strings.CutPrefix(r.URL.Path, base)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case name == "style.css":
		css, err := stylesheet(realm)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(css)
	case strings.HasPrefix(name, "logos/") && logos[strings.TrimPrefix(name, "logos/")]:
		f, err := assetFS.Open("assets/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		ct := "image/svg+xml"
		if strings.HasSuffix(name, ".png") {
			ct = "image/png"
		}
		w.Header().Set("Content-Type", ct)
		_, _ = io.Copy(w, f)
	default:
		http.NotFound(w, r)
	}
}
