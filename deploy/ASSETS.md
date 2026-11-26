# Built-in assets

The binary embeds the stylesheet and the provider logos of the chooser page
(`internal/web/assets`). The logos are served from each realm's assets path.

| File | What | Source | Licence and terms |
| --- | --- | --- | --- |
| `internal/web/assets/logos/apple.svg` | Apple logo on a black square (white logo, 56 px with a 6 px margin) for the black button | `Sign in with Apple - Logo Only/SVG/Logo - SIWA - Logo-only - White.svg` from the Sign in with Apple logo kit, https://devimages-cdn.apple.com/design/resources/download/Logo-Sign-in-with-Apple.dmg (linked from https://developer.apple.com/design/resources/), unmodified, downloaded 2026-11-11 | Apple Design Resources License (accepted by the project owner when opening the kit) and Human Interface Guidelines for Sign in with Apple |
| `internal/web/assets/logos/github.svg` | GitHub Invertocat, white, for the dark button | `GitHub Logos/SVG/GitHub_Invertocat_White.svg` from https://brand.github.com/GitHub_Logos.zip (linked from https://github.com/logos), unmodified, downloaded 2026-11-11 | GitHub's logo and usage guidelines (https://github.com/logos) |
| `internal/web/assets/logos/facebook.png` | Facebook "f" logo, white, for the blue button (120 px) | `Facebook Brand Asset Pack/Logo/Secondary Logo/Facebook_Logo_Secondary.png` from https://about.meta.com/brand/resources/facebook/logo/ (Facebook-Brand-Asset-Pack.zip), downscaled from 2084 px to 120 px with `sips -Z 120`, otherwise unmodified, downloaded 2026-11-11 | Meta's brand guidelines (https://about.meta.com/brand/resources/facebook/) |
| `internal/web/assets/logos/google.png` | Google's own "G" button icon (Light, Show text=No, Square, 120 px) | `Android + Web/PNG @3x/Light/` from https://developers.google.com/static/identity/images/signin-assets.zip (linked from the branding guidelines page), unmodified, downloaded 2026-11-11 | Sign in with Google branding guidelines (https://developers.google.com/identity/branding-guidelines) |

Status (2026-11-11): all four logos are the vendors' own downloads. Google's
kit has no plain SVG (every SVG needs `foreignObject`) and Meta's kit has only
PNG and Adobe Illustrator files, so those two are PNG; the chooser draws
Google's button as its icon square plus localised text.

Before a public release, check the button colours and sizes in
`internal/web/assets/style.css` against each vendor's current rules (the Google,
Apple and Facebook button layouts were not checked in a browser).

`internal/web/assets/style.css` is original to this project. The realm's accent
colour is added in front of it as the custom property `--accent`.
