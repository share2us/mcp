# Third-party notices

The Share2Us MCP server is licensed under GPL-3.0-only (see `LICENSE`). It links
the third-party Go modules below, each under its own licence, all compatible with
the GPLv3.

- **Apache-2.0** is compatible with GPLv3 but NOT with GPLv2-only — the reason the
  Share2Us clients are GPLv3 rather than the Linux kernel's GPLv2.
- **MPL-2.0** is GPL-compatible via its Secondary Licenses election unless a file
  carries the "Incompatible With Secondary Licenses" notice; verified 2026-09-07
  that the string appears only as Exhibit B boilerplate in LICENSE files, never
  in source.

Regenerate from `go list -deps ./...`.

| Module | Licence |
| --- | --- |
| `dario.cat/mergo@v1.0.1` | BSD |
| `github.com/BobuSumisu/aho-corasick@v1.0.3` | MIT |
| `github.com/Masterminds/goutils@v1.1.1` | Apache-2.0 |
| `github.com/Masterminds/semver/v3@v3.3.0` | MIT |
| `github.com/Masterminds/sprig/v3@v3.3.0` | MIT |
| `github.com/STARRY-S/zip@v0.2.1` | BSD |
| `github.com/andybalholm/brotli@v1.1.2-0.20250424173009-453214e765f3` | MIT |
| `github.com/aymanbagabas/go-osc52/v2@v2.0.1` | MIT |
| `github.com/bodgit/plumbing@v1.3.0` | BSD |
| `github.com/bodgit/sevenzip@v1.6.0` | BSD |
| `github.com/bodgit/windows@v1.0.1` | BSD |
| `github.com/charmbracelet/colorprofile@v0.2.3-0.20250311203215-f60798e515dc` | MIT |
| `github.com/charmbracelet/lipgloss@v1.1.0` | MIT |
| `github.com/charmbracelet/x/ansi@v0.8.0` | MIT |
| `github.com/charmbracelet/x/cellbuf@v0.0.13-0.20250311204145-2c3ea96c31dd` | MIT |
| `github.com/charmbracelet/x/term@v0.2.1` | MIT |
| `github.com/dsnet/compress@v0.0.2-0.20230904184137-39efe44ab707` | BSD |
| `github.com/fatih/semgroup@v1.2.0` | BSD |
| `github.com/fsnotify/fsnotify@v1.8.0` | BSD |
| `github.com/gitleaks/go-gitdiff@v0.9.1` | MIT |
| `github.com/google/uuid@v1.6.0` | BSD |
| `github.com/h2non/filetype@v1.1.3` | MIT |
| `github.com/hashicorp/errwrap@v1.1.0` | MPL-2.0 |
| `github.com/hashicorp/go-multierror@v1.1.1` | MPL-2.0 |
| `github.com/hashicorp/go-version@v1.7.0` | MPL-2.0 |
| `github.com/hashicorp/golang-lru/v2@v2.0.7` | MPL-2.0 |
| `github.com/hashicorp/hcl@v1.0.0` | MPL-2.0 |
| `github.com/huandu/xstrings@v1.5.0` | MIT |
| `github.com/klauspost/compress@v1.18.0` | Apache-2.0 |
| `github.com/klauspost/pgzip@v1.2.6` | MIT |
| `github.com/lucasb-eyer/go-colorful@v1.2.0` | MIT |
| `github.com/magiconair/properties@v1.8.9` | BSD |
| `github.com/mattn/go-colorable@v0.1.14` | MIT |
| `github.com/mattn/go-isatty@v0.0.20` | MIT |
| `github.com/mattn/go-runewidth@v0.0.16` | MIT |
| `github.com/mholt/archives@v0.1.2` | MIT |
| `github.com/minio/minlz@v1.0.0` | Apache-2.0 |
| `github.com/mitchellh/copystructure@v1.2.0` | MIT |
| `github.com/mitchellh/mapstructure@v1.5.0` | MIT |
| `github.com/mitchellh/reflectwalk@v1.0.2` | MIT |
| `github.com/muesli/termenv@v0.16.0` | MIT |
| `github.com/nwaples/rardecode/v2@v2.1.0` | BSD |
| `github.com/pelletier/go-toml/v2@v2.2.3` | MIT |
| `github.com/pierrec/lz4/v4@v4.1.21` | BSD |
| `github.com/rivo/uniseg@v0.4.7` | MIT |
| `github.com/rs/zerolog@v1.33.0` | MIT |
| `github.com/sagikazarmark/slog-shim@v0.1.0` | BSD |
| `github.com/shopspring/decimal@v1.4.0` | MIT |
| `github.com/skip2/go-qrcode@v0.0.0-20200617195104-da1b6568686e` | MIT |
| `github.com/sorairolake/lzip-go@v0.3.5` | Apache-2.0 |
| `github.com/spf13/afero@v1.15.0` | Apache-2.0 |
| `github.com/spf13/cast@v1.7.1` | MIT |
| `github.com/spf13/pflag@v1.0.6` | BSD |
| `github.com/spf13/viper@v1.19.0` | MIT |
| `github.com/subosito/gotenv@v1.6.0` | MIT |
| `github.com/therootcompany/xz@v1.0.1` | CC0-1.0 (public domain) |
| `github.com/ulikunitz/xz@v0.5.12` | BSD |
| `github.com/xo/terminfo@v0.0.0-20220910002029-abceb7e1c41e` | MIT |
| `github.com/zricethezav/gitleaks/v8@v8.30.1` | MIT |
| `go4.org@v0.0.0-20230225012048-214862532bf5` | Apache-2.0 |
| `golang.org/x/crypto@v0.51.0` | BSD |
| `golang.org/x/exp@v0.0.0-20250218142911-aa4b98e5adaa` | BSD |
| `golang.org/x/sync@v0.20.0` | BSD |
| `golang.org/x/sys@v0.44.0` | BSD |
| `golang.org/x/text@v0.37.0` | BSD |
| `gopkg.in/ini.v1@v1.67.0` | Apache-2.0 |
| `gopkg.in/yaml.v3@v3.0.1` | Apache-2.0 |
