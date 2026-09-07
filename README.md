# Share2Us MCP

The [Model Context Protocol](https://modelcontextprotocol.io) server behind
`s2u mcp serve` in the [Share2Us CLI](https://github.com/share2us/cli). It lets AI
agents (Codex, Claude Code, Gemini CLI, …) share files and text through Share2Us —
with the same local secret-scanning and upload controls as the CLI itself.

This module is consumed by the CLI and builds on the shared
[cli-core](https://github.com/share2us/cli-core) library.

## Packages

| Package | What it does |
| --- | --- |
| `mcp` | The MCP server — stdio + HTTP transports, tool definitions for share/get/list. |
| `preflight` | Pre-upload checks: local secret scanning (gitleaks) and content classification. |

## Install

```sh
go get github.com/share2us/mcp@latest
```

Most people don't import this directly — run it via the CLI: `s2u mcp serve`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[GNU General Public License v3.0 only](LICENSE) © 2026 Hassan Khurram

The Share2Us MCP server is free software: you may use, study, share and modify
it. If you distribute it — modified or not — you must pass on the same freedoms
and make the corresponding source available under the GPL.

Releases published before 2026-09-07 (module `v0.1.0`) remain under the MIT
licence they were issued with; a licence already granted cannot be withdrawn.
Dependency licences are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
