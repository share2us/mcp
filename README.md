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

[MIT](LICENSE.md) © Share2Us
