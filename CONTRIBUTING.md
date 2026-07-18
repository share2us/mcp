# Contributing to Share2Us MCP

Thanks for your interest. Bug reports and pull requests are welcome.

## Security issues

Do **not** open a public issue for a vulnerability — this server handles file
uploads and secret scanning. Email **support@share2.us** and we'll coordinate a fix.

## Development

Requires **Go 1.25+**.

```sh
git clone https://github.com/share2us/mcp
cd mcp
go test ./...
go vet ./...
gofmt -l .
```

Most behavior is exercised through the [CLI](https://github.com/share2us/cli)
(`s2u mcp serve`); changes here should keep it building and green. The MCP server
must never weaken the pre-upload secret scan — high-confidence findings are a hard
block that agents cannot override.

## Pull requests

- Keep changes focused; add tests for behavior you change.
- Run `gofmt`, `go vet`, and `go test ./...` before pushing.
- Match the commit style: `scope: short summary`.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE.md).
