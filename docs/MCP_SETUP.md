# MCP Setup: Perplexity + Firecrawl

How the two research/scraping MCP servers used alongside this project are wired
into Claude Code, and how to reproduce the setup on a fresh machine.

```
Claude Code
 ├── perplexity  (MCP) -> web research / search
 └── firecrawl   (MCP) -> scrape / crawl / extract websites
```

## Why MCP at all

MCP (Model Context Protocol) is the standard way Claude Code talks to external
tools. Each server is a separate process Claude Code launches over stdio; it
advertises a list of tools, and Claude calls them by name. Nothing about MCP is
specific to Aegis - these two servers are developer tooling, not runtime
dependencies of the application. No Aegis source, container, or CI job imports
them.

- **Perplexity** answers research questions against live web sources, with
  citations. Useful for CVE write-ups, vendor documentation, and detection
  research where a stale training cutoff would mislead.
- **Firecrawl** fetches and structures actual page content - single-page scrape,
  whole-site crawl, and schema-driven extraction. Useful when you need the text
  of a specific advisory or docs page rather than a summary of it.

## Servers

| Name | Scope | Transport | Package | Command |
| --- | --- | --- | --- | --- |
| `perplexity` | user (global) | stdio | [`server-perplexity-ask`](https://www.npmjs.com/package/server-perplexity-ask) | `npx -y server-perplexity-ask` |
| `firecrawl` | user (global) | stdio | [`firecrawl-mcp`](https://www.npmjs.com/package/firecrawl-mcp) | `npx -y firecrawl-mcp` |

**User scope** means the config lives in `~/.claude.json` and applies to every
project you open, not just this one. That is deliberate: these are general
research tools, and a project-local `.mcp.json` would be committed to the repo
and shared with anyone who clones it - which is the wrong blast radius for
tooling that needs personal API keys.

## Install

Requires Node.js 18+ (`npx` ships with it). Run from anywhere:

```bash
claude mcp add --scope user perplexity \
  --env 'PERPLEXITY_API_KEY=${PERPLEXITY_API_KEY}' \
  -- npx -y server-perplexity-ask

claude mcp add --scope user firecrawl \
  --env 'FIRECRAWL_API_KEY=${FIRECRAWL_API_KEY}' \
  -- npx -y firecrawl-mcp
```

Note the **single quotes**. They stop the shell from expanding the variable, so
the literal string `${PERPLEXITY_API_KEY}` is what gets written to
`~/.claude.json`. Claude Code expands it from your environment at launch time.
The key itself is never written to any config file, and never reaches the repo.

The resulting entry looks like this - a reference, not a secret:

```json
{
  "mcpServers": {
    "perplexity": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "server-perplexity-ask"],
      "env": { "PERPLEXITY_API_KEY": "${PERPLEXITY_API_KEY}" }
    }
  }
}
```

## API keys

Both servers need a key. Export them from your shell profile
(`~/.bashrc`, `~/.zshrc`) so every Claude Code session inherits them:

```bash
export PERPLEXITY_API_KEY="pplx-..."   # https://www.perplexity.ai/settings/api
export FIRECRAWL_API_KEY="fc-..."      # https://www.firecrawl.dev/app/api-keys
```

Then `source ~/.zshrc` (or open a new terminal) and restart Claude Code.

Do **not** put these in the repo's `.env` or `.env.example`. Those files
parameterise the Aegis container stack; these keys belong to your development
machine and have nothing to do with the application.

Without a key, `claude mcp list` still reports the server as connected - the
process starts fine - but every tool call fails at the API boundary. The health
check flags the gap explicitly:

```
[Warning] [perplexity] mcpServers.perplexity: Missing environment variables: PERPLEXITY_API_KEY
```

## Verify

```bash
claude mcp list          # health check for every configured server
claude mcp get firecrawl # full config for one server
```

Expected output when both are wired correctly:

```
perplexity: npx -y server-perplexity-ask - ✓ Connected
firecrawl: npx -y firecrawl-mcp - ✓ Connected
```

Inside a session, `/mcp` shows the same status plus the tool list.

## Tools exposed

`perplexity` (`server-perplexity-ask` 0.1.3) exposes one tool:

- `perplexity_ask` - conversational search against the Sonar API, returning an
  answer with citations.

`firecrawl` (`firecrawl-mcp` 3.24.0) exposes 27. The ones that matter day to day:

| Tool | Use |
| --- | --- |
| `firecrawl_scrape` | One URL to clean markdown |
| `firecrawl_map` | Discover every URL on a site |
| `firecrawl_crawl` | Crawl many pages (async; poll with `firecrawl_check_crawl_status`) |
| `firecrawl_search` | Web search with optional content fetch |
| `firecrawl_extract` | Pull structured data out of pages against a schema |
| `firecrawl_parse` | Parse a document (e.g. PDF) into text |

The rest cover browser interaction (`firecrawl_interact`), agentic browsing
(`firecrawl_agent`), scheduled change monitoring (`firecrawl_monitor_*`), and
academic/code search (`firecrawl_research_*`, `firecrawl_developer_search`).

## Removing

```bash
claude mcp remove perplexity -s user
claude mcp remove firecrawl -s user
```

## Troubleshooting

**"Missing environment variables"** - the key is not exported in the shell that
launched Claude Code. GUI-launched editors do not always inherit a shell
profile; confirm with `echo $FIRECRAWL_API_KEY` in Claude Code's own terminal.

**Server fails to start** - run the command by hand to see the real error:
`FIRECRAWL_API_KEY=test npx -y firecrawl-mcp`. It should sit and wait for JSON-RPC
on stdin; anything else is a startup failure.

**401 / 403 on every tool call** - the server is running and the key is being
passed, but the key itself is invalid or out of credit. Check the provider
dashboard.
