# Tool registry schema

Every YAML file under `tools_registry/<stage>/` must match the same schema so the
registry loader can validate and inspect it safely. The registry is used only for
local tool metadata and does not itself execute the tools; actual execution still
happens through the runner layer.

## Required schema

Each tool file must contain the following structure:

```yaml
name: subfinder
stage: 01_subdomain_passive
description: "Passive subdomain enumeration via public sources"
binary: subfinder
check:
  command: "subfinder -version"
  success_returncode: 0
  timeout: 10
install:
  method: go
  command: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  post_install: null
  manual_instructions: null
timeout: 600
run:
  command: "subfinder -d {target} -all -silent -o {out}"
  timeout: 600
output:
  format: plain_lines
  parser: plain_lines
requires_api_key: []
notes: ""
```

Field meanings:

- `name`: unique lowercase identifier; it must exactly match the filename stem (for example, `subfinder.yaml` must declare `name: subfinder`).
- `stage`: the stage directory name, such as `01_subdomain_passive` or `03_dns`.
- `description`: short human-readable description of what the tool does.
- `binary`: command name on PATH, such as `subfinder`, or `null` for special built-in/fetch-only tools like `crtsh`.
- `binary_candidates`: optional ordered list of candidate names to try when the actual binary name is ambiguous or a distro ships a shadow binary. The first one that validates wins.
- `signature`: optional text that must appear (case-insensitive) in the validation output before a candidate is accepted as the real tool. This is used to guard against shadow tools like Kali's unrelated `httpx` package.
- `check.command`: the validation command used to verify the binary is installed and working. When `binary` is `null`, this is also `null` and the checker should treat the tool as already available.
- `check.success_returncode`: optional integer return code expected from the validation command; default is `0`.
- `check.timeout`: optional validation timeout in seconds; default is `10`.
- `install.method`: one of `go`, `pip`, `pipx`, `apt`, `cargo`, `git`, or `manual`.
- `install.command`: command used to install the tool. Required unless `install.method == manual`.
- `install.post_install`: optional shell command executed after a successful install.
- `install.manual_instructions`: required when `install.method == manual`; shown to the user instead of running a package manager command.
- `run.command`: command used to run the tool. It may include placeholders such as `{target}`, `{input_file}`, `{out}`, or `{wordlist}`. Some tools also accept custom placeholders like `{target_ip}` or `{port_list}`; the stage module is responsible for populating those values before execution.
- `run.timeout`: timeout in seconds for the actual tool run.
- `output.format`: output format, such as `plain_lines`, `jsonl`, `xml`, or `custom`.
- `output.parser`: parser module name, usually a module under `parsers/`.
- `requires_api_key`: list of key names from `config/api_keys.yaml`; use an empty list if the tool does not require a key.
- `notes`: optional free-form notes, such as quirks or special runner behavior.

Important validation rules:

- `name` must equal the filename stem (`subfinder.yaml` -> `name: subfinder`).
- `install.method` must be one of: `go`, `pip`, `pipx`, `apt`, `cargo`, `git`, `manual`.
- `install.method: manual` requires a non-empty `install.manual_instructions` message.
- `install.command` is required whenever the method is not `manual`.
- `binary: null` is allowed only for built-in fetchers or sources without a local CLI binary; a `check.command` of `null` is also allowed in that case.
- `binary_candidates` is optional and overrides the single-name check when a tool has a known shadowing problem or multiple valid package names.
- `signature` is optional but highly recommended for ambiguous binaries; the dependency checker will reject a candidate if its validation output does not include the configured text.
- `check.command` must be non-empty when `binary` or `binary_candidates` is used.
- `run.command` must be non-empty.
- `output.format` and `output.parser` are required.
- `requires_api_key` must be a list, even when empty.

Special case: `binary: null`

The `crtsh` tool is an example of a built-in fetcher with no CLI binary. In that
case, the registry loader treats the tool as always available and skips the binary
check. The command is not spawned as a subprocess; instead, a special runner hook
can handle it. The YAML still follows the schema and remains loadable, even though
its command is not a shell command.

Annotated example: `subfinder.yaml`

```yaml
name: subfinder
stage: 01_subdomain_passive
description: "Passive subdomain enumeration via public sources"
binary: subfinder
check:
  command: "subfinder -version"
  success_returncode: 0
  timeout: 10
install:
  method: go
  command: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  post_install: null
  manual_instructions: null
run:
  command: "subfinder -d {target} -all -silent -o {out}"
  timeout: 600
output:
  format: plain_lines
  parser: plain_lines
requires_api_key: []
notes: "Uses public sources and does not require an API key by default."
```

Placeholders used by the registry and runtime include `{target}`, `{input_file}`
`{out}`, `{out_dir}`, `{wordlist}`, `{resolvers}`, `{threads}`, and `{rate}`.
Some tools consume a file of inputs (for example `{input_file}` for dnsx) rather
than a single target hostname.
