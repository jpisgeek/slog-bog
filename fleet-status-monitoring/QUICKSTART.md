# Start with one system

This package supplies two behavior types and a manual workflow. It does not
start a listener, install monitoring agents, or enable a schedule. Use an
existing authenticated Swamp Server and a credential authorized to create these
definitions. Keep the credential private. Set `SWAMP_SERVER_URL` and
`SWAMP_SERVER_TOKEN_FILE` for your own connection; no credential value belongs
in a report or this guide.

Install the package after its first release:

```sh
swamp extension pull @jpisgeek/fleet-status-monitoring \
  --server "$SWAMP_SERVER_URL" --token-file "$SWAMP_SERVER_TOKEN_FILE"
```

Create the two definitions. The example inventory labels a macOS machine; choose
`group=linux` and an appropriate label for a Linux server. The reported OS
version is observed by the probe; the inventory group is declared by you.

```sh
swamp behavior create @jpisgeek/fleet-status-monitoring/system fleet-counters \
  --global-arg 'targets=[{"id":"local","label":"Mac Mini","group":"macos","kind":"physical","collector":"local"}]' \
  --global-arg cycleBehavior=fleet-health \
  --server "$SWAMP_SERVER_URL" --token-file "$SWAMP_SERVER_TOKEN_FILE"

swamp behavior create @jpisgeek/fleet-status-monitoring fleet-health \
  --global-arg sourceBehavior=fleet-counters \
  --server "$SWAMP_SERVER_URL" --token-file "$SWAMP_SERVER_TOKEN_FILE"
```

The local probe uses native OS APIs. Validate before running:

```sh
swamp workflow validate @jpisgeek/fleet-status-monitoring/local \
  --server "$SWAMP_SERVER_URL" --token-file "$SWAMP_SERVER_TOKEN_FILE"
swamp workflow run @jpisgeek/fleet-status-monitoring/local \
  --server "$SWAMP_SERVER_URL" --token-file "$SWAMP_SERVER_TOKEN_FILE"
swamp data query 'behavior("fleet-health") && name == "state"' --select content \
  --server "$SWAMP_SERVER_URL" --token-file "$SWAMP_SERVER_TOKEN_FILE"
```

The workflow starts a scan marker, runs the typed native local probe, normalizes
its result, then writes canonical state and `fleet-report.html`. A failed probe
becomes a coverage gap. Workflow completion means the report was generated; use
the report's health and gap counts to assess the systems. The HTML data artifact
must be served as HTML by an authorized host; a source-data viewer may display
its markup.

Choose thresholds in `fleet-health.globalArguments.policy`. Add your own
`coverageNotes` when you intentionally exclude systems; the package does not
assume an exclusion policy for you. If you rename the example definitions, edit
all workflow references and collector source names consistently, then validate.

Add a 15-minute schedule only after a successful attended run. No schedule is
shipped, so installation cannot silently start recurring checks. Do not create
an agent-owned scheduler alongside Swamp's scheduler.

For remote systems, pull the official `@swamp/ssh` extension separately and
configure exact targets with your own scoped vault-backed credentials and
trusted host keys. Add `collector: ssh` inventory rows with `sourceHost`
matching each SSH host name, set `transportBehavior`, and place the SSH probe
after the scan marker and before collection. Its output must follow the contract
in DESIGN.md. Prefer a key restricted to a fixed probe, without shell or
forwarding access. Key installation and privileged bootstrap are outside this
package.
