# Server Control

Independent operations panel for the Phira multiplayer server. It is mounted at
`/control` and does not share routes, sessions, or authentication with
`web-dashboard`.

## Features

- Online player, room, CPU, memory, event-loop, GC, disk, and process metrics
- Plugin list and selective plugin reload
- Live server logs and paginated historical log viewing
- Historical game, command, control-login, and ban log analysis
- Visual editing for `.env`, plugin configuration, and plugin data files
- CSRF-protected file reveal, save, command, and reload operations
- Independent password authentication with login throttling and audit logs

## Requirements

- A compatible Phira multiplayer server with the Server Control plugin API
- `ENABLE_WEB_SERVER=true`
- `PLUGINS_ENABLED=true`
- Node.js available when using the offline password-hash utility

## Installation

From the server directory:

```bash
cd plugins
git clone https://github.com/chuzouX/phira-mp-nodejsver-server-control.git server-control
cd ..
```

The explicit `server-control` destination keeps the plugin directory, config
directory, and reload command names consistent. Restart the server after cloning.
On first load, the server creates:

```text
config/server-control/config.yaml
```

## Password Setup

Generate a password hash with the plugin's offline utility:

```bash
node plugins/server-control/scripts/hash-password.js "a-long-unique-password"
```

Alternatively, after the plugin has loaded, use the server console:

```text
/server-control hash "a-long-unique-password"
```

Copy the complete `scrypt$...` value into
`config/server-control/config.yaml`:

```yaml
passwordHash: 'scrypt$16384$8$1$...'
```

Restart the server, then open:

```text
http://<server-host>:<web-port>/control
```

The panel rejects every login while `passwordHash` is empty. For temporary
deployments, `SERVER_CONTROL_PASSWORD_HASH` may be used instead of the YAML
setting.

## Console Commands

```text
/server-control help
/server-control status
/server-control hash "<password-at-least-10-characters>"
```

The `server-control` command is registered with the plugin API's
`redactInput` tag. Its arguments are passed to the plugin normally, but the
server writes only the following form to `logs/command.log`:

```text
执行指令: /server-control <redacted>
```

The hash command only prints a hash. It never writes plugin configuration.
`/server-control password` and `/server-control set-password` are explicitly
rejected. Password changes must be made manually in
`config/server-control/config.yaml`, followed by a server restart.

## File Editing

The panel only permits UTF-8 text files under `.env`, `config/`, and `data/`.
Paths outside those roots, symbolic-link escapes, binary files, and files over
the configured size limit are rejected. Existing files receive a `.bak` copy
before an atomic save. Secret-like keys are masked until explicitly revealed.

Saving does not reload anything automatically. The UI offers a separate,
confirmed reload for an affected plugin or for hot-reloadable server settings.
The `server-control` plugin itself requires a server restart after its own
configuration changes.

## Security Notes

- Use HTTPS, a private network, or a VPN for production access.
- Keep `config/server-control/config.yaml` out of source control.
- Do not commit a real `passwordHash` to this repository.
- Limit access to `logs/server-control-audit.log` and `logs/command.log`.
- Command redaction protects `command.log`; plugin developers must still avoid
  writing sensitive command arguments to other logs.
