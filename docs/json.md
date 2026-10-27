# JSON output (`--json`)

`whycant --json` prints one JSON document. The format is versioned by
`schema_version`; fields are only added within a version, never renamed or
removed. Exit codes are the same as for text output.

```json
{
  "schema_version": 1,
  "verdict": "denied",
  "confidence": "certain",
  "action": "read",
  "path": "/srv/app/config/db.yml",
  "subject": {
    "name": "www-data", "uid": 33, "gid": 33,
    "groups": [33], "stale_groups": [], "source": "nss"
  },
  "chain": [
    {
      "path": "/srv/app", "resolved": "/srv/app", "role": "ancestor",
      "need": "x", "exists": true, "mode": "drwxr-x---",
      "owner": "deploy", "group": "deploy", "uid": 1001, "gid": 1001,
      "acl": false, "flags": [], "mount": "/", "fstype": "ext4",
      "result": "blocker", "evaluated": true
    }
  ],
  "findings": [
    {
      "check": "dac", "path": "/srv/app", "severity": "blocker",
      "confidence": "certain",
      "summary": "other class has no execute permission",
      "detail": "…",
      "fixes": [
        {
          "description": "Grant traverse only to www-data via ACL",
          "commands": ["sudo setfacl -m u:www-data:x /srv/app"],
          "risk": "low", "note": ""
        }
      ]
    }
  ],
  "warnings": [],
  "verify": null
}
```

## Top level

| Field | Type | Meaning |
|-------|------|---------|
| `schema_version` | int | `1` |
| `verdict` | string | `allowed`, `denied` or `unknown` |
| `confidence` | string | `certain`, `likely` or `possible` (for `denied`) |
| `action` | string | canonical action name (`read`, `write`, `append`, `exec`, `list`, `traverse`, `create`, `delete`) |
| `path` | string | the path as given, made absolute |
| `subject` | object | who was checked |
| `chain` | array | every path component, in lookup order |
| `findings` | array | problems that decide the verdict (`blocker` and `unknown` severity) |
| `warnings` | array | everything else worth knowing (`warn` and `info` severity) |
| `verify` | object or null | `--verify` result |

## `subject`

`name` (empty if the uid has no passwd entry), `uid`, `gid`, `groups`
(every group in effect, including `gid`), `stale_groups` (configured but
not active in the current session), `source` (`nss`, `files`, `session` or
`pid:<n>`) and, when known, `label` (SELinux context or AppArmor profile).

## `chain[]`

| Field | Meaning |
|-------|---------|
| `path` | physical path of the component |
| `resolved` | for symlinks, where the link points; otherwise `path` |
| `role` | `ancestor`, `target`, `parent` (directory that gets an entry created or deleted), `symlink`, `interpreter`, `loader` |
| `need` | permission bits the component must grant, e.g. `x`, `wx`, `rx`; empty for none |
| `exists` | whether it could be inspected |
| `mode`, `owner`, `group`, `uid`, `gid` | as `ls -l` shows them; omitted when `exists` is false |
| `acl` | an access ACL beyond the mode bits is present |
| `flags` | `immutable`, `append_only` |
| `link` | symlink target as stored |
| `mount`, `fstype` | mount point and filesystem type holding the component |
| `result` | `pass`, `info`, `warn`, `unknown`, `blocker`, or `not_evaluated` |
| `evaluated` | false for components after the first blocker (unless `--all`) |

## `findings[]` and `warnings[]`

`check` (`path`, `dac`, `mount`, `attrs`, `protected`, `sticky`, `exec`,
`acl`, `capacity`, `selinux`, `apparmor`, `identity`, `container`), `path`,
`severity`, `confidence`, `summary` (one line), `detail` (may contain
newlines) and `fixes`, ranked safest first. Each fix has a `description`,
`commands` (already shell-quoted; may be empty when the fix is not a
command), `risk` (`low`, `medium`, `high`) and an optional `note`.

## `verify`

`null` without `--verify`. Otherwise `probe` (`allowed` or `denied`, what
`access(2)` returned when run as the subject), `match` (whether it agrees
with `verdict`) and `error` when the probe could not run.
