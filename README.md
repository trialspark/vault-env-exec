# vault-env-exec

Shim program to inject Vault secrets into program execution environment.

On startup the program authenticates to Vault and then filters the current
environment, replacing specially formatted values.

Variable format: `KEY_NAME=vault:engine:path:key`

## Usage

```bash
$ vault-env-exec user:group -- /path/to/binary --flag=val --no-other-flag
```

## Variable Examples

```bash
KEY_NAME=vault:secrets:jenkins/jobs:1pass-auth-email
```

Would get replaced with the value at `secrets/jenkins/jobs/1pass-auth-email`
