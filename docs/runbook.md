# When Arx alerts: what to do

Every alert names a finding id. `sudo arx status` lists them with what Arx already did. Nothing Arx
does on its own is irreversible, and whatever it contained stays contained until you decide.

## First, keep the evidence

```bash
sudo arx forensics                 # sealed report of what happened (verify it later with --verify)
sudo arx forensics --indicators    # just the indicators (IPs, hashes) to share or block elsewhere
```

## By kind of alert

| The alert says | Arx already | You decide |
|---|---|---|
| A new program, port or service that can't prove where it came from | Confined it (no outbound network) or blocked the port; it keeps running | Yours: `sudo arx accept <id>`. Not yours: stop and remove it |
| An update "cannot be trusted" (its package, or a library it loads) | Confined the service; it keeps serving | Check the reason in the alert. Legitimate: `sudo arx accept <id>` trusts that exact version. Otherwise roll the package back |
| A service "tried to reach … outside its usual behavior" | Cut that connection in the kernel | A new legitimate destination: `sudo arx accept <id>` |
| A service "started …, which it never ran" | Isolated that process without network; the service keeps running | Expected (a new feature, a new job): `sudo arx accept <id>` |
| sshd "before authenticating anyone, ran …" | Froze that process and isolated it | Treat it as a compromise: keep the evidence, update OpenSSH and its libraries from a trusted source, rotate keys. Only if you configured that command yourself: `sudo arx accept <id>` |
| A web server or database "started a shell" | Froze that process | Look for a webshell in the site's files; then `sudo arx accept <id>` lifts it |
| Login from an unknown origin | Closed that account's sessions and access (on your word, or the model's) | `sudo arx unlock` only once you know it was legitimate |
| A planted cron job, SUID bit, second root account, changed critical file | Alerted and asked for your word | `sudo arx authorize <id>` to restore or remove; `sudo arx accept <id>` if it was you |
| Arx stopped, or its unit or files changed | Told you through your channels | If it wasn't you, assume someone with root is trying to blind it: work from another machine |

## Lifting a containment

`sudo arx accept <id>` marks the change as normal and lifts what contained it. Account locks are the
exception: they only lift with `sudo arx unlock`. A Tier 2 action waiting for you shows its id in
`sudo arx status`; authorize it with `sudo arx authorize <id>` and your authorization word.

## Removing Arx

`sudo apt purge arx` gives the network back to everything Arx confined and leaves nothing of its own
behind. See "Removing it" in the README for decoys, locked accounts and applied proposals.
