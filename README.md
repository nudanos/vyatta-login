## vyatta-login

Data models, configuration and operational mode support for the
Vyatta login feature

On Debian, login auto-disable requires a managed local-only PAM authentication
stack. Custom stacks and configured remote authentication are rejected before
commit. The default appliance can retain Debian's TACACS and SSS PAM profiles
even after `system login auth-chain method local` is configured. On an appliance
confirmed to use only local accounts, disable those unused profiles with the
supported Debian profile manager before enabling auto-disable:

```sh
sudo pam-auth-update --disable tacplus sss
```

Then configure the desired auto-disable attempts and duration through the normal
CLI. The profile names above describe the default Debian appliance; retain any
profiles needed by the actual authentication configuration. Administrator-edited
or otherwise unrecognized PAM stacks require explicit integration.

Upgrade the login helpers and login YANG package together. Their package
constraints enforce the compatible validation interface. Configd refreshes an
active service after package configuration; an explicit local `policy-rc.d`
denial is respected and requires an administrator restart or reboot before the
new daemon behavior is active.
