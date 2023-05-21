# Example

## Generate a provision key

To do this, simply use `nix run .#create_provision_key` and let yourself guided.

Of course feel free to mess with the options in the flake to experiment.

As this project uses a flake, you'll need to add the generated keys to the git
repo in order to get something working (`git add <keys>`)

## Setup some secrets

To setup the secrets, use `nix run .#edit_secrets`, and edit the file to add secrets.

This command will require you to setup a password to protect your passwords in the
repository.

The nixos configuration in `machine.nix` requires at least 2 secrets:

``` json
{
    "a": "some secret data, whatever",
    "passwords": {
        "username": "weakpass"
    }
}
```

Add the file `secrets.json` to your repository, and take a look at it if you want
to know how things will be stored in the repo.

## Create a VM to test this setup

In order to have a working system, you'll need to set the option
`secrets.provision_key.key` in `machine.nix` to the path where your
provision key is stored (encrypted at this point).

The default package in this example is set up to generate a QEMU VM (without gui)
so you can test this setup easily, for this you simply have to run `nix build` and
execute `result/bin/run-nixos-vm`.

During the boot, you'll get a line asking for your password to unlock the provision
key:

```
enter AES-256-CBC decryption password:
```

once entered, all the secrets are decrypted, but as the users are not yet created
by the system, it's only later using a systemd service that the permissions are
set, you can see its status using `systemctl status setup_secrets_perms.service`.

## Have fun with the NixOS configuration

You can see how the password is set using `passwordFile` and the `transform` option
to pass the hash as expected by the configuration option.

A lot of services in `services.<name>` options takes secrets using a path to a file,
so it is really easy to configure:

``` nix
services.gitlab = let
    scfg = config.secrets.store.services.gitlab;
in {
    smtp.passwordFile = scfg.smtp_password.file;
    secrets.secretFile = scfg.secretDb.file;
};

secrets.store.services.gitlab = {
    smtp_password.user = config.services.gitlab.user;
    secretDb.user = config.services.gitlab.user;
};
```

Of course you'll have to be sure to have your secrets set in consequence:

``` json
{
    "services": {
        "gitlab": {
            "smtp_password": "ppzoergkl,lkzeflkaz,",
            "secretDb": "beopocazpejfzpeofvklwxn"
        },
    }
}
```

The good news is that you'll have a nix build error if your secrets doesn't
match, because if the secret `services.gitlab.smtp_password` isn't set,
the config `config.secrets.store.services.gitlab.smtp_password` won't
exist either !

### Transform a secret

When passing the password for a user for example, the value expected is the hash of the
password, not the plaintext value.

To handle this (and any other similar cases), we transform the secret by doing so:
``` nix
secrets = {
    passwords.username.transform = "${pkgs.openssl}/bin/openssl passwd -6 -stdin";
}  ;

users.users.username.passwordFile = config.secrets.store.passwords.username.file;
```

The secret will be piped into the code:
```
<decrypted secret> | <transformation code> > /path/to/destination
```
