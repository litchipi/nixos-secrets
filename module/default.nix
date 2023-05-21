seclib: system_secrets: {config, lib, pkgs, ...}@args: let
  cfg = config.secrets;

  # Create options for a given secret
  mkSecOptions = parents: name: data: let
    # Allows to consult the current config of other options of a secret to set default value
    #   Exemple:  Default group is the current config set for the user
    get_opt_cfg = p: tree: if (builtins.length p) == 0
      then tree
      else get_opt_cfg (lib.lists.drop 1 p) (builtins.getAttr (builtins.head p) tree);
    opt_cfg = get_opt_cfg (parents ++ [ name ]) cfg.store;
  in {
    # Required in order to know if an attr is a secret, or not
    __is_leaf = lib.mkOption {
      default = true;
      visible = false;
    };
    file = lib.mkOption {
      description = "Where to decrypt the secret ${name}";
      default = seclib.gen_secret_path parents name;
      type = lib.types.str;
      visible = false;
    };
    name = lib.mkOption {
      type = lib.types.str;
      description = "Name of the secret ${name}";
      default = name;
      visible = false;
    };
    age_enc_data = lib.mkOption {
      type = lib.types.str;
      description = "Encrypted data for the secret ${name}";
      default = data.pubk;
      visible = false;
    };
    user = lib.mkOption {
      type = lib.types.str;
      description = "User owning the secret ${name}";
      default = "root";
    };
    group = lib.mkOption {
      type = lib.types.str;
      description = "Group owning the secret ${name}";
      default = opt_cfg.user;
    };
    perms = lib.mkOption {
      type = lib.types.str;
      description = "Permissions granted to the file containing the secret ${name}";
      default = "400";
    };
    link = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      description = "Destination where to create a symlink for the secret file ${name}";
      default = null;
    };
    transform = lib.mkOption {
      type = lib.types.str;
      description = ''
        Bash code to transform ${name} before saving to file.
        The secret will be piped into the code:
          <decrypt> | <transformation code> > /path/to/destination
      '';
      default = "tee";
    };
  };

  # Goes through the secrets tree and create secrets options if it's a "leaf"
  mkOptionTree = parents: name: data: if builtins.hasAttr "__password__" data
      then mkSecOptions parents name data
      else lib.attrsets.mapAttrs (mkOptionTree (parents ++ [ name ])) data;

in {
  options.secrets = {
    store = lib.attrsets.mapAttrs (mkOptionTree []) system_secrets.secrets;

    # Options related to the provision key, the master key that will decrypt
    #   all the other secrets in the system
    provision_key = {
      key = lib.mkOption {
        type = lib.types.path;
        description = "Which provision key to use for this system";
      };
      file = lib.mkOption {
        type = lib.types.str;
        description = "Where to store the provision key on the system";
        default = "/etc/secrets_key";
      };
      checksum = lib.mkOption {
        type = lib.types.str;
        description = "Where to store the checksum of the key";
        default = "/etc/secrets_key.sha512sum";
      };
    };

    decrypt_key_cmd = lib.mkOption {
      default = seclib.decrypt_provision_file;
      description = "Function to use to decrypt the provision key";
    };

    secret_files = lib.mkOption {
      type = lib.types.attrsOf seclib.types.secret_file_def;
      description = "Secret files to create";
      default = {};
    };
  };

  config = let
    decrypt_provision_key = import ./decrypt_provision_key.nix seclib args;
    decrypt_provision_key_check = ''
      if ! [ -f ${cfg.provision_key.file} ]; then
        ${decrypt_provision_key}
      elif ! [ -f ${cfg.provision_key.checksum} ]; then
        ${decrypt_provision_key}
      elif ! echo "$(cat ${cfg.provision_key.checksum}) ${cfg.provision_key.key}"|sha512sum --check 1>/dev/null; then
        ${decrypt_provision_key}
      fi
    '';
  in {
    systemd.services = import ./services.nix seclib args;

    system.activationScripts.decrypt_secrets = let
      decrypt_secret = parents: secret: let
        dst = seclib.gen_secret_path parents secret.name;
        decrypt_cmd = builtins.concatStringsSep " | " [
          "echo \"${secret.age_enc_data}\""
          "base64 -d"
          "${pkgs.rage}/bin/rage --decrypt -i ${cfg.provision_key.file}"
          secret.transform
        ];
      in ''
        mkdir -p $(dirname ${dst})
        echo "Decrypting ${builtins.concatStringsSep "." parents}.${secret.name}..."
        ${decrypt_cmd} > ${secret.file}
      '';

      decrypt_all_secrets = parents: name: data: if builtins.hasAttr "__is_leaf" data
        then decrypt_secret parents data
        else lib.attrsets.mapAttrsToList (decrypt_all_secrets (parents ++ [ name ])) data;

      decrypt_all_secrets_cmd = builtins.concatStringsSep "\n" (lib.lists.flatten (
        lib.attrsets.mapAttrsToList (decrypt_all_secrets []) cfg.store
        ));
    in ''
      if [ -f ${cfg.provision_key.file} ]; then
        ${decrypt_all_secrets_cmd}
        echo "All secrets decrypted successfully"
      else
        echo "No provision key set"
      fi
    '';
  };
}
