seclib: system_secrets: {config, lib, pkgs, ...}@args: let
  cfg = config.secrets;
  sectypes = import ./types.nix {inherit config lib pkgs; };

  # Create options for a given secret
  mkSecOptions = parents: name: data: {
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
      default = data.__rage__;
      visible = false;
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
  mkOptionTree = parents: name: data: if builtins.hasAttr "__rage__" data
      then mkSecOptions parents name data
      else lib.attrsets.mapAttrs (mkOptionTree (parents ++ [ name ])) data;

in {
  options.secrets = {
    store = lib.attrsets.mapAttrs (mkOptionTree []) system_secrets.secrets;
    setup = lib.mkOption {
      type = lib.types.attrsOf sectypes.secretSetupType;
      default = {};
      description = "Setup options for secrets to decrypt on this system";
    };

    # Options related to the provision key, the master key that will decrypt
    #   all the other secrets in the system
    provision_key = lib.mkOption {
      type = lib.types.str;
      description = "Where to store the provision key on the system";
      default = "/etc/secrets_key";
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

  config = {
    systemd.services = import ./services.nix seclib args;

    system.activationScripts.decrypt_secrets = let
      decrypt_secret = parents: { age_enc_data, transform, file, ...}: let
        secret_id = builtins.concatStringsSep "." parents;
        decrypt_cmd = builtins.concatStringsSep " | " [
          "echo \"${age_enc_data}\""
          "base64 -d"
          "${pkgs.rage}/bin/rage --decrypt -i ${cfg.provision_key}"
          transform
        ];
        script = pkgs.writeShellScript "decrypt-${secret_id}" ''
          mkdir -p $(dirname ${file})
          echo "Decrypting ${secret_id}..."
          ${decrypt_cmd} > ${file}
        '';
      in "${script}";

      decrypt_all_secrets = parents: data: if builtins.hasAttr "__is_leaf" data
        then decrypt_secret parents data
        else lib.attrsets.mapAttrsToList (n: s: decrypt_all_secrets (parents ++ [n]) s) data;

      decrypt_all_secrets_cmd = builtins.concatStringsSep "\n" (lib.lists.flatten (
        lib.attrsets.mapAttrsToList (n: s: decrypt_all_secrets [n] s.secret) cfg.setup
      ));
    in ''
      if [ -f ${cfg.provision_key} ]; then
        ${decrypt_all_secrets_cmd}
        echo "All secrets decrypted successfully"
      else
        echo "No provision key set"
      fi
    '';
  };
}
