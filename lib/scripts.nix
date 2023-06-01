{ manage_secrets, pkgs, lib, ... }: let
  openssl_provision_key_common_args = "-pbkdf2 -aes-256-cbc -salt";
  default_encrypt_provision_key = key: file: builtins.concatStringsSep " " [
    "${pkgs.openssl}/bin/openssl enc"
    openssl_provision_key_common_args
    "-in \"${key}\""
    "-out \"${file}\""
  ];
  default_decrypt_provision_key = key: file: builtins.concatStringsSep " " [
    "${pkgs.openssl}/bin/openssl dec"
    openssl_provision_key_common_args
    "-d"
    "-in \"${key}\""
    "-out \"${file}\""
  ];
in {
  mkDecryptProvKeyScript = {
      privk_dir,
      decrypt_key_cmd ? default_decrypt_provision_key,
      secret_key_path ? "/etc/secrets_key",
      runtimeInputs ? [],
    }: let
      script = ''
        if [ $# -ne 1 ]; then
          echo "Usage: $0 <key path>"
          exit 1;
        fi
        
        KEYPATH=$(realpath "$1")
        if ! [ -f "$KEYPATH" ]; then
          echo "Key path $KEYPATH doesn't exist"
          exit 1;
        fi
        
        sudo ${decrypt_key_cmd "$KEYPATH" secret_key_path}
        sudo chmod 400 ${secret_key_path}
        sudo chown root:root ${secret_key_path}
      '';

      script_file = pkgs.writeShellApplication {
        name = "decrypt_provision_key";
        text = script;
        inherit runtimeInputs;
      };
    in {
      type = "app";
      program = "${script_file}/bin/decrypt_provision_key";
    };

    mkProvisionKeyScript = {
      pubk_dir,
      privk_dir,
      secretf,
      key_type ? "rsa",
      encrypt_key_cmd ? default_encrypt_provision_key,
      runtimeInputs ? [],
      argon2_time ? 4,
      argon2_memory ? 65536,
      argon2_parallelism ? 16,
      ...
    }: let
      args = builtins.concatStringsSep " " [
        "-f ${secretf}"
        "-t ${builtins.toString argon2_time}"
        "-m ${builtins.toString argon2_memory}"
        "-p ${builtins.toString argon2_parallelism}"
        "--re-encrypt"
        "-d ${pubk_dir}"
      ];
      script = ''
        mkdir -p ${pubk_dir} ${privk_dir}
        read -r -p "Enter the name of the provision key: " keyname
        ${pkgs.openssh}/bin/ssh-keygen -t ${key_type} -f "$keyname" -P ""
        mv "$keyname.pub" "${pubk_dir}/$keyname.pub"
        ${encrypt_key_cmd "$keyname" "${privk_dir}/$keyname"}
        ${pkgs.srm}/bin/srm -D "$keyname"
        ${manage_secrets} ${args}
      '';
      script_file = pkgs.writeShellApplication {
        name = "make_provision_key";
        text = script;
        runtimeInputs = runtimeInputs ++ [ pkgs.rage ];
      };
    in {
      type = "app";
      program = "${script_file}/bin/make_provision_key";
    };

    mkEditScript = {
      secretf,
      pubk_dirs ? [],
      # add_pubk ? {},
      argon2_time ? 4,
      argon2_memory ? 65536,
      argon2_parallelism ? 16,
    }: let
      args = builtins.concatStringsSep " " ([
        "-f ${secretf}"
        "-t ${builtins.toString argon2_time}"
        "-m ${builtins.toString argon2_memory}"
        "-p ${builtins.toString argon2_parallelism}"
      ]
      # ++ (lib.attrsets.mapAttrsToList (name: k: "-k \"${name}:${k}\"") add_pubk)
      ++ (builtins.map (d: "-d ${d}") pubk_dirs));

      script = ''
        ${manage_secrets} ${args}
      '';
      script_file = pkgs.writeShellApplication {
        name = "edit_nixos_secrets";
        text = script;
        runtimeInputs = [ pkgs.rage ];
      };
    in {
      type = "app";
      program = "${script_file}/bin/edit_nixos_secrets";
    };
}
