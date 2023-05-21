{ manage_secrets, pkgs, lib, ... }: let
  tryInitSecrets = {
    secretf,
    pubk_dirs_args,
    add_pubk_args,
    pwd_cache,
  ... }: ''
    if ! [ -f ${secretf} ]; then
      ${manage_secrets} --pwd-cache ${pwd_cache} init \
        ${secretf} \
        ${pubk_dirs_args} \
        ${add_pubk_args}
    fi
  '';

  loadSecrets = {
    secretf,
    plaintext_file,
    pwd_cache,
    secrets_owners,
  ... }: ''
    echo "$OWNER" | xargs ${manage_secrets} --pwd-cache ${pwd_cache} \
      ${plaintext_file} \
      --owners '${builtins.toJSON secrets_owners}'
      ${secretf} \
      load
  '';

  saveSecrets = {
    secretf,
    pubk_dirs_args,
    add_pubk_args,
    plaintext_file,
    pwd_cache,
    secrets_owners,
  ... }: ''
    echo "$OWNER" | xargs ${manage_secrets} --pwd-cache ${pwd_cache} secure \
      ${plaintext_file} \
      ${secretf} \
      ${pubk_dirs_args} \
      ${add_pubk_args} \
      --owners '${builtins.toJSON secrets_owners}'
  '';

  openssl_provision_key_common_args = "-pbkdf2 -aes-256-cbc -salt";
  default_encrypt_provision_key = key: file: builtins.concatStringsSep " " [
    "${pkgs.openssl}/bin/openssl enc"
    openssl_provision_key_common_args
    "-in \"${key}\""
    "-out \"${file}\""
  ];
  default_decrypt_provision_key = key: file: builtins.concatStringsSep " " [
    "${pkgs.openssl}/bin/openssl enc"
    openssl_provision_key_common_args
    "-d"
    "-in \"${key}\""
    "-out \"${file}\""
  ];
in {
  mkDecryptProvKeyScript = {
      keypath,
      privk_dir,
      decrypt_key_cmd ? default_decrypt_provision_key,
      secret_key_path ? "/etc/secrets_key",
      secret_key_chechsum_file ? "/etc/secrets_key.sha512sum",
      runtimeInputs ? [],
    }: let
      script = ''
        sudo ${decrypt_key_cmd keypath secret_key_path}
        sha512sum ${keypath} | cut -d " " -f 1 | sudo tee ${secret_key_chechsum_file}
        sudo chmod 400 ${secret_key_path} ${secret_key_chechsum_file}
        sudo chown root:root ${secret_key_path} ${secret_key_chechsum_file}
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
      key_type ? "rsa",
      encrypt_key_cmd ? default_encrypt_provision_key,
      runtimeInputs ? [],
      ...
    }: let
      script = ''
        mkdir -p ${pubk_dir} ${privk_dir}
        read -r -p "Enter the name of the provision key: " keyname
        ${pkgs.openssh}/bin/ssh-keygen -t ${key_type} -f "$keyname" -P ""
        mv "$keyname.pub" "${pubk_dir}/$keyname.pub"
        ${encrypt_key_cmd "$keyname" "${privk_dir}/$keyname"}
        ${pkgs.srm}/bin/srm -D "$keyname"
      '';
      script_file = pkgs.writeShellApplication {
        name = "make_provision_key";
        text = script;
        inherit runtimeInputs;
      };
    in {
      type = "app";
      program = "${script_file}/bin/make_provision_key";
    };

    mkEditScript = {
      secretf,
      editor_fct,
      plaintext_file ? ".secrets_plain.json",
      pwd_cache ? ".nixos_secrets_password_cache",
      pubk_dirs ? [],
      add_pubk ? {},
      secrets_owners ? {},
      argon2_time ? 4,
      argon2_memory ? 64,
      argon2_parallelism ? 4,
      argon2_salt ? 64,
    }: let
      args = builtins.concatStringsSep " " ([
        "-f ${secretf}"
        "-s '${builtins.toJSON secrets_owners}'"
        "-c ${pwd_cache}"
        "-p ${plaintext_file}"
        "-o \"$OWNER\""
        "-at ${builtins.toString argon2_time}"
        "-am ${builtins.toString argon2_memory}"
        "-ap ${builtins.toString argon2_parallelism}"
        "-as ${builtins.toString argon2_salt}"
      ] ++ (lib.attrsets.mapAttrsToList (name: k: "-k \"${name}:${k}\"") add_pubk)
      ++ (builtins.map (d: "-d ${d}") pubk_dirs));
      # TODO  Trap any error and delete sensitive data if anything goes wrong
      script = ''
        set -e
        if [ $# -eq 1 ]; then
          OWNER="$1"
        else
          OWNER=
        fi
        ${manage_secrets} load ${args}
        ${editor_fct plaintext_file}
        ${manage_secrets} secure ${args}
        ${pkgs.srm}/bin/srm -D ${plaintext_file} ${pwd_cache}
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
