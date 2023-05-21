seclib: {config, lib, pkgs, ...}: let
  cfg = config.secrets;

  target_bind = "local-fs.target";
in {
  # Script triggered at system activation or boot time
  #   Will decrypt the provision key from password if needed
  #   Will decrypt all secrets from provision key, and generate correct symlinks
  #   Will NOT set permissions yet as the users may not yet be created
  create-secret-files = {
    script = builtins.concatStringsSep "\n\n" (lib.attrsets.mapAttrsToList
      (name: f: let
          group = if builtins.isNull f.group then f.user else f.group;
        in ''
          mkdir -p $(dirname ${seclib.getSecretFileDest name})
          cat << EOF > ${seclib.getSecretFileDest name}
          ${f.text}
          EOF
          chown ${f.user}:${group} ${seclib.getSecretFileDest name}
          chmod ${f.perms} ${seclib.getSecretFileDest name}
        '')
        cfg.secret_files);
    after = [target_bind];
    wantedBy = [target_bind];
    # requiredBy = [target_bind];
    serviceConfig.Type = "oneshot";
  };

  # Service triggered when setting the system, will set up the right permissions
  #   for all the secrets
  setup-secrets-perms-and-links = {
    # requiredBy = [ target_bind ];
    wantedBy = [ "local-fs.target" ];
    after = [ "local-fs.target" ];
    serviceConfig.Type = "oneshot";
    script = let
      # Go through the secrets config and set permissions based on their configuration set
      set_perms_and_link = _: data: if builtins.hasAttr "__is_leaf" data
        then (''
          chmod 400 ${data.file}
          chown ${data.user}:${data.group} ${data.file}
        '' + (if builtins.isNull data.link then "" else ''
          ${pkgs.su}/bin/su ${data.user} -c 'mkdir -p $(dirname ${data.link})'
          rm -f ${data.link}
          ln -s ${data.file} ${data.link}
          chown ${data.user}:${data.group} ${data.link}
        ''))
        else lib.attrsets.mapAttrsToList set_perms_and_link data;
    in builtins.concatStringsSep "\n" (
      lib.lists.flatten (lib.attrsets.mapAttrsToList set_perms_and_link cfg.store)
    );
  };
}
