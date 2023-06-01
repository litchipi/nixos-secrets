seclib: {config, lib, pkgs, ...}: let
  cfg = config.secrets;

  target_bind = "local-fs.target";
in {
  create-secret-files = {
    script = builtins.concatStringsSep "\n\n" (lib.attrsets.mapAttrsToList
      (name: f: let
          group = if builtins.isNull f.group then f.user else f.group;
        in (if !f.enable then "" else ''
          mkdir -p $(dirname ${seclib.getSecretFileDest name})
          cat << EOF > ${seclib.getSecretFileDest name}
          ${f.text}
          EOF
          chown ${f.user}:${group} ${seclib.getSecretFileDest name}
          chmod ${f.perms} ${seclib.getSecretFileDest name}
        ''))
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
      set_perms_and_link = user: group: perms: data:
        if builtins.hasAttr "__is_leaf" data
        then ''
            if [ -f ${data.file} ]; then
              chmod ${perms} ${data.file}
              chown ${user}:${group} ${data.file}
            else
              echo "File ${data.file} not found, skipping ..."
            fi
          '' + (if builtins.isNull data.link then "" else ''
            ${pkgs.su}/bin/su ${user} -c 'mkdir -p $(dirname ${data.link})'
            rm -f ${data.link}
            ln -s ${data.file} ${data.link}
            chown ${user}:${group} ${data.link}
          '')
        else lib.attrsets.mapAttrsToList (_: d: set_perms_and_link user group perms d) data;

      set_tree_perms_and_link = _: { secret, user, group, perms }: let
        applied_group = if builtins.isNull group then user else group;
      in set_perms_and_link user applied_group perms secret;

   in builtins.concatStringsSep "\n" (
      lib.lists.flatten (lib.attrsets.mapAttrsToList set_tree_perms_and_link cfg.setup)
    );
  };
}
