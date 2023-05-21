{ config, lib, pkgs, ... }: {
  secrets = lib.secrets.enableSecrets config.secrets.store {
    provision_key.key = ./some/path;
    store = {
      passwords.username.transform = "${pkgs.openssl}/bin/openssl passwd -6 -stdin";
      a = {
        enable = true;
        user = "username";
        link = "/home/username/a_secret";
      };
      services.gitlab = lib.secrets.set_common_config {
        enable = true;
        user = "gitlab";
      } config.secrets.services.gitlab;
    };
  };

  users = {
    users.username = {
      passwordFile = config.secrets.store.passwords.username.file;
      isNormalUser = true;
    };
    groups.username = {};
  };

  system.stateVersion = "22.11";
}
