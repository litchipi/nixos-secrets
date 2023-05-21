{ config, lib, pkgs, ... }: {
  secrets = {
    provision_key.key = ./some/path;
    store = {
      passwords.username.transform = "${pkgs.openssl}/bin/openssl passwd -6 -stdin";
      a = {
        user = "username";
        link = "/home/username/a_secret";
      };
      services.gitlab = lib.secrets.set_common_config {
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
