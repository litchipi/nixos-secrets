{ lib, ... }: {
  secret_file_def = lib.types.submodule {
    options = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          If set to true, will decrypt the secret file, if not it will stay encrypted and be unusable.
        '';
      };
      perms = lib.mkOption {
        description = "Permissions to set for the file";
        default = "400";
        type = lib.types.str;
      };
      user = lib.mkOption {
        description = "The owner of the secret file";
        default = "root";
        type = lib.types.str;
      };
      group = lib.mkOption {
        description = "The group owning the secret file";
        default = null;
        type = lib.types.nullOr lib.types.str;
      };
      text = lib.mkOption {
        description = "The text inside the secret file";
        default = "";
        type = lib.types.str;
      };
    };
  };
}
