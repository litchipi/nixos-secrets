{ lib, ... }: {
  secretSetupType = lib.types.submodule {
    options = {
      secret = lib.mkOption {
        type = lib.types.attrs;  # TODO  IMPORTANT  Have a special type for the secret
        description = "Secret data to decrypt";
      };
      user = lib.mkOption {
        type = lib.types.str;
        description = "User owning the secret";
        default = "root";
      };
      group = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        description = "Group owning the secret";
        default = null;
      };
      perms = lib.mkOption {
        type = lib.types.str;
        description = "Permissions granted to the file containing the secret";
        default = "400";
      };
    };
  };
}
