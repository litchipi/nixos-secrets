{ lib, ... }: {
  secretType = name: lib.types.submodule {
    options = {
      __is_leaf = lib.mkOption {
        visible = false;
        type = lib.types.bool;
      };

      name = lib.mkOption {
        visible = false;
        type = lib.types.str;
      };

      enable = lib.mkEnableOption {
        visible = false;
      };

      file = lib.mkOption {
        visible = false;
        type = lib.types.path;
      };

      age_enc_data = lib.mkOption {
        visible = false;
        type = lib.types.str;
      };

      link = lib.mkOption {
        visible = false;
        type = lib.types.nullOr lib.types.path;
      };

      transform = lib.mkOption {
        visible = false;
        type = lib.types.str;
      };
    };
  };
}
