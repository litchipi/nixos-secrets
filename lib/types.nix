{ lib, ... }: {
  secretType = name: lib.types.submodule {
    options = {
      enable = lib.mkEnableOption {
        description = ''
          If set to true, will decrypt the secret file, if not it will stay encrypted and be unusable.
        '';
      };
      file = lib.mkOption {
        type = lib.types.path;
        description = "Where to decrypt the secret ${name}";
      };
      age_enc_data = lib.mkOption {
        type = lib.types.str;
        description = "Encrypted data for the secret ${name}";
      };
      link = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        description = "Destination where to create a symlink for the secret file ${name}";
      };
      transform = lib.mkOption {
        type = lib.types.str;
        description = ''
          Bash code to transform ${name} before saving to file.
          The secret will be piped into the code:
            <decrypt> | <transformation code> > /path/to/destination
        '';
      };
    };
  };
}
