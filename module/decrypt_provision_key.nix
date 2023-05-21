seclib: {config, lib, pkgs, ...}: let
  cfg = config.secrets;
in pkgs.writeShellScript "decrypt_all" ''
  set -e
  while true; do
    ${cfg.decrypt_key_cmd cfg.provision_key.key cfg.provision_key.file} && break
    echo "Wrong password"
  done
  sha512sum ${cfg.provision_key.key} | cut -d " " -f 1 > ${cfg.provision_key.checksum}
  chmod 400 ${cfg.provision_key.file} ${cfg.provision_key.checksum}
  chown root:root ${cfg.provision_key.file} ${cfg.provision_key.checksum}

  echo "All secrets decrypted successfully"
  echo "The system will reboot now"
  sleep 2
  reboot
''
