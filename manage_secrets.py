import os
import sys
import json
import base64
import argon2
import random
import hashlib
import getpass
import argparse
import subprocess
import argon2.low_level
from Crypto.Cipher import AES
from argon2 import PasswordHasher

# TODO  When you edit secrets using a specific owner, any secrets ADDED will get this owner only
# TODO  Handle case where a key is modified (re-generated) but with same name

ENC_SECRETS_KEYS = ["secrets", "keys", "settings"]
ARGON2_KEYDERIV_TYPE = argon2.low_level.Type.ID
KEY_DERIVATION_HASH_LEN = 16
FAKE_KEYDERIV_HASH = argon2.hash_password("fake keyderiv".encode()).decode().split("$")[-1]

def call_rage(stdin, *args):
    p = subprocess.Popen(
        ["rage"] + list(args),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = p.communicate(input=stdin.encode())
    if p.returncode > 0:
        err_msg = f"Rage command failed: {p.returncode}\n\n"
        err_msg += "Command called: `rage {}`\n\n".format(" ".join(args))
        err_msg += f"Error message:\n{stderr.decode()}\n"
        raise Exception(err_msg)
    return base64.b64encode(stdout).decode()

def flatten_keys_tree(tree, key=None):
    res = dict()
    for name, val in tree.items():
        if name == "__password__":
            continue
        if type(val) == dict:
            res.update(flatten_keys_tree(val, key=name))
        elif key is None:
            res[name] = val
        else:
            res[f"{key}/{name}"] = val
    return res

def find_all_keys_in_dir(dirpath):
    if dirpath is None:
        return {}
    if not os.path.isdir(dirpath):
        raise FileNotFoundError(f"{dirpath} isn't a path to a valid directory")
    res = dict()
    for root, dirs, files in os.walk(dirpath):
        for keyfname in files:
            with open(os.path.join(root, keyfname), "r") as f:
                res[".".join(keyfname.split(".")[:-1])] = f.read()
        for d in dirs:
            res[d] = find_all_keys_in_dir(os.path.join(root, d))
    return res

class SecretsManager:
    def __init__(self, args):
        self.argon2_params = {
            "time_cost": args.argon2_time,
            "memory_cost": args.argon2_memory * 1024,
            "parallelism": args.argon2_parallelism,
            "salt_len": args.argon2_salt,
        }
        self.secrets_owners = json.loads(args.secrets_owners)
        self.owner = None
        if args.owner:
            self.owner = args.owner

        # Get all keys
        self.keys = dict()
        for add_key in args.add_pubk:
            name, key = add_key.split(":")
            self.keys[name] = key
        if args.pubk_dir:
            for keys_dir in args.pubk_dir:
                self.keys.update(find_all_keys_in_dir(keys_dir))
        self.keys = flatten_keys_tree(self.keys)
        if len(flatten_keys_tree(self.keys)) == 0:
            raise Exception("No public key provided to encrypt data")

        self.secrets_path = args.secrets_path
        self.password_cache_file = args.password_cache_file
        if os.path.isfile(self.secrets_path):
            try:
                self.encdata = self.load_secrets()
            except Exception as err:
                print(f"Unable to load the secrets file: {err}")
                sys.exit(1)
        else:
            self.init_secrets()
            self.save_secrets()

        self.keys["__password__"] = dict.copy(self.encdata["keys"]["__password__"])

        self.plaintext_file = args.plaintext_file
        if args.command == "load":
            self.load()
        elif args.command == "secure":
            self.old_enc_data = self.encdata["secrets"]
            self.secure()
        else:
            raise Exception(f"Command {args.command} not found")

    def is_owner(self, key, secrets_owners):
        if key not in secrets_owners:
           return True
        else:
            if type(secrets_owners[key]) == dict:
                return True
            elif type(secrets_owners[key]) == list:
                if not self.owner:
                    return True
                else:
                    return self.owner in secrets_owners[key]
            elif type(secrets_owners[key]) == str:
                return (not self.owner) or (secrets_owners[key] == self.owner)
            else:
                raise Exception("Wrong secrets owner format")

    def get_not_owned_data(self, data, secrets_owners):
        res = dict()
        for key, val in data.items():
            if type(data) != dict:
                raise Exception("Malformed data, expecting only dicts")

            if "__password__" in val.keys():
                if not self.is_owner(key, secrets_owners):
                    res[key] = val
            elif self.is_owner(key, secrets_owners):
                new_secrets_owners = {}
                if key in secrets_owners:
                    new_secrets_owners = secrets_owners[key]
                res[key] = self.get_not_owned_data(val, new_secrets_owners)
            else:
                res[key] = dict.copy(val)
        return res


    def hash(self, data: str):
        return base64.b64encode(hashlib.sha512(data.encode()).digest()).decode()

    def load_secrets(self):
        if not os.path.isfile(self.secrets_path):
            raise FileNotFoundError(f"Secret file {self.secrets_path} not found")
        with open(self.secrets_path, "r") as f:
            return json.load(f)
        # TODO  Encrypted data validation

    def save_secrets(self):
        with open(self.secrets_path, "w") as f:
            json.dump(self.encdata, f, indent=2)

    def init_password(self):
        while True:
            plain_pwd = getpass.getpass("Enter a password: ")
            confirm_plain_pwd = getpass.getpass("Confirm your password: ")
            if plain_pwd != confirm_plain_pwd:
                print("The passwords doesn't match")
                continue
            break
        hint = input("Enter a hint to remember this password: ")
        pwd = self.hash(plain_pwd)
        with open(self.password_cache_file, "w") as f:
            f.write(pwd)
        return pwd, hint

    def get_verified_password(self, password_data):
        use_cache=True
        while True:
            pwd = self.get_password(password_data["hint"], use_cache=use_cache)
            ph = PasswordHasher()
            try:
                ph.verify(password_data["hash"], pwd)
                return pwd
            except argon2.exceptions.VerifyMismatchError:
                print("Wrong password")
                use_cache = False

    def get_password(self, hint, use_cache=True):
        if use_cache and os.path.isfile(self.password_cache_file):
            with open(self.password_cache_file, "r") as f:
                pwd = f.read()
        else:
            print(f"Password hint: {hint}")
            plain_pwd = getpass.getpass("Enter your password: ")
            pwd = self.hash(plain_pwd)
            with open(self.password_cache_file, "w") as f:
                f.write(pwd)
        return pwd

    def encrypt_data_with_password(self, data, pwd):
        if type(data) != str:
            raise Exception("Only strings secrets can be handled by this tool")
        ph_params = dict.copy(self.argon2_params)
        ph = PasswordHasher(
            hash_len=KEY_DERIVATION_HASH_LEN,
            type=ARGON2_KEYDERIV_TYPE,
            **ph_params)
        res = dict()
        key_deriv_hash = ph.hash(pwd)
        key_deriv = base64.b64decode(key_deriv_hash.split("$")[-1] + "===")
        res["salt"] = "$".join(key_deriv_hash.split("$")[:-1])
        jsondata = {
            "h": self.hash(data),
            "d": data,
            "r": random.randbytes(random.randrange(16, 64)).hex()
        }
        cipher = AES.new(key_deriv, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(        # type: ignore [no-redef]
            json.dumps(jsondata).encode()
        )
        res["nonce"] = base64.b85encode(cipher.nonce).decode() # type: ignore [no-redef]
        res["tag"] = base64.b85encode(tag).decode()
        res["ciphertext"] = base64.b85encode(ciphertext).decode()
        return res

    def encrypt_data(self, data, pwd):
        res = dict()
        res["__password__"] = self.encrypt_data_with_password(data, pwd)
        all_keys = [f"-r{key.rstrip().lstrip()}"
            for keyname, key in self.keys.items()
            if keyname != "__password__"]
        res["pubk"] = call_rage(data, "--encrypt", *all_keys)
        return res

    def encrypt_tree(self, data, pwd, secrets_owners):
        res = dict()
        for key, val in data.items():
            if type(val) != dict:
                if not self.is_owner(key, secrets_owners):
                    continue

                data_hash = None
                if key in self.old_enc_data:
                    data_hash = self.decrypt_data(
                        self.old_enc_data[key]["__password__"],
                        pwd,
                    )["h"]
                if data_hash:
                    if (key not in self.old_enc_data) or (data_hash != self.hash(val)):
                        res[key] = self.encrypt_data(val, pwd)
                    else:
                        res[key] = self.old_enc_data[key]
                else:
                    res[key] = self.encrypt_data(val, pwd)
            elif self.is_owner(key, secrets_owners):
                new_secrets_owners = {}
                if key in secrets_owners:
                    new_secrets_owners = secrets_owners[key]
                res[key] = self.encrypt_tree(val, pwd, new_secrets_owners)
        return res

    def decrypt_data(self, data, pwd):
        argon2_params = argon2.extract_parameters(data["salt"] + "$" + FAKE_KEYDERIV_HASH)
        salt = base64.b64decode(data["salt"].split("$")[-1] + "===")
        key_deriv = argon2.low_level.hash_secret_raw(
            pwd.encode(),
            salt,
            time_cost=argon2_params.time_cost,
            memory_cost=argon2_params.memory_cost,
            parallelism=argon2_params.parallelism,
            hash_len=KEY_DERIVATION_HASH_LEN,
            type=argon2_params.type,
        )
        cipher = AES.new(key_deriv, AES.MODE_GCM, base64.b85decode(data["nonce"]))
        dec_data = cipher.decrypt_and_verify(           # type: ignore [no-redef]
            base64.b85decode(data["ciphertext"]),
            base64.b85decode(data["tag"])
        )
        return json.loads(dec_data.decode())

    def decrypt_tree(self, data, pwd, secrets_owners):
        res = dict()
        for key, val in data.items():
            if type(data) != dict:
                raise Exception("Malformed data, expecting only dicts")

            if "__password__" in val.keys():
                if self.is_owner(key, secrets_owners=secrets_owners):
                    res[key] = self.decrypt_data(val["__password__"], pwd)["d"]
            elif self.is_owner(key, secrets_owners):
                if key not in secrets_owners:
                    res[key] = self.decrypt_tree(val, pwd, {})
                else:
                    res[key] = self.decrypt_tree(val, pwd, secrets_owners[key])
        return res

    def init_secrets(self):
        pwd, hint = self.init_password()
        ph = PasswordHasher(**self.argon2_params)
        self.encdata = dict.fromkeys(ENC_SECRETS_KEYS, {})
        self.encdata["settings"] = {
            "argon2_params": self.argon2_params,
        }
        self.encdata["keys"] = {
            "__password__": {
                "hash": ph.hash(pwd),
                "hint": hint,
            },
        }
        self.encdata["keys"].update(self.keys)
        self.encdata["secrets"] = self.encrypt_tree(
            dict(),
            pwd,
            self.secrets_owners,
        )

    def load(self):
        data = self.load_secrets()
        pwd = self.get_verified_password(
            data["keys"]["__password__"],
        )
        dec_dict = self.decrypt_tree(
            data["secrets"],
            pwd,
            self.secrets_owners,
        )
        with open(self.plaintext_file, "w") as f:
            json.dump(dec_dict, f, indent=2)

    def secure(self):
        with open(self.plaintext_file, "r") as f:
            plain = json.load(f)
        pwd = self.get_verified_password(self.encdata["keys"]["__password__"])
        new_enc_data = self.get_not_owned_data(dict.copy(self.encdata["secrets"]), self.secrets_owners)
        new_enc_data.update(self.encrypt_tree(
            plain,
            pwd,
            self.secrets_owners,
        ))
        self.encdata = {
            "secrets": new_enc_data,
            "keys": self.keys,
            "settings": {
                "argon2_params": self.argon2_params,
            },
        }
        self.save_secrets()

# IMPORTANT     As this Python script is meant to be used with the nix functions only
#   it's simplicity to use is irrelevant as a simple wrapper will be set on top of it.
#
#   This is why the arguments expected by this tool can be ridiculous and impractical
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        help="What action to perform with the secrets",
    )
    parser.add_argument(
        "--secrets-path", "-f",
        help="Path to the file where to store the secrets",
        default = "secrets.json",
    )
    parser.add_argument(
        "--secrets-owners", "-s",
        help="JSON data containing the owners of some secrets",
        default = {},
    )
    parser.add_argument(
        "--owner", "-o",
        help="Load / Save using this key ownership",
    )
    parser.add_argument(
        "--password-cache-file", "-c",
        help="Path to the file containing the password cache",
        default = ".pwd_cache",
    )
    parser.add_argument(
        "--add-pubk", "-k",
        help="Additionnal key to the format <name>:<key>",
        default=[],
        nargs="*",
    )
    parser.add_argument(
        "--pubk-dir", "-d",
        help="Directory where to search encryption keys from",
        default=[],
        nargs="*",
    )
    parser.add_argument(
        "--plaintext-file", "-p",
        help="Path where to store the (temporary) secrets in plaintext",
        default = ".plain_secrets.json",
    )
    parser.add_argument(
        "--argon2-time", "-at",
        help="Time cost parameter for the Argon2 key derivation function",
        type=int,
        default = 4,
    )
    parser.add_argument(
        "--argon2-memory", "-am",
        help="Memory cost parameter for the Argon2 key derivation function (in Ko)",
        type=int,
        default = 64,
    )
    parser.add_argument(
        "--argon2-parallelism", "-ap",
        help="Parallelism to allow for the Argon2 key derivation function",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--argon2-salt", "-as",
        help="Length of the salt for the Argon2 key derivation function",
        type=int,
        default=64,
    )

    args = parser.parse_args()
    if not args.command:
        parser.print_usage()
        sys.exit(1)
    if args.owner == "":
        args.owner = None
    return args

if __name__ == "__main__":
    SecretsManager(parse_args())
