#-*-encoding:utf-8*-

import os
import sys
import json
import base64
import getpass
import hashlib
import argparse
import subprocess
from cmd import Cmd
from Crypto.Cipher import AES
from argon2 import PasswordHasher
from argon2.low_level import Type

AES_MODE = AES.MODE_GCM
ARGON2_SALT_LEN = 64
ARGON2_DEFAULT_PARAMS = {
    "time_cost": 32,
    "memory_cost": 65536,
    "parallelism": 16,
}
KEY_DERIVATION_HASH_LEN = 16
ARGON2_HASH_TYPE = Type.ID
PLAIN_DATA_PADDING_SIZE = 64

def get_pubk_id(key):
    return sha512hash(key)

def sha512hash(data):
    if type(data) == str:
        data = data.encode()
    return base_encode(hashlib.sha512(data).digest())

def pad(data, padding_char, nb):
    if len(data) % nb == 0:
        return data
    res =  data + (padding_char * (nb - (len(data) % nb)))
    assert (len(res) % nb) == 0
    return res

def get_keys(keystr):
    return [k for k in keystr.split(".") if k != ""]

def set_from_keys(data, keys, value):
    if len(keys) == 0:
        return

    for key in keys[:-1]:
        if key not in data:
            data[key] = dict()
        if type(data[key]) != dict:
            data[key] = dict()
        data = data[key]

    assert isinstance(data, dict)
    if keys[-1] not in data:
        data[keys[-1]] = dict()

    changed = False
    if keys[-1] not in data:
        changed = True
    elif data[keys[-1]] != value:
        changed = True
    data[keys[-1]] = value
    return changed

def get_from_keys(data, keys):
    if len(keys) == 0:
        return data

    for key in keys:
        if type(data) != dict:
            return None
        if key not in data:
            return None
        data = data[key]
    return data

def rm_from_keys(data, keys):
    assert type(data) == dict

    if len(keys) == 0:
        for key in data.keys():
            del data[key]

    for key in keys[:-1]:
        if key not in data:
            return
        if type(data[key]) != dict:
            return
        data = data[key]

    if keys[-1] in data:
        del data[keys[-1]]

def rage_encrypt(data, pubkeys):
    p = subprocess.Popen(
        ["rage", "--encrypt"] + ["-r" + k.strip() for k in pubkeys],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = p.communicate(input=data)
    if p.returncode > 0:
        err_msg = f"Rage command failed: {p.returncode}\n\n"
        err_msg += "Command called: `rage {}`\n\n".format(" ".join(args))
        err_msg += f"Error message:\n{stderr.decode()}\n"
        raise Exception(err_msg)
    return base64.b64encode(stdout).decode()

def base64_extract(data: str):
    return base64.b64decode(pad(data.encode(), b'=', 4))

def base_decode(data: str):
    return base64.b85decode(pad(data.encode(), b'=', 4))

def base_encode(data) -> str:
    if type(data) == str:
        data = data.encode()
    return base64.b85encode(data).decode()

def ask_confirm(msg):
    print(msg, end="")
    got = input(" y/N ")
    return got.lower() == "y"

def fusion_dict(data, new, parents = []):
    changed = []
    for key, val in new.items():
        if key not in data:
            data[key] = val
            changed.append(parents + [key])
        else:
            keyname = ".".join(parents + [key])
            if isinstance(data[key], dict):
                if isinstance(val, dict):
                    changed.extend(fusion_dict(data[key], val, parents=parents + [key]))
                elif ask_confirm(
                     f"Key {keyname} exist in original data, and is a dict, override with new data ?"):
                    data[key] = val
                    changed.append(parents + [key])
            else:
                if isinstance(val, dict):
                    if ask_confirm(f"Key {keyname} exist in original data, override with new data ?"):
                        data[key] = val
                        changed.append(parents + [key])
                else:
                    if (val != data[key]) and ask_confirm(f"Key {keyname} got a different value, override it ?"):
                        data[key] = val
                        changed.append(parents + [key])
    return changed

class SecretsREPL(Cmd):
    def __init__(self, plain):
        Cmd.__init__(self)
        self.changed = []
        self.data = plain
        self.base = []

    def display_dict(self, data):
        if data is None:
            print("Data not found")
        else:
            print(json.dumps(data, indent=2))

    # TODO  Add more commands
    #    ls: list keys
    #    cd ..: come back from 1 node
    #    generate: generate a secret
    #    editfile: edit a secret file using a given command
    def do_read(self, args):
        '''
        Usage: read <fname> <key> <type>
        Read a file into a secret
        Types of files supported: [plaintext, json, binary]
        '''
        args = args.split()
        if len(args) != 3:
            self.do_help("read")
            return
        fname = args[0]
        keys = get_keys(args[1])
        type = args[2]
        if type.lower() == "plaintext":
            with open(fname, "r") as f:
                changed = set_from_keys(self.data, self.base + keys, f.read().strip("\n"))
        elif type.lower() == "json":
            with open(fname, "r") as f:
                changed = set_from_keys(self.data, self.base + keys, json.load(f))
        elif type.lower() == "binary":
            with open(fname, "rb") as f:
                changed = set_from_keys(self.data, self.base + keys, base64.b64encode(f.read()).decode())
        else:
            print("Type not supported")
            self.do_help("read")
            return 

        if changed:
            self.changed.append(self.base + keys)

    def do_import(self, args):
        '''
        Usage: import <fname>
        Import a plaintext json  
        '''
        if len(args) != 1:
            self.do_help("import")
            return
        fname = args.split()[0]
        if not os.path.isfile(fname):
            print("Filename not found")
            return

        try:
            with open(fname, "r") as f:
                data = json.load(f)
        except Exception as err:
            print(f"Error while loading JSON data: {err}")
            return

        self.changed.extend(fusion_dict(self.data, data))

    def do_export(self, args):
        '''
        Usage: export <fname>
        Export the secrets as a plaintext json  
        '''
        args = args.split()
        if len(args) != 1:
            self.do_help("export")
            return
        if not ask_confirm("Are you sure you want to export the PLAINTEXT secrets as JSON format ?"):
            return
        fname = args[0]

        try:
            with open(fname, "w") as f:
                json.dump(self.data, f, indent=2)
        except Exception as err:
            print(f"Error while writing JSON data: {err}")
            return

    def do_EOF(self, args):
        return self.do_exit(args)

    def do_exit(self, args):
        print("")
        raise KeyboardInterrupt

    def do_cd(self, args):
        '''
        Usage: cd <key>
        Change the current base to the given key
        '''
        args = args.split()
        if len(args) == 0:
            self.base = []
        else:
            keys = [k for k in args[0].split(".") if k != ""]
            self.base.extend(keys)
        self.prompt = ".".join(self.base) + ">>> "

    def do_copy(self, args):
        '''
        Usage: copy <source> <destination>
        Copy a secret from a source to a destination
        '''
        args = args.split()
        if len(args) != 2:
            self.do_help("copy")
            return
        source = get_keys(args[0])
        destination = get_keys(args[1])
        if set_from_keys(
            self.data,
            self.base + destination,
            get_from_keys(self.data, self.base + source)
        ):
            self.changed.append(self.base + destination)

    def do_get(self, args):
        '''
        Usage: get <key>
        Display the data under the given key (relative to base)
        '''

        args = args.split()
        if len(args) == 0:
            self.display_dict(get_from_keys(self.data, self.base))
        else:
            keys = args[0].split(".")
            data = get_from_keys(self.data, self.base + keys)
            self.display_dict(data)
        
    def do_rm(self, args):
        '''
        Usage: rm <key>
        Deletes all data under the given key (relative to base)
        '''
        args = args.split()
        if len(args) < 1:
            self.do_help("rm")
            return

        keys = get_keys(args[0])
        data = rm_from_keys(self.data, self.base + keys)
        self.changed.append(self.base + keys)
        
    def do_set(self, args):
        '''
        Usage: set <key> <data>
        Set the given data as a secret for the given key (relative to base)
        '''
        args = args.split()
        if len(args) < 2:
            self.do_help("set")
            return

        val = " ".join(args[1:])
        keys = get_keys(args[0])
        if set_from_keys(self.data, self.base + keys, val):
            self.changed.append(self.base + keys)

class SecretsManager:
    def __init__(self, args):
        self.re_encrypt = args.re_encrypt
        self.enable_debug = args.debug
        self.debug(args)

        self.enc = self.load_secret_file(args)
        self.pubkeys = self.enc["keys"]
        for key in self.load_public_keys(args.pubk_dir):
            key_id = get_pubk_id(key)
            if key_id not in self.pubkeys:
                self.pubkeys[key_id] = key
        self.argon2_hasher = self.prepare_argon2_hasher()

        self.pwkd = self.get_pwd_deriv()
        self.plain = self.decrypt_data(self.enc["secrets"])

        if not self.re_encrypt:
            self.start_repl()

        self.encrypt_data()
        self.store_encrypted_data(args.secrets)

    def debug(self, fmt, *args):
        if self.enable_debug:
            if len(args) >= 1:
                print("DBG", fmt.format(*args))
            else:
                print("DBG", fmt)

    def warn(self, fmt, *args):
        if len(args) >= 1:
            print("WARN", fmt.format(*args))
        else:
            print("WARN", fmt)

    def error(self, msg, fail=True):
        print("ERROR", msg)
        if fail:
            sys.exit(1)

    def load_public_keys(self, dirs):
        pubkeys = []
        for d in dirs:
            for (root, subdir, files) in os.walk(d):
                for pubk in files:
                    if pubk.endswith(".pub"):
                        with open(os.path.join(root, pubk), "r") as f:
                            pubkeys.append(f.read().strip())
        self.debug("Found {} public keys", len(pubkeys))
        return pubkeys

    def load_secret_file(self, args):
        data = {
            "secrets": {},
            "keys": {},
            "aes": {},
            "argon2": {
                "time": args.argon2_time,
                "memory": args.argon2_memory,
                "parallelism": args.argon2_parallelism,
            },
        }
        if os.path.isfile(args.secrets):
            with open(args.secrets, "r") as f:
                data.update(json.load(f))
        return data

    def prepare_argon2_hasher(self, t, m, p):
        # We want type ID, which is default.
        return PasswordHasher(
            time_cost=self.enc["argon2"]["time"],
            memory_cost=self.enc["argon2"]["memory"],
            parallelism=self.enc["argon2"]["parallelism"],
            hash_len=KEY_DERIVATION_HASH_LEN,
            salt_len=ARGON2_SALT_LEN,
            type=ARGON2_HASH_TYPE,
        )

    def get_pwd_deriv(self):
        if "hash" in self.enc["aes"].keys():
            hint = self.enc["aes"]["hint"]
            print(f"Password hint {hint}")
            pwd_hash = None
            while pwd_hash != self.enc["aes"]["hash"]:
                pwd_plain = getpass.getpass("Enter your password: ")
                pwd_hash = sha512hash(pwd_plain)
            salt = base64_extract(self.enc["aes"]["pwkd_salt"])
            pwkd = self.argon2_hasher.hash(pwd_plain, salt=salt)
        else:
            while True:
                pwd_plain = getpass.getpass("Enter your new password: ")
                confirm_pwd_plain = getpass.getpass("Confirm your password: ")
                if pwd_plain == confirm_pwd_plain:
                    break
                print("Passwords doesn't match")
            hint = input("Enter a hint to remember this password: ")
            pwd_hash = sha512hash(pwd_plain)

            pwkd = self.argon2_hasher.hash(pwd_plain)
            pwkd_salt = pwkd.split("$")[-2]
            self.enc["aes"] = {
                "hash": pwd_hash,
                "hint": hint,
                "pwkd_salt": pwkd_salt,
            }

        return base64_extract(pwkd.split("$")[-1])

    def decrypt_data(self, branch):
        assert isinstance(branch, dict)
        if "__aes__" in branch:
            enc = branch["__aes__"]
            key_deriv = self.argon2_hasher.hash(self.pwkd, salt=base64_extract(enc["salt"]))
            aes_key = base64_extract(key_deriv.split("$")[-1])
            aes_key_hash = sha512hash(key_deriv.split("$")[-1])
            if aes_key_hash != enc["pwkd_hash"]:
                self.error(f"AES key doesn't match", fail=False)
                return None
            
            cipher = AES.new(aes_key, AES_MODE, nonce=base_decode(enc["nonce"]))
            plain = cipher.decrypt_and_verify(
                base_decode(enc["data"]),
                base_decode(enc["tag"])
            )
            return self.unwrap_plain_data(plain)

        data = {}
        for key, val in branch.items():
            if type(val) != dict:
                self.warn(f"Got non-dict branch {key} in data")
                continue
            res = self.decrypt_data(val)
            if res is not None:
                data[key] = res
        return data

    def encrypt_tree(self, data):
        result = {}
        for key, val in data.items():
            if isinstance(val, dict):
                    result[key] = self.encrypt_tree(val)
            else:
                aesd, raged = self.encrypt_leaf(val)
                result[key] = {
                    "__aes__": aesd,
                    "__rage__": raged,
                }
        return result

    def encrypt_leaf(self, plain_data):
        assert plain_data != dict
        data = {}
        key_deriv = self.argon2_hasher.hash(self.pwkd)
        aes_key = base64_extract(key_deriv.split("$")[-1])
        aes_key_hash = sha512hash(key_deriv.split("$")[-1])
        pwkd_salt = key_deriv.split("$")[-2]

        cipher = AES.new(aes_key, AES_MODE)
        ciphertext, tag = cipher.encrypt_and_digest(self.wrap_plain_data(plain_data))
        aes_data = {
            "salt": pwkd_salt,
            "pwkd_hash": aes_key_hash,
            "data": base_encode(ciphertext),
            "nonce": base_encode(cipher.nonce),
            "tag": base_encode(tag),
        }
        rage_data = rage_encrypt(plain_data.encode(), self.pubkeys.values())
        return aes_data, rage_data
    
    def encrypt_data(self):
        if self.re_encrypt:
            set_from_keys(self.enc, ["secrets"], self.encrypt_tree(self.plain))
            self.enc["argon2"] = self.argon2_opts
            return
        
        for changed in self.key_changed:
            plain_data = get_from_keys(self.plain, changed)
            if plain_data is None:
                rm_from_keys(self.enc["secrets"], changed)
            elif isinstance(plain_data, dict):
                tree = self.encrypt_tree(plain_data)
                set_from_keys(self.enc["secrets"], changed, tree)
            else:
                aesd, raged = self.encrypt_leaf(plain_data)
                set_from_keys(self.enc["secrets"], changed, {
                    "__aes__": aesd,
                    "__rage__": raged,
                })

    def store_encrypted_data(self, fname):
        with open(fname, "w") as f:
            json.dump(self.enc, f, indent=2)

    def start_repl(self):
        repl = SecretsREPL(self.plain)
        repl.prompt = ">>> "
        try:
            repl.cmdloop("Use the commands in the REPL to set the secrets")
        except KeyboardInterrupt:
            print("Done")
        self.plain = repl.data
        self.key_changed = repl.changed
        self.debug("Changed: {}", self.key_changed)

    def wrap_plain_data(self, data, length=8):
        assert len(data) < 2**(8*length)
        buffer = int(len(data)).to_bytes(length=length, byteorder="big", signed=False)
        buffer += data.encode()
        buffer = pad(buffer, b'=', PLAIN_DATA_PADDING_SIZE)
        return buffer

    def unwrap_plain_data(self, buffer, length=8):
        self.debug(buffer)
        datalen = int.from_bytes(bytes=buffer[0:length], byteorder="big", signed=False)
        self.debug("datalen {}", datalen)
        return buffer[length:length+datalen].decode()

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--secrets", "-f",
        help="Path to the file where to store the secrets",
        required = True,
    )
    parser.add_argument(
        "--pubk-dir", "-d",
        help="Directory where to search encryption keys from, expects a \".pub\" file extension",
        default=[],
        nargs="*",
    )
    parser.add_argument(
        "--argon2-time", "-t",
        help="Time cost parameter for the Argon2 key derivation function",
        type=int,
        default = ARGON2_DEFAULT_PARAMS["time_cost"],
    )
    parser.add_argument(
        "--argon2-memory", "-m",
        help="Memory cost parameter for the Argon2 key derivation function (in Ko)",
        type=int,
        default = ARGON2_DEFAULT_PARAMS["memory_cost"],
    )
    parser.add_argument(
        "--argon2-parallelism", "-p",
        help="Parallelism to allow for the Argon2 key derivation function",
        type=int,
        default=ARGON2_DEFAULT_PARAMS["parallelism"],
    )
    parser.add_argument("--debug", action='store_true')
    parser.add_argument("--re-encrypt", action='store_true')

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    SecretsManager(parse_args())
