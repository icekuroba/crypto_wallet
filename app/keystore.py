import os
import json
import base64
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidTag

# Constantes tomadas de crypto_utils
from crypto_utils import (
    generate_ed25519_keys, derive_aes_key, encrypt_data, decrypt_data, derive_address_btc_style,
    ARGON_TIME_COST, ARGON_MEM_COST_KIB, ARGON_PARALLELISM, ARGON_SALT_LEN_BYTES
)

#                                                 vv Any porque son varios tipos de datos
def create_keystore(passphrase: str) -> Dict[str, Any]:
    '''
    Crea un nuevo keystore, sin almacenarlo en disco
    - Crea un par de llaves Ed25519
    - Deriva la dirección "BTC-Style" a partir de la llave pública
    - Deriva la clave de cifrado AES con Argon2id, la passphrase y el salt definido en crpyto_utils
    - Cifra la clave privada con AES-256-GCM
    - Devuelve un diccionario del keystore
    '''
    # Toma los pasos de crypto_utils para hacer el diccionario
    private_key_bytes, public_key_bytes = generate_ed25519_keys()

    address = derive_address_btc_style(public_key_bytes)

    # La documentación de python (https://docs.python.org/3/library/random.html) dice que no debe usarse random()
    # para seguridad, urandom si es apto para criptografía (https://docs.python.org/3/library/os.html#os.urandom)
    salt = os.urandom(ARGON_SALT_LEN_BYTES)

    aes_key = derive_aes_key(passphrase, salt)

    ciphertext, nonce, tag = encrypt_data(private_key_bytes, aes_key)

    # Contrucción del diccionario para el Keystore
    keystore: Dict[str, Any]= {
        #Se podría poner variables en los strings para dinamismo, pero se desfinnieron así para no complicarnos
        "kdf": "Argon2id",
        "kdf_params": {
            "salt_b64":base64.b64encode(salt.decode("utf-8")),
            "t_cost":ARGON_TIME_COST,
            "m_cost":ARGON_MEM_COST_KIB,
            "parallelism":ARGON_PARALLELISM
            },
        "cipher": "AES-256-GCM",
        "cipher_params":{"nonce_b64": base64.b64encode(nonce).decode("utf-8")},
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "tag_b64": base64.b64encode(tag).decode("utf-8"),
        "pubkey_b64": base64.b64encode(public_key_bytes).decode("utf-8"),
        "created": os.path.getmtime,
        "scheme": "Ed25519",
        "address": address
    }

    return keystore

def save_keystore(keystore: Dict[str, Any], filepath: Path | str) -> None:
    '''
    Guarda el keystore en un archivo JSON en UTF-8
    '''
    path = Path(filepath)
    #Si el directorio no existe lo crea
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(keystore, indent=2), encoding='utf-8')

def load_keystore(filepath: Path | str) -> Dict[str, Any]:
    '''
    Carga un keysotre desde un JSON en UTF-8
    '''
    path = Path(filepath)
    keystore_json = path.read_text(encoding='utf-8')
    return json.loads(keystore_json)

#TODO: Descifrar el keystore