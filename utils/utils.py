import os
import jwt
import re
import json
import struct
import base64
import subprocess
import requests
import binascii
from roadtools.roadlib.deviceauth import DeviceAuthentication
from roadtools.roadlib.auth import Authentication
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MFA_NEEDLE = "use multi-factor authentication to access"

def get_nonce():
    response = requests.post(
        url=f"https://login.microsoftonline.com/645064ee-9b6e-43db-9d46-fe81a65cfdea/oauth2/token",
        data='grant_type=srv_challenge'
        )
    return response.json()['Nonce']

def get_tenantid(domain):
    res = requests.get(f'https://login.microsoftonline.com/{domain}/.well-known/openid-configuration')
    token_endpoint = res.json()['token_endpoint']
    return token_endpoint.split('/')[3]

def get_devicetoken(tenant, certpfx):
    nonce = get_nonce()
    tid = get_tenantid(tenant)

    certpath = f'device_cert.pem'
    keypath = f'device_key.pem'
    extract_pfx(certpfx, certpath, keypath)

    with open(certpath, "rb") as certf:
        certificate = x509.load_pem_x509_certificate(certf.read())
    with open(keypath, "rb") as keyf:
        keydata = keyf.read()
    
    os.remove(certpath)
    os.remove(keypath)

    certder = certificate.public_bytes(serialization.Encoding.DER)
    certbytes = base64.b64encode(certder)

    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "x5c": certbytes.decode('utf-8'),
    }        
    payload = {
        "resource": "https://enrollment.manage.microsoft.com/",
        "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",
        "request_nonce": nonce,
        "win_ver": "10.0.19041.1806",
        "grant_type": "device_token",
        "scope":"sid",
        "redirect_uri": "ms-aadj-redir://auth/mdm",
        "iss": "aad:brokerplugin"
    }

    reqjwt = jwt.encode(payload, algorithm='RS256', key=keydata, headers=headers)  

    res = requests.post(
        url=f'https://login.microsoftonline.com/{tid}/oauth2/token',
        data=f'windows_api_version=2.2&grant_type=urn%3aietf%3aparams%3aoauth%3agrant-type%3ajwt-bearer&request={reqjwt}'
        )
    return res.json()['access_token']

def gettokens(username, password, clientid, resource, proxy):
    auth = Authentication(username, password, None, clientid)
    auth.proxies = proxy
    auth.resource_uri = resource
    response = auth.authenticate_username_password()
    return response['accessToken'], response['refreshToken']

def deviceauth(username, password, refresh_token, certpfx, proxy):
    device_auth = DeviceAuthentication()
    device_auth.proxies = proxy
    device_auth.verify = False
    auth = Authentication()
    auth.proxies = proxy
    auth.verify = False
    device_auth.auth = auth

    device_auth.loadcert(None, None, certpfx, 'password')
    
    if password:
        response = device_auth.get_prt_with_password(username, password)
    else:        
        response = device_auth.get_prt_with_refresh_token(refresh_token)

    return response['refresh_token'], response['session_key']

def _load_roadtools_auth(path):
    try:
        if not os.path.isfile(path):
            print("File does not exist: {}".format(path))
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        access_token = (
            data.get("access_token") or data.get("accessToken") or data.get("AccessToken")
        )
        refresh_token = (
            data.get("refresh_token") or data.get("refreshToken") or data.get("RefreshToken")
        )
        if access_token and refresh_token:
            print("Loaded access/refresh tokens from .roadtools_auth.")
            return access_token, refresh_token
        print("Could not find both access and refresh tokens in the provided file.")
        return None
    except Exception as e:
        print("Failed to read/parse .roadtools_auth: {}".format(e))
        return None


def _load_roadtx_prt(path="roadtx.prt"):
    """
    Read refresh_token (PRT) and session_key from a roadtx.prt JSON file.
    Returns (prt_str, session_key_hex) or None on failure.
    """
    try:
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        prt = data.get("refresh_token") or data.get("refreshToken")
        session_key = data.get("session_key") or data.get("sessionKey")
        if prt and session_key:
            print("Loaded PRT and session_key from {}.".format(path))
            return prt, session_key
        return None
    except Exception as e:
        print("Failed to read/parse {}: {}".format(path, e))
        return None


def _prompt_and_load_auth():
    """
    Prompt the user for a .roadtools_auth path until success or empty input.
    Returns (access_token, refresh_token) or None.
    """
    while True:
        path = input("Enter the path to the generated .roadtools_auth file (or press Enter to cancel): ").strip()
        if not path:
            return None
        tokens = _load_roadtools_auth(path)
        if tokens:
            return tokens
        print("Could not load tokens from that path. Please try again.\n")


def _call_broker(device_auth, client_id, resource, redirect_uri):
    """
    Wrap the aad_brokerplugin_prt_auth call and normalize results.
    Returns:
      - ("ok", (access_token, refresh_token))
      - ("mfa", "error text")
      - ("err", "error text")
    """
    try:
        res = device_auth.aad_brokerplugin_prt_auth(
            client_id=client_id,
            resource=resource,
            redirect_uri=redirect_uri,
        )
    except Exception as e:
        err_desc = str(e) if e else ""
        if MFA_NEEDLE in err_desc.lower():
            return "mfa", err_desc
        return "err", err_desc

    # dict error shape
    if isinstance(res, dict) and res.get("error"):
        err_desc = res.get("error_description") or res.get("error") or ""
        if MFA_NEEDLE in err_desc.lower():
            return "mfa", err_desc
        return "err", err_desc

    # happy path
    if isinstance(res, dict):
        return "ok", (res.get("access_token"), res.get("refresh_token"))

    # unexpected
    return "err", "Unexpected response: {!r}".format(res)


def prtauth(prt, session_key, client_id, resource, redirect_uri, proxy):
    print("Running prtauth with client_id={}, resource={}, redirect_uri={}".format(client_id, resource, redirect_uri))

    device_auth = DeviceAuthentication()
    device_auth.proxies = proxy
    device_auth.verify = False

    auth = Authentication()
    auth.proxies = proxy
    auth.verify = False
    device_auth.auth = auth

    # Helper to set creds on device_auth from prt + session_key(hex)
    def _set_creds(prt_val, sess_hex):
        device_auth.prt = prt_val
        try:
            device_auth.session_key = binascii.unhexlify(sess_hex)
            return True
        except Exception as e:
            print("Failed to parse session_key as hex: {}".format(e))
            return False

    # 1) Try the provided prt/session_key
    if not _set_creds(prt, session_key):
        # If given session_key was bad, try roadtx.prt immediately
        fallback = _load_roadtx_prt()
        if fallback and _set_creds(fallback[0], fallback[1]):
            status, payload = _call_broker(device_auth, client_id, resource, redirect_uri)
        else:
            status, payload = "err", "Invalid session_key and no valid roadtx.prt"
    else:
        status, payload = _call_broker(device_auth, client_id, resource, redirect_uri)

    # 2) If failed (any error), try reading ./roadtx.prt and retry once
    if status in ("err", "mfa"):
        if status == "err":
            print("aad_brokerplugin_prt_auth failed: {}".format(payload))
        else:
            # We'll still try the fallback first; MFA may be satisfied if prt/session_key in roadtx.prt is enriched
            print("MFA indicated or failure. Trying fallback from ./roadtx.prt before prompting...")

        fallback = _load_roadtx_prt()
        if fallback:
            if _set_creds(fallback[0], fallback[1]):
                status2, payload2 = _call_broker(device_auth, client_id, resource, redirect_uri)
                if status2 == "ok":
                    return payload2  # (access_token, refresh_token)
                status, payload = status2, payload2  # keep most recent error/MFA
        # else: no roadtx.prt present; proceed to MFA prompt / error handling

    # 3) If still MFA, instruct user and prompt for .roadtools_auth path
    if status == "mfa":
        print("\nMFA required for this flow. Do the following with roadtx:\n")
        print("  1) roadtx prt")
        print("  2) roadtx prtenrich")
        print("  3) roadtx prtauth")
        print("     (use the same resource/client_id/redirect_uri as shown below)")
        print("     resource: {}".format(resource))
        print("     client_id: {}".format(client_id))
        print("     redirect_uri: {}\n".format(redirect_uri))

        tokens = _prompt_and_load_auth()
        return tokens  # may be None

    # 4) Non-MFA error -> give user the option to provide .roadtools_auth as a fallback
    if status == "err":
        print(payload or "Unknown error from aad_brokerplugin_prt_auth.")
        print("You can provide a .roadtools_auth file to continue.")
        tokens = _prompt_and_load_auth()
        return tokens  # may be None

    # 5) Success
    if status == "ok":
        return payload  # (access_token, refresh_token)

    # Safety
    print("Unexpected state: {}".format(status))
    return None

def renew_token(refresh_token, client_id, scope, proxy):
    data = {
        'client_id':client_id,
        'grant_type':'refresh_token',
        'refresh_token':refresh_token,
        'scope':scope
    }
    
    response = requests.post(
        "https://login.microsoftonline.com/common/oAuth2/v2.0/token",
        data=data,
        proxies=proxy,
        verify=False
    )
    json = response.json()
    return json['access_token'], json['refresh_token']

def token_renewal_for_enrollment(url, access_token, proxy):
    headers = {'Authorization': 'Bearer {}'.format(access_token)}

    response = requests.get(
        url=f"{url}?api-version=1.0",
        headers=headers,
        proxies=proxy,
        verify=False
    )

    return response.json()['Result']['Token']

def create_pfx(certpath, keypath, pfxpath):
    with open(certpath, 'rb') as public_key_file:
        cert_bytes = public_key_file.read()
    
    with open(keypath, 'rb') as private_key_file:
        key_bytes = private_key_file.read()
    
    certificate = load_pem_x509_certificate(cert_bytes, default_backend())
    private_key = serialization.load_pem_private_key(key_bytes, None, default_backend())

    pfx = serialization.pkcs12.serialize_key_and_certificates(
        pfxpath.encode('utf-8'),
        private_key,
        certificate,
        None,
        serialization.BestAvailableEncryption(b'password')
        )

    with open(pfxpath, 'wb') as outfile:
        outfile.write(pfx)

    return

def extract_pfx(pfxpath, certpath, keypath):
    subprocess.run(f'openssl pkcs12 -in {pfxpath} -nodes -password pass:password -out {certpath} -clcerts', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)    
    subprocess.run(f'openssl pkcs12 -in {pfxpath} -nodes -password pass:password -out {keypath} -nocerts -nodes', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return

def get_str_and_next(blob, start):
    str_size = (struct.unpack('<I', blob[start:start+0x4])[0]) * 2
    str = blob[start+0xc:start+0xc+str_size].decode('utf-16le')

    next = start+0xc+len(str)*2
    if next % 4 != 0:
        next +=+2

    return str, next

def save_encrypted_message_as_smime(encrypted_message, filename):
    
    smime_header = (
        "MIME-Version: 1.0\n"
        f'Content-Disposition: attachment; filename="{filename}"\n'
        f'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="{filename}"\n'
        "Content-Transfer-Encoding: base64\n\n"
    )

    wrapped_string = '\n'.join([encrypted_message[i:i+64] for i in range(0, len(encrypted_message), 64)])
    smime_message = smime_header + wrapped_string

    with open(filename, "w") as f:
        f.write(smime_message)

def decrypt_smime_file(filename, keypath):
    result = subprocess.run(f'cat {filename} | openssl cms -decrypt -inkey {keypath}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8')

def aes_decrypt(key, iv, content):    
    cipher = Cipher(algorithms.AES(base64.b64decode(key)), modes.CBC(base64.b64decode(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(content) + decryptor.finalize()
    return decrypted_data