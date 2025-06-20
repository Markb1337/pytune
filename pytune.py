import os
import json
import jwt
import getpass
import argparse
from colr import color
from device.device import Device
from device.android import Android
from device.windows import Windows
from device.linux import Linux
from device.macos import MacOS
from device.ios import IOS
from utils.utils import deviceauth, prtauth, create_pfx
from utils.logger import Logger

version = '1.2'
banner = r'''
 ______   __  __     ______   __  __     __   __     ______    
/\  == \ /\ \_\ \   /\__  _\ /\ \/\ \   /\ "-.\ \   /\  ___\   
\ \  _-/ \ \____ \  \/_/\ \/ \ \ \_\ \  \ \ \-.  \  \ \  __\   
 \ \_\    \/\_____\    \ \_\  \ \_____\  \ \_\\"\_\  \ \_____\ 
  \/_/     \/_____/     \/_/   \/_____/   \/_/ \/_/   \/_____/ 
                                                               
''' + \
    f'      Faking a device to Microsft Intune (version:{version})'


class Pytune:
    def __init__(self, logger):
        self.logger = logger
        return

    def get_password(self, password):
        if password is None:
            password = getpass.getpass("Enter your password: ")
        return password

    def new_device(self, operatingsystem, device_name, username, password, refresh_token, certpfx, proxy):
        prt = None
        session_key = None
        tenant = None
        deviceid = None
        uid = None

        if certpfx:
            prt_file_candidates = [
                "roadtx.prt",
                os.path.join(os.path.expanduser("~"), ".roadtools", "roadtx.prt"),
            ]
            for roadtx_file in prt_file_candidates:
                if not os.path.exists(roadtx_file):
                    continue
                try:
                    with open(roadtx_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    prt = data.get("refresh_token")
                    session_key = data.get("session_key")
                    if prt and session_key:
                        self.logger.info(
                            f"Using existing PRT and session key from {roadtx_file}"
                        )
                        break
                except Exception as e:
                    self.logger.warning(f"Failed to load {roadtx_file}: {e}")

            if prt is None or session_key is None:
                if refresh_token is None:
                    password = self.get_password(password)
                prt, session_key = deviceauth(
                    username, password, refresh_token, certpfx, proxy, self.logger
                )

            access_token, refresh_token = prtauth(prt, session_key, '29d9ed98-a469-4536-ade2-f981bc1d605e', 'https://enrollment.manage.microsoft.com/', 'ms-appx-web://Microsoft.AAD.BrokerPlugin/DRS', proxy, self.logger)
            claims = jwt.decode(access_token, options={"verify_signature": False}, algorithms=['RS256'])
            tenant = claims['upn'].split('@')[1]
            deviceid = claims['deviceid']
            uid = claims['oid']

        if operatingsystem == 'Android':
            device = Android(self.logger, operatingsystem, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        elif operatingsystem == 'Windows':
            device = Windows(self.logger, operatingsystem, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        elif operatingsystem == 'Linux':
            device = Linux(self.logger, operatingsystem, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        elif operatingsystem == 'macOS':
            device = MacOS(self.logger, operatingsystem, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        elif operatingsystem == 'iOS':
            device = IOS(self.logger, operatingsystem, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        return device

    def entra_join(self, username, password, access_token, device_name, operatingsystem, deviceticket, proxy):
        device = self.new_device(operatingsystem, device_name, None, None, None, None, proxy)
        if access_token is None:
            password = self.get_password(password)

        device.entra_join(username, password, access_token, deviceticket)
        return

    def entra_delete(self, certpfx, proxy):
        device = Device(self.logger, None, None, None, None, None, None, None, proxy)
        device.entra_delete(certpfx)
        return

    def enroll_intune(self, operatingsystem, device_name, username, password, refresh_token, certpfx, proxy):
        device = self.new_device(operatingsystem, device_name, username, password, refresh_token, certpfx, proxy)
        device.enroll_intune()

    def checkin(self, operatingsystem, device_name, username, password, refresh_token, certpfx, mdmpfx, hwhash, proxy):
        device = self.new_device(operatingsystem, device_name, username, password, refresh_token, certpfx, proxy)
        device.hwhash = hwhash
        device.checkin(mdmpfx)
        return

    def retire_intune(self, operatingsystem, username, password, refresh_token, certpfx, proxy):
        device = self.new_device(operatingsystem, None, username, password, refresh_token, certpfx, proxy)
        device.retire_intune()
        return

    def check_compliant(self, operatingsystem, username, password, refresh_token, certpfx, proxy):
        device = self.new_device(operatingsystem, None, username, password, refresh_token, certpfx, proxy)
        device.check_compliant()
        return

    def download_apps(self, device_name, mdmpfx, proxy):
        device = self.new_device('Windows', device_name, None, None, None, None, proxy)
        device.download_apps(mdmpfx)

    def download_remediation_scripts(self, device_name, mdmpfx, proxy):
        device = self.new_device('Windows', device_name, None, None, None, None, proxy)
        device.download_remediation_scripts(mdmpfx)

    def pem2pfx(self, certpem, keypem, pfxpath):
        create_pfx(certpem, keypem, pfxpath)
        self.logger.success(f"successfully created {pfxpath}")
        self.logger.info("password is 'password'")

    def list_policies(self, operatingsystem, username, password, refresh_token, certpfx, proxy):
        device = self.new_device(operatingsystem, None, username, password, refresh_token, certpfx, proxy)
        device.list_policies()

    def list_groups(self, operatingsystem, username, password, refresh_token, certpfx, proxy):
        device = self.new_device(operatingsystem, None, username, password, refresh_token, certpfx, proxy)
        device.list_device_groups()


def main():
    description = f"{banner}"
    parser = argparse.ArgumentParser(add_help=True, description=color(description, fore='deepskyblue'), formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-x', '--proxy', action='store', help='proxy to be used during authentication (format: http://proxyip:port)')
    subparsers = parser.add_subparsers(dest='command', description='pytune commands')

    entra_join_parser = subparsers.add_parser('entra_join', help='join device to Entra ID')
    entra_join_parser.add_argument('-u', '--username', action='store', help='username')
    entra_join_parser.add_argument('-p', '--password', action='store', help='password')
    entra_join_parser.add_argument('-a', '--access_token', action='store', help='access token for device registration service')
    entra_join_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')
    entra_join_parser.add_argument('-o', '--os', required=True, action='store', help='os')
    entra_join_parser.add_argument('-D', '--deviceticket', required=False, action='store', help='device ticket')

    entra_delete_parser = subparsers.add_parser('entra_delete', help='delete device from Entra ID')
    entra_delete_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')

    enroll_intune_parser = subparsers.add_parser('enroll_intune', help='enroll device to Intune')
    enroll_intune_parser.add_argument('-u', '--username', action='store', help='username')
    enroll_intune_parser.add_argument('-p', '--password', action='store', help='password')
    enroll_intune_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    enroll_intune_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    enroll_intune_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')
    enroll_intune_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    checkin_parser = subparsers.add_parser('checkin', help='checkin to Intune')
    checkin_parser.add_argument('-u', '--username', action='store', help='username')
    checkin_parser.add_argument('-p', '--password', action='store', help='password')
    checkin_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    checkin_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    checkin_parser.add_argument('-m', '--mdmpfx', required=True, action='store', help='mdm pfx path')
    checkin_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')
    checkin_parser.add_argument('-o', '--os', required=True, action='store', help='os')
    checkin_parser.add_argument('-H', '--hwhash', required=False, action='store', help='Autopilot hardware hash')

    retire_intune_parser = subparsers.add_parser('retire_intune', help='retire device from Intune')
    retire_intune_parser.add_argument('-u', '--username', action='store', help='username')
    retire_intune_parser.add_argument('-p', '--password', action='store', help='password')
    retire_intune_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    retire_intune_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    retire_intune_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    check_compliant_parser = subparsers.add_parser('check_compliant', help='check compliant status')
    check_compliant_parser.add_argument('-u', '--username', action='store', help='username')
    check_compliant_parser.add_argument('-p', '--password', action='store', help='password')
    check_compliant_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    check_compliant_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    check_compliant_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    download_apps_intune_parser = subparsers.add_parser('download_apps', help='download available win32apps and scripts (only Windows supported since I\'m lazy)')
    download_apps_intune_parser.add_argument('-m', '--mdmpfx', required=True, action='store', help='mdm pfx path')
    download_apps_intune_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')

    download_remediations_intune_parser = subparsers.add_parser('get_remediations', help='download available remediation scripts (only Windows supported since I\'m lazy)')
    download_remediations_intune_parser.add_argument('-m', '--mdmpfx', required=True, action='store', help='mdm pfx path')
    download_remediations_intune_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')

    list_policies_parser = subparsers.add_parser('list_policies', help='enumerate Intune policies')
    list_policies_parser.add_argument('-u', '--username', action='store', help='username')
    list_policies_parser.add_argument('-p', '--password', action='store', help='password')
    list_policies_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    list_policies_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    list_policies_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    list_groups_parser = subparsers.add_parser('list_groups', help='enumerate device groups')
    list_groups_parser.add_argument('-u', '--username', action='store', help='username')
    list_groups_parser.add_argument('-p', '--password', action='store', help='password')
    list_groups_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    list_groups_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    list_groups_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    pem2pfx_parser = subparsers.add_parser('pem2pfx', help='convert pem and key to pfx')
    pem2pfx_parser.add_argument('-c', '--certpem', required=True, action='store', help='certificate pem file')
    pem2pfx_parser.add_argument('-k', '--keypem', required=True, action='store', help='private key file')
    pem2pfx_parser.add_argument('-o', '--output', required=True, action='store', help='output pfx path')

    args = parser.parse_args()
    proxy = None
    if args.proxy:
        proxy = {
            'https': args.proxy,
            'http': args.proxy
        }

    logger = Logger()
    pytune = Pytune(logger)

    if args.command == 'entra_join':
        pytune.entra_join(args.username, args.password, args.access_token, args.device_name, args.os, args.deviceticket, proxy)
    if args.command == 'entra_delete':
        pytune.entra_delete(args.certpfx, proxy)
    if args.command == 'enroll_intune':
        pytune.enroll_intune(args.os, args.device_name, args.username, args.password, args.refresh_token, args.certpfx, proxy)
    if args.command == 'checkin':
        pytune.checkin(args.os, args.device_name, args.username, args.password, args.refresh_token, args.certpfx, args.mdmpfx, args.hwhash, proxy)
    if args.command == 'retire_intune':
        pytune.retire_intune(args.os, args.username, args.password, args.refresh_token, args.certpfx, proxy)
    if args.command == 'check_compliant':
        pytune.check_compliant(args.os, args.username, args.password, args.refresh_token, args.certpfx, proxy)
    if args.command == 'download_apps':
        pytune.download_apps(args.device_name, args.mdmpfx, proxy)
    if args.command == 'get_remediations':
        pytune.download_remediation_scripts(args.device_name, args.mdmpfx, proxy)
    if args.command == 'pem2pfx':
        pytune.pem2pfx(args.certpem, args.keypem, args.output)
    if args.command == 'list_policies':
        pytune.list_policies(args.os, args.username, args.password, args.refresh_token, args.certpfx, proxy)
    if args.command == 'list_groups':
        pytune.list_groups(args.os, args.username, args.password, args.refresh_token, args.certpfx, proxy)

if __name__ == "__main__":
    main()
