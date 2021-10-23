#!/usr/bin/env python3
# ursecret.py -*-python-*-
# Copyright 2021 by Rik Faith (rikfaith@users.noreply.github.com)
# This program comes with ABSOLUTELY NO WARRANTY.

import os
import pwd
import re
import select
import socket
import subprocess
import sys
import time

# Imports that might have to be installed
try:
    import paramiko
except ImportError as e:
    print('''\
# Cannot load paramiko: {}
# Consider: apt-get install python3-paramiko'''.format(e))
    raise SystemExit from e


class UrSecret():
    # pylint: disable=dangerous-default-value
    def __init__(self, remote, local,
                 users=None,
                 ports=None,
                 debug=False, timeout=5):
        self.remote = remote
        self.local = local

        if users is None:
            users = ['root', 'pi']
        self.users = [pwd.getpwuid(os.getuid()).pw_name] + users

        if ports is None:
            self.ports = [22, 222, 993]
        else:
            self.ports = ports

        self.debug = debug
        self.timeout = timeout
        self.helper = 'ursecret-helper.py'

        self.client = None
        self.pubkey = None
        self.privkey = None
        self.user, self.port = self.find_user_port()
        if self.user is None or self.port is None:
            print('F: Cannot determine user:port for ssh access to '
                  f'{self.remote}')
            sys.exit(1)

        self.key_type = self.find_key_type()
        if self.key_type is None:
            print(f'F: Cannot determine supported key type on {self.remote}')
            sys.exit(1)

    @staticmethod
    def fatal(message):
        print(f'F: {message}')
        sys.exit(1)

    def _connect(self, user, port):
        self.client = paramiko.client.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(
            paramiko.client.AutoAddPolicy())

        prefix = 'Cannot ssh to {}@{}:{}: '.format(user, self.remote, port)
        try:
            self.client.connect(self.remote, username=user, port=port,
                                timeout=self.timeout)
        except paramiko.ssh_exception.PasswordRequiredException as exception:
            return prefix + 'Invalid username, or password required'
        except Exception as exception:
            return prefix + str(exception)

        self.user = user
        self.port = port
        return None

    def _connect_using_privkey(self):
        client = paramiko.client.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())

        prefix = 'Cannot ssh to {}@{}:{}: '.format(self.user, self.remote,
                                                   self.port)
        try:
            client.connect(self.remote, username=self.user, port=self.port,
                           key_filename=self.privkey, look_for_keys=False,
                           allow_agent=False, timeout=self.timeout)
        except paramiko.ssh_exception.PasswordRequiredException as exception:
            self.fatal(prefix + 'Invalid username, or password required')
        except Exception as exception:
            self.fatal(prefix + str(exception))

        return client

    def find_user_port(self):
        if self.client is not None:
            return self.user, self.port

        for user in self.users:
            for port in self.ports:
                result = self._connect(user, port)
                if result is None:
                    print('I: Using {}@{}:{}'.format(user, self.remote, port))
                    return user, port
                if self.debug:
                    print('D:', result)
        return None, None

    @staticmethod
    def _linesplit(channel, timeout=None, ending=None):
        channel.setblocking(0)
        start = time.time()
        buffer = ''
        while not channel.exit_status_ready():
            rlist, _, _ = select.select([channel], [], [], 1.0)
            if len(rlist) == 0:
                if timeout and time.time() - start > timeout:
                    break
                if ending and buffer.endswith(ending):
                    break
                continue
            if len(rlist) > 0:
                try:
                    buffer += channel.recv(4096).decode('utf-8')
                except socket.timeout:
                    time.sleep(.1)
            while '\n' in buffer or '\r' in buffer:
                try:
                    line, buffer = re.split('[\r\n]+', buffer, 1)
                except ValueError:
                    yield re.sub(r'[\n\r]*', '', buffer)
                    buffer = ''
                    break
                yield line
        try:
            buffer += channel.recv_stderr(4096).decode('utf-8')
        except socket.timeout:
            time.sleep(.1)
        if len(buffer) > 0:
            yield buffer

    def find_key_type(self):
        channel = self.client.get_transport().open_session()
        channel.exec_command('ssh -Q key')

        key_type = 'rsa'
        for line in self._linesplit(channel, timeout=self.timeout):
            if self.debug:
                print('D:', line)
            if re.search(line, 'ssh-ed25519'):
                key_type = 'ed25519'
                return key_type  # This is the best, so return immediately
            if re.search(line, 'ecdsa', line):
                key_type = 'ecdsa'  # Keep looking for a better type
        return key_type

    def generate_key(self):
        filename = os.path.join(os.path.expanduser('~'), '.ssh',
                                f'{self.remote}-ursecret-{self.local}')
        if os.path.exists(filename) or os.path.exists(filename + '.pub'):
            self.fatal(f'Will not overwrite existing key in {filename}')
        current_time = time.strftime('%Y%m%d-%H%M%S')
        command = ['ssh-keygen',
                   '-f',
                   filename,
                   '-C',
                   f'{self.user}@{self.remote}-{self.local}-{current_time}',
                   '-N',
                   '']
        if self.key_type == 'rsa':
            command.extend(['-t', 'rsa', '-b', '4096'])
        elif self.key_type == 'ecdsa':
            command.extend(['-t', 'ecdsa', '-b', '521'])
        elif self.key_type == 'ed25519':
            command.extend(['-t', 'ed25519', '-a', '100'])
        else:
            self.fatal(f'Unknown key_type: {self.key_type}')
        print(f'I: Generating key with: {" ".join(command)}')
        p = subprocess.Popen(command, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        results = p.communicate()[0]
        p.wait()
        if self.debug:
            for result in results.split():
                print('D:', result)
        self.privkey = filename
        self.pubkey = filename + '.pub'
        return self.pubkey

    def get_authorized_keys(self):
        result = []
        channel = self.client.get_transport().open_session()
        channel.exec_command('cat ~/.ssh/authorized_keys')
        found_key = False
        for line in self._linesplit(channel, timeout=self.timeout):
            if self.debug:
                print('D:', line)
            if re.search(f'{self.remote}-{self.local}', line):
                found_key = True
            result.append(line)
        return result, found_key

    def install_helper(self):
        helper = f'''#!/usr/bin/env python3
# {self.helper} -*-python-*-'''
        helper += '''
import os
import sys


class Secret():
    def __init__(self):
        self.dirname = os.path.join(os.path.expanduser('~'), '.ursecret')
        self.envname = 'SSH_ORIGINAL_COMMAND'

        if not os.path.isdir(self.dirname):
            os.mkdir(self.dirname, 0o700)

        if self.envname not in os.environ:
            self.fatal('invalid command')

        self.args = os.environ[self.envname].split()
        if len(self.args) <= 1:
            self.fatal('invalid command')

    def fatal(self, message):
        print('F: {}: {}'.format(message, self.args), file=sys.stderr)
        sys.exit(1)

    def get(self, key):
        filename = os.path.join(self.dirname, key)
        if not os.path.exists(filename):
            self.fatal('unknown key')
        with open(filename, 'r') as fp:
            value = fp.read()
        print(value)

    def put(self, key, value):
        filename = os.path.join(self.dirname, key)
        with open(filename, 'w') as fp:
            fp.write(value)
        print('I: key written to {}'.format(filename))

    def run(self):
        if self.args[0] == 'get':
            if len(self.args) != 2:
                self.fatal('illegal get')
            self.get(self.args[1])
        elif self.args[0] == 'put':
            if len(self.args) != 3:
                self.fatal('illegal put')
            self.put(self.args[1], self.args[2])
        else:
            self.fatal('illegal command')


if __name__ == '__main__':
    s = Secret()
    s.run()
    sys.exit(0)
'''

        print(f'I: Installing {self.helper} on {self.user}@{self.remote}')
        with self.client.open_sftp() as ftp:
            file = ftp.file(f'.ssh/{self.helper}', 'w')
            for line in helper:
                file.write(line)
            file.flush()
            ftp.chmod(f'.ssh/{self.helper}', 0o700)

    def install_key(self):
        print(f'I: Installing key on {self.user}@{self.remote}')
        with self.client.open_sftp() as ftp:
            file = ftp.file('.ssh/authorized_keys', 'a')
            with open(self.pubkey, 'r') as fp:
                for line in fp:
                    file.write(f'command="./.ssh/{self.helper}",'
                               'no-agent-forwarding,no-port-forwarding,no-pty,'
                               'no-user-rc,no-x11-forwarding ' + line)
            file.flush()

    def locate_key(self):
        if self.privkey is not None:
            return self.privkey
        dirname = os.path.join(os.path.expanduser('~'), '.ssh')
        with os.scandir(dirname) as it:
            for entry in it:
                if re.search(f'{self.remote}-ursecret-{self.local}',
                             entry.name) and entry.is_file():
                    if entry.name.endswith('.pub'):
                        self.pubkey = os.path.join(dirname, entry.name)
                    else:
                        self.privkey = os.path.join(dirname, entry.name)
        if self.debug:
            print(f'D: located {self.privkey}')
        return self.privkey

    def get_secret(self, key):
        client = self._connect_using_privkey()
        _, stdout, stderr = client.exec_command(f'get {key}')
        value = None
        for line in stdout:
            value = line.strip()
            break
        if value is None:
            for line in stderr:
                print('E (from remote):', line.strip())
            self.fatal('Could not get secret')
        return value

    def put_secret(self, key, value):
        client = self._connect_using_privkey()
        _, stdout, stderr = client.exec_command(f'put {key} {value}')
        for line in stdout:
            print('E (from remote):', line.strip())
        for line in stderr:
            print('E (from remote):', line.strip())


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Generate, store, and retrieve secrets via ssh')
    parser.add_argument('--remote', type=str, default=None,
                        help='name of remote host')
    parser.add_argument('--local', type=str, default=None,
                        help='name of local host (for query purposes)')
    parser.add_argument('--install', action='store_true', default=False,
                        help='install new ssh key')
    parser.add_argument('--get', type=str, default=None,
                        help='get named secret', metavar='KEY')
    parser.add_argument('--put', type=str, default=None, nargs=2,
                        help='put named secret', metavar=('KEY', 'VALUE'))
    parser.add_argument('--debug', action='store_true', default=False,
                        help='verbose debugging output')
    args = parser.parse_args()

    if not args.remote or not args.local:
        parser.print_help()
        sys.exit(1)

    if not args.install and not args.get and not args.put:
        parser.print_help()
        sys.exit(1)

    secret = UrSecret(args.remote, args.local, debug=args.debug)

    if args.install:
        _, match = secret.get_authorized_keys()
        secret.install_helper()
        print(f'I: helper installed on {args.remote}')
        if match:
            secret.fatal(f'key for {args.remote}-{args.local} found on '
                         f'{args.remote}: will not replace')
        secret.generate_key()
        secret.install_key()

    elif args.get:
        secret.locate_key()
        secret = secret.get_secret(args.get)
        print(f'K: {secret}')

    elif args.put:
        secret.locate_key()
        secret.put_secret(*args.put)
        print(f'I: secret installed on {args.remote}')

    sys.exit(0)
