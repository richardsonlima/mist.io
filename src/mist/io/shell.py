"""mist.io.shell

This module contains everything that is need to communicate with machines via
SSH.

"""


import logging
from time import time


import paramiko
import socket



from mist.io.exceptions import BackendNotFoundError, KeypairNotFoundError
from mist.io.exceptions import MachineUnauthorizedError
from mist.io.exceptions import RequiredParameterMissingError
from mist.io.exceptions import ServiceUnavailableError
from mist.io.helpers import get_temp_file

log = logging.getLogger(__name__)


class Shell(object):
    """sHell

    This class takes care of all SSH related issues. It initiates a connection
    to a given host and can send commands whose output can be treated in
    different ways. It can search a user's data and autoconfigure itself for
    a given machine by finding the right private key and username. Under the
    hood it uses paramiko.

    Use it like:
        shell = Shell('localhost', username='root', password='123')
        print shell.command('uptime')
    Or:
        shell = Shell('localhost')
        shell.autoconfigure(user, backend_id, machine_id)
        for line in shell.command_stream('ps -fe'):
            print line

    """

    def __init__(self, host, username=None, key=None, port=22):
        """Initialize a Shell instance

        Initializes a Shell instance for host. If username is provided, then
        it tries to actually initiate the connection, by calling connect().
        Check out the docstring of connect().

        """
        if not host:
            raise RequiredParameterMissingError('host not given')

        self.username = ''
        self.key = ''
        self.host = host
        self.port = port
        self.timeout = 10

        from fabric.api import run, env

        env.abort_on_prompts = True
        env.no_keys = True
        env.no_agent = True
        env.host_string = "%s:%s" % (self.host, self.port)
        env.warn_only = True
        env.combine_stderr = True
        env.keepalive = 15
        env.key = ''
        env.user = ''

        self.env = env
        self.run = run

        if username and key:
            self.connect(username, key)

    def connect(self, username, key):
        """Initialize an SSH connection.

        Tries to connect and configure self. If only password is provided, it
        will be used for authentication. If key is provided, it is treated as
        and OpenSSH private RSA key and used for authentication. If both key
        and password are provided, password is used as a passphrase to unlock
        the private key.

        Raises MachineUnauthorizedError if it fails to connect.

        """

        self.env.key = key
        self.env.user = username
        log.info("Attempting to connect to %s@%s:%s.",
                 username, self.host, port)

        ## try:
        output = self.run(command, timeout=10)
        return output
        ## except Exception as e:
            ## if 'SSH session not active' in e:
                ## from fabric.state import connections
                ## conn_keys = [k for k in connections.keys() if host in k]
                ## for key in conn_keys:
                    ## del connections[key]
                ## try:
                    ## cmd_output = run(command, timeout=COMMAND_TIMEOUT)
                    ## log.warn("Recovered!")
                ## except Exception as e:
                    ## log.error("Failed to recover :(")
                    ## log.error('Exception while executing command: %s' % e)
                    ## os.remove(tmp_path)
                    ## return Response('Exception while executing command: %s' % e, 503)
            ## else:
                ## log.error('Exception while executing command: %s' % e)
                ## os.remove(tmp_path)
                ## return Response('Exception while executing command: %s' % e, 503)
        ## except SystemExit as e:
            ## log.warn('Got SystemExit: %s' % e)
            ## os.remove(tmp_path)
            ## return Response('SystemExit: %s' % e, 401)


        ## attempts = 3
        ## while attempts:
            ## attempts -= 1
            ## try:
                ## self.ssh.connect(
                    ## self.host,
                    ## port=port,
                    ## username=username,
                    ## password=password,
                    ## pkey=rsa_key,
                    ## allow_agent=False,
                    ## look_for_keys=False,
                    ## timeout=10
                ## )
            ## except paramiko.AuthenticationException as exc:
                ## log.error("ssh exception %r", exc)
                ## raise MachineUnauthorizedError("Couldn't connect to %s@%s:%s. %s"
                                               ## % (username, self.host, port, exc))
            ## except socket.error as exc:
                ## log.error("Got ssh error: %r", exc)
                ## if not attempts:
                    ## raise ServiceUnavailableError("SSH timed-out repeatedly.")


    ## def disconnect(self):
        ## """Close the SSH connection."""
        ## log.info("Closing ssh connection to %s", self.host)
        ## try:
            ## self.ssh.close()
        ## except:
            ## pass

    def _check(self, username=None, key=None):
        try:
            self._command('uptime', username, key)
        except:
            return False
        return True

    def _command(self, cmd, username=None, key=None, pty=True):
        """Helper method used by command and stream_command."""

        from fabric.context_managers import settings

        try:
            old_username = self.env.user
            if username is not None:
                self.env.user = username
            old_key = self.env.key
            if key is not None:
                self.env.key = key
            log.info("Executing '%s' as %s@%s", cmd, self.env.user, self.env.host_string)
            out = self.run(cmd, self.timeout)
        except SystemExit:
            # fabric sucks
            log.error("Got system exit. Probably authentication failure.")
            self.env.user = old_username
            self.env.key = old_key
            raise MachineUnauthorizedError()
        except BaseException as exc:
            log.error("Got ssh exception %r", exc)
            self.env.user = old_username
            self.env.key = old_key
            raise ServiceUnavailableError()
        return out

        ## try:
            ## output = self.run(cmd, timeout=10)
        ## except Exception as e:
            ## if 'SSH session not active' in e:
                ## from fabric.state import connections
                ## conn_keys = [k for k in connections.keys() if self.host in k]
                ## for key in conn_keys:
                    ## del connections[key]
                ## try:
                    ## output = self.run(command, timeout=10)
                    ## log.warn("Recovered!")
                ## except Exception as e:
                    ## log.error("Failed to recover :(")
                    ## log.error('Exception while executing command: %s' % e)
                    ## raise MachineUnauthorizedError()
            ## else:
                ## log.error('Exception while executing command: %s' % e)
                ## raise MachineUnauthorizedError()
        ## except SystemExit as e:
            ## log.warn('Got SystemExit: %s' % e)
            ## raise MachineUnauthorizedError('SystemExit: %s' % e)
        ## return output

    def command(self, cmd, username=None, key=None, pty=True):
        """Run command and return output.

        If pty is True, then it returns a string object that contains the
        combined streams of stdout and stderr, like they would appear in a pty.

        If pty is False, then it returns a two string tupple, consisting of
        stdout and stderr.

        """
        ## log.info("running command: '%s'", cmd)
        ## stdout, stderr = self._command(cmd, pty)
        ## if pty:
            ## return stdout.read()
        ## else:
            ## return stdout.read(), stderr.read()
        return self._command(cmd, username, key)

    def command_stream(self, cmd, username=None, key=None):
        """Run command and stream output line by line.

        This function is a generator that returns the commands output line
        by line. Use like: for line in command_stream(cmd): print line.

        """
        ## log.info("running command: '%s'", cmd)
        ## stdout, stderr = self._command(cmd)
        ## line = stdout.readline()
        ## while line:
            ## yield line
            ## line = stdout.readline()
        return self._command(cmd, username, key).split('\n')

    def autoconfigure(self, user, backend_id, machine_id,
                      key_id=None, username=None, password=None):
        """Autoconfigure SSH client.

        This will do its best effort to find a suitable keypair and username
        and will try to connect. If it fails it raises
        MachineUnauthorizedError, otherwise it initializes self and returns a
        (key_id, ssh_user) tupple. If connection succeeds, it updates the
        association information in the key with the current timestamp and the
        username used to connect.

        """

        log.info("autoconfiguring Shell for machine %s:%s",
                 backend_id, machine_id)
        if backend_id not in user.backends:
            raise BackendNotFoundError(backend_id)
        if key_id is not None and key_id not in user.keypairs:
            raise KeypairNotFoundError(key_id)

        # get candidate keypairs if key_id not provided
        keypairs = user.keypairs
        if key_id:
            pref_keys = [key_id]
        else:
            default_keys = [key_id for key_id in keypairs
                            if keypairs[key_id].default]
            assoc_keys = []
            recent_keys = []
            root_keys = []
            sudo_keys = []
            for key_id in keypairs:
                for machine in keypairs[key_id].machines:
                    if [backend_id, machine_id] == machine[:2]:
                        assoc_keys.append(key_id)
                        if len(machine) > 2 and \
                                int(time() - machine[2]) < 7*24*3600:
                            recent_keys.append(key_id)
                        if len(machine) > 3 and machine[3] == 'root':
                            root_keys.append(key_id)
                        if len(machine) > 4 and machine[4] is True:
                            sudo_keys.append(key_id)
            pref_keys = root_keys or sudo_keys or assoc_keys
            if default_keys and default_keys[0] not in pref_keys:
                pref_keys.append(default_keys[0])

        # try to connect
        for key_id in pref_keys:
            keypair = user.keypairs[key_id]

            # find username
            users = []
            # if username was specified, then try only that
            if username:
                users = [username]
            else:
                for machine in keypair.machines:
                    if machine[:2] == [backend_id, machine_id]:
                        if len(machine) >= 4 and machine[3]:
                            users.append(machine[3])
                            break
                # if username not found, try several alternatives
                # check to see if some other key is associated with machine
                for other_keypair in user.keypairs.values():
                    for machine in other_keypair.machines:
                        if machine[:2] == [backend_id, machine_id]:
                            if len(machine) >= 4 and machine[3]:
                                ssh_user = machine[3]
                                if ssh_user not in users:
                                    users.append(ssh_user)
                # check some common default names
                for name in ['root', 'ubuntu', 'ec2-user']:
                    if name not in users:
                        users.append(name)
            for ssh_user in users:
                try:
                    self.command(cmd='uptime',
                                 username=ssh_user,
                                 key=keypair.private)
                except:
                    continue
                # this is a hack: if you try to login to ec2 with the wrong
                # username, it won't fail the connection, so a
                # MachineUnauthorizedException won't be raised. Instead, it
                # will prompt you to login as some other user.
                # This hack tries to identify when such a thing is happening
                # and then tries to connect with the username suggested in
                # the prompt.
                resp = self.command(cmd='uptime', username=ssh_user,
                                    key=keypair.private)
                new_ssh_user = None
                if 'Please login as the user ' in resp:
                    new_ssh_user = resp.split()[5].strip('"')
                elif 'Please login as the' in resp:
                    # for EC2 Amazon Linux machines, usually with ec2-user
                    new_ssh_user = resp.split()[4].strip('"')
                if new_ssh_user:
                    log.info("retrying as %s", new_ssh_user)
                    try:
                        self.command(cmd='uptime', username=ssh_user,
                                     key=keypair.private)
                        ssh_user = new_ssh_user
                    except:
                        continue
                # we managed to connect succesfully, return
                # but first update key
                assoc = [backend_id,
                         machine_id,
                         time(),
                         ssh_user,
                         True]
                with user.lock_n_load():
                    updated = False
                    for i in range(len(user.keypairs[key_id].machines)):
                        machine = user.keypairs[key_id].machines[i]
                        if [backend_id, machine_id] == machine[:2]:
                            user.keypairs[key_id].machines[i] = assoc
                            updated = True
                    # if association didn't exist, create it!
                    if not updated:
                        user.keypairs[key_id].machines.append(assoc)
                    user.save()
                return key_id, ssh_user

        log.error("All attempts failed.")
        raise MachineUnauthorizedError("%s:%s" % (backend_id, machine_id))
