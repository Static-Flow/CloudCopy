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
