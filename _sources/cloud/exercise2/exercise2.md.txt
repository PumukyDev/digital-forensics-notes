# Cloud Forensics Analysis

## Extraction of Evidence from On-Premise / IaaS Virtual Machines

One of the situations we may face as future forensic professionals is dealing with virtual machines, either in local installations (our own or a client’s) or in third-party infrastructures.

In local installations, we have more possibilities for forensic acquisition. We can operate from inside the virtual machine itself or directly from the hypervisor. The first scenario is very similar to the forensic procedures already studied in class: we can use DumpIt or similar tools to perform a memory dump, execute scripts to collect forensic artifacts, and also clone the hard drive or obtain a logical image.

The second scenario is the one covered in Part A of this practice.

Part B focuses on extracting forensic evidence when the virtual machines are hosted by third-party providers, such as Azure Cloud. In this case, memory dumps can be obtained using the same methods previously studied in class. Additionally, scripts may be executed to collect relevant forensic artifacts for later analysis. Virtual hard drives can also be downloaded or cloned directly in the cloud for analysis from another virtual machine.

## Objectives

- Become aware of the forensic acquisition possibilities offered by cloud environments and virtualized systems.
- Extract forensic evidence from some of the most widely used cloud systems.

## Materials

- Any Windows distribution virtualized on your system.
- Azure Cloud.
- Libcloudforensics.

# PART A: Extraction of On-Premise Evidence

In this practical exercise we will learn how to perform a forensic analysis of a system virtualized with VMware

**List all the running machines**

```bash
vmrun list
```

![alt text](./images/image-32.png)

**Take a snapshot of the machine**

It can be done through the Vmware GUI:

![alt text](./images/image-5.png)

Or using a CLI command:

```bash
vmrun snapshot "/home/adrian/desktop/vmware/DC-1/DC-1.vmx" "Snapshot 3"
```

As shown, the snapshot is stored correctly. Move it to Kali in order to analyze it correctly.

![alt text](./images/image-6.png)

**Analyze the memory dump**

Once the dump is taken, we can analyze it using volatily as shown below

```bash
vol3 -f DC-1-Snapshot3.vmem -s ~/desktop/tools/volatility3/volatility3/symbols/ banners.Banner
```
![alt text](./images/image-7.png)

# PART B: Extraction of Evidence from Azure Cloud

Sign in Azure CLoud and click on "Virtual machines"

![alt text](./images/image.png)

Clik con "Create" and select "Virtual machine"

![alt text](./images/image-1.png)

There, create a machine of your preferences

![alt text](./images/image-2.png)

Once finished, a menu like the image below should appear.

![alt text](./images/image-3.png)

Connect to the deployed machine via ssh

```bash
ssh -i <private-key> azureuser@9.223.178.153
```

![alt text](./images/image-4.png)

Download avml and make a memory dump

```bash
wget https://github.com/microsoft/avml/releases/latest/download/avml
chmod +x avml
sudo ./avml memdump.raw
sudo chown azureuser:azureuser memdump.raw 
```

![alt text](./images/image-8.png)

Copyy the memory dump into your local machine

```
scp -i azure-forensics-key.pem azureuser@9.223.178.153:~/memdump.raw .
```

![alt text](./images/image-21.png)

Analyze the memory dump using volatility.

```bash
vol3 -f memdump.raw -s ~/desktop/tools/volatility3/volatility3/symbols/ banners.Banner
```

![alt text](./images/image-22.png)

In order to make the disk clone in Azure, click over the disk name

![alt text](./images/image-9.png)

Then click on "Create snapshot".

![alt text](./images/image-10.png)

Type a name for the snapshot and click on "Review + create".

![alt text](./images/image-11.png)

Verify that the validation is passed and click on "Create"

![alt text](./images/image-12.png)

Lastly, verigy that th edeplyment is completed and the snapshot is done.

![alt text](./images/image-14.png)

In order to use Azure Cli, run the following docker container and execute the login command.

```bash
docker run -it mcr.microsoft.com/azure-cli
az login
```

![alt text](./images/image-16.png)

Pasete en the browser the code displayed in the command line

![alt text](./images/image-15.png)

Write yout azure account mail and click on "Next"

![alt text](./images/image-17.png)

Once signed, you can close the window

![alt text](./images/image-18.png)

A command line will appear in the terminal

![alt text](./images/image-19.png)

Using the following command, a temporal URL can be created with access to te snapshot that we have generated previously.

```bash
az snapshot grant-access \
  --resource-group forensics \
  --name snapshot-1 \
  --duration-in-seconds 3600
```

![alt text](./images/image-20.png)

Copy the URL, which in this case is:

```json
{
  "accessSAS": "https://md-d3hcbtldht5q.z31.blob.storage.azure.net/mmjzwc4ms50k/abcd?snapshot=2026-05-16T20%3A11%3A11.0777366Z&sv=2018-11-09&sr=bs&si=ac513c6f073b4bf0ae1dbe1708e749d33e75b39012e740e1832fe1c1e332dd67&sig=1GPN32p0qzTJJLwQx46zwOh%2FLxw8Jrez2BDSWQVTffM%3D"
}
```

And paste it in your browser, the download should start automatically.

![alt text](./images/image-23.png)

In order to create a disk clone of the VM retrieve some important data with the following commands:

```bash
az account show
```

![alt text](./images/image-24.png)

```bash
az ad sp create-for-rbac --name "forensics-sp"
```
![alt text](./images/image-25.png)

```bash
az role assignment create \
  --assignee <appId> \
  --role "Contributor" \
  --scope /subscriptions/<id>
```

![alt text](./images/image-26.png)

Once all the information is retrieved, activate a python venv and install libcloudforensics

```bash
python3 -m venv venv  
source venv/bin/activate
pip install libcloudforensics
```

Export some the previously retrieved data

```bash
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<app-id>"
export AZURE_CLIENT_SECRET="<client-secret>"
```

![alt text](./images/image-30.png)


And create a python script with the following content

![alt text](./images/image-28.png)

Execute it and the clone will be generated inmmediately.

```bash
python3 forensics.py
```

![alt text](./images/image-31.png)