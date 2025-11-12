# Rancher(Rod) Machine, a fork of [Docker Machine](https://github.com/docker/machine)

Hello! My name is Rodrigo and this is fork of Rancher Machine (which is a fork of Docker Machine), which I called rod-machine.  
The main objective of this fork was add support to Azure Spot to use in a gitlab instance maintaned by me.  
Due lack of support to support in upstream project, I first forked and added the support. I plan add this back to original project as PR if not implemented yet.  


## Azure-Specific Enhancements of rod-machine

### Key Enhancements in This Version:

#### Azure Spot Integration
One of the notable enhancements in this version of Rancher Machine is the integration of Azure Spot parameters. Azure Spot VMs offer a cost-effective solution for running interruptible workloads, allowing users to take advantage of unused Azure capacities at significantly reduced prices. This feature is particularly useful for scaling GitLab runners or other CI/CD tools, where flexibility in workload management can lead to substantial cost savings.

#### Focused on Azure and GitLab Runner
While Rancher Machine supports multiple cloud providers, this version includes optimizations and additional features specifically designed for Azure users. 
These enhancements aim to streamline the deployment and management of Docker hosts on Azure, making it more efficient and cost-effective.


### Getting Started

The easy way to use is just donwload latest release using wget and copying to some directory in PATH environment.  

### Building 

As you noted, this project is a GO project.  
To build a new executable is relativelly simple:

1. install make and docker 
2. Clone this repository
3. Make desired changes
4. Tag in format vx.y.z (it uses tagging to generate verison)
4. Run make 
5. It will generate executable in bin/rancher-machine and distributable in dist/ 
6. run bin/rancher-machine -v to confirm is compiled the version you built

### Merging upstream 

Maybe you can want merge with upstream (the rancher/docker-machine) which can contains cool updates, like latest docker client packages.  
The process is simple (if no conflicts with your changes). You can use UI or command line.  

Using command line:  

1. Clone repo 
2. Add upstream: git remote add upstream https://github.com/rancher/machine
3. pull:   git pull upstream 
4. merge:  git merge upstream/master 
5. Resolve conflics, if any.
6. Commit 
7. Make build (as described in previous section)
8. Resolve errors if any 
9. If all is ok, tag and run make build  
10. Commit to save!


For this project, I just generate the executable in bin and upload  git release.  

For more details of build process, check [BUILDING.md](BUILDING.md), which is the original file provided by upstream project. I used here to start.  


## Azure Usage Guide  

I addes some doc into the azure provider docs.
Consult the [Azure start guide](drivers/azure).  
This guide covers everything from authentication and VM creation to advanced Azure Spot configurations, providing a comprehensive resource for effectively managing Docker hosts on Azure.
