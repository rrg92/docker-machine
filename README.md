# Rancher Machine, a fork of [Docker Machine](https://github.com/docker/machine)

Machine lets you create Docker hosts on your computer, on cloud providers, and inside your own data center.  
It creates servers, installs Docker on them, then configures the Docker client to talk to them.

## Azure-Specific Enhancements

Rancher Machine is a fork of the popular [Docker Machine](https://github.com/docker/machine) tool, designed to simplify the process of managing Docker hosts on various cloud platforms. This enhanced version introduces specific adjustments tailored for Azure, with a particular focus on leveraging Azure Spot instances to optimize costs, especially beneficial for use cases like GitLab runners.

### Key Enhancements in This Version:

#### Azure Spot Integration
One of the notable enhancements in this version of Rancher Machine is the integration of Azure Spot parameters. Azure Spot VMs offer a cost-effective solution for running interruptible workloads, allowing users to take advantage of unused Azure capacities at significantly reduced prices. This feature is particularly useful for scaling GitLab runners or other CI/CD tools, where flexibility in workload management can lead to substantial cost savings.

#### Focused on Azure
While Rancher Machine supports multiple cloud providers, this version includes optimizations and additional features specifically designed for Azure users. These enhancements aim to streamline the deployment and management of Docker hosts on Azure, making it more efficient and cost-effective.

### Getting Started

To begin using this enhanced version of Rancher Machine with Azure, follow these steps:

1. **Building Rancher Machine**: For instructions on compiling Rancher Machine from source, refer to the [build documentation](BUILDING.md). The build guide provides detailed steps to help you compile the tool, ensuring you have the latest version with all enhancements included.

2. **Azure Usage Guide**: For detailed instructions on using Rancher Machine with Azure, including how to leverage Azure-specific features and optimizations, consult the [Azure start guide](drivers/azure). This guide covers everything from authentication and VM creation to advanced Azure Spot configurations, providing a comprehensive resource for effectively managing Docker hosts on Azure.

### Conclusion

This enhanced version of Rancher Machine is an invaluable tool for developers and DevOps professionals working with Docker on Azure.  
The main purpose of this changes is use with gitlab.  
By incorporating Azure Spot functionality and other Azure-specific enhancements, it offers a more tailored and cost-efficient solution for container management in the cloud.  
Whether you're scaling GitLab runners or managing a fleet of Docker hosts, this version of Rancher Machine is designed to meet your needs with Azure in mind.

Machine lets you create Docker hosts on your computer, on cloud providers, and
inside your own data center. It creates servers, installs Docker on them, then
configures the Docker client to talk to them.


## Installation and documentation
The original full Docker Machine documentation [is available here](https://gcbw.github.io/docker.github.io/machine/).

This project is intended to be embedded and executed by the full [Rancher](https://github.com/rancher/rancher) product
and the stand alone cli functionality will remain but the human use of it will not be the primary focus as we will expect
inputs provided by other things like Terraform or UIs.

Cli binaries can be found in our [Releases Pages](https://github.com/rancher/machine/releases)

## Issues

For historical context you can read the [Docker Machine Issues](https://github.com/docker/machine/issues)
but all new issues created for Rancher Machine will need to be created 
in [Rancher](https://github.com/rancher/rancher/issues) 

## Driver Plugins

In addition to the core driver plugins bundled alongside Rancher Machine, users
can make and distribute their own plugin for any virtualization technology or
cloud provider.  To browse the list of known Rancher Machine plugins, please [see
this document in our
docs repo](https://github.com/docker/docker.github.io/blob/master/machine/AVAILABLE_DRIVER_PLUGINS.md).
