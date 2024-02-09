# Enhanced Azure Driver Documentation

This documentation provides essential information and guidance for using the Azure driver with Docker Machine. It covers how to obtain help, authenticate with Azure, and leverage Azure Spot instances for cost-effective resource management.

## Getting Help

For a comprehensive list of supported parameters and their descriptions, you can utilize the built-in help feature of Docker Machine. Execute the following command to display all available options for the Azure driver:

```bash
./rancher-machine create -d azure --help
```

This will output a detailed list of parameters, allowing you to customize your Azure VM creations according to your needs.

## Authentication

To interact with Azure services, you must authenticate using an Azure App Registration. This can be created through the Azure Portal and provides you with a Client ID (Application ID) and the ability to generate a Client Secret, which functions similarly to an API Token.

### Setting Credentials

Credentials can be specified directly as parameters in your commands or as environment variables for enhanced security and convenience. The following example demonstrates how to set up your environment variables for authentication:

```sh
export AZURE_CLIENT_SECRET="your_client_secret"    # Your Client Secret
export AZURE_CLIENT_ID="your_app_id"               # Application ID
export AZURE_TENANT_ID="your_tenant_id"            # Directory (Tenant) ID
export AZURE_SUBSCRIPTION_ID="your_subscription_id" # Azure Subscription ID

./rancher-machine create -d azure TestMachine1
```

### Permissions

Ensure the App Registration has the necessary permissions within Azure RBAC (Role-Based Access Control). Typically, you might require read access to the subscription and contributor access to the resource group where the VM will be deployed. Assign these roles to the service principal associated with your App Registration.

## Utilizing Azure Spot Instances

Azure Spot instances offer a cost-effective solution for running workloads that can tolerate interruptions. They are ideal for scenarios such as GitLab runners, where flexibility in VM availability can significantly reduce costs.

### Example: Setting Up GitLab Runners on Azure Spot

The following example demonstrates how to configure environment variables for deploying GitLab runners on Azure Spot instances. Adjust the parameters according to your specific requirements, such as disk size, region, VM size, and the maximum price you're willing to pay for Spot instances.

```sh
export AZURE_CLIENT_SECRET="your_client_secret"    # Your Client Secret
export AZURE_CLIENT_ID="your_app_id"               # Application ID
export AZURE_TENANT_ID="your_tenant_id"            # Directory (Tenant) ID
export AZURE_SUBSCRIPTION_ID="your_subscription_id" # Azure Subscription ID
export AZURE_RESOURCE_GROUP="gitlab-runners"
export AZURE_LOCATION="eastus2"
export AZURE_DISK_SIZE=30
export AZURE_MANAGED_DISKS=1
export AZURE_SIZE="Standard_D2_v2"
export AZURE_STORAGE_TYPE="Standard_LRS"
export AZURE_IMAGE="canonical:UbuntuServer:18.04-LTS:latest"
export AZURE_PRIORITY="Spot"
export AZURE_MAX_PRICE="0.05"                      # Max price for Spot instance, or -1 for on-demand pricing
export AZURE_EVICTION_POLICY="Deallocate"

./docker-machine create -d azure TestMachine1
```

By setting `AZURE_PRIORITY` to `"Spot"` and specifying a maximum price with `AZURE_MAX_PRICE`, you can take advantage of Azure Spot's pricing model. Remember, Spot instances may be preempted based on capacity and pricing, so they are best suited for workloads that can handle possible interruptions.

This enhanced documentation aims to clarify the steps and considerations involved in using the Azure driver with Docker Machine, ensuring a smoother experience in managing Azure resources.