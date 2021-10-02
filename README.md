
# Attack Surface API
----------  
This service intend to provide customers the ability to understand the potential attack vectors risking their cloud data centers. This service enables the customer query and get the attack surface of a specific VM in his cloud - meaning which other virtual machines in the account can access and attack it.

## Prerequisites
------
Please make sure that you meet that following requiemnets:
* Python 3.9.X
* Run `pip install -r requiements.txt`

## Running the Service
----
To run the service, run the following command on your termina;:
`python3 app.py <path_to_json>`

**Note**: Make sure that your terminal is located inside the service folder.

### Parameters:
`<path_to_json>` - A path to the cloud data, you can find multiple data jsons inside the `service/data/` folder.

## Endpoints

Endpoints table:

| Routes         | description                              | params           |
|----------------|------------------------------------------|------------------|
| /api/v1/attack | Get the attack surface for a specific VM | vm_id: the VM ID |
| /api/v1/stats  | Getting the cloud statistics             |                  |
