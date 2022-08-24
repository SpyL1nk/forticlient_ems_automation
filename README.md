# FortiClient EMS APIv1

Warning ! This script is provided as a Proof of Concept for the API usage of the FortiClient.
Use it at your own risk. It could have serious impacts on the database and the performance of the FortiClient EMS.

## Introduction

This is a quick PoC used to connect to FortiClient EMS API and delete endpoints.

Partial API documentation can be found on the Fortinet Developer Network (FNDN) : https://fndn.fortinet.net/index.php?/fortiapi/48-forticlient-ems/ (requires an account)

This scripts currently parse a CSV file given as a parameter and delete endpoints based on the `device_id` provided in the CSV file (first column).

## Configuration file

The configuration file must be name `.fctems` in the working directory for now.
It contains one section :
- fctems :
    - fctems_url : URL of the FortiClient EMS server (including the schema, `https://`, and the ending `/`)
    - fctems_username : Username of an administrator account of the FortiClient EMS;
    - fctems_password : Password of the administrator account used;

```INI
[fctems]
fctems_url = https://fctems.labs-cheops.fr/
fctems_username = spyl1nk
fctems_password = changeme
```

## CSV File

Currently only CSV file using `;` delimiter are supported.
The CSV file must contain at least two columns. The first one must be the device_id and the second on the device_name.
No headers should be present, the script reads the first line as data.

This is highly based on the output of an existing [MSSQL request](https://github.com/SpyL1nk/forticlientems-sql-collection/blob/main/spGetOfflineEndpointListSince.sql) used to extract endpoint offline since a certain amount of time.
Using the tool SSMS, when executing this request, it is possible to directly save the output in a CSV file and use it with this script.

## Usage

For now, two options are available :
- `-f` or `--file` : Provide the path of the CSV file to be used. Mandatory;
- `-l` or `--logfile` : Provide the path of the logfile. Optional, this defaults to `./fctems_automation.log`

```
python3 fctems_automation.py --file endpointlist.csv
```