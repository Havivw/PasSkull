# PasSkull
​
PasSkull is a web tool for managing 'Password Dump' files that are retrieved from the internet, including upload, search and export utilities. 

## Prerequisites
* install Cassandra.
```
$ echo "deb https://downloads.apache.org/cassandra/debian 311x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
$ curl https://downloads.apache.org/cassandra/KEYS | sudo apt-key add -
$ sudo apt-get update
$ sudo apt-get install cassandra
$ sudo pip3 install cassandra-driver
$ sudo apt-get install build-essential python-dev python3-pip libev4 libev-dev -y
```
​
## PasSkull Installation
Download the PasSkull folder and install with pip.
​
```shell
$ sudo pip3 install -r requirement.txt
```

### with MFA
```shell
$ python3 app.py
```

### without MFA #TODO:WIP!
```shell
$ python3 app_no_MFA.py
```
​
## Supported ​
 * Searching by user name.
 * Searching by email address.
 * Searching by domain.
 * Searching by users list.
 * Searching by hash list.
 * Getting random credentials from DB.
 * Multiple users (admin and regular).
   
## TODO

 * presenting only hash and passwords (unique) while searching for hash.
 * MFA test after create user.
 * fixing DeprecationWarning from WTForms.
 
## Additional Information
  Cassandra needs Storage for data!
  
### * Important Disclaimer: 
### * This project is for study purposes only
### * Saving leaked passwords data is illegal 
### * The use of this code is your responsibility
### * use at your own risk

## Thanks
* shirlyrl for contribute and help.

## Contributions..
​
..are always welcome.
