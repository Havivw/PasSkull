# PasSkull
​
Pass Skull is a web tool for manage your Password Dump file from the internet.

##Prerequisites

Please install Cassandra.
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
$ sudo pip install -r requirement.txt
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
## Additional Information
​Cassandra need Storage for data!

​
##Supported 
​
 * Searching by user name.
 * Searching by email address.
 * Searching by domain.
 * Searching by users list.
 * Searching by hash list.
 * Getting random credentials from DB.
 * Multiple users (admin and regular).
 
  
##TODO
 * while search hash show only hash and passwords.
 * MFA test after create user.
 
## Contributions..
​
..are always welcome.
