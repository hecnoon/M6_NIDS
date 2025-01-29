# Siemens PROFINET OT Network Anomaly Detection Proof Of Concept

![alt text](Amnemonemomne.png)

# Preperation
Copy the pcapng files you wish to extract "rules" from to the data/train directory (default some samples are included)  
Copy the pcapng for validation and testing in the corresponding directories (default some samples are included)

# Execute 
To run the python scripts: 

Make sure all requirements are installed. This can be done by running ```./init.sh``` from the root directory of the 
repository. This will create a venv environment and allows you to run the python scripts locally.

Now run:
```
source .venv/bin/activate
cd scripts
python get_unique_features.py ../data/train/ unique_features.csv 10000 
```
The output is now written to unique_features.csv  
10000 packets are inspected, use -1 to inspect all

To test a cab file against a set of features run:
```
python test_against_unique_features.py ../data/test/xxx.pcapng unique_features.csv 1000000
```
The given file from the data directory is scanned for "anomalies" based on unique_features.csv  
1000000 packets are inspected, use -1 to inspect all
The output is written to anomalies.csv  