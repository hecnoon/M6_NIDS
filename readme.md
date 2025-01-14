![alt text](Amnemonemomne.png)

# Preperation
Copy the pcapng files you wish to extrat "rules" from to the data/train directory (exclude the network scan pcap file)  
Copy the baseline to the data directory  

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
10000 packets are inspected

To test the baseline run:
```
python test_baseline.py ../data/Baseline\ 6-1-2025\ 1\ uur\ capture.pcapng unique_features.csv 1000000 anomalies.csv
```
The baseline from the data directory is scanned for "anomalies" based on unique_features.csv  
1000000 packets are inspected  
The output is written to anomalies.csv  