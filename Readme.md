# Adversarial Attacks and Defenses on Network-based Intrusion Detection Systems in Industrial Networks

## _Framework for Adversarial Spoofing and Evasion of Rule-based ICS-NIDS (FASER-IN)_ Description

The framework aims to systematically identify the vulnerabilities of Rule-based NIDS in ICS environments, emphasizing the need for more robust intrusion detection mechanisms in ICS network security.

_FASER-IN_ includes three main stages: surrogate model generation, adversarial example generation, and evasion attack execution. We conduct our analysis on a dataset captured from a miniaturized ICS testbed and target a Rule-based NIDS from a commercial vendor. In the surrogate model generation stage, _FASER-IN_ generates multiple decision tree-based surrogate models to approximate the behavior of the black-box NIDS and selects the model with the highest Fidelity for subsequent attack evaluations. Further, in the adversarial example generation stage, the framework crafts adversarial examples using our novel algorithm, _AutoSpoofing_ that automates the process of spoofing the attacker's IP and MAC addresses while preserving the network packet integrity. Our approach leverages the association and dependency between various source and destination devices present in the ICS network for replacing the attacker's IP/MAC addresses. Finally, we execute the evasion attack by sending the adversarial examples to both the selected surrogate model and the NIDS and evaluate their robustness. 

_FASER-IN_ can also be tested to generate adversarial examples for other network related domains.

## Requirements

python (3.10.6)

pyshark (0.6)

c45-decision-tree (1.0.2)

pandas (2.0.2)

numpy (1.24.3)

seaborn (0.13.2)

matplotlib (3.7.2)

scipy (1.10.1)

scikit-learn (1.2.2)

graphviz (0.20.1)

scapy (2.5.0)

notebook (7.0.6)

## File Overview

packet_info.py: Provides the packet numbers corresponding to the generated NIDS notifications.

- Inputs: NIDS Notifications (all notifications_inbox.csv files), PCAP (filtered_attack.pcap, eval.pcap etc.)

- Outputs: NIDS Notifications with corresponding packet numbers (all notifications_inbox_packet_numbers.csv files)

multiple_occ.py: The targeted NIDS gives notification for only the first occurrence of an anomaly. This script generates NIDS notifications for multiple occurrences of an anomaly along with the corresponding packet number.

- Inputs: PCAP (filtered_attack.pcap)

- Outputs: NIDS notifications for multiple occurrences of an anomaly along with the corresponding packet number (notifications_test_occurrences_10.csv). It also provides a list of packet numbers (packets_list_10.csv) which is later used by features.py to extract the network packet features. 

features.py: Extracts the relevant network packet features. Modify as per your requirement

- Inputs: PCAP (filtered_attack.pcap), Packet Numbers (packet_list_10.csv), Output File Name (features_10.csv)

- Outputs: Extracted features from PCAP in CSV format (features_10.csv)

dataset.ipynb: Contains the dataset generation steps and the preprocessing steps such as appending NIDS predictions etc. These steps might vary for different NIDS models.

- Inputs: NIDS Notifications, features_10.csv (contains the extracted features from the pcap along with the ground truth)

- Outputs: Dataset (dataset_10.csv) which is further split into dataset_train.csv and dataset_eval.csv, Evaluation PCAP (eval.pcap), Notifications_Avoided.csv (contains the number and types of notifications avoided after the evasion attack)

FASER_IN.ipynb: This is the _Framework for Adversarial Spoofing and Evasion of Rule-based ICS-NIDS (FASER-IN)_. It consists of three stages: Surrogate Model Generation, Adversarial Example Generation _(AutoSpoofing)_, and Evasion Attack Execution.

- Inputs: Training and Evaluation Datasets (dataset_train.csv, dataset_eval.csv) as well as Attacker's IP and MAC addresses.

- Outputs: Clean Performance of NIDS and its surrogate models against cyberattacks, decision trees of surrogate models, model.pkl of selected surrogate model, Association/Dependency of features, Conditional Probability values between Source IP and Source MAC, Source MAC and Destination MAC as well as Source IP and Destination IP, Adversarial Dataset (perturbations.csv) and Adversarial PCAP (perturbations.pcap), Robust Performance of NIDS and its selected surrogate model against Adversarial Examples, If required Refined Adversarial Dataset (refined_perturbations.csv) and Refined Adversarial PCAP (refined_perturbations.pcap).

## Execution Steps

FASER_IN.ipynb takes preprocessed training and evaluation datasets (csv files containing the network features along with the labeling) as well as the attacker's IP and MAC addresses as inputs. You can use the features.py to extract the relevant network features and also modify it as per your requirement. Throughout the process, the framework generates various outputs [(as mentioned in File Overview)](#file-overview). 

To launch the evasion attack on the NIDS, the user utilizes the Adversarial PCAP (perturbations.pcap) generated by FASER_IN.ipynb and records the NIDS model's responses. These responses are then fed back into FASER_IN.ipynb to evaluate both the attack’s effectiveness and the robustness of the NIDS.

Other scripts such as dataset.ipynb, multiple_occ.py and packet_info.py are the utility scripts required for the preprocessing steps particular to our targeted NIDS. They are provided to verify the reproducibility of the results.

