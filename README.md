antipwny
========
Authors: Rohan Vazarkar, David Bitner

A host based IDS/IPS written in C#, targetted at Metasploit Payloads.

Current Features
--------
* Scans Registry for Meterpreter Persistence/MetSvc
* Active Memory Scans to detect Meterpreter
* IDS/IPS Mode
* View outbound connections in compromised processes

Detected Payloads:
--------
* Meterpreter
* Java Meterpreter
* Reverse Shell

Planned Features
--------
* Firewall Support
* Detect Cobalt Strike Beacon
* Network Firewall Support
* Self Check for Integrity to catch Migration
