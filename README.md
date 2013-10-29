antipwny
========
Authors: Rohan Vazarkar, David Bitner

A host based IDS/IPS written in C#, targeted at Metasploit Payloads.

Instructions
--------
AntiPwny requires .NET Framework 4.5, which can be acquired [here](http://www.microsoft.com/en-us/download/details.aspx?id=30653).

Pre-compiled binaries can be found in the exe folder in the root directory. Make sure you use the proper platform or you will get errors! The DLL file included is necessary for AntiPwny to run.

AntiPwny was compiled using Visual Studio 2012 Professional. To compile it yourself, check out the source and compile it against your target platform.

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
* Fix configuration tab to actually work

The ObjectListView library was used to create AntiPwny. It can be found [here] (http://objectlistview.sourceforge.net/cs/index.html)
