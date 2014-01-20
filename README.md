Analyse PCAP
============

This tool makes it easy to analyse PCAP trace files and product reports as to
what is using the network capacity. It takes a simple spec file that consists
of a list of BPF filters that identify network flows and produces a table 
showing traffic in bytes per second to each of those. There is a simple example
in 'metrics.spec'.

It targets Visual Studio on Windows at the moment, but should be simple to port
to Linux.

