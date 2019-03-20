Security Analysis of Devolo HomePlug Devices
--

Vulnerabilities in smart devices often are particular severe from a
privacy point of view. If these devices form central components of the
underlying infrastructure, such as Wifi repeaters, even an entire
network may be compromised. The devastating effects of such a compromise
recently became evident in light of the Mirai botnet. In this project,
we have conducted a thorough security analysis of so-called HomePlug
devices by Devolo, which are used to establish network communication
over power lines. We have identified multiple security issues and find
that hundreds of vulnerable devices are openly connected to the Internet
across Europe. 87% run an outdated firmware, showing the deficiency of
manual updates in comparison to automatic ones. However, even the
default configurations of updated devices lack basic security mechanisms.

## Vulnerabilities

All vulnerabilities have been responsibly disclosed to vendor:

- XSS (12-19-2014)
- XSS Filter bypass via faulty URL Decode (21-03-2018)
- DoS (21-03-2018)
- Vulnerable default configuration (21-03-2018)
  - DNS Rebind
  - Remote syslog
  - DHCI remote adminstration

## Dissemination

In February 2019 a scan revealed 1,991 vulnerable devices across
Europe that are publically exposed to the Internet.

<img src="https://dev.sec.tu-bs.de/devolo/europe.svg" width="400">

## Code

The repository contains several tools for analyzing HomePlug devices.
`dvl_builder`, for instance, enables to unpack, modify, and re-package
firmware images, while `dvl_web` contains scripts for conducting
web-based attacks.

### Dependencies

- python3
- python3-requests

### Install

```
git clone https://github.com/device-sec/devolo.git
devolo/dvl_urlencode.py --help
```

## Publication

A detailed description of our work is going to be presented at the
12th ACM European Workshop on Systems Security (EuroSec 2019) in
March 2019. If you would like to cite our work, please use the reference
as provided below.

```
@InProceedings{SchWre19,
  author =    {Rouven Scholz and Christian Wressnegger},
  title =     {Security Analysis of Devolo HomePlug Devices},
  booktitle = {Proc. of the {ACM} European Workshop on Systems
               Security ({EuroSec})},
  year =      2019,
  month =     mar,
  days =      {25.}
}
```

A preprint of the paper is available [here](https://dev.sec.tu-bs.de/devolo/2019-eurosec.pdf).
