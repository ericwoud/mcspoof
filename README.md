# Mc Spoof

A netfilter module to use when directly bridging your wifi interface to your network, without using NAT or masquerade.

Ever tried to make an Acces Point (AP) by directly adding your wifi interface to the bridge on your AP? Why doesn't his work as expected? Why do you need to IPforward or use a NAT or somethin similar? When you add the wifi interface to the AP bridge the following happens:

Your wifi client was first connected to your wireless router. Let's say you use your phone to test it. Look at the Forwarding DataBase (FDB) on both your router and AP by typing 'bridge fdb show' on a command prompt when possible. Locate your phones MAC address and see how network packets get send through the bridges on your network.

Now connect your phone to the wifi on your AP (make it forget about the router wifi so it does never try to connect to it again). The wifi connection to the AP is made but there everything stops. No IP is retreived through dhcp. Why not? Look at the FDB on both bridges again and notice that nothing has changed. All network packet are still being send to the router as if your phone is still connected to your router. This is why network traffic is not working at the moment. Of course you would be googling for and trying for some answers and after a X amount of minutes, you found it, it works again somehow, but you cannot figure out why. Look at your bridges FDB again and see the situation has changed. All packets are now send to the AP and everything works, including DHCP and other services that only work on local network like DLNA and mDNS, etc. But now if you connect to the router again this connection does not work anymore. 

What happened is after a certain amount of minutes the FDB entries are cleaned up if they have not been used and everything works again until you switch from AP to wireless router or from wireless router to AP.

If you want to change from router to AP more smoothly you will need to apply some fix. I have 2 solutions for this problem. 

1. [FDB Deamon](https://github.com/ericwoud/bridgefdbd) It deletes the MAC address from the FDB on all bridges whenever a wifi client connects/disconnects to hostapd for a wifi connection. You need to be able to install the bridgefdbd program on your AP AND also on your wireless router. Your wifi client gets the same MAC and IP number on router and AP. There can also be no ethernet switch between the router an AP's, becasue the switch's FDB does not get cleaned up.

2. [Mc Spoof](https://github.com/ericwoud/mcspoof) It applies a technique called MAC spoofing. Your wifi client gets a different MAC and IP number on the wireless router then on the AP. It adds a fixed number to the mac address of the wifi client. You only need to install it on all AP's and wireless router, except one, usually your wireless router. If you cannot install custom software on your wireless router, this is the way to go. It is however more of a hack and is likely to break more easily. However, it is possible to have an ethernet switch between the router ans AP's.

## Getting Started with Mc Spoof

You need to build the program from source.

### Prerequisites

You only need to install it on all AP's and router, except one, usually your router. On the AP the wifi interface needs to be added to the lan bridge.

### Installing


Clone from Git

```
git clone https://github.com/ericwoud/mcspoof.git
```

Change directory

```
cd mcspoof
```

Now build the executable.
```
make
```

Now test the executable before installing it.
```
insmod ./mcspoof.ko
```

Stop the test.
```
rmmod mcspoof
```

Only if the test succeeded: On Debian/Ubuntu you can use the following to copy the file to the needed location and add a line to /etc/modules. You may need to use sudo if not logged on as root. Reboot your device.

```
make install
```

Edit the /etc/modules file and add the following line.

```
mcspoof
```

If you install mcspoof on more then one system, edit /etc/modules as follows, choose a different digit to add on the second system.

```
mcspoof add=00:00:00:00:00:10
```

Other make options:

Remove the installation:
```
make remove
```

Clean:
```
make clean
```

## Features

The default arguments are:

* if=""                 : The name of the wireless interface, if omitted then all bridged wireless interfaces.
* add=00:00:00:00:00:01 : The bytes to add to mac address written as a mac address.
* debug=n               : Print debug information about the packets y/n.

Add any changed arguments to the insmod command or to the line inside the /etc/modules file.

