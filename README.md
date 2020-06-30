# My journey of hacking and unbricking an Opticam O8 IP camera (Foscam FI9961EP clone)

I received this camera in soft bricked condition and decided to have a look under the hood.
I have had no real experience with hardware hacking or serial connections in the past so this was quite exiting to work on.

What I have here is an Opticam O8 (Model number 5089) which seems to be a clone/cut down version of a Foscam FI9961EP.

![Opticam O8 without the dome](https://raw.githubusercontent.com/santeri3700/opticam_o8_hacking/master/pics/opticam-o8-without-dome.jpg)

First thing I was looking for was the UART / Serial pins. This way I could check what was possibly wrong with it.
You can see the pins next to the piece of metal which is holding the camera sensor module and where the blue, white and black wires are going.

![Opticam O8 inside](https://raw.githubusercontent.com/santeri3700/opticam_o8_hacking/master/pics/opticam-o8-motherboard-mounted.jpg)
Here is a close up and explanation of the pins. I just tried my luck when figuring out which one is RX/TX/GND.

![Opticam O8 serial pins](https://raw.githubusercontent.com/santeri3700/opticam_o8_hacking/master/pics/opticam-o8-motherboard-above-serial-pins.jpg)![Opticam O8 serial pins below](https://raw.githubusercontent.com/santeri3700/opticam_o8_hacking/master/pics/opticam-o8-motherboard-serial-pins.jpg)
Now that I had located the pins and soldered some wires to them, it was time to check if we get any serial output.

I connected the wires to an USB to TTL module which then connects to my laptop.
![USB TO TTL](https://raw.githubusercontent.com/santeri3700/opticam_o8_hacking/master/pics/usb-to-ttl.jpg)
After experimenting a bit with different serial clients I ended up using MiniCom.
Settings: 115200 Bps 8N1 and Hardware Flow Control **disabled**.

Powering up the camera and... Success!

                 ___  ___  _________                _   
                / _ \ |  \/  || ___ \              | |  
               / /_\ \| .  . || |_/ /  ___    ___  | |_ 
               |  _  || |\/| || ___ \ / _ \  / _ \ | __|
               | | | || |  | || |_/ /| (_) || (_) || |_ 
               \_| |_/\_|  |_/\____/  \___/  \___/  \__|
    ----------------------------------------------------------
    Amboot(R) Ambarella(R) Foscam(R) Copyright (C) 2004-2014 2015-05-23
    Foscam(R) Copyright (C) 2015-05-23
    will reset phy by g95
    reset phy completed, gpios2 data: 0xB8001EFF
    net init ok, now config phy leds
    will config phy leds
    scan phy addr completed, phy_id:0x00000000
    config phy leds completed
    auto update ipc from sd card or tftp server
    Auto-update from SD Card
    start update ip.c from sd card
    running SD test ...
    press any key to terminate!
    No sdmmc present.
    sdmmc init sd fail!!!
    No sdmmc present.
    sdmmc init mmc fail!!!
    total_secs: 0
    Help for 'sd':
            [slot]: 0/1/2/..
            [mode]: ds/hs/sdr12/sdr25/sdr50/sdr104/ddr50
            [clock]: clock in MHz
            sd init slot [mode] [clock]
            sd read slot [mode] [clock]
            sd write slot [mode] [clock]
            sd verify slot [mode] [clock]
            sd erase slot [ssec] [nsec]
            sd shmoo slot [mode] [clock]
            sd show partition/info
    Test SD.
    CMD error: cmd=0x0000113A, eis=0x00000001, nis=0x00008000
    failed Read at 0 sector
    give up sd -update
    start update ipc from tftp server
    Auto-update from TFTP: 
    trying update file recover_image_amba.bin
    Bind UDP fail ...
    load_from_tftp failgive up tftp-update
    Can't load upgrade file, give up update
    [    0.000000] Booting Linux on physical CPU 0x0
    [    0.000000] Initializing cgroup subsys cpu
    [    0.000000] Linux version 3.10.73 (root@foscam-virtual-machine) (gcc version 4.9.1 20140625 (prerelease) (crosstool-NG - Ambarella Linaro Multilib GCC [CortexA9 & ARMv6k] 2014.06) ) #1 PRE7
    [    0.000000] CPU: ARMv7 Processor [414fc091] revision 1 (ARMv7), cr=10c53c7d
    [    0.000000] CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
    [    0.000000] Machine: Ambarella S2L (Flattened Device Tree), model: Ambarella S2LM Kiwi Board
    [    0.000000] Memory policy: ECC disabled, Data cache writeback
    [    0.000000] Ambarella:      AHB = 0xe0000000[0xe0000000],0x01000000 0
    [    0.000000] Ambarella:      APB = 0xe8000000[0xe8000000],0x01000000 0
    [    0.000000] Ambarella:      PPM = 0x00000000[0xdfe00000],0x00200000 9
    [    0.000000] Ambarella:      AXI = 0xf0000000[0xf0000000],0x00030000 0
    [    0.000000] Ambarella:    DRAMC = 0xdffe0000[0xef000000],0x00020000 0
    [    0.000000] Ambarella:   DBGBUS = 0xec000000[0xec000000],0x00200000 0
    [    0.000000] Ambarella:  DBGFMEM = 0xee000000[0xee000000],0x01000000 0
    [    0.000000] Ambarella:   IAVMEM = 0x07000000[          ],0x09000000
    [    0.000000] CPU: All CPU(s) started in SVC mode.
    [    0.000000] Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 27940
    [    0.000000] Kernel command line: console=ttyS0 ubi.mtd=lnx root=ubi0:rootfs rw rootfstype=ubifs init=/linuxrc
    [    0.000000] PID hash table entries: 512 (order: -1, 2048 bytes)
    [    0.000000] Dentry cache hash table entries: 16384 (order: 4, 65536 bytes)
    [    0.000000] Inode-cache hash table entries: 8192 (order: 3, 32768 bytes)
    [    0.000000] Memory: 110MB = 110MB total
    [    0.000000] Memory: 106272k/106272k available, 6368k reserved, 0K highmem

Looks like the camera is running Linux 3.10.73 on and ARMv7 processor and 110MB of usable memory.
I started reading the boot messages to try and figure out what was wrong with the device.

    ...
    Welcome to Ambarella Flexible Linux S2LM (2.5.0)!
    
    Expecting device dev-ttyS0.device...
    [  OK  ] Reached target Remote File Systems.
    [  OK  ] Reached target Paths.
    [  OK  ] Reached target Swap.
    [  OK  ] Created slice Root Slice.
    [  OK  ] Created slice User and Session Slice.
    [  OK  ] Listening on /dev/initctl Compatibility Named Pipe.
    [  OK  ] Listening on Delayed Shutdown Socket.
    [  OK  ] Listening on Journal Socket (/dev/log).
    ...
    [FAILED] Failed to listen on Journal Gateway Service Socket.
    See 'systemctl status systemd-journal-gatewayd.socket' for details.
    ...
    ==== Your model name is Opticam_O8 SENSOR=15 WIFI=0 LANGUAGE=2 MODELVERSION=72 MODELNUM=5089 ====
    ...
    Default init without lens driver
    Use default settings
    ...
    tar: corrupted data
    tar: short read
    Connection established with kernel.
    
    Welcome to Ambarella
    Ambarella login:
The camera is using systemd and some services/units failed to load and there seemed to be some corrupted tar archive which was being extracted on boot.
Perhaps the internal flash got corrupted because of a power outage or failed firmware update?

After reading the logs I decided to try and get root access.

    Ambarella login: root
    Password:

After trying some common passwords like "*root*", "*1234*", "*foscam*" and "*admin*" I gave up and started looking for a way to change the Linux "cmdline" so I could change the init.

I found a Defcon presentation which showed how to root gain access by physical access on a similar device.
https://www.defcon.org/images/defcon-22/dc-22-presentations/Moore-Wardle/DEFCON-22-Colby-Moore-Patrick-Wardle-Synack-DropCam-Updated.pdf
Mirror: http://web.archive.org/web/20180825160226/https://defcon.org/images/defcon-22/dc-22-presentations/Moore-Wardle/DEFCON-22-Colby-Moore-Patrick-Wardle-Synack-DropCam-Updated.pdf

From that presentation, I learned I could access the Amboot bootloader by pressing Enter while powering up the camera.

                ___  ___  _________                _   
                / _ \ |  \/  || ___ \              | |  
               / /_\ \| .  . || |_/ /  ___    ___  | |_ 
               |  _  || |\/| || ___ \ / _ \  / _ \ | __|
               | | | || |  | || |_/ /| (_) || (_) || |_ 
               \_| |_/\_|  |_/\____/  \___/  \___/  \__|
    ----------------------------------------------------------
    Amboot(R) Ambarella(R) Copyright (C) 2004-2014
    Boot From: NAND 2048 RC BCH 6bit
    SYS_CONFIG: 0x3007005B POC: 101
    Cortex freq: 600000000
    iDSP freq: 216000000
    Dram freq: 528000000
    Core freq: 216000000
    AHB freq: 108000000
    APB freq: 54000000
    UART freq: 24000000
    SD freq: 50000000
    SDIO freq: 50000000
    SDXC freq: 60000000
    1st input Passwd:
    1st input Passwd:
    1st input Passwd:
Alright.. Now I needed the password.. The presentation didn't mention this so I went and did a bit of Googling.
After some digging I found a [forum post](https://ipcamtalk.com/threads/bricked-foscam-fi9828p.12322/post-117179) where a user had dumped the password from the firmware image.
I tried the password "*ipc.fos~*" on my camera and it worked! Now I had full access to the bootloader.

I knew what the original "cmdline" was from the earlier boot so I tried booting the camera like this.

    amboot > boot console=ttyS0 ubi.mtd=lnx root=ubi0:rootfs rw rootfstype=ubifs init=/bin/sh

after boot
```
# whoami
root
# uname -a
Linux Ambarella 3.10.73 #1 PREEMPT Tue Novv 11:33:40 CST 2015 armv7l GNU/Linux
# cat /etc/passwd
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:100:sync:/bin:/bin/sync
mail:x:8:8:mail:/var/spool/mail:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
operator:x:37:37:Operator:/var:/bin/sh
haldaemon:x:68:68:hald:/:/bin/sh
dbus:x:81:81:dbus:/var/run/dbus:/bin/sh
nobody:x:99:99:nobody:/home:/bin/sh
sshd:x:103:99:Operator:/var:/bin/sh
pulse:x:101:101:Linux User,,,:/var/lib/pulse:/bin/false
systemd-journal-gateway:x:998:998:systemd Journal Gateway:/:/sbin/nologin
systemd-bus-proxy:x:997:997:systemd Bus Proxy:/:/sbin/nologin
systemd-network:x:996:996:systemd Network Management:/:/sbin/nologin
systemd-resolve:x:995:995:systemd Resolver:/:/sbin/nologin
systemd-timesync:x:994:994:systemd Time Synchronization:/:/sbin/nologin
ftpuser1:x:1001:1001:ftpgroup:/mnt/sd:

# cat /etc/shadow
root:$1$xY/YSetV$dbTV4dHv6gWzmAlfYTboG1:16609:0:99999:7:::
bin:*:10933:0:99999:7:::
daemon:*:10933:0:99999:7:::
adm:*:10933:0:99999:7:::
lp:*:10933:0:99999:7:::
sync:*:10933:0:99999:7:::
shutdown:*:10933:0:99999:7:::
halt:*:10933:0:99999:7:::
uucp:*:10933:0:99999:7:::
operator:*:10933:0:99999:7:::
nobody:*:10933:0:99999:7:::
ftpuser1:!:10957:0:99999:7:::
```
I'm in.. At this point I wanted to figure our the original root password by checking the hash above.
I searched Google, some forums and [Crackstation](https://crackstation.net/) without success.
Cracking the hash by myself would have taken forever so I just decided to change the password and hope that it was persistent.

    # passwd
    New password: 
    Retype new password:
    passwd: all authentication tokens updated successfully.
    # sync; reboot
I had to power off the camera at this point since it kernel panicked.
After a normal boot I tried the new password.

    Welcome to Ambarella
    Ambarella login: root
    Password:
    # whoami
    root

I worked! So the root password is persistent for this device.
Next thing I did was to look around the filesystem and I found and interesting script which seemed to be the source of the tar error message.

    less /mnt/mtd/boot.sh
    ...
    tar -Jxf /mnt/mtd/app/www.tar.xz -C /tmp/
    ...

I inspected the `www.tar.xz` archive and it indeed was corrupted.
I couldn't fix it so I decided to look for a way to flash the firmware without getting access via the web management.

I searched the web and found out that there is a way to recover a Foscam IP camera via SD card.
After some extensive digging I compiled a list of official Foscam recovery images and guides [here](https://github.com/santeri3700/misc/blob/master/foscam_recovery_images.md).
Since my camera is a close clone of Foscam FI9961EP, I used its recovery image.

I put the SD card with the recovery image in to the camera and powered it up.
After a few minutes, the serial output said "-recovery success-!!!" and I restarted the camera.

Initially the camera wasn't fully working and it kept restarting every two minutes.
I logged in via the serial connection and figured out that the firmware wasn't 100% compatible.

I had to remove some lines from the init scripts so wlan0 wasn't being enable on every boot.
I unfortunately do not have notes from this, but the problematic script was `/mnt/mtd/loadDiffParam.sh`

After stripping everything about wlan0 the camera booted just fine and I was able to login to the web management etc.

#### Now I have a happy and working IP camera!

## Extras
There is a possible way to get root access to the camera without soldering wires or logging in to the web management.
Check this init script from `/etc/local/bin/init.sh` which is being executed on every boot.

    #!/bin/sh
    
    echo $PATH | grep "/usr/local/bin"
    if [ $? -eq 1 ]; then
          export PATH=$PATH:/usr/local/bin
    fi
    
    AMBARELLA_CONF=ambarella.conf
    
    [ -r /etc/$AMBARELLA_CONF ] && . /etc/$AMBARELLA_CONF
    
    kernel_ver=$(uname -r)
    
    if [ -d /sys/module/ambarella_config/parameters ]; then
    	config_dir=/sys/module/ambarella_config/parameters
    fi
    #set socket send and receive max buf size
    #echo 655360 > /proc/sys/net/core/wmem_max
    
    if [ -x /tmp/mmcblk0p1/ext-pro.sh ]; then
    echo "==============================================="
    echo "Exec: /tmp/mmcblk0p1/ext-pro.sh"
    echo "==============================================="
    /tmp/mmcblk0p1/ext-pro.sh
    elif [ -x /home/default/ext-pro.sh ]; then
    echo "==============================================="
    echo "Exec: /home/default/ext-pro.sh"
    echo "==============================================="
    /home/default/ext-pro.sh
    fi
    case "$?" in
        0)
    	;;
        *)
      	echo "Exec ext-pro.sh failed!"
    	exit 1
    	;;
    esac
    ...

So if I were to write a script named `ext-pro.sh` to the root of the SD card, I could possibly gain root access to the camera by running telnetd or something.

I didn't test this since I already had root access to the camera, but maybe someone else will benefit from this (just don't be evil, please)