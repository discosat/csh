# Hardware Set Up Guide

This guide is meant to help you set up two computers with their respective hardware radios so you can do tests using hardware at the DASYA Lab.

The RX will be the computer that will be doing the receiving.
The TX will be the computer that will be doing the tranmission.

## Hardware

The hardware that was used for this guide is:

RX:
- USRP B205 mini-i 
- Porcoolpine Computer with Ubuntu 24.04
- USB3

TX:
- USRP B205 mini-i 
- Porcoolpine Computer with Ubuntu 24.04
- USB2


## Linux Guide

> OBS: It's important to first install the UHD drivers for the USRP before installing GNURadio, for whatever reason it will sometimes fail to find them if you install them after GNURadio, not sure if this was ever patched up just fyi

0. Make sure you have the software needed to build (cmake, etc) and also you have dependencies for GNURadio if you are installing from source
   - `sudo apt install build-essential git cmake g++ libboost-all-dev libgmp-dev swig python3-numpy \
        python3-mako python3-sphinx python3-lxml doxygen libfftw3-dev \
        libsdl1.2-dev libgsl-dev libqwt-qt5-dev libqt5opengl5-dev python3-pyqt5 \
        liblog4cpp5-dev libzmq3-dev python3-yaml python3-click python3-click-plugins \
        python3-zmq python3-scipy python3-gi python3-gi-cairo gir1.2-gtk-3.0 \
        libcodec2-dev libgsm1-dev libusb-1.0-0 libusb-1.0-0-dev libudev-dev python3-setuptools`

1. Download and install the UHD Drivers
    - You can add them via
        -`sudo apt-get install libuhd-dev uhd-host`
    - You can also build them from source. [Here is a good guide to do it by Ettus](https://files.ettus.com/manual/page_build_guide.html)
    - Once installed, run `sudo uhd_images_downloader` to download the firmware for the USRP


2. Clone and install the `disco_gnuradio`
    - `git clone https://github.com/spaceinventor/disco_gnuradio`
    - `cd disco_gnuradio/gr-disco`
    - `./install.sh`

3. Build & install `gr-satellites`
    - `git clone https://github.com/daniestevez/gr-satellites`
    - `cd gr-sattelites`
    - `git checkout v5.8.0`
    - `mkdir build`
    - `cd build`
    - `cmake ..`
    - `make` (you can also pass the `-j` flag to make and specify how many processors you want to use for the build process like so `make -j $(nproc)`)
    - `sudo make install`
    - `sudo ldconfig`

4. Download and install GNURadio
    - You can download it from the package manager
        - `sudo apt install gnuradio`
    - Or you can build it from source. [Here is a good guide that includes all the necessary dependencies from the GNURadio Wiki](https://wiki.gnuradio.org/index.php/UbuntuInstall) 

5. In case you are using other hardware, now is a good idea to install its drivers

### Software TroubleShooting Guide

#### GNURadio doesn't find the drivers/blocks I need

This happened a few times, the only advice I can give is to make sure that GNURadio is installed/built after all necessary drivers/packages have been installed

#### `gnuradio-companion` does not show a UI

This happened in a different distro than Ubuntu that used Hyrpland as its compositor, disabling fractional scaling solved the issue

#### Components and blocks inside GNURadio crash the UI

This also happened a few times. I figured it was an issue with QT and Python, that the version of GNURadio had somehow missmatching ones. Since Python is managed by the package manager, I made sure the latest Python was installed. In one case, this meant upgrading from Ubuntu 22.04 to 24.04

#### The UI has weird colors/inverted colors

This happens because the default QT GUI colors have changed, you can revert them back to normal/pick other colors by going to the `Tools` tab of the gnuradio-companion and then choosing `Set Default QT GUI Theme`

## Hardware connection and tests

Once everything has been installed, we can do a test of the hardware. For this, we'll first open up a terminal and run the following commands.

1. Run the `sudo uhd_images_downloader` command
    - In case the command is not found, first check if your path is correctly configured, if it's still not found, you can manually run the file by going to the `/usr/lib/x86_64-linux-gnu/uhd/utils/` directory
2. Run the `uhd_find_devices` command
    - You should be able to see the exact model in the output of this command
3. Run the `uhd_usrp_probe` command
    - If everything outputs without any issues or major warnings, you are ready to use the hardware with GNURadio

## Running GNURadio and using the hardware sinks

## macOS Guide

> Disclaimer: This was done on an M1 Pro Mac, however, I have not written down the exact steps needed to make it work since I didn't expect to use it. Because of this, I have a lot less detail but this is broadly what I remember

1. Downloaded the `gnuradio` package from brew
    - Luckily, this package already includes the uhd drivers needed for the USRP
2. Built all the dependencies changing the prefix of the `make` command so they are installed in brew's path/folder structure
    - If you are having issues finding this, when you run `gnuradio-companion` on a terminal, it will print on the CLI the path it uses
3. Run the `gnuradio-companion` command from the CLI
    - If the UI is not appearing (it can take a bit...) try making sure fractional scaling is not on

# Resources and Guides I followed that helped write this up

- https://kb.ettus.com/Building_and_Installing_UHD_and_GNU_Radio_in_an_Offline_Environment
- 
