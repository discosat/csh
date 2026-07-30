# disco2-sdr
This repository contains the software defined radio (SDR) documentation for the ITU Groundstation (ITU-GS) and the DISCO-2 satellite. 

It is organised in folders, each containing documentation for its respective scripts and tools:

```
├── installation_guide
│   └── README.md
├── pass_recording
│   └── README.md
├── recording_analysis
│   └── README.md
└── recording_decoding
    ├── DISCO-1
    │   ├── pingdecoding_working
    │   └── README.md
    └── DISCO-2
        ├── ITUGS_recording_decode
        ├── PE0SAT_recording_decode
        ├── README.md
        └── terrestrial_ping_decode
```

> [!NOTE]
> To be able to test and modify the GNURadio Companion files, you will need to install the following packages which are also mentioned in the installation guide:
> - disco_gnuradio
> - gr-satellites 

For the documentation for DISCO1, check the [disco_gnuradio](https://github.com/discosat/disco_gnuradio) repository.
