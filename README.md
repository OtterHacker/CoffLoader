# CoffLoader
It's just un implementation of in-house CoffLoader supporting CobaltStrike standard BOF and BSS initialized variables.

Look at the main.c file to change the BOF and its parameters. CobalStrike handles the BOF parameter in a special way, the `Arg` structure is here to pass parameters easier.

No better way to understand something than digging in the code so no real README here, but if you want full theoretical explanation, look at my [paper](https://otterhacker.github.io/Malware/CoffLoader.html)

The beacon.h implementation comes from the TrustedSec [repo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/)

