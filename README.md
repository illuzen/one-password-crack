This script does a parallel search thru a given password list to find the preimage of a given password hash. This hash is found in different places depending on the version of 1password. For some versions it is found in a profile.js next to the *.opvault file. In others it is stored in a OnePassword.sqlite database in the "profiles" table. The target values are overview_key_data, master_key_data, iterations and salt. 

Please note that the hash function is pbkdf2_hmac, so one core can do about 20 passwords / second. If you need to brute force billions of passwords, you should probably use something like [hashcat](https://hashcat.net/hashcat/) instead.This script is more suitable for when you almost know the password because of a hint or examples of other passwords.

`python3 crack.py`


Most of this code was adapted from [OblivionCloudControl](https://github.com/OblivionCloudControl/opvault/blob/master/opvault/onepass.py) so thank you [Steyn](https://github.com/steynovich) for making your code open source! 
