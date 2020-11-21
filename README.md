# AES 128 bit Cracking Challenge
This program is my first try at creating an AES Cracking tool. I have not implemented any parrallel optimization yet, but I plan to in the future.
This was originally started as part of a cracking challenge for my college. 

*The program contains the library, Tiny AES in C. so aes.c, aes.h, and aes.hpp are not my code.*

The program takes in a text file labeled: "Cipher-to-crack.txt" and the text inside is laid out as(without quotation marks): "# of Key Bits" -space- "cipher text".
Once the program finds the key it exits out and all the output will be saved into a text file labeled: "output.txt".
