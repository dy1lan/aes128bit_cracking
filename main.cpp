#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <fstream>
#include <bits/stdc++.h>
#include "aes.hpp"

using namespace std;

bool b_FOUNDKEY = false; //global variable to exit program when key has been found

string trim(const string& str,const string& whitespace = " \t") // removes extra whitespaces
{
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == string::npos)
        return ""; // no content

    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

void runCheck(int pos, ofstream& outfile, uint8_t (&key)[16], uint8_t (&inarray)[16], uint8_t (&resetin)[16], uint8_t (&rstkey)[16]);
void runHalfCheck(int pos, ofstream& outfile, uint8_t (&key)[16], uint8_t (&inarray)[16], uint8_t (&resetin)[16], uint8_t (&rstkey)[16]);

int main()
{
    int KeyBits;
    int pos = 16; //initialize it to higher than the array size.
    string hexvalue;
    uint8_t inarray[16];
    uint8_t resetin[16];

    ifstream infile;
    infile.open("Cipher-to-crack.txt"); //text file should include(without the quotations): "# of bits" -space- "hex value of cipher code"
    infile >> KeyBits;
    getline(infile,hexvalue);
    hexvalue = trim(hexvalue);
    if (hexvalue.substr(0,2) == "0x") {
        hexvalue = hexvalue.substr(2,hexvalue.length()-2);
    }

    infile.close();

    int hexlen = hexvalue.length();
    int counts = 0;
    for (int i=0; i < hexlen; i+=2)
    {
        string two = hexvalue.substr(i,2);
        inarray[counts] = strtol(two.c_str(), nullptr,16);
        counts++;
    }

    copy(begin(inarray), end(inarray), begin(resetin));

    uint8_t key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t rstkey[16];

    copy(begin(key), end(key), begin(rstkey));

    cout << "Cracking Cipher: " << hexvalue << endl;
    cout << "Key Bits: " << KeyBits << endl;

    ofstream outfile;
    outfile.open("output.txt");

    time_t start, endtime;

    time(&start);

    if(KeyBits % 8 == 0) {
        pos = 16 - (KeyBits / 8);
        runCheck(pos, outfile, key, inarray, resetin, rstkey);
    }
    else if(KeyBits % 4 == 0) {
        //means we will have to use half of one hex.
        pos = 16 - (((KeyBits - 4) / 8) + 1);
        runHalfCheck(pos, outfile, key, inarray, resetin, rstkey);
    }
    // Recording end time.
    time(&endtime);

    // Calculating total time taken by the program.
    double time_taken = double(endtime - start);
    cout << "Time taken by program is : " << fixed
         << time_taken << setprecision(5);
    cout << " sec " << endl;

    outfile << "Time taken by program is : " << fixed
         << time_taken << setprecision(5);
    outfile << " sec " << endl;

    outfile.close();
}

void runCheck(int pos, ofstream& outfile, uint8_t (&key)[16], uint8_t (&inarray)[16], uint8_t (&resetin)[16], uint8_t (&rstkey)[16])
{
    stringstream word;
    int counts = 0;
    while (pos < 16 && !b_FOUNDKEY) {
        key[pos] = 0x00;
        while ((int)key[pos] < 255) {
            struct AES_ctx ctx;

            if(counts != 0) {key[pos]++;}

            copy(begin(resetin), end(resetin), begin(inarray)); //resets inarray to original input.

            AES_init_ctx(&ctx, key);
            AES_ECB_decrypt(&ctx, inarray);

            /**
            Converts inarray to a string of the hex values
            **/
            word.str(""); //set word to nothing
            for (uint8_t i = 0; i < sizeof(inarray); i++) {
                if(inarray[i] < 0x10) {
                    word << "0" << std::hex << (int)inarray[i];
                }
                else  word << std::hex << (int)inarray[i];
            }

            /**
            Converts the string of hex values to ascii characters that the user can read and validate.
            **/
            int len = word.str().length();
            string msg = "";
            bool valid = true;
            for(int i = 0; i < len; i+=2) {
                string byte = word.str().substr(i,2);
                int chk = (int)strtol(byte.c_str(), nullptr, 16);
                /**
                The following checks if the character is actual words and not random symbols.
                **/
                if((chk == 0x00 || (chk >= 0x61 && chk <= 0x7A) || (chk >= 0x41 && chk <= 0x5A)) && valid) {
                    valid = true;
                    char chr = (char) chk;
                    msg.push_back(chr);
                }
                else valid = false;
            }

            /**
            If valid is still true that means the whole string contained valid characters and not
            random symbols.
            **/
            if(valid) {
                stringstream keyfound;
                for (uint8_t i = 0; i < sizeof(key); i++) {
                    if (key[i] < 0x10) {
                        keyfound << "0" << std::hex <<(int)key[i];
                    }
                    else keyfound << std::hex << (int)key[i];
                }

                cout << "Key Found!: " << keyfound.str() << " ";
                outfile << "Key Found!: " << keyfound.str() << " ";
                cout << " Word: " << msg << endl;
                outfile << " Word: " << msg << endl;
                b_FOUNDKEY = true;
                break;
            }
            counts++;
            if(pos + 1 < 16) runCheck(pos + 1,outfile,key, inarray, resetin, rstkey); //recursive call to brute force the lower bits.
        }
        pos++;
    }
}

void runHalfCheck(int pos, ofstream& outfile, uint8_t (&key)[16], uint8_t (&inarray)[16], uint8_t (&resetin)[16], uint8_t (&rstkey)[16])
{
    stringstream word;
    int counts = 0;
    while (pos < 16 && !b_FOUNDKEY) {
        key[pos] = 0x00;
        while (key[pos] < 0x0f) {
            struct AES_ctx ctx;

            if(counts != 0) {key[pos]++;}

            copy(begin(resetin), end(resetin), begin(inarray)); //resets inarray to original input.

            AES_init_ctx(&ctx, key);
            AES_ECB_decrypt(&ctx, inarray);



            /**
            Converts inarray to a string of the hex values
            **/
            word.str("");
            for (uint8_t i = 0; i < sizeof(inarray); i++) {
                if(inarray[i] < 0x10){
                    word << "0" << std::hex << (int)inarray[i];
                }
                else  word << std::hex << (int)inarray[i];
            }

            /**
            Converts the string of hex values to ascii characters that the user can read and validate.
            **/
            int len = word.str().length();
            string msg = "";
            bool valid = true;
            for(int i = 0; i < len; i+=2) {
                string byte = word.str().substr(i,2);
                int chk = (int)strtol(byte.c_str(), nullptr, 16);

                /**
                The following checks if the character is actual words and not random symbols.
                **/
                if((chk == 0x00 || (chk >= 0x61 && chk <= 0x7A) || (chk >= 0x41 && chk <= 0x5A)) && valid) {
                    char chr = (char) chk;
                    msg.push_back(chr);
                    valid = true;
                }
                else valid = false;
            }

            /**
            If valid is still true that means the whole string contained valid characters and not
            random symbols.
            **/
            if(valid) {
                stringstream keyfound;
                for (uint8_t i = 0; i < sizeof(key); i++) {
                    if (key[i] < 0x10){
                        keyfound << "0" << std::hex <<(int)key[i];
                    }
                    else keyfound << std::hex << (int)key[i];
                }
                cout << "Key Found!: " << keyfound.str() << " ";
                outfile << "Key Found!: " << keyfound.str() << " ";
                cout << " Word: " << msg << endl;
                outfile << " Word: " << msg << endl;
                b_FOUNDKEY = true;
                break;
            }
            counts++;
            if(pos + 1 < 16) runCheck(pos + 1,outfile,key, inarray, resetin, rstkey); //recursive call to brute force the lower bits.
        }
        pos++;
    }
}




