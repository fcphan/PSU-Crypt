# PSU-Crypt

This is an implementation of PSU-Crypt, a Feistel Cipher encryption based on Skipjack and Twofish. It takes in a 16 character key and a textfile of any length. The file can then be encrypted or decrypted with the provided key. If encrypting, the results (hex blocks) will be written to the destination file and the amount of padding added to the message will be displayed. If decrypting, the result (the decrypted plaintext) will be writeen to the destination file. Please note that when decrypting, the padding amount is required, as I could not figure out a way to figure out the padding from the encrypted blocks.

## How to use

_If not already downloaded from some other source_
`git clone XXXX`

_Otherwise run the following_
`python3 main.py <mode> <input> <key> <output> <padding>*`

- `<mode>` can either be `encrypt` or `decrypt`. Used to tell the program if it is encrypting or decrypting the given textfile.
- `<input>` is the source textfile. The expected inputs are plaintext for encryption and ciphertext for decryption. The ciphertext requires the `0x` prefix on the hex blocks.
- `<key>` is the textfile containing the key used for encryption or decryption. Much like the ciphertext, the `0x` prefix is required.
- `<output>` is the destination textfile. The results of the program (whether it be plaintext or ciphertext blocks) will be written to this file.
- `<padding>` is the amount of padding used to encrypt the text. This is a requirement when decryption, but is not for encryption. After encrypting the text, the program will output both the ciphertext blocks and the padding used. This number is not saved anywhere, and will be required to decrypt properly. If the user provides the wrong padding, the message will most likely be cut shorter than expected.

In the event that not enough arguments are supplied to the program, the base case will instead be run. If the file I/O fails for anything other than the key, the program will raise an exception and terminate abnormally. If the key file I/O is the only one that fails, the base case's key will be used instead.

## Program Output

The program will display two main sections of text as the output.

The "Inputs" section will tell the user the values read in from the provided text files. If the input file was plaintext, it will display the plaintext normally. If the input was ciphertext blocks, the program will print out each block. Additionally, if the mode is `decrypt`, then the program will also print out the padding as an input.

The "Output" section will tell the user the results of the program with the given inputs as arguments. In the case of encryption, the program will display the ciphertext blocks and the padding added to the message in order to generate 64-bit blocks. In the case of decryption, the program will only display the resulting plaintext.

At the very end of output, the program will tell the user where the results where written to, which should be the provided output file.

## Example command prompt inputs

_The following examples are making use of the default values found in the base files provided with the program_

- plaintext.txt
  > The quick brown fox jumps over the lazy dog.
- key.txt
  > 0xabcdef0123456789

Encryption:
`python3 main.py encrypt plaintext.txt key.txt ciphertext.txt`
Decryotion:
`python3 main.py decrypt ciphertext.txt key.txt output.txt 20`

## Details on extra files

The `constants.py` file contains the variables that remain constant throughout the program execution. Additionally, the f-table provided for key generation is also stored in this file. Since none of these values are ever directly or indirectly modified by the program, it made sense to keep it isolated from the rest of the code in order to prevent any accidental modifications. Additionally, the file contains a color class defined that was only used for cosmetics. It is used to make the execution block stand out more, to put emphasis on bad files (when file I/O failed), and for general debugging since colors help pick out specific text in the output.

The `helpers.py` file primarily contains functions that were relatively simple to implement when compared to the rest of the cipher. While these functions are essential to the rest of the cipher (bit rotation and splitting) I found it easier to just have it in a separate file since once it was made, I rarely needed to go back and modify it. As such, keeping it isolated was to keep it from being modifed accidently. In addition to these functions, there is the display functions for both the base case and the output of the cipher with the provided arguments.
