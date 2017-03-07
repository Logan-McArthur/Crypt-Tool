# Crypt-Tool
Created by: Logan McArthur

A tool to encrypt a file with a password.
Has been reviewed, but not extensively, and therefore should not be used in a professional capacity.

The process:
The password is passed along with a 32 byte random salt into a KDF with 100000 iterations.
The derived key is used as the master key in two HMAC functions which sign two known string constants to generate an encryption key and a key for the encrypted file HMAC.
A file is read and encrypted using CBC and a random IV with 256 bit AES and then run through an HMAC so that the file can be verified before recovery.
Everything is Base 64 Encoded before being written to a file.
