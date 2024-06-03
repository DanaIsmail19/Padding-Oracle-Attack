# Padding-Oracle-Attack

We did manual attacks in the previous task. In this task, we will automate the attack process, and this time,
we need to get all the blocks of the plaintext. When the container starts, two padding oracle servers will 
be started, one for the Level-1 , and the other is for the Level-2 , i.e., this task. The Level-2 server
listens to port 6000. Although the key and the secret message are in the binary code of the oracle program,
we have tried to obfuscate them, so it will not be very easy to find them from the binary. Moreover, learning
the secret message does not help the padding oracle attack at all. 

It should be noted that every time you make a new connection to the oracle, the oracle will generate a
new key and IV to encrypt the secret message (the message is still the same). That is why you will see a
different ciphertext. However, if you stay inside an existing connection, the key and IV will not change.
You can write a program to derive all the blocks of the secret message in one run, but you are allowed
to write your program to get one block at a time. 
