# PGP-Groupchat-Cryptosystem
This project entails the implementation of a Java group chat application between three users. The chat application uses the TCP protocol at the transport layer and security was implemented through a PGP cryptosystem that combines shared key encryption, public-key encryption and certificates. Cryptographic functions were implemented through the Java security API and Bouncy Castle library.

## How to compile:
**Linux use command:**

**To compile all files**
`javac -cp .:1.jar:2.jar:3.jar:4.jar:5.jar:6.jar *.java`

**To run the Server:**
`java -cp .:1.jar:2.jar:3.jar:4.jar:5.jar:6.jar Server`

**To run the Client:**
`java -cp .:1.jar:2.jar:3.jar:4.jar:5.jar:6.jar Client`

**Windows use command:**

**To compile all files:**
`javac -cp .;1.jar;2.jar;3.jar;4.jar;5.jar;6.jar *.java`

**To run the Server:**
`java -cp .;1.jar;2.jar;3.jar;4.jar;5.jar;6.jar Server`

**To run the Client:**
`java -cp .;1.jar;2.jar;3.jar;4.jar;5.jar;6.jar Client`

Run one server instance and 3 client instances for the chat application to function.
