What can I do to protect my own code from padding oracle attacks?
If you're using symmetric encryption, that's easy. Simply use authenticated encryption, or put a MAC on all of your ciphertexts. Do this correctly and Vaudenay padding oracles will not trouble you.

RSA encryption is more difficult. The 'best practice' in implementing RSA is: don't implement RSA. Other people have done it better than you can. Go find a good implementation of RSA-OAEP and use that. End of story.

Unfortunately, even with RSA-OAEP, this can be difficult. There are attacks on OAEP encryption too (some are mentioned in this paper).

http://blog.cryptographyengineering.com/2012/06/bad-couple-of-years-for-cryptographic.html
