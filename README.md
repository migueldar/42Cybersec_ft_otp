This code generates pseudo-random one time passwords following totp protocol specified in https://datatracker.ietf.org/doc/html/rfc6238

To run, execute ./ft_otp with -g to add the new password, which is saved in ft_otp.key and do ./ft_otp -k nameOfFileWithKey to generate new keys

Feel free to compile the code your self, all of the source code is here and can be compiled using go build (golang has to be installed in your system)
