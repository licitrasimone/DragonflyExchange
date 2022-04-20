# DragonflyExchange
implementation of Dragonfly Exchange using ECC

The Dragonfly exchange consists of two message exchanges, a "Commit Exchange" in which both sides commit to a single guess of the 
password, and a "Confirm Exchange" in which both sides confirm knowledge of the password.  A side effect of running the Dragonfly
exchange is an authenticated, shared, and secret key whose cryptographic strength is set by the agreed-upon group.
