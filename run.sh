#docker build -t truebad0ur/ssh-honeypot:v0.0.6 .
docker run -p 22:22 -v $(pwd)/app/honeypot.db:/project/honeypot.db ssh-honeypot:v0.0.6
#litecli