# ez-SYN-TCP-FLOOD
The simplest TCP SYN Flooder 


Read more on SYN Flooding: https://en.wikipedia.org/wiki/SYN_flood 


#### Catch the flooding with something as simple as this in your Intrusion Detection System
```
alert tcp any any -> $HOME_NET any (flags: S; msg:"Possible TCP SYN Flood"; flow: stateless; threshold: type both, track by_src, count 50, seconds 10; sid:10001;rev:1;)
```
