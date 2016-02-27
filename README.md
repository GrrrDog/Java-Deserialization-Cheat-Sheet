# ACED-Cheat-Sheet
A cheat sheet about Java Native Binary Deserialization vulnerabilities

For pentesters

## Overview ##
- [From Foxgloves Security](http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) 
- [From Terse Systems](https://tersesystems.com/2015/11/08/closing-the-open-door-of-java-object-serialization/)

## Main talks & presentaions ##
### AppSecCali 2015: Marshalling Pickles ###
by [@frohoff](https://twitter.com/frohoff) & [@gebl](https://twitter.com/gebl)

- [Video](https://www.youtube.com/watch?v=KSA7vUkXGSg) 
- [Slides](http://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
- [Other stuff](http://frohoff.github.io/appseccali-marshalling-pickles/ )

### Exploiting Deserialization Vulnerabilities in Java ###
by [@matthias_kaiser](https://twitter.com/matthias_kaiser)

- [Video](https://www.youtube.com/watch?v=VviY3O-euVQ)

## Payload generators ###
### yososerial ###
[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)

RCE via:

- Apache Commons Collections <= 3.1
- Apache Commons Collections <= 4.0
- Groovy <= 2.3.9
- Spring Core <= 4.1.4 (?)
- JDK <=7u21
- Apache Commons beanutils 1.9.2 + Commons Collections <=3.1 + Commons Logging 1.2 (?)

How does it work:
- [https://blog.srcclr.com/commons-collections-deserialization-vulnerability-research-findings/](https://blog.srcclr.com/commons-collections-deserialization-vulnerability-research-findings/)

### Universal billion-laughs DoS ###
[https://gist.github.com/coekie/a27cc406fc9f3dc7a70d](https://gist.github.com/coekie/a27cc406fc9f3dc7a70d)

Won't fix DoS via default Java classes

### ACEDcup ###
[https://github.com/GrrrDog/ACEDcup](https://github.com/GrrrDog/ACEDcup)

Any file upload via Apache Commons FileUpload <= 1.3 (CVE-2013-2186) and Oracle JDK < 7u40 

## Exploits ##
[Foo](#yososerial)
### RMI ###
### JMX ###
### T3 (Weblogic) ###
### Websphere ###
### Jenkins ###
### Restlet ###
### Bamboo ###

## Detectors ##

## Tips ## 
find
Active
addons

## Vulnerable apps (without sploits) ## 
activemq

## Protection ##
### Theory ###

### NotSoSerial ###
[https://github.com/kantega/notsoserial](https://github.com/kantega/notsoserial)

### SerialKiller ###
[https://github.com/ikkisoft/SerialKiller](https://github.com/ikkisoft/SerialKiller)

## Other serialization ##
### XMLEncoder ###
[http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html](http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html)

### XStream ###
[http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html](http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html)
[http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/)
[https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream)
