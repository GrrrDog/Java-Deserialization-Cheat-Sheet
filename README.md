# Java-Deserialization-Cheat-Sheet
A cheat sheet about Java Native Binary Deserialization vulnerabilities

From pentester for pentesters


### Overview
- [From Foxgloves Security](http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) 
- [From Terse Systems](https://tersesystems.com/2015/11/08/closing-the-open-door-of-java-object-serialization/)

### Main talks & presentaions 
##### AppSecCali 2015: Marshalling Pickles 
by [@frohoff](https://twitter.com/frohoff) & [@gebl](https://twitter.com/gebl)

- [Video](https://www.youtube.com/watch?v=KSA7vUkXGSg) 
- [Slides](http://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
- [Other stuff](http://frohoff.github.io/appseccali-marshalling-pickles/ )

##### Exploiting Deserialization Vulnerabilities in Java 
by [@matthias_kaiser](https://twitter.com/matthias_kaiser)

- [Video](https://www.youtube.com/watch?v=VviY3O-euVQ)

### Payload generators 
##### yososerial 
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

##### Universal billion-laughs DoS 
[https://gist.github.com/coekie/a27cc406fc9f3dc7a70d](https://gist.github.com/coekie/a27cc406fc9f3dc7a70d)

Won't fix DoS via default Java classes

##### ACEDcup 
[https://github.com/GrrrDog/ACEDcup](https://github.com/GrrrDog/ACEDcup)

File uploading via:
- Apache Commons FileUpload <= 1.3 (CVE-2013-2186) and Oracle JDK < 7u40 

### Exploits 

##### RMI 
- Protocol
- Default - 1099/tcp for registry

[yososerial](#yososerial) (works only on RMI registry service)

##### JMX 
- Protocol based on RMI
- Default - ?/tcp

[yososerial](#yososerial)

##### T3 of Oracle Weblogic
- Protoclo
- Default - 7001/tcp on localhost interface

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits) (doesn't work for all Weblogic versions)

##### Websphere 
[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)

##### JBoss 
- [JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)
- [https://github.com/njfox/Java-Deserialization-Exploit](https://github.com/njfox/Java-Deserialization-Exploit)

##### Jenkins 
[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)

##### Restlet  
- <= 2.1.2
- When Rest API accepts seriazed objects (ObjectRepresentation)

### Detect 

##### Code review 

##### Burp plugins 
- Look for the magic bytes 'ac ed 00 05' bytes  or 'rO0' for Base64
- [Java Deserialization Scanner ](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [SuperSerial](https://github.com/DirectDefense/SuperSerial)
- [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)

### Vulnerable apps (without public sploits)  
##### ActiveMQ
- <= 5.12.1
- [CVE-2015-5254](http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txthttp://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt)
 
- [Explanation of the vuln](https://srcclr.com/security/deserialization-untrusted-data/java/s-1893)

##### Atlassian Bamboo
- 2.2 <= version < 5.8.5
- 5.9.0 <= version < 5.9.7
- [CVE-2015-6576](https://confluence.atlassian.com/x/Hw7RLg)

##### Tomcat

### Protection 
- [Look-ahead Java deserialization](http://www.ibm.com/developerworks/library/se-lookahead/ )
- [NotSoSerial](https://github.com/kantega/notsoserial)
- [SerialKiller](https://github.com/ikkisoft/SerialKiller)
- [ValidatingObjectInputStream](https://issues.apache.org/jira/browse/IO-487)

### For Android 
- [One Class to Rule Them All: 0-Day Deserialization Vulnerabilities in Android](https://www.usenix.org/conference/woot15/workshop-program/presentation/peles)
- [Android Serialization Vulnerabilities Revisited](https://www.rsaconference.com/events/us16/agenda/sessions/2455/android-serialization-vulnerabilities-revisited)

### Other serialization 
##### XMLEncoder 
- [http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html](http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html)

##### XStream 
- [http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/)
- [http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html](http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html)
- [https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream)

##### Kryo
- [https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-1-kryo](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-1-kryo)
