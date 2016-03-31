# Java-Deserialization-Cheat-Sheet
A cheat sheet for pentesters about Java Native Binary Deserialization vulnerabilities

###  Table of content
- [Overview](#overview)
- [Main talks & presentaions ](#main-talks--presentaions)
- [Payload generators](#payload-generators)
- [Exploits](#exploits)
- [Detect](#detect)
- [Vulnerable apps (without public sploits/need more info)](#vulnerable-apps-without-public-sploitsneed-more-info)
- [Protection](#protection)
- [For Android](#for-android)
- [Other serialization types](#other-serialization-types)

### Overview
- [From Foxgloves Security](http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) 

### Main talks & presentaions 
##### Marshalling Pickles 
by [@frohoff](https://twitter.com/frohoff) & [@gebl](https://twitter.com/gebl)

- [Video](https://www.youtube.com/watch?v=KSA7vUkXGSg) 
- [Slides](http://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
- [Other stuff](http://frohoff.github.io/appseccali-marshalling-pickles/ )

##### Exploiting Deserialization Vulnerabilities in Java 
by [@matthias_kaiser](https://twitter.com/matthias_kaiser)

- [Video](https://www.youtube.com/watch?v=VviY3O-euVQ)

##### Serial Killer: Silently Pwning Your Java Endpoints
by [@pwntester](http://twitter.com/pwntester) & [@cschneider4711](http://twitter.com/cschneider4711)

- [Slides](https://www.rsaconference.com/writable/presentations/file_upload/asd-f03-serial-killer-silently-pwning-your-java-endpoints.pdf)
- [White Paper](http://community.hpe.com/hpeb/attachments/hpeb/off-by-on-software-security-blog/722/1/HPE-SR%20whitepaper%20java%20deserialization%20RSA2016.pdf)

##### Deserialize My Shorts: Or How I Learned To Start Worrying and Hate Java Object Deserialization  
by [@frohoff](https://twitter.com/frohoff) & [@gebl](https://twitter.com/gebl)

- [Slides](http://www.slideshare.net/frohoff1/deserialize-my-shorts-or-how-i-learned-to-start-worrying-and-hate-java-object-deserialization)

### Payload generators 
##### yososerial 
[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)

[Lastest release of ysoserial](https://github.com/frohoff/ysoserial/releases/download/v0.0.4/ysoserial-0.0.4-all.jar)

RCE via:

- Apache Commons Collections <= 3.1
- Apache Commons Collections <= 4.0
- Groovy <= 2.3.9
- Spring Core <= 4.1.4 (?)
- JDK <=7u21
- Apache Commons beanutils 1.9.2 + Commons Collections <=3.1 + Commons Logging 1.2 (?)

How does it work:
- [https://blog.srcclr.com/commons-collections-deserialization-vulnerability-research-findings/](https://blog.srcclr.com/commons-collections-deserialization-vulnerability-research-findings/)
- [http://gursevkalra.blogspot.ro/2016/01/ysoserial-commonscollections1-exploit.html](http://gursevkalra.blogspot.ro/2016/01/ysoserial-commonscollections1-exploit.html)

##### Universal billion-laughs DoS 
[https://gist.github.com/coekie/a27cc406fc9f3dc7a70d](https://gist.github.com/coekie/a27cc406fc9f3dc7a70d)

Won't fix DoS via default Java classes

##### ACEDcup 
[https://github.com/GrrrDog/ACEDcup](https://github.com/GrrrDog/ACEDcup)

File uploading via:
- Apache Commons FileUpload <= 1.3 (CVE-2013-2186) and Oracle JDK < 7u40 

### Exploits 

##### RMI 
- *Protocol*
- *Default - 1099/tcp for rmiregistry*

[yososerial](#yososerial) (works only against a RMI registry service)

##### JMX 
- *Protocol based on RMI*

[yososerial](#yososerial)

##### T3 of Oracle Weblogic
- *Protocol*
- *Default - 7001/tcp on localhost interface*
- CVE-2015-4852

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits) (doesn't work for all Weblogic versions)

##### Websphere 
- *wsadmin*
- *Default port - 8880/tcp*
- CVE-2015-7450

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)

##### JBoss 
- *http://jboss_server/invoker/JMXInvokerServlet*
- *Default port - 8080/tcp*
- CVE-2015-7501

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)

[https://github.com/njfox/Java-Deserialization-Exploit](https://github.com/njfox/Java-Deserialization-Exploit)

##### Jenkins 
- *Jenkins CLI*
- *Default port - High number/tcp*
- CVE-2015-8103

[JavaUnserializeExploits](https://github.com/foxglovesec/JavaUnserializeExploits)

##### Restlet
- *<= 2.1.2*
- *When Rest API accepts serialized objects (uses ObjectRepresentation)*

no spec tool

##### OpenNMS
- RMI

[yososerial](#yososerial)

##### Progress OpenEdge RDBMS
- RMI

[yososerial](#yososerial)

### Detect 
##### Code review 
- *ObjectInputStream.readObject*
- *ObjectInputStream.readUnshared*
- Tool: [Find Security Bugs](http://find-sec-bugs.github.io/)

##### Traffic
- *Magic bytes 'ac ed 00 05' bytes*
- *'rO0' for Base64*

##### Burp plugins 
- [Java Deserialization Scanner ](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [SuperSerial](https://github.com/DirectDefense/SuperSerial)
- [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)

### Vulnerable apps (without public sploits/need more info)  
##### ActiveMQ
- [*CVE-2015-5254*](http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txthttp://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt)
- *<= 5.12.1*
- [*Explanation of the vuln*](https://srcclr.com/security/deserialization-untrusted-data/java/s-1893)

##### Atlassian Bamboo 1
- [*CVE-2015-6576*](https://confluence.atlassian.com/x/Hw7RLg)
-  *2.2 <= version < 5.8.5*
- *5.9.0 <= version < 5.9.7*

##### Atlassian Bamboo 2
- [*CVE-2015-8360*](https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2016-01-20-794376535.html)
- *2.3.1 <= version < 5.9.9*
- Bamboo JMS port (port 54663 by default)

##### AMF (Action Message Format)
- *Protocol*

[Belch](https://appsec-labs.com/belch/)

##### Jenkins 2
- CVE-2016-0788

##### JSF ViewState
##### JMS (Java Messaging System)
##### Spring Service Invokerts (HTTP, JMS, RMI...)

##### Apache Camel 
- CVE-2015-5348

##### VMWare vCenter/vRealize (various) 
- CVE-2015-6934

##### Cisco 
- CVE-2015-6420

##### Symantec Endpoint Protection Manager 
- CVE-2015-6555

#####  McAfee ePolicy Orchestrator 
- CVE-2015-8765

##### Adobe Experience Manager 
- CVE-2016-0958

#####  Unify OpenScape 
- CVE-2015-8237
- CVE-2015-8238

##### Apache TomEE
- CVE-2015-8581
- CVE-2016-0779

##### IBM Congnos BI 
- CVE-2012-4858

#####  Commvault Edge Server 
- CVE-2015-7253

##### Apache SOLR 
- SOLR-8262

##### Apache Shiro 
- SHIRO-550

##### Apache HBase 
- HBASE-14799

##### Apache Tomcat
##### Apache Batchee
##### Apache JCS
##### Apache OpenJPA
##### Apache OpenWebBeans

### Protection 
- [Look-ahead Java deserialization](http://www.ibm.com/developerworks/library/se-lookahead/ )
- [NotSoSerial](https://github.com/kantega/notsoserial)
- [SerialKiller](https://github.com/ikkisoft/SerialKiller)
- [ValidatingObjectInputStream](https://issues.apache.org/jira/browse/IO-487)
- [Some protection bypasses](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md#serial-killer-silently-pwning-your-java-endpoints)

### For Android 
- [One Class to Rule Them All: 0-Day Deserialization Vulnerabilities in Android](https://www.usenix.org/conference/woot15/workshop-program/presentation/peles)
- [Android Serialization Vulnerabilities Revisited](https://www.rsaconference.com/events/us16/agenda/sessions/2455/android-serialization-vulnerabilities-revisited)

### Other serialization types
##### XMLEncoder 
- [http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html](http://blog.diniscruz.com/2013/08/using-xmldecoder-to-execute-server-side.html)

##### XStream 
- [http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/)
- [http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html](http://blog.diniscruz.com/2013/12/xstream-remote-code-execution-exploit.html)
- [https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream)

##### Kryo
- [https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-1-kryo](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-1-kryo)
