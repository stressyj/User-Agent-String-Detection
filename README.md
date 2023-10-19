<h1>User Agent Strings Detection Using Splunk</h1>


<h2>Description</h2>
In This project, I'll be walking you through a step by step tutorial on how to capture User Agent Strings in order to detect potential adversaries or APTs in a network.
<br />


<h2>Languages and Utilities Used</h2>

- <b>Splunk</b> 
- <b>whois.domaintools.com</b>
- <b>ripe.whois.net</b> 
- <b>whatsmybrowser.com</b>

<h2>Environments Used </h2>

- <b>Splunk</b> 

<h2>Program walk-through:</h2>

I am going to want to start by having a look at metadata just so I have an understanding of my data:

<p align="left">
| metadata type=sourcetypes index=main

&nbsp;


I want to see all the hosts that have data in the ‘os’ index because I know data in that index may be of importance to me in my hunt:

<p align="left">
| metadata type=hosts index=os

&nbsp;

Let us just navigate the environment and know what kind of data we are working with:

<p align="left">
| metadata type=sourcetypes index=main
<p align="left">
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S")
<p align="left">
| eval lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
<p align="left">
| eval recentTime=strftime(recentTime, "%Y-%m-%d %H:%M:%S")

&nbsp;

I may want to check if there are specific hosts that have not sent data to Splunk in the past 24 hours. The command for that is:

<p align="left">
| metadata type=sourcetypes index=main
<p align="left">
| Eval “Last Seen”=now()-recentTime
<p align="left">
| search “Last Seen” > 86400
<p align="left">
| rename totalCount as Count firstTime as “First Event” lastTime as “Last Event” recentTime as “Last Update”
<p align="left">
| fieldformat “First Event” =strftime(‘First Event’, c%)
<p align="left">
| fieldformat “Last Event” =strftime(‘Last Event’, c%)
<p align="left">
| fieldformat “Last Update” =strftime(‘Last Update’, c%)
<p align="left">
| eval “Minutes Behind”= round((‘Last Seen’ /60),
<p align="left">
| eval “Hours Behind”= round((‘Last Seen’ /3600),
<p align="left">
| table host, “First Event” “Last Event” “Last Update” “Hours Behind” “Minutes Behind”
<p align="left">
| sort - “Minutes Behind”

&nbsp;


I’ll click on apps then enterprise security to check for assets and identities. I’ll then go to security domains then identity then asset center for systems then identify center for users.

<p align="center">
<br/>
<img src="https://i.imgur.com/jv7TPGV.png" height="80%" width="80%" alt="Assets and Identities"/>
<br />

&nbsp;

I’m going to start with looking for user agent strings to see where the adversary may be sloppy with their trade craft and left some nice clues for us. The command for this is:

<p align="left">
Index=main sourcetype=stream:http site=www.company.com
<p align="left">
| stats count by http_user_agent
<p align="left">
| sort - count

&nbsp;

Now perhaps I have seen some dodgy user agent strings or maybe there are some that look a little fishy, I am going to go to https://explore.whatismybrowser.com/useragents/parse/#parse-useragent

Now when I go through these user agent strings, I’m going to be looking for indicators that show me it’s foreign. E.g a foreign language code like ko-KP instead of en-US or foreign font particularly Chinese or Russian. Ko-KP is North Korean.

Let's say I have found a dodgy sounding browser like "NaenaraBrowser/3.5b4". That's going to ring alarm bells.


Googling the browser will help give us an insight into where the browser is from. Here it shows it's from North Korea.

<p align="center">
<br/>
<img src="https://i.imgur.com/glHMPoo.jpg" height="80%" width="80%" alt="Assets and Identities"/>
<br />

&nbsp;

Let’s say I find a dodgy string. I’m going to drill down into it and see what systems this user agent touched. I’ll particularly have a look at the uri_path

<p align="center">
Index=main sourcetype=stream:http site=www.company.com 
“Mozilla/5.0 (X11; U; Linux i686; ko-KP, rv: 19.1 1br) Gecko/20130508 Fedora/1.9 1-2.5. Rs3.0 NaenaraBrowser/3.5b4”

&nbsp;

I am now going to check which systems this User Agent has touched. Here is the command:

<p align="center">
Index=main sourcetype=stream:http site=www.company.com 
“Mozilla/5.0 (X11; U; Linux i686; ko-KP, rv: 19.1 1br) Gecko/20130508 Fedora/1.9 1-2.5. Rs3.0 NaenaraBrowser/3.5b4”
| stats count by src dest

&nbsp;

Once I’ve seen the source / destination ip pairs that are linked to this user agent string. I can then go back to the asset centre to see which systems are linked to particular ip addresses.

<p align="center">
<br/>
<img src="https://i.imgur.com/VmXYSIq.png" height="80%" width="80%" alt="Assets and Identities"/>
<br />

&nbsp;

Let's say during my search, I came across these fictional IP addresses/systems that the User Agent has interacted with. I’ll run the following commands to look for any extra activity
/Traffic going between them in either direction:

Index=main sourcetype=stream:http src=102.203.47.86 dest=172.16.0.92
| stats count

Index=main sourcetype=stream:http src=172.16.0.92 dest=102.203.47.86
| stats count

&nbsp;

Https://whois.domaintools.com will give us information about the IP address.

<p align="center">
<br/>
<img src="https://i.imgur.com/whIsaJi.png" height="80%" width="80%" alt="Assets and Identities"/>
<br />

&nbsp;

A search with [Ripe.Whois.net](https://apps.db.ripe.net/db-web-ui/query) will give us the asn:

<p align="center">
<br/>
<img src="https://i.imgur.com/XjmAi7i.png" height="80%" width="80%" alt="Assets and Identities"/>
<br />


The ASN or autonomous system number and the RIR or regional internet register could be looked into and it’s possible to determine the route that the attacker took to get to our systems.

I will go on v4.whois.cymru.com lookup v1.0 to confirm my findings.

I’ll also google any VPN’s I see during the look up.

If I drill down for more detail. I could go on the sourcetype=stream:http field to have a look at the http_content_type and have a look at the uri_path. Let's assume I've found
an companycontacts.xlsx file served up to a naenara browser request: 

I’ll gather up URI path, timestamps and url and include it in my search:

Index=main sourcetype=stream:http “Mozilla/5.0 (x11; U , Linux i686; ko-KP, rv: 19.1 1br) Gecko/2939363 Fedora/1.9 1-2.5. Rs3.0 NaemaraBrowser/3.5b4” http_content_type = companycontacts.xlsx
| table _time src dest uri_path url

Which should indicate that the source ip address downloaded the file from the company website. 




