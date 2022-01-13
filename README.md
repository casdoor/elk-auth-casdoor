# elk-auth-casdoor
This is a reverse proxy plugin for authenticating elk's user with casdoor. This plugin intercepts all users' requests towards kibana, check whether this user  is authenticated by casdoor. 

Request will be proceeded if this user has been correctly authenticated. 

If this user hasn't been correctly authenticated, request will be temporarly cached, and the user will be redirect to Casdoor login page. After user correctly logs in through casdoor, the cached request will be restored and sent to kibana. So it's ok if a POST request (or something other than GET) is intercepted, and user won't need to refill the form and resend the request. The reverse proxy will remember it for you.

## Quick start

1. register your proxy as an app of Casdoor.

2. modify the configuration

The configuration file locates in "conf/app.conf".
```ini
appname = .
# port on which the reverse proxy shall be run
httpport = 8080
runmode = dev
#EDIT IT IF NECESSARY. The url of this reverse proxy
pluginEndpoint="http://localhost:8080"
#EDIT IT IF NECESSARY. The url of the kibana 
targetEndpoint="http://localhost:5601"
#EDIT IT. The url of casdoor 
casdoorEndpoint="http://localhost:8000"
#EDIT IT. The clientID of your reverse proxy in casdoor  
clientID=ceb6eb261ab20174548d
#EDIT IT. The clientSecret of your reverse proxy in casdoor 
clientSecret=af928f0ef1abc1b1195ca58e0e609e9001e134f4
#EDIT IT. The application name of your reverse proxy in casdoor 
appName=ELKProxy
#EDIT IT. The organization to which your reverse proxy belongs in casdoor
organization=built-in
```
3. `go run main.go`

4. visit <http://localhost:8080>, and log in following the guidance of redirection, and you shall see kibana protected and authenticated by casdoor.

5. If everything works well, don't forget to block the visits of original kibana's port comming from outside by configurating your firewall(or something else), so that outsiders can only visit kibana via this reverse proxy.