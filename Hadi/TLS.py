import requests
import socket
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning, SSLError
from urllib3.exceptions import InsecureRequestWarning
#---------------------------------------------------------------------------------------------------------------------------------------------------by Hadi

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)#disable InsecureRequestWarning to suppress SSL/TLS-related warnings

def checkSSLTLS(url): #takes a URL as input and checks various SSL/TLS features.
    try:
        #check for HTTPS support
        httpsURL = 'https://' + url #constructing an HTTPS URL.
        responseHTTPS = requests.get(httpsURL, verify=False) #using requests.get to make an http GET request to the provided url with ssl verification disabled
        
        if responseHTTPS.status_code == 200:#if the HTTPS response has a status code of 200, 
                                            #set the protocol to 'https'
           
            urlProtocol = 'https'
        
        else:
            print(f"The website {url} does not support HTTPS and is vulnerable to SSL stripping.") #else print it doesn't support https
            return

        #check HSTS
        if urlProtocol == 'https' and 'Strict-Transport-Security' in responseHTTPS.headers: #checks for HSTS (HTTPS Strict-Transport-Security) in https header
            print(f"The website {httpsURL} has HSTS enabled.") #prints it has hsts
        elif urlProtocol == 'https':
            print(f"The website {httpsURL} does not have HSTS enabled and might be vulnerable to SSL stripping.")#else prints website doesn't have hsts
        
        #creating a custom SSL context to get SSL/TLS information, this part is from chatgpt-------------------------------------------------------
        hostname = url.split('://', 1)[-1].split('/')[0] # Extract the hostname from the URL.
        sslContext = ssl.create_default_context() # Use ssl.create_default_context() to create a default SSL context
        conn = sslContext.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) # Wrap the socket with the SSL context to create a secure socket.
        conn.connect((hostname, 443)) # Establish a connection to the server using the SSL-wrapped socket.
            
        
        print(f"Cipher suite: {conn.cipher()}")#prints cipher suite
        print(f"SSL/TLS version: {conn.version()}")#prints TLS version
#--------------------------------------------------------------------------------------------------------------------------------------------------      
        # Check for secure flag in cookies
        if 'Set-Cookie' in responseHTTPS.headers:
            cookies = responseHTTPS.headers['Set-Cookie'].split(';')
            for cookie in cookies:
                if 'Secure' in cookie:
                    print("Secure flag found in cookies.")  #prevents the attacker from easily capturing sensitive session cookies because 
                                                            #the browser will not send them over an unsecured HTTP connection
                    break
            else:
                print("Warning: Some cookies do not have the 'Secure' flag.")#checks for Set-Cookie in the header
        
    except (requests.exceptions.RequestException, SSLError) as e:
        print(f"Error: {e}")#handles errors

checkSSLTLS('www.socialstudieshelp.com/')#takes website as input
