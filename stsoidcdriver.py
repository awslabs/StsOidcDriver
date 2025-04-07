from bottle import Bottle, request, response, redirect
import requests
import os
import webbrowser
import argparse
from urllib.parse import urlencode
import json
import boto3
import botocore.config
import threading
import time
import secrets
import base64
import logging
import hashlib
import sys
import jwt #confusingly named package, make sure you're using pyjwt 
import traceback

app = Bottle()

# Configuration. Globals here are constants through the lifecycle of an execution.
PORT = 6432 #6432 is "OIDC" with the standard touch pad letter/number mapping.
REDIRECT_URI = f'http://localhos:{PORT}/callback' #You could change this, but in almost all cases you would want this to be only on localhost and not exposed over a network or on a remote server.
STATE = secrets.token_urlsafe(32)
NONCE = secrets.token_urlsafe(16)
CODE_VERIFIER = secrets.token_urlsafe(32)
CODE_CHALLENGE = base64.urlsafe_b64encode(
            hashlib.sha256(CODE_VERIFIER.encode('ascii')).digest()
        ).decode('ascii').rstrip('=')
shutdown_flag = threading.Event()
USER_AGENT = "STS OIDC Driver (Python Requests)" #Useragent for bare requests calls
BOTO_SESSION_CONFIG = botocore.config.Config( user_agent_extra="StsOIDCDriver") #useragent for boto3 calls
SCOPES = "openid email" #this is the default set of scopes for using OIDC/Oauth. Your provider may require custom and you may need to consult your docs. 
#Okta requires the "offline_access" scope and there is a hack for that later.
IS_DYNAMIC_CLIENT = False #not dynamic until proven otherwise





logger = logging.getLogger('stsoidcdriver')
logger.setLevel(logging.INFO)  # Default level
handler = logging.StreamHandler()
formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class DynamicClient:
    def __init__(self):
        self.client_id = None
        self.client_secret = None

    def register_client(self, registration_endpoint):
        logger.debug(f"Starting client registration at endpoint: {registration_endpoint}")
        client_name_randomness = secrets.token_urlsafe(8)

        try:
            registration_data = {
                "application_type": "native",
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "none",  # Simplest auth method for public clients If there is demand for autheticated, dynamic, public clients, we'll add that in!
                "response_types": ["code"],  
                "grant_types": ["authorization_code"],  
                "client_name": f"AWS STS OIDC Driver {client_name_randomness}",
                "code_challenge_methods_supported": ["S256"]
            }
            logger.debug("Attempting registration with payload:")
            logger.debug(json.dumps(registration_data, indent=2))

            response = requests.post(
                registration_endpoint,
                json=registration_data,
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT },
                timeout=5
            )
            
            logger.debug(f"Registration response status: {response.status_code}")
            logger.debug("Response headers:")
            logger.debug(json.dumps(dict(response.headers), indent=2))
            
            try:
                 response_json = response.json()
                 logger.debug("Response body:")
                 logger.debug(json.dumps(response_json, indent=2))
            except json.JSONDecodeError:
                 logger.error(f'Failed registering dynamic client')
                 logger.debug("Raw response body:")
                 logger.debug(response.text)
                 sys.exit(1)
                
            if response.status_code == 201:
                registration_response = response.json()
                self.client_id = registration_response['client_id']
                logger.debug(f"Successfully registered client with ID: {self.client_id}")
                return True
            else:
                logger.debug(f"Registration failed with status {response.status_code}")
                return False

        except Exception as e:
            logger.debug(f"Exception during registration: {str(e)}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            return False



def get_oidc_config():
    try:
        response = requests.get(OIDC_DISCOVERY_URL,headers={"User-Agent": USER_AGENT},timeout=5)
        config = response.json()    
        logger.debug(f"OIDC configuration received: {json.dumps(config, indent=2)}")
    except Exception as e:
        logger.error(f"Failed to get OIDC configuration from {OIDC_DISCOVERY_URL} with error {e}")
        sys.exit("Issue communicated with OIDC provider. Check the provider URL provided.")
    return config



""" HTTP LOGIC"""
@app.route('/')
def home():
    """Initial page that starts the OIDC flow. Browsers will be open to this."""
    logger.debug(f"Server received request on \"/\"")
    scopes = SCOPES 
    auth_parms = {}
    if  not IS_DYNAMIC_CLIENT and not IMPLICIT :  
        #Not Dynamic and Not Implic = Authorization Code Grant for a public client
        if "okta.com" in OIDC_DISCOVERY_URL.lower():
            scopes = "openid email offline_access" #okta requires this for a public client using authorization code grant, other IDP's don't support it.
            logger.debug(f"Okta native client detected, setting scopes to {scopes}")


        logger.debug(f"We believe this is a public client using authz code flow")
        auth_params = {
            'client_id': OIDC_CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'scope': scopes,
            'state': STATE,
            'nonce': NONCE,
            "code_challenge": CODE_CHALLENGE,
            "code_challenge_method": "S256"
            }
        
    elif IS_DYNAMIC_CLIENT:
        #No client_id was specified, so we're going to try to register a dynamic one.
        logger.debug(f"We believe this is a dynamic client using authz code flow")
        #If the user doesn't give us a CLIENT_ID, we will try to do dynamic client registration
        #This did work well with Auth0, but need further IDPs to test with
        DYNAMIC_CLIENT.register_client(OIDC_CONFIG['registration_endpoint'])
        auth_params = {
            'client_id': DYNAMIC_CLIENT.client_id,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'scope': scopes,
            'state': STATE,
            'nonce': NONCE,
            "code_challenge": CODE_CHALLENGE,
            "code_challenge_method": "S256"
             }
        
    elif not IS_DYNAMIC_CLIENT and IMPLICIT:
        #Customer is using implicit grant
        logger.debug(f"We believe this is a public client using implicit flow")
        auth_params = {
            'client_id': OIDC_CLIENT_ID,
            'response_type': 'id_token token',
            'redirect_uri': REDIRECT_URI,
            'scope': scopes,
            'state': STATE,
            'nonce': NONCE,
            "code_challenge": CODE_CHALLENGE,
            "code_challenge_method": "S256"
            }

    
    auth_url = f"{OIDC_CONFIG['authorization_endpoint']}?{urlencode(auth_params)}"
    return redirect(auth_url)  #


"""For portability and packaging, the HTML and javascript response are within this same file."""
@app.route('/callback')
def callback():
    logger.debug(f"Server received on /callback")
    return f"""
    <!doctype html>
    <head><title>Handling OIDC</title></head>
    <body>
       <script>
            (function() {{
             function signalAuthFailure(reason) {{
        fetch('/auth/authfail', {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json'
            }},
            body: JSON.stringify({{ reason: reason }})
        }})
    }}        
                      
                        {{
                const urlParams = new URLSearchParams(window.location.search);
                const code = urlParams.get('code');
                
                function handleError(response) {{
                    if (!response.ok) {{
                        return response.json().then(errorData => {{
                            throw new Error(errorData.message || 'Authentication failed');
                        }});
                    }}
                    return response.json();
                }}

                function showError(message) {{
                    document.body.innerHTML = `
                        <div style="text-align: center; padding: 20px; font-family: Arial, sans-serif;">
                            <h2 style="color: #c62828;">❌ Authentication Failed</h2>
                            <p style="color: #c62828;">${{message}}</p>
                            <p style="color: #c62828;">$Additional debug information from your identity provider may be present in the address bar. </p>
                            <p>Please close this window and try again.</p>
                        </div>`;
                }}

                function showSuccess() {{
                    document.body.innerHTML = `
                        <div style="text-align: center; padding: 20px; font-family: Arial, sans-serif;">
                            <h2 style="color: #2e7d32;">✅ Authentication Successful for role {AWS_ROLE_ARN}!</h2>                                    
                            <p>Your AWS credentials have been updated in the file <strong>{AWS_CONFIG_FILE}</strong> in the profile <strong>{PROFILE_TO_UPDATE}</strong></p>
                            <p>To reference this profile with the AWS CLI, use <strong>--profile {PROFILE_TO_UPDATE}</strong> with all AWS CLI commands </p>
                            <p>To use this profile with the AWS SDK, please see your SDK's documentation on specifying a profile for credentials </p>
                            <p>You may now close this window.</p>
                        </div>`;
                        window.location.hash = '';
                }}
                
                if (code) {{
                    console.log("Detected authorization code flow");
                    const receivedState = urlParams.get('state');
                    if (!receivedState || receivedState !== '{STATE}') {{
                            showError('Invalid state parameter');
                            signalAuthFailure('invalid_state');
                            return;
                            }}
                    
                    fetch('/process_token', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            code: code,
                            grant_type: 'authorization_code'
                        }})
                    }})
                    .then(handleError)
                    .then(data => {{
                        if (data.status === 'success') {{
                            showSuccess();
                        }} else {{
                            showError(data.message || 'Unknown error occurred');
                            signalAuthFailure('unknown_error');
                        }}
                    }})
                    .catch(error => {{
                        showError(error.message || 'Failed to process authentication');
                        signalAuthFailure('unknown_error');
                    }});
                    
                }} else {{
                    const hash = window.location.hash.substr(1);
                    const result = hash.split('&').reduce((result, item) => {{
                        const [key, value] = item.split('=');
                        result[key] = decodeURIComponent(value);
                        return result;
                    }}, {{}});

                    if (!result.state || result.state !== '{STATE}') {{
                            showError('Invalid state parameter');
                            signalAuthFailure('invalid_state');
                            return;
                            }}
                    if (result.id_token) {{
                        console.log("Detected implicit flow");

                        fetch('/process_token', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                            }},
                            body: JSON.stringify({{
                                id_token: result.id_token,
                                grant_type: 'implicit'
                            }})
                        }})
                        .then(handleError)
                        .then(data => {{
                            if (data.status === 'success') {{
                                showSuccess();
                            }} else {{
                                showError(data.message || 'Unknown error occurred');
                                signalAuthFailure('unknown_error');
                            }}
                        }})
                        .catch(error => {{
                            showError(error.message || 'Failed to process authentication');
                            signalAuthFailure('unknown_error');
                        }});
                    }} else {{
                        showError('No code or token found in response');
                        signalAuthFailure('no_token');
                    }}
                }}
            }}
            }}
            )();
        </script>
        <div style="text-align: center; padding: 20px; font-family: Arial, sans-serif;">
            <p>Processing authentication...</p>
        </div>
    </body>
    """

@app.route('/auth/authfail', method='POST')
def auth_failure():
    try:
        data = request.json
        logger.info(f"Requested by front end to shutdown for: {data['reason']}")
    except:
        logger.info("Received request to terminate from frontend, no reason received")
    logger.debug(f"Server received request on /auth/authfail")
    shutdown_flag.set()

    return {'status': 'success'}



def handle_authorization_code(code):
    """Handle authorization code grant flow"""
    logger.debug("Authorization code received on /process_token")
    
    if IS_DYNAMIC_CLIENT:
        return handle_dynamic_client_token_exchange(code)
    else:
        return handle_standard_token_exchange(code)

def handle_dynamic_client_token_exchange(code):
    """Handle token exchange for dynamic clients"""
    logger.debug("/process_token is handling a dynamic client")
    token_response = requests.post(
        OIDC_CONFIG['token_endpoint'],
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': DYNAMIC_CLIENT.client_id,
            "code_verifier": CODE_VERIFIER
        },
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            "User-Agent": USER_AGENT
        },
        timeout=5
    )
    return process_token_response(token_response)

def handle_standard_token_exchange(code):
    """Handle token exchange for standard clients"""
    logger.debug("/process_token is handling a non-dynamic client using authorization code grant")
    token_response = requests.post(
        OIDC_CONFIG['token_endpoint'],
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': OIDC_CLIENT_ID,
            'code_verifier': CODE_VERIFIER
        },
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            "User-Agent": USER_AGENT
        },
        timeout=5
    )
    return process_token_response(token_response)

def process_token_response(token_response):
    """Process the token response and extract id_token"""
    if token_response.status_code != 200:
        logger.info(f"Token exchange failed: {token_response.text}")
        response.status = 400
        return {'status': 'error', 'message': f'Acquiring tokens from OpenID Provider Failed: {token_response.text}'}

    tokens = token_response.json()
    try:
        id_token = tokens.get('id_token')
    except:
        print("No id_token in token response")
        response.status = 400
        return {'status': 'error', 'message': 'No id_token in token response'}
    
    try:
        access_token = tokens.get('access_token')
    except:
        logger.debug("no access token in server response")
        access_token = None
        pass

    
    return {'status': 'success', 'id_token': id_token, 'access_token': access_token}

def assume_role_with_token(token):
    """Assume AWS role using the JWT passed into this method"""
    logger.debug("Attempting to assume role with web identity")
    try:
        sts = boto3.client('sts', region_name=AWS_REGION, config=BOTO_SESSION_CONFIG)
        decoded_token = jwt.decode(token, options={"verify_signature": False}) #we're just grabbing the sub without verifying the JWT. JWT validation is the responsibility of STS in this case.

        #tryign to claims that will likely identify the end user

        try:
            role_session_name = decoded_token["email"]
            logger.debug(f"using the email claim with a value of ${role_session_name} for the assume role call")
        except:
            role_session_name = decoded_token["sub"]
            logger.debug(f"using the sub claim with a value of ${role_session_name} for the assume role call")
        
        sts_response = sts.assume_role_with_web_identity(
            RoleArn=AWS_ROLE_ARN,
            RoleSessionName=role_session_name, #above, we try to grab email if it's present, and fail back to sub. you can customize this
            WebIdentityToken=token,
            DurationSeconds=DURATION_SECONDS
        )
        return {'status': 'success', 'credentials': sts_response['Credentials']}
    except Exception as e:
        print(f"Exception during role assumption: {str(e)}")
        shutdown_flag.set()
        response.status = 400
        return {'status': 'error', 'message': f'Failed to assume role with web identity {str(e)}'}

def write_credentials(credentials):
    """Write AWS credentials to config file"""
    config = f"""[{PROFILE_TO_UPDATE}]
aws_access_key_id = {credentials['AccessKeyId']}
aws_secret_access_key = {credentials['SecretAccessKey']}
aws_session_token = {credentials['SessionToken']}
"""
    
    os.makedirs(os.path.dirname(AWS_CONFIG_FILE), exist_ok=True)
    with open(AWS_CONFIG_FILE, 'w') as f:
        f.write(config)
    
    print(f"Successfully wrote credentials to profile {PROFILE_TO_UPDATE} in {AWS_CONFIG_FILE}")
    return {'status': 'success'}

@app.route('/process_token', method='POST')
def process_token():
    """Process the authorization code or ID token and get AWS credentials"""
    try:
        data = request.json
        if not data:
            logger.debug("No body received on post to /process_token")
            response.status = 400
            return {'status': 'error', 'message': 'No JSON data received'}

        # Handle authorization code flow
        if 'code' in data:
            result = handle_authorization_code(data['code'])
            if result['status'] != 'success':
                return result
            id_token = result['id_token']
            logger.debug(f"Received id_token: {id_token}")
            try:
                access_token = result['access_token']
                logger.debug(f"Received access token: {access_token}")
            except:
                logger.debug("no access token in response")
                pass
        
        # Handle implicit flow
        elif 'id_token' in data:
            logger.debug("/process_token is handling an implicit flow request")
            id_token = data['id_token']
            logger.debug(f"Received id_token: {id_token}")
            try:
                access_token = result['access_token']
                logger.debug(f"Received access token: {access_token}")
            except:
                logger.debug("no access token in response")
                pass
        
        else:
            logger.debug("no id_token or code found in the post to /process_token")
            response.status = 400
            return {'status': 'error', 'message': 'No code or id_token provided'}

        # Assume role and write credentials
        # Because this tool is built around OIDC, it will use the id_token. However if you wanted to use an access token here, you could by changing the below line.
        assume_result = assume_role_with_token(id_token)
        if assume_result['status'] != 'success':
            return assume_result
        
        write_result = write_credentials(assume_result['credentials'])
        shutdown_flag.set()
        return write_result

    except Exception as e:
        print(f"Error in when attempting to process token or authorization code: {str(e)}")
        response.status = 500
        return {'status': 'error', 'message': str(e)}

def open_browser():
    """Open browser after a short delay to ensure server is running"""
    # time.sleep(0.5)  # Wait for server to start
    webbrowser.open(f'http://localhost:{PORT}',new=1)

def main():
    parser = argparse.ArgumentParser(description='STS OIDC driver. Gets credentials for AWS using OIDC.')
    parser.add_argument('--role', help='Role ARN to assume')
    parser.add_argument('--openid_url', help='OpenID Connect Discovery URL')
    parser.add_argument('--client_id', help='Optional Client ID (if not using dynamic registration)')
    parser.add_argument('--region', type=str, default='us-east-1', help='AWS Region (default: us-east-1)')
    parser.add_argument('--duration-seconds', type=int, default=3600, help='seconds to assume role for (3600 default)')
    parser.add_argument('--profile-to-update', type=str,help='the name of the AWS profile to update when')
    parser.add_argument('--aws-config-file', type=str, help='path to aws config file you want updated. used with profile')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--implicit', action='store_true', help='use implicit grant. Not recommended. Requires client_id')
    
    args = parser.parse_args()

    # These globals are set based on input from the user.
    global AWS_ROLE_ARN, OIDC_DISCOVERY_URL, OIDC_CLIENT_ID, PROFILE_TO_UPDATE, AWS_CONFIG_FILE, AWS_REGION, IMPLICIT, OIDC_CONFIG, DYNAMIC_CLIENT, DURATION_SECONDS

    if args.role:
        AWS_ROLE_ARN = args.role
    elif os.environ.get('AWS_ROLE_ARN'):
        AWS_ROLE_ARN = os.environ.get('AWS_ROLE_ARN')
    else:
        sys.exit("You must provide a role ARN either via --role or AWS_ROLE_ARN environment variable")

    if args.implicit:
        IMPLICIT = args.implicit
    else:
        IMPLICIT = False

    if args.openid_url:
        OIDC_DISCOVERY_URL = args.openid_url
    elif os.environ.get('OIDC_DISCOVERY_URL'):
        OIDC_DISCOVERY_URL = os.environ.get('OIDC_DISCOVERY_URL')
    else:
        sys.exit("You must provide an OIDC discovery URL either via --openid_url or OIDC_DISCOVERY_URL environment variable")   

    if not ".well-known/openid-configuration" in OIDC_DISCOVERY_URL:
        #We will append .well-known/openid-configuration, if not present.
        OIDC_DISCOVERY_URL = f"{OIDC_DISCOVERY_URL.rstrip('/')}/.well-known/openid-configuration"

    if args.client_id:
        OIDC_CLIENT_ID = args.client_id
    elif os.environ.get('OIDC_CLIENT_ID'):
        OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID')
    else:
        #By the user not specifying a client_id, we infer this is a dynamic client
        IS_DYNAMIC_CLIENT = True
        OIDC_CLIENT_ID="dynamic" #doesn't actually get used
        DYNAMIC_CLIENT = DynamicClient()


    if args.aws_config_file:
        AWS_CONFIG_FILE = args.aws_config_file
    elif os.environ.get("AWS_CONFIG_FILE"):
        AWS_CONFIG_FILE = os.environ.get("AWS_CONFIG_FILE")
    else:
        AWS_CONFIG_FILE = os.path.expanduser("~/.aws/credentials")

    if args.profile_to_update:
        PROFILE_TO_UPDATE = args.profile_to_update
    elif os.environ.get("PROFILE_TO_UPDATE"):
        PROFILE_TO_UPDATE = os.environ.get("PROFILE_TO_UPDATE")
    else:
        PROFILE_TO_UPDATE = "default"

    if args.duration_seconds:
        DURATION_SECONDS = args.duration_seconds
    elif os.environ.get("DURATION_SECONDS"):
        DURATION_SECONDS = os.environ.get("DURATION_SECONDS")
    else:
        DURATION_SECONDS = 3600
    
    #make the ARWWI calls use regional endpoints. silly hack.
    os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = "regional"
    if args.region:
        AWS_REGION = args.region
    elif os.environ.get("AWS_REGION"):
        AWS_REGION = os.environ.get("AWS_REGION")
    else:
        AWS_REGION = "us-east-1"

    OIDC_CONFIG = get_oidc_config()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.debug(f"Using OIDC discovery URL: {OIDC_DISCOVERY_URL}")
    logger.debug(f"Using OIDC client ID: {OIDC_CLIENT_ID}")
    logger.debug(f"Using AWS role ARN: {AWS_ROLE_ARN}")
    logger.debug(f"Using AWS config file: {AWS_CONFIG_FILE}")
    logger.debug(f"Using AWS profile: {PROFILE_TO_UPDATE}")
    logger.debug(f"Using AWS region: {AWS_REGION}")
    logger.debug(f"Using DURATION_SECONDS: {DURATION_SECONDS}")


    # Start the server in a separate thread
    server_thread = threading.Thread(
        target=lambda: app.run(host='localhost', port=PORT,quiet=True)
    )
    server_thread.daemon = True
    server_thread.start()

    # Start browser in a separate thread
    threading.Thread(target=open_browser).start()

    
    start_time = time.time()
    timeout_minutes = 2  # 2 minutes timeout
    shutdown_flag.wait()

    try:
        # Wait for the shutdown signal and call shutdown when it's received
        while not shutdown_flag.is_set():
            if time.time() - start_time > (timeout_minutes * 60):
                logger.info(f"Operation timed out after {timeout_minutes} minutes")
                shutdown_flag.set()
            time.sleep(0.5)  # Small sleep to prevent busy waiting
        
        shutdown()
    except KeyboardInterrupt:
        shutdown_flag.set()
        shutdown()


def shutdown():
    time.sleep(.5)
    sys.exit(0)

if __name__ == "__main__":
        main()