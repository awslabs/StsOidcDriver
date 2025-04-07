# STS OIDC Authentication Driver

The STS OIDC Driver (stsoidcdriver) is a Python-based tool that enables you to request temporary AWS security credentials for an IAM role, using ID tokens, from your OpenID Connect(OIDC) provider (OpenID provider, in their parlance). 

This tool lets you register an "application" or "client" in your OpenID Provider, and use it to "sign-in" to the AWS CLI, or other programs written using the AWS SDK using OIDC. It does this by calling the AWS STS [AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) API using the ID token that is delivered by your OIDC provider. This is useful setting up federation to AWS using OIDC for your workforce, or simply testing any OIDC integration or provider with AWS. 

This tool works by kicking off an OIDC flow. The tool supports authorization code flow, implicit flow, and dynamic client registration. This tool requires Proof Key for Code Exchange[PKCE](https://www.rfc-editor.org/rfc/rfc7636).

When you execute it the tool will open your default browser to your OpenID provider with the parameters you specify, and listen for a respose on http://127.0.0.1:6432. It will attempt to update an aws profile with credentials so that you can use them with the AWS CLI or AWS SDK. After the tool receives an ID token or authorization code from 

This tool is intended as a reference and has been tested with different OpenID providers, however there are many non-standard implimentations of this standard and you may need to test and adapt this tool for your provider.

The tool display meaningful success and error messages to the user in their browser, like so:

![Success Message](./images/success_example.png "Successful Authentication")

### Flow Diagram

![Flow Diagrame](./images/flow_diagram.png "Flow Diagram for STSOIDCDRIVER")

### Prerequisites
- Python 3.6 or higher
- AWS CLI installed and configured
- An OIDC provider with either:
  - Support for Implicit client flow with PKCE
  - Support for secret-less authorization flow (public clients) with PKCE
  - Support for dynamic client registration with PKCE
- Required Python packages:
  - bottle
  - requests
  - PyJWT
  - boto3

The requirements are also listed in the requirements.txt for the versions this tool was tested and developed with.

### Installation

You can clone directly from this repo and install using pip:

```bash
# Clone the repository
git clone https://github.com/awslabs/StsOidcDriver.git
cd StsOidcDriver
pip3 install .
```

Or you can install directly from pypi
```bash
# Clone the repository
pip3 install stsoidcdriver
```

## Usage

You can invoke this script with environment variables set, or pass arguments to the script.

### Required parameters

`--role`

The Amazon Resource Name (ARN) of the IAM role you want to assume

the script will attempt to read the variable AWS_ROLE_ARN from the environment if no `--role` argument is passed.



`--openid_url` The discovery URL for your OpenID Connect provider

The script will attempt to read the variable OIDC_DISCOVERY_URL from the enviroment if no `--openid_url` argument is passed.

### Optional parameters

`--client_id` The client ID of your OpenID Connect client. 

While `--client_id` optional because this tool supports dynamic client registration, it is likely your provider will require this argument. The script will attempt to this from the OIDC_CLIENT_ID variable if no `--client_id` is passed. 

`--implicit` Tells the tool to attempt using implicit flow. Implicit flow is generally not recommended, for more information see: https://datatracker.ietf.org/doc/html/rfc9700#name-implicit-grant . We recommend you do not use implicit mode if you have the choice.

`--region` AWS region to use for API calls (defaults to us-east-1)

`--duration-seconds` How long the assumed role credentials should remain valid, in seconds (defaults to 3600/1 hour)

`--profile-to-update` Name of the AWS profile to update with the new credentials. defaults to `default`

`--aws-config-file` location of the aws config/credentials file to update

`--debug` Enables verbose logging

## Usage examples

### Using authorization code flow, with input from environment variables

```bash
export OIDC_DISCOVERY_URL="https://auth.example.com/"
export OIDC_CLIENT_ID="your_client_id"
export AWS_ROLE_ARN="arn:aws:iam::111122223333:role/youroidcrole"

stsoidcdriver
```

### Using authorization code flow, with input from parameters
```bash
stsoidcdriver --client_id "your_client_id" --openid_url "https://auth.example.com/" --role "arn:aws:iam::111122223333:role/youroidcrole"
```

### Using Dynamic Client Registration with authorization code flow, with input from parameters
```bash
stsoidcdriver --role "arn:aws:iam::111122223333:role/youroidcrole" --openid_url "https://auth.example.com/"
```

### Using an implicit flow, with input from parameters
```bash
# Set environment variables for dynamic registration
stsoidcdriver --implicit --openid_url "https://auth.example.com/" --role "arn:aws:iam::111122223333:role/youroidcrole" --client_id "your_client_id"
```

### Troubleshooting

#### EnableDebug Mode
Enable verbose logging:
```bash
stsoidcdriver --debug [YOUR PARAMETERS]
```

replace [YOUR PARAMETERS] with your parameters - your role, client_id, openid_url etc.


The web page and CLI will also attempt to output useful troubleshooting errors and hints. OpenID providers often times put debug hints inside hash parameters or query string parameters, if you're encountering errors remember to check your browsers address bar for any hints the IDP put there.

#### Scope Handling

Most OpenId Providers play nicely with the standard OIDC scopes. This tool only really wants the token, and attempts to use the 'email' value from a token to set the role_session_name to something readable and attempts to use the scopes `openid email` when requesting tokens.

Okta seems to require the `offline_access` scope when signing into a native client using authorization code flow. If the tool sees okta.com in the OIDC_DISCOVERY_URL and it's trying authorization code flow, it will automatically ask for the offline_access scope. This tool does not store refresh tokens if they are issued when requesting offline_access, or otherwise.

If your provider requires additional scopes beyond what is standard, you may customize this code to use your required scopes.


#### Setting up OIDC In your AWS account

To learn more about how to use OIDC/JWT authentication with AWS, and setting up OIDC in your AWS accounts, [please refer to the AWS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html).

If you're encountering errors from calls to AWS STS, please see the [troubleshooting guide on aws re:post](https://repost.aws/knowledge-center/iam-sts-invalididentitytoken).


#### Setting up your OIDC client or application in your OpenID provider

This will vary based on your provider. Here's a link to a few common ones:

`https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate%2Cexpose-a-web-api`

`https://support.okta.com/help/s/article/create-an-oidc-web-app-in-dashboard?language=en_US`

The high level guidance is you will register an application with your OpenID provider. Configure the application to use either Implicit Flow, or Authorization Code flow (as a public client, with no client secret), and configure the application in your OpenID provider to accept redirects from `http://127.0.0.1:6432` if required, and configure `http://127.0.0.1:6432/callback` as a redirect URI for sign-in. Providers may use proprietary terms for the different configuration elements of an application, you should consult your OpenID provider's documentation for guidance on how to configure an application.

This was tested with Entra, Okta, and Auth0 and in our testing there were no compatibility issues discovered. If you discover a provider that this tool does not support, please open an issue on github and we will investigate.

#### I'm getting a failure from my OpenID Provider that doesn't redirect back to the OIDC driver

If you're getting a failure from your OpenID Provider, such as an invalid redirect_uri, your OpenID provider may not redirect your browser back to the tool to finish the OIDC flow, or give you an error message from the tool. In such an event, your OpenID provider will usually give a meaningful error message that tells you what you have to do.

The tool will remain listening for up to two minutes, and if you're encountering errors from your you should terminate the tool (ctrl+c) and run it again after your OpenID rrovider has been updated and you're ready to try again.


