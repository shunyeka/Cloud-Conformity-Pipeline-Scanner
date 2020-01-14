# Cloud Conformity Pipeline Scanner

Scan and secure your CloudFormation templates **before** they're deployed.

## Usage

To use the script, specify the following required environment variables:
  * CC_API_KEY
  * CC_REGION
  * CFN_TEMPLATE_FILE_LOCATION

And, if necessary, the optional environment variable:
  * CC_RISK_LEVEL (default: LOW)