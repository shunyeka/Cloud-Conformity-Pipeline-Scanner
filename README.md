# Cloud Conformity Pipeline Scanner

Scan and secure your CloudFormation templates **before** they're deployed.

## Usage

To use the script, specify the following required environment variables:
  * CC_API_KEY
  * CFN_TEMPLATE_FILE_LOCATION

And, if necessary, the optional environment variables:
  * CC_REGION (default: us-west-2)
    * Options: [CC docs](https://github.com/cloudconformity/documentation-api#endpoints)
  * CC_RISK_LEVEL (default: LOW)
    * Options: LOW | MEDIUM | HIGH | VERY_HIGH | EXTREME