# Cloud Conformity Pipeline Scanner

Pipeline scanner uses Cloud Conformity's [Template Scanner](https://www.cloudconformity.com/solutions/aws/cloudformation-template-scanner.html) to secure your CloudFormation templates **before** they're deployed.

## Usage

To use the script, specify the following required environment variables:
  * `CC_API_KEY`
  * `CFN_TEMPLATE_FILE_LOCATION`
  * `CC_REGION`
    * Options: See the Cloud Conformity [documentation](https://github.com/cloudconformity/documentation-api#endpoints)

And, if necessary, the optional environment variable:
  * `CC_RISK_LEVEL` (default: `LOW`)
    * Options: `LOW` | `MEDIUM` | `HIGH` | `VERY_HIGH` | `EXTREME`

## Examples

See the [Cloud Conformity Pipeline Demos](https://github.com/OzNetNerd/Cloud-Conformity-Pipeline-Demos) repo for example pipelines.

# Contact

* Blog: [oznetnerd.com](https://oznetnerd.com)
* Email: will@oznetnerd.com