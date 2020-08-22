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
  * `FAIL_PIPELINE` (default: pipeline will fail)
    * Options: `disabled`
  * `FAIL_PIPELINE_CFN` (default: pipeline will fail)
    * Options: `enabled`
  * `CC_PROFILE_ID` (default: `default`)
    * Options: Profile ID(s) found in your Conformity account     

If `FAIL_PIPELINE` is `disabled`, the script **will not** fail the pipeline even if the template is deemed insecure. 

If `FAIL_PIPELINE_CFN` is `enabled`, the script will look for the `FailConformityPipeline` parameter in the template. If the parameter is set to `disabled`, the pipeline **will not** fail even if the template is deemed insecure. See `insecure-s3-bucket-disable-failure.yaml` or `insecure-s3-bucket-disable-failure.json` for examples.

## Examples
### Default

An example of the pipeline scanner being run with its default settings. If Conformity finds any LOW severity issues or above, the pipeline will fail. 

```
export CC_REGION=ap-southeast-2
export CC_API_KEY=<API_KEY>
export CFN_TEMPLATE=/tmp/demo/insecure-s3-bucket.yaml

python3 scanner.py
```

### Fail pipeline

An example of the pipeline scanner being run with the `FAIL_PIPELINE` environment variable set to `disabled`.

```
export CC_REGION=ap-southeast-2
export CC_API_KEY=<API_KEY>
export CFN_TEMPLATE=/tmp/demo/insecure-s3-bucket.yaml
export FAIL_PIPELINE=disabled

python3 scanner.py
```

### Fail pipeline CFN

An example of the pipeline scanner being run with the `FAIL_PIPELINE_CFN` environment variable set to `enabled`. 

```
export CC_REGION=ap-southeast-2
export CC_API_KEY=<API_KEY>
export CFN_TEMPLATE=/tmp/demo/insecure-s3-bucket-disable-failure.yaml
export FAIL_PIPELINE_CFN=enabled

python3 scanner.py
```

## Dev Notes

To ensure all tests pass, you must set the following environment variables:
 
 * `CC_API_KEY`
 * `CC_REGION`
 * `CC_PROFILE_ID`

Use the following command to run all tests:

```
pytest -v
```

And the following command to skip tests which call the Conformity API:

```
pytest -v -m 'not external' 
```

Use the following command to test code coverage:

```
pytest --cov=code --cov-report term-missing
```

# Contact

* Blog: [oznetnerd.com](https://oznetnerd.com)
* Email: will@oznetnerd.com