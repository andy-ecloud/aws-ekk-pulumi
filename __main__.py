"""An AWS Python Pulumi program"""

import pulumi
from pulumi_aws import s3
import pulumi_aws as aws
import json

# get current region
current = aws.get_caller_identity()
pulumi.export("accountId", current.account_id)
pulumi.export("callerArn", current.arn)
pulumi.export("callerUser", current.user_id)

pulumi.export("region id:", aws.get_region().id)

# Create an AWS resource (S3 Bucket)
bucket = s3.Bucket('my-bucket')

# Export the name of the bucket
pulumi.export('bucket_name', bucket.id)

AmazonKinesisFirehoseFullAccess = aws.iam.get_policy(name="AmazonKinesisFirehoseFullAccess")
AmazonS3FullAccess = aws.iam.get_policy(name="AmazonS3FullAccess")
CloudWatchFullAccess = aws.iam.get_policy(name="CloudWatchFullAccess")
AmazonESFullAccess = aws.iam.get_policy(name="AmazonESFullAccess")
CloudWatchFullAccess  = aws.iam.get_policy(name="CloudWatchFullAccess")


ekk_ec2 = aws.iam.Role("EKK-EC2",
    assume_role_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}",
    description="Allows EC2 instances to call AWS services on your behalf.",
    force_detach_policies=False,
    max_session_duration=3600,
    name="EKK-EC2",
    path="/",
    managed_policy_arns=[AmazonKinesisFirehoseFullAccess.arn],
    )

ekk_firehose = aws.iam.Role("EKK-Firhose",
    assume_role_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"firehose.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}",
    description="Allows Firhose to call AWS services on your behalf.",
    force_detach_policies=False,
    max_session_duration=3600,
    name="EKK-Firhose",
    path="/",
    managed_policy_arns=[AmazonS3FullAccess.arn, CloudWatchFullAccess.arn, AmazonESFullAccess.arn],
    )
    
ekk_lambda = aws.iam.Role("EKK-Lambda",
    assume_role_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}",
    description="Allows Lambda to call AWS services on your behalf.",
    force_detach_policies=False,
    max_session_duration=3600,
    name="EKK-Lambda",
    path="/",
    managed_policy_arns=[AmazonS3FullAccess.arn, CloudWatchFullAccess.arn, AmazonESFullAccess.arn],
    )


ip = "59.124.14.121/32"
opensearch_domain = "ekk-log-test"
ekk_log_us_east_1 = aws.elasticsearch.Domain("ekk-log-us-east-1",
    domain_name="ekk-log-us-east-1",
    elasticsearch_version="OpenSearch_1.0",
    access_policies=pulumi.Output.all([opensearch_domain, ip]).apply(
            lambda args: json.dumps(
               {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Effect": "Allow",
                      "Principal": {
                        "AWS": "*"
                      },
                      "Action": "es:*",
                      "Resource": "arn:aws:es:{}:{}:domain/{}/*".format(aws.get_region().id, current.account_id, args[0]),
                      "Condition": {
                        "IpAddress": {
                          "aws:SourceIp": "{}".format(args[1])
                        }
                      }
                    }
                  ]
                }
            )
        ),
    )
    
pu_t__op_s__c_jqda = aws.kinesis.FirehoseDeliveryStream("PUT-OPS-CJqda",
    destination="elasticsearch",
    s3_configuration=aws.kinesis.FirehoseDeliveryStreamS3ConfigurationArgs(
        role_arn=ekk_firehose.arn,
        bucket_arn=bucket.arn,
        buffer_size=10,
        buffer_interval=400,
        # compression_format="GZIP",
    ),
    name="PUT-OPS-CJqda",
    elasticsearch_configuration=aws.kinesis.FirehoseDeliveryStreamElasticsearchConfigurationArgs(
        domain_arn=ekk_log_us_east_1.arn,
        role_arn=ekk_firehose.arn,
        index_name="apachelog",
        # type_name="log",
        processing_configuration=aws.kinesis.FirehoseDeliveryStreamElasticsearchConfigurationProcessingConfigurationArgs(
            enabled=False,
            # processors=[aws.kinesis.FirehoseDeliveryStreamElasticsearchConfigurationProcessingConfigurationProcessorArgs(
            #     type="Lambda",
            #     parameters=[aws.kinesis.FirehoseDeliveryStreamElasticsearchConfigurationProcessingConfigurationProcessorParameterArgs(
            #         parameter_name="LambdaArn",
            #         parameter_value=f"{aws_lambda_function['lambda_processor']['arn']}:$LATEST",
            #     )],
            # )],
        ),
    ))
    