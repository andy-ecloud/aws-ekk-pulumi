"""An AWS Python Pulumi program"""

import pulumi
from pulumi_aws import s3
import pulumi_aws as aws

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


# ekk_log_us_east_1 = aws.elasticsearch.Domain("ekk-log-us-east-1",
#     domain_name="ekk-log-us-east-1",
#     elasticsearch_version="OpenSearch_1.0",
#     )
    
# pu_t__op_s__c_jqda = aws.kinesis.FirehoseDeliveryStream("PUT-OPS-CJqda",
#     destination="extended_s3",
#     name="PUT-OPS-CJqda",
#     )
    
    
    
    
    