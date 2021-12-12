"""An AWS Python Pulumi program"""

import pulumi
import pulumi_aws as aws
import json
import pulumi_tls as tls

tags = {
    'Owner': "andy.chuang"
}


# get current region
current_identity = aws.get_caller_identity()
pulumi.export("accountId", current_identity.account_id)
pulumi.export("callerArn", current_identity.arn)
pulumi.export("callerUser", current_identity.user_id)

pulumi.export("region id:", aws.get_region().id)

config = pulumi.Config()
print('Password: {}'.format(config.require('dbPassword')))

ip = "0.0.0.0/0" #"59.124.14.121/32"
opensearch_domain = "ekk-log-us-east-1"
ekk_firehose_name = "EKK-LogFirehose-apachelog"

# Iam Policy
AmazonKinesisFirehoseFullAccess = aws.iam.get_policy(name="AmazonKinesisFirehoseFullAccess")
AmazonS3FullAccess = aws.iam.get_policy(name="AmazonS3FullAccess")
CloudWatchFullAccess = aws.iam.get_policy(name="CloudWatchFullAccess")
AmazonESFullAccess = aws.iam.get_policy(name="AmazonESFullAccess")
CloudWatchFullAccess  = aws.iam.get_policy(name="CloudWatchFullAccess")

# Iam Role for ekk
ekk_ec2_role = aws.iam.Role("EKK-EC2",
    assume_role_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}",
    description="Allows EC2 instances to call AWS services on your behalf.",
    force_detach_policies=False,
    max_session_duration=3600,
    name="EKK-EC2",
    path="/",
    managed_policy_arns=[AmazonKinesisFirehoseFullAccess.arn],
    )

ekk_firehose_role = aws.iam.Role("EKK-Firhose",
    assume_role_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"firehose.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}",
    description="Allows Firhose to call AWS services on your behalf.",
    force_detach_policies=False,
    max_session_duration=3600,
    name="EKK-Firhose",
    path="/",
    managed_policy_arns=[AmazonS3FullAccess.arn, CloudWatchFullAccess.arn, AmazonESFullAccess.arn],
    )
    
ekk_lambda_role = aws.iam.Role("EKK-Lambda",
    assume_role_policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}",
    description="Allows Lambda to call AWS services on your behalf.",
    force_detach_policies=False,
    max_session_duration=3600,
    name="EKK-Lambda",
    path="/",
    managed_policy_arns=[AmazonS3FullAccess.arn, CloudWatchFullAccess.arn, AmazonESFullAccess.arn],
    )



ekk_log_us_east_1 = aws.elasticsearch.Domain(opensearch_domain,
    domain_name=opensearch_domain,
    elasticsearch_version="OpenSearch_1.0",
    cluster_config=aws.elasticsearch.DomainClusterConfigArgs(
        instance_type="t3.medium.elasticsearch",
    ),
    ebs_options=aws.elasticsearch.DomainEbsOptionsArgs(
        ebs_enabled=True,
        volume_size=10,
        volume_type="gp2"
        ),
    node_to_node_encryption=aws.elasticsearch.DomainNodeToNodeEncryptionArgs(
        enabled=True
        ),
    encrypt_at_rest=aws.elasticsearch.DomainEncryptAtRestArgs(
        enabled=True
        ),
    domain_endpoint_options=aws.elasticsearch.DomainDomainEndpointOptionsArgs(
        enforce_https=True,
        tls_security_policy="Policy-Min-TLS-1-0-2019-07"
        ),
    advanced_security_options=aws.elasticsearch.DomainAdvancedSecurityOptionsArgs(
        enabled=True,
        internal_user_database_enabled=True,
        master_user_options=aws.elasticsearch.DomainAdvancedSecurityOptionsMasterUserOptionsArgs(
            master_user_name="admin",
            master_user_password=config.require('dbPassword')
            ),
        ),
    access_policies=pulumi.Output.all(opensearch_domain, ip).apply(
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
                      "Resource": "arn:aws:es:{}:{}:domain/{}/*".format(aws.get_region().id, current_identity.account_id, args[0]),
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
pulumi.export("es domain:", ekk_log_us_east_1.endpoint)

# Create an AWS resource (S3 Bucket)
ekk_bucket_name = "ekk-bucket"
ekk_bucket = aws.s3.Bucket(ekk_bucket_name,
    force_destroy = True,
)
pulumi.export("ekk bucket id", ekk_bucket.id)
pulumi.export("ekk bucket arn", ekk_bucket.arn)

ekk_bucket_policy = aws.s3.BucketPolicy("ekk-bucketPolicy",
    bucket=ekk_bucket.id,
    policy=pulumi.Output.all(ekk_bucket.arn).apply(
        lambda args: json.dumps(
            {
                "Version": "2012-10-17",
                "Id": "MYBUCKETPOLICY",
                "Statement": [
                    {
                        "Sid": "Allow",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [
                            args[0],
                            f"{args[0]}/*",
                        ],
                    }
                ],
            }
        )
    )
)

# Cloudtrail
current_partition = aws.get_partition()

cloudtrail_log_group = aws.cloudwatch.LogGroup("cloudtrail-log-group")
pulumi.export("log group arn", cloudtrail_log_group.arn)

aws_cloud_trail_create_log_stream_role = aws.iam.Role("AWSCloudTrailCreateLogStreamRole", 
    assume_role_policy=f"""{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "",
      "Effect": "Allow",
      "Principal": {{
        "Service": "cloudtrail.{current_partition.dns_suffix}"
      }},
      "Action": "sts:AssumeRole"
    }}
  ]
}}
""")

aws_cloud_trail_create_log_stream_role_policy = aws.iam.RolePolicy("AWSCloudTrailCreateLogStreamRolePolicy",
    role=aws_cloud_trail_create_log_stream_role.id,
    policy=pulumi.Output.all().apply(
        lambda args: json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSCloudTrailCreateLogStream",
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        )
    ),
)

# # cloudtrail_bucket = aws.s3.Bucket("cloudtrail-bucket")
ekk_cloud_trail = aws.cloudtrail.Trail("ekk-cloudtrail",
    s3_bucket_name=ekk_bucket.id,
    s3_key_prefix="prefix",
    cloud_watch_logs_role_arn=aws_cloud_trail_create_log_stream_role.arn,
    cloud_watch_logs_group_arn=cloudtrail_log_group.arn.apply(lambda arn: f"{arn}:*"),
    is_multi_region_trail=True,
    enable_log_file_validation=True,
    include_global_service_events=True,
    )

# Lambda
ekk_log_to_es_lambda = aws.lambda_.Function("ekk-log-to-elasticsearch",
    code=pulumi.FileArchive("./lambda_code/index.zip"),
    role=ekk_lambda_role.arn,
    handler="index.handler",
    runtime="nodejs12.x",
    architectures=["x86_64"],
    timeout=60,
    environment=aws.lambda_.FunctionEnvironmentArgs(
        variables={
            "endpoint": ekk_log_us_east_1.endpoint,
        }
    ),
    )

# lambda log group
ekk_lambda_log_group = aws.cloudwatch.LogGroup("ekk-log-group",
    name=pulumi.Output.concat("/aws/lambda/", ekk_log_to_es_lambda.id)
    )

allow_cloudwatch = aws.lambda_.Permission("allowCloudwatch",
    action="lambda:InvokeFunction",
    function=ekk_log_to_es_lambda.name,
    principal="logs.amazonaws.com",
    source_arn=pulumi.Output.concat(cloudtrail_log_group.arn, ":*"),
    # qualifier=test_alias.name,
    statement_id = "allow-cloudwatch-lambda"
    )

# log group subscription filter
ekk_log_to_es_lambda_logfilter = aws.cloudwatch.LogSubscriptionFilter("ekk-log-to-es-lambda-log-filterr",
    # role_arn=ekk_lambda_role.arn,
    log_group=cloudtrail_log_group.id,
    filter_pattern="",
    destination_arn=ekk_log_to_es_lambda.arn,
    )



# ekk_firehose = aws.kinesis.FirehoseDeliveryStream(ekk_firehose_name,
#     destination="elasticsearch",
#     s3_configuration=aws.kinesis.FirehoseDeliveryStreamS3ConfigurationArgs(
#         role_arn=ekk_firehose_role.arn,
#         bucket_arn=ekk_bucket.arn,
#         buffer_size=10,
#         buffer_interval=400,
#         # compression_format="GZIP",
#     ),
#     name=ekk_firehose_name,
#     elasticsearch_configuration=aws.kinesis.FirehoseDeliveryStreamElasticsearchConfigurationArgs(
#         domain_arn=ekk_log_us_east_1.arn,
#         role_arn=ekk_firehose_role.arn,
#         index_name="apachelog",
#         # type_name="log",
#         processing_configuration=aws.kinesis.FirehoseDeliveryStreamElasticsearchConfigurationProcessingConfigurationArgs(
#             enabled=False,
#             # processors=[aws.kinesis.FirehoseDeliveryStreamElasticsearchConfigurationProcessingConfigurationProcessorArgs(
#             #     type="Lambda",
#             #     parameters=[aws.kinesis.FirehoseDeliveryStreamElasticsearchConfigurationProcessingConfigurationProcessorParameterArgs(
#             #         parameter_name="LambdaArn",
#             #         parameter_value=f"{aws_lambda_function['lambda_processor']['arn']}:$LATEST",
#             #     )],
#             # )],
#         ),
#     ))
# pulumi.export("firehose:", ekk_firehose.id) 
# pulumi.export("firehose tags all:", ekk_firehose.tags_all)   

# kinesis_agent_json=pulumi.Output.all([ekk_firehose_name]).apply(lambda args:
#     json.dumps(
#         {
#           "cloudwatch.emitMetrics": True,
#           "firehose.endpoint": "{}".format(ekk_log_us_east_1.endpoint),
#           "flows": [
#             {
#               "filePattern": "/var/log/httpd/access_log*",
#               "deliveryStream": "{}".format(args[0]),
#               "dataProcessingOptions": [
#                 {
#                   "optionName": "LOGTOJSON",
#                   "logFormat": "COMMONAPACHELOG"
#                 }
#               ]
#             }
#           ]
#         }
#     )
# )

# kinesis_agent_json = pulumi.Output.all([ekk_firehose_name]).apply(lambda args:
#     json.dumps(
#         {
#           "cloudwatch.emitMetrics": True,
#           "firehose.endpoint": "{}".format(ekk_log_us_east_1.endpoint),
#           "flows": [
#             {
#               "filePattern": "/var/log/httpd/access_log*",
#               "deliveryStream": "{}".format(args[0]),
#               "dataProcessingOptions": [
#                 {
#                   "optionName": "LOGTOJSON",
#                   "logFormat": "COMMONAPACHELOG"
#                 }
#               ]
#             }
#           ]
#         }
#     )
# )

# userdata = pulumi.Output.concat(
# """#!/bin/bash
# # install 
# sudo yum install aws-kinesis-agent –y -y
# # sudo yum install aws-kinesis-agent –y 
# cat > /etc/aws-kinesis/agent.json << EOF
# """,
# """{\"cloudwatch.emitMetrics\": true, \"firehose.endpoint\": \"""",
# "",
# """\", \"flows\": [{\"filePattern\": \"/var/log/httpd/access_log*\", \"deliveryStream\": \"""",
# ekk_firehose_name,
# """\", \"dataProcessingOptions\": [{\"optionName\": \"LOGTOJSON\", \"logFormat\": \"COMMONAPACHELOG\"}]}]}\n""",
# """EOF

# sudo service aws-kinesis-agent start
# sudo chkconfig aws-kinesis-agent on

# sudo yum install -y git
# git clone https://github.com/kiritbasu/Fake-Apache-Log-Generator.git
# sudo yum install python-pip -y
# cd Fake-Apache-Log-Generator/
# sudo pip install -r requirements.txt
# cd ~
# """,
# """echo \"#!/bin/bash

# # chkconfig: 2345 10 90

# cd /var/log/httpd/

# while true

# do

# sudo python /Fake-Apache-Log-Generator/apache-fake-log-gen.py -n 100 -o LOG

# sleep 10

# done\" > ~/test.sh
# """,
# """
# cat > ~/test.sh << EOF
# #!/bin/bash
# # chkconfig: 2345 10 90
# mkdir -p /var/log/httpd/
# cd /var/log/httpd/
# while true
# do
# sudo python /Fake-Apache-Log-Generator/apache-fake-log-gen.py -n 100 -o LOG
# sleep 10
# done
# """,
# """EOF
# sudo sh ~/test.sh
# """

# )
# pulumi.export("userdata", userdata)

# my_vpc = aws.ec2.Vpc("myVpc",
#     cidr_block="172.16.0.0/16",
#     tags={
#         "Name": "pulumi vpc",
#     })
# my_subnet = aws.ec2.Subnet("mySubnet",
#     vpc_id=my_vpc.id,
#     cidr_block="172.16.10.0/24",
#     availability_zone="us-west-2a",
#     tags={
#         "Name": "pulumi subnet",
#     })
# igw = aws.ec2.InternetGateway("gw",
#     vpc_id=my_vpc.id,
#     tags={
#         "Name": "pulumi igw",
#     })

# security_group = aws.ec2.SecurityGroup('all-traffic',
#     vpc_id=my_vpc.id,
#     description='Enable HTTP access',
#     ingress=[aws.ec2.SecurityGroupIngressArgs(
#         protocol='tcp',
#         from_port=1,
#         to_port=65535,
#         cidr_blocks=['0.0.0.0/0'],
#     )],
#     egress=[aws.ec2.SecurityGroupEgressArgs(
#         from_port=0,
#         to_port=0,
#         protocol="-1",
#         cidr_blocks=["0.0.0.0/0"],
#         ipv6_cidr_blocks=["::/0"],
#     )])
    
# ami = aws.ec2.get_ami(most_recent=True,
#                   owners=["amazon"],
#                   filters=[aws.GetAmiFilterArgs(name="name", values=["amzn2-ami-kernel-5.10*"])])
                  
# # create key
# private_key = tls.PrivateKey('private_key',
#               algorithm = 'RSA',
#               rsa_bits=2048)
               
# pulumi.export('public openssh', private_key.public_key_openssh)
# pulumi.export('public pem', private_key.public_key_pem)
# pulumi.export('private pem', private_key.private_key_pem)

# # create key pair
# keypair = aws.ec2.KeyPair("keypair",
#     key_name="keypair",
#     public_key=private_key.public_key_openssh)
                  
# ec2_apachelog_poc = aws.ec2.Instance('EC2-ApacheLog-poc',
#     subnet_id=my_subnet.id,
#     instance_type='t3.micro',
# #     iam_instance_profile=instance_profile.name,
#     vpc_security_group_ids=[security_group.id],
#     user_data=userdata,
#     ami=ami.id,
#     key_name=keypair.id,
#     tags=dict(tags, **{"Name": "EC2-ApacheLog-poc"}),
#     volume_tags=dict(tags, **{"Name": "EC2-ApacheLog-poc"}),
#     )


# TODO
pulumi.export("TODO ----> opensearch dashboard -> role mapping", ekk_lambda_role.arn)