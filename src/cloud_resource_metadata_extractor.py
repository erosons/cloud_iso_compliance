import boto3
from botocore.exceptions import ClientError
from pprint import pprint
from typing import Dict,TypeVar,Generic,ClassVar
from dotenv import load_dotenv
import json
from dataclasses import dataclass
# from os.path import join, dirname
import os

load_dotenv()


T = TypeVar('T')
U=TypeVar('U')
@dataclass
class ComplianceManager(Generic[T, U], object):
    compliance_feature: ClassVar[json] = {
        'ApplyServerSideEncryptionByDefault':0,
        "PasswordReusePrevention":0,
        "MFA":0,
        "HardExpriy":0,
        "MaxPasswordAge":0,
        "MinimumPasswordLength":0,
        "ExpirePassword":0,
        "Secure Transfer Config":0,
        "Key Management service":0,
        "Access Restriction" :0,
        "User Management":0,
        "Privileged Access" :0,
        "Secret Auth Management" :0,
        "Logging & Monitoring":0,
    }
    secrets :str| None = os.getenv('Secret_access_key')
    access_key :str| None= os.getenv('access_key')
    region  :str| None = os.getenv('region')
    if not secrets or not access_key:
        raise Exception('Access denied: Missing credentials')
    else:
        session_connection=  boto3.Session(aws_access_key_id=access_key,
                                    aws_secret_access_key=secrets,
                                    region_name=region
                                    )

    def __check_compliance_feature(
        self, container: dict
    ) -> json:
        """
        Check if the compliance feature is in the container.
        """

        for features in self.compliance_feature.keys():
            if features in container.keys():
                self.compliance_feature[features] = 1
        return self.compliance_feature

    # A.9.4.1 - Use of Secret Authentication Information
    def check_iam_compliance(self,container:dict)->json:
        """
        Check IAM password policy for minimum password length compliance.
        """
        try:
            iam = self.session_connection.client('iam')
            response = iam.get_account_password_policy()
            policy = response['PasswordPolicy']
            pprint(policy , indent=3)
            if type(policy) == dict:
                container.update(policy)
                container['ControlID'] = 'A.9.4.1' 
                container["Control Description"] = (
                 """ Use of Secret Authentication Information: 
                 IAM supports the management of secret authentication
                 information (passwords, keys) through policies 
                 enforcing password complexity, rotation, and multi-factor """
                )
                #pprint(container, indent=3)
                return self.__check_compliance_feature(container)
            else:
                container.update({
                    'check': 'Minimum password length',
                    'status': 'FAILED',
                    'details': 'Compliant with minimum password length of 12 characters.'
                })
                pprint(container,indent=3)
        except ClientError as e:
            container.append({
                'details': str(e)
            })

        return

    def check_s3_encryption_at_rest(self,container)->json:
        """
        Check if S3 buckets are configured to ensure secure data transfers.
        """
        try:
            s3 = self.session_connection.client('s3')
            response = s3.get_bucket_encryption(Bucket='iso-complince')
            rules = response['ServerSideEncryptionConfiguration']['Rules'][0]
            if type(rules) == dict:
                container.update(rules)
                container['ControlID'] = 'A.10.1.1' 
                container.update({'Key Management service':'AWS KMS'})
                container["Control Description"] = (
                 """ Cryptographic Controls: Ensuring that data stored
                     in S3 buckets is encrypted, both at rest and in
                     transit, aligns with the requirement for protecting
                    sensitive information using cryptographic measures. """
                )
                pprint(container, indent=3)
                return self.__check_compliance_feature(container)

        except ClientError as e:
            container.update({
                'check': 'S3 Bucket Policy',
                'status': 'FAIL',
                'details': str(e)
            })

    # managing network security  A.9.1.2:
    def S3_secure_data_acl(self,container)->json:
        """
        Check if encryption at rest is enabled for S3 buckets.
        """
        try:
            s3 = self.session_connection.client('s3')
            response = s3.get_bucket_policy(Bucket='iso-complince')
            policy = response['Policy']
            policy=json.loads(policy)
            if type(policy) == dict:
                container.update(policy)
                container['Privileged Access']= container['Statement']
                container['User Management']= container['Statement'][0]['Principal']
                container['ControlID'] = 'A.9.2.3 & A.13.1.1' 
                container["Control Description"] = (
                    """ Access to Networks and Network Services: 
                    IAM policies that restrict access to AWS services
                    based on user roles and responsibilities support this
                    control by managing who has access to the network and 
                    network services. """
                )
                container.pop('Statement',None)
                return self.__check_compliance_feature(container)
            else:
                container.update({
                    'check': 'Encryption at Rest',
                    'status': 'FAIL',
                    'details': 'Encryption at rest is not enabled for S3 buckets.'
                })
        except ClientError as e:
            container.update({
                'check': 'Encryption at Rest',
                'status': 'ERROR',
                'details': str(e)
            })

    def kms_compliance_audit(self,container)->json:
        # AWS KMS (Key Management Service) A.10.1.1 - Cryptographic Controls:
        # AWS KMS is central to managing cryptographic keys for data encryption,
        # directly supporting the control requiring the use and management of cryptographic techniques and keys.():
        """
        Check if AWS KMS is used for managing cryptographic keys.
        """
        try:
            kms = self.session_connection.client('kms')
            response = kms.describe_key(KeyId='f5faf926-7f61-4213-a883-4fa74bf77a7a')
            if type(response['KeyMetadata'])== dict:
                crytographic_control=response['KeyMetadata']
                pprint(crytographic_control, indent=3)
                container.update(crytographic_control
                                   )
                container['ControlID'] = 'A.10.1.2'
                container["Control Description"] = (
                    """ 
                   Cryptographic Controls: AWS KMS is central to managing cryptographic
                    keys for data encryption, directly supporting the control requiring
                    the use and management of cryptographic techniques and keys.
                    """
                )
                container['Key Management service'] = container['KeyManager']
                container['ApplyServerSideEncryptionByDefault'] = container['EncryptionAlgorithms']
                container['Secret Auth Management'] = container['Enabled']
                container.pop('KeyManager',None)
                container.pop('EncryptionAlgorithms',None)
                return self.__check_compliance_feature(container)
            else:
                container.update({
                    'check': 'AWS KMS',
                    'status': 'FAIL',
                    'details': 'AWS KMS is not used for managing cryptographic keys.'
                })
        except ClientError as e:
            container.update({
                'check': 'AWS KMS',
                'status': 'ERROR',
                'details': str(e)
            })


    def check_cloud_trail_logging(self,container)->json:
        from datetime import datetime, timedelta
        # A.12.4.1 - Logging and Monitoring: Integration of IAM with AWS CloudTrail ensures
        # that logging and monitoring controls are met by recording and analyzing actions made on AWS resources.
        """
        Check if S3 bucket logging is enabled.
        """
        # Define the time range for your query
        end_time = datetime.now(tz=None)
        start_time = end_time - timedelta(days=7)  # Adjust the time range as needed
        try:
            cloud_trail = self.session_connection.client('cloudtrail')
            # Call lookup_events to find events in the specified time frame
            response = cloud_trail.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                LookupAttributes=[
                    {
                        'AttributeKey': 'Username',  # You can choose from other attribute keys
                        'AttributeValue': 'Admin'  # Specify the event name you want to search for
                    }
                ],
                MaxResults=10 
            )
            cloudtrail = response['Events'][0]['CloudTrailEvent']
            cloud_trail = json.loads(cloudtrail)
            container.update(cloud_trail)
            container['ControlID'] = 'A.12.4.1 L'
            container["Control Description"] = (
                """ Logging and Monitoring: Integration of IAM with AWS CloudTrail ensures
                that logging and monitoring controls are met by recording and analyzing actions
                made on AWS resources. """
            )
            container["Logging & Monitoring"] = container['managementEvent']
            container['Privileged Access'] = container['userIdentity']
            container.pop('managementEvent',None)
            container.pop('userIdentity',None)

            return self.__check_compliance_feature(container)
        except ClientError as e:
            container.update({
                'check': 'S3 Bucket Logging',
                'status': 'ERROR',
                'details': str(e)
            })

# Define the structure for storing compliance check results

container = {}
# # Run the compliance check functions

compliance_checker = ComplianceManager()
# password_requirement=compliance_checker.check_iam_minimum_password_length(container)
# print(password_requirement)
#s3_encryption_at_rest = compliance_checker.check_s3_encryption_at_rest(container)
#kms_strc = compliance_checker.check_iam_compliance(container)

