import boto3
from botocore.exceptions import ClientError
from pprint import pprint
from typing import Dict,TypeVar,StringVar,Generic
from dotenv import load_dotenv
import json
from dataclasses import dataclasses
# from os.path import join, dirname
import os

load_dotenv()

T = TypeVar('T')
U=TypeVar('U')
@dataclasses
class ComplianceChecker(Generic[T,U],object):
    secrets :str| None = os.getenv('Secret_access_key')
    access_key :str| None= os.getenv('access_key')
    region  :str| None = os.getenv('region')
    if not secrets or not access_key:
        raise Exception('Access denied: Missing credentials')
    else:
        session_connection =  boto3.Session(aws_access_key_id=access_key,
                                    aws_secret_access_key=secrets,
                                    region_name=region
                                    )
        


    # Define the structure for storing compliance check results
    container = {}

    # A.9.4.1 - Use of Secret Authentication Information
    def check_iam_minimum_password_length(self,container)->json:
        """
        Check IAM password policy for minimum password length compliance.
        """
        try:
            iam = self.session_conn.client('iam')
            response = iam.get_account_password_policy()
            policy = response['PasswordPolicy']
            if type(policy) == dict:
                container.update(policy)
                pprint(container,indent=3)
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


    def check_mfa_compliance(self,container)->json:
        """
        Check if MFA is enabled for privileged IAM users.
        """
        try:
            iam = self.session_conn.client('iam')
            users = iam.list_users()['Users']
            mfa_not_enabled = []
            for user in users:
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                if not mfa_devices['MFADevices']:
                    mfa_not_enabled.append(user['UserName'])
            
            if mfa_not_enabled:
                container.update({
                    'check': 'MFA for Privileged Users',
                    'status': 'FAILED',
                    'details': f'MFA not enabled for privileged users: {", ".join(mfa_not_enabled)}'
                })
                pprint(container,indent=3)
            else:
                container.update({
                    'check': 'MFA for Privileged Users',
                    'status': 'PASSED',
                    'details': 'All privileged users have MFA enabled.'
                })
                pprint(container,indent=3)
        except ClientError as e:
            container.update({
                'check': 'MFA for Privileged Users',
                'status': 'ERROR',
                'details': str(e)
            })
            pprint(container,indent=3)

     # managing network security. (A.13.1.1)():
    def S3_secure_data_transfers(self,container)->json:
        """
        Check if S3 buckets are configured to ensure secure data transfers.
        """
        try:
            s3 = self.session_conn.client('s3')
            response = s3.get_bucket_policy(Bucket='bucket-name')
            policy = response['Policy']
            container.append({
                'check': 'S3 Bucket Policy',
                'status': 'PASS',
                'details': 'S3 bucket policy is configured correctly.'
            })
        except ClientError as e:
            container.append({
                'check': 'S3 Bucket Policy',
                'status': 'FAIL',
                'details': str(e)
            })

    # A.13.2.1 - Information Transfer Policies and Procedures:
    def check_s3_encryption_at_rest(self,container)->json:
        """
        Check if encryption at rest is enabled for S3 buckets.
        """
        try:
            s3 = self.session_conn.client('s3')
            response = s3.get_bucket_encryption(Bucket='bucket-name')
            rules = response['ServerSideEncryptionConfiguration']['Rules']
            if rules:
                container.append({
                    'check': 'Encryption at Rest',
                    'status': 'PASS',
                    'details': 'Encryption at rest is enabled for S3 buckets.'
                })
            else:
                container.append({
                    'check': 'Encryption at Rest',
                    'status': 'FAIL',
                    'details': 'Encryption at rest is not enabled for S3 buckets.'
                })
        except ClientError as e:
            container.append({
                'check': 'Encryption at Rest',
                'status': 'ERROR',
                'details': str(e)
            })

    def check_s3_encryption_at_rest(self,container)->json:
    # AWS KMS (Key Management Service) A.10.1.1 - Cryptographic Controls: 
    # AWS KMS is central to managing cryptographic keys for data encryption,
    # directly supporting the control requiring the use and management of cryptographic techniques and keys.():
        """
        Check if AWS KMS is used for managing cryptographic keys.
        """
        try:
            kms = self.session_conn.client('kms')
            keys = kms.list_keys()
            if keys['Keys']:
                container.append({
                    'check': 'AWS KMS',
                    'status': 'PASS',
                    'details': 'AWS KMS is used for managing cryptographic keys.'
                })
            else:
                container.append({
                    'check': 'AWS KMS',
                    'status': 'FAIL',
                    'details': 'AWS KMS is not used for managing cryptographic keys.'
                })
        except ClientError as e:
            container.append({
                'check': 'AWS KMS',
                'status': 'ERROR',
                'details': str(e)
            })

    #AWS S3 (Simple Storage Service) A.8.2.3 - Asset Management and Classification: 
    #S3 buckets containing data must be classified according to their information security level.
    #A.10.1.1 - Cryptographic Controls: Ensuring that data stored in S3 buckets is encrypted, 
    # both at rest and in transit, aligns with the requirement for protecting sensitive information using cryptographic measures.

    def check_s3_bucket_classification(self,container)->json:
        """
        Check if S3 buckets are classified according to their information security level.
        AWS S3 (Simple Storage Service) A.8.2.3 - Asset Management and Classification: S3 buckets containing data must be classified according to their information security level.
        """
        try:
            s3 = self.session_conn.client('s3')
            response = s3.get_bucket_tagging(Bucket='bucket-name')
            tags = response['TagSet']
            if tags:
                container.append({
                    'check': 'S3 Bucket Classification',
                    'status': 'PASS',
                    'details': 'S3 buckets are classified according to their information security level.'
                })
            else:
                container.append({
                    'check': 'S3 Bucket Classification',
                    'status': 'FAIL',
                    'details': 'S3 buckets are not classified according to their information security level.'
                })
        except ClientError as e:
            container.append({
                'check': 'S3 Bucket Classification',
                'status': 'ERROR',
                'details': str(e)
            })
    
    def logging_and_monitoring(self,container)->json:
        #A.12.4.1 - Logging and Monitoring: Integration of IAM with AWS CloudTrail 
        # ensures that logging and monitoring controls are met by recording and analyzing actions made on AWS resources.
        """
        Check if IAM is integrated with AWS CloudTrail.
        """
        try:
            cloudtrail = self.session_conn.client('cloudtrail')
            trails = cloudtrail.describe_trails()
            if trails['trailList']:
                container.append({
                    'check': 'CloudTrail Integration',
                    'status': 'PASS',
                    'details': 'IAM is integrated with AWS CloudTrail.'
                })
            else:
                container.append({
                    'check': 'CloudTrail Integration',
                    'status': 'FAIL',
                    'details': 'IAM is not integrated with AWS CloudTrail.'
                })
        except ClientError as e:
            container.append({
                'check': 'CloudTrail Integration',
                'status': 'ERROR',
                'details': str(e)
            })
    
    
    def check_kms_key_lifecycle(self,container)->json:
        # A.10.1.2 - Management of Cryptographic Keys: Specifically addressing the 
        # lifecycle management of cryptographic keys, including generation, distribution, 
        # storage, and destruction, which KMS facilitates.
        """
        Check if AWS KMS is used for managing the lifecycle of cryptographic keys.
        """
        try:
            kms = self.session_conn.client('kms')
            keys = kms.list_keys()
            if keys['Keys']:
                container.append({
                    'check': 'KMS Key Lifecycle',
                    'status': 'PASS',
                    'details': 'AWS KMS is used for managing the lifecycle of cryptographic keys.'
                })
            else:
                container.append({
                    'check': 'KMS Key Lifecycle',
                    'status': 'FAIL',
                    'details': 'AWS KMS is not used for managing the lifecycle of cryptographic keys.'
                })
        except ClientError as e:
            container.append({
                'check': 'KMS Key Lifecycle',
                'status': 'ERROR',
                'details': str(e)
            })
    
    def check_s3_bucket_logging(self,container)->json:
        # A.12.4.1 - Logging and Monitoring: Integration of IAM with AWS CloudTrail ensures that logging and monitoring controls are met by recording and analyzing actions made on AWS resources.
        """
        Check if S3 bucket logging is enabled.
        """
        try:
            s3 = self.session_conn.client('s3')
            response = s3.get_bucket_logging(Bucket='bucket-name')
            logging_enabled = response['LoggingEnabled']
            if logging_enabled:
                container.append({
                    'check': 'S3 Bucket Logging',
                    'status': 'PASS',
                    'details': 'S3 bucket logging is enabled.'
                })
            else:
                container.append({
                    'check': 'S3 Bucket Logging',
                    'status': 'FAIL',
                    'details': 'S3 bucket logging is not enabled.'
                })
        except ClientError as e:
            container.append({
                'check': 'S3 Bucket Logging',
                'status': 'ERROR',
                'details': str(e)
            })
  
    # # Run the compliance check functions
    check_iam_minimum_password_length()
    # check_user_registration_deregistration()
    # check_privileged_access_management()
    # check_mfa_for_privileged_users()

    # # Example of how to print the results
    # for result in container:
    #     print(result)
