import boto3
import csv
import json
import botocore

IamClient = boto3.client('iam')
S3Resource = boto3.resource('s3')
S3Client = boto3.client('s3')

with open('permissions.csv', 'w', newline='') as file:
    CsvWriter = csv.writer(file)
    CsvRow = ['User', 'Policy Type', 'Group', 'Policy', 'Managed Policy', 'Affect', 'Resource', 'Action', 'JSON']
    CsvWriter.writerow(CsvRow)
    print(CsvRow)

    Users = IamClient.list_users()
    for Usr in Users['Users']:
        # IAM user can have inline or managed (attached) policies

        # get the names of the inline policies embedded in the specified IAM user definition.
        InlinePolicies = IamClient.list_user_policies(UserName=Usr['UserName'])
        for InlinePolicy in InlinePolicies['PolicyNames']:
            UsrPolicy = IamClient.get_user_policy(UserName=Usr['UserName'], PolicyName=InlinePolicy)
            for Stmt in UsrPolicy['PolicyDocument']['Statement']:
                CsvRow = [Usr['UserName'], 'InlinePolicy', '', InlinePolicy, '', Stmt['Effect'], Stmt['Resource'],
                          Stmt['Action'], UsrPolicy]
                CsvWriter.writerow(CsvRow)
                print(CsvRow)

        # get all managed policies that are attached to an IAM user
        AttachedPolicies = IamClient.list_attached_user_policies(UserName=Usr['UserName'])
        for AttachedPolicy in AttachedPolicies['AttachedPolicies']:
            CsvRow = [Usr['UserName'], 'AttachedManagedPolicy', '', '', AttachedPolicy['PolicyArn'], '', '', '',
                      IamClient.get_policy(PolicyArn=AttachedPolicy['PolicyArn'])]
            CsvWriter.writerow(CsvRow)

        # In addition to the above inline/managed user level policies, a user can be member of a group. In that case the
        # group's inline and managed (attached) policies are also applied to the user

        # get the assigned groups for an IAM user
        Groups = IamClient.list_groups_for_user(UserName=Usr['UserName'])
        # iterate through the groups
        for Grp in Groups['Groups']:

            # get the group's inline policies
            InlineGroupPolicies = IamClient.list_group_policies(GroupName=Grp['GroupName'])
            for InlineGrpPolicy in InlineGroupPolicies['PolicyNames']:
                GrpPolicy = IamClient.get_group_policy(GroupName=Grp['GroupName'], PolicyName=InlineGrpPolicy)
                for Stmt in GrpPolicy['PolicyDocument']['Statement']:
                    CsvRow = [Usr['UserName'], 'InlineGroupPolicy', Grp['GroupName'], InlineGrpPolicy, '',
                              Stmt['Effect'], Stmt['Resource'], Stmt['Action'], GrpPolicy]
                    CsvWriter.writerow(CsvRow)
                print(CsvRow)

            # get the group's attached managed policies
            AttachedGrpPolicies = IamClient.list_attached_group_policies(GroupName=Grp['GroupName'])
            for AttachedGrpPolicy in AttachedGrpPolicies['AttachedPolicies']:
                CsvRow = [Usr['UserName'], 'ManagedGroupPolicy', Grp['GroupName'], '',
                          AttachedGrpPolicy['PolicyArn'], '', '', '',
                          IamClient.get_policy(PolicyArn=AttachedGrpPolicy['PolicyArn'])]
                CsvWriter.writerow(CsvRow)
                print(CsvRow)

    # In addition to policies assigned to an user in IAM, S3 bucket policies can assign permissions to an user
    CsvRow = ['bucket policies giving access to iam users to read/write/delete/list the buckets']
    print(CsvRow)
    CsvWriter.writerow(CsvRow)
    for Bucket in S3Resource.buckets.all():
        try:
            Bp = S3Client.get_bucket_policy(Bucket=Bucket.name)
            # json.loads(bp['Policy'])
            if 'arn:aws:iam' in Bp['Policy'] and (':user/' in Bp['Policy'] or ':group/' in Bp['Policy']):
                for Stmt in json.loads(Bp['Policy'])['Statement']:
                    if 'AWS' in Stmt['Principal']:
                        CsvRow = [Stmt['Principal']['AWS'], 'BucketPolicy', '', '', '', Stmt['Effect'],
                                  Stmt['Resource'], Stmt['Action']]
                        print(CsvRow)
                        CsvWriter.writerow(CsvRow)
        except botocore.exceptions.ClientError:
            pass

# rolesObj = client.list_roles() # returns a dictionary
# Role_list = rolesObj['Roles']
# for key in Role_list:
#     print(key['RoleName'], key['Arn'])
#
