import json
import boto3
from datetime import datetime

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    ec2 = boto3.client('ec2')
    
    findings = []
    remediations = []
    
    # ============================================================
    # 1. S3 Public Bucket Detection & Auto-Remediation
    # ============================================================
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False
            
            # Check ACLs
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    grantee = grant.get('Grantee', {})
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        is_public = True
                        break
            except:
                pass
            
            # Check bucket policy if ACL didn't flag
            if not is_public:
                try:
                    policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
                    if policy_status['PolicyStatus']['IsPublic']:
                        is_public = True
                except:
                    pass
            
            if is_public:
                findings.append({
                    'type': 'public_bucket',
                    'resource': bucket_name,
                    'risk_score': 9,
                    'cost_impact': 1000.0,
                    'fix_cost': 0.0,
                    'details': f'Bucket {bucket_name} is publicly accessible'
                })
                # Auto-remediate: block all public access
                try:
                    s3.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    remediations.append(f'Blocked public access on {bucket_name}')
                except Exception as e:
                    print(f"Remediation failed for {bucket_name}: {e}")
    except Exception as e:
        print(f"S3 scan error: {e}")
    
    # ============================================================
    # 2. EBS Unencrypted Volumes Detection (no auto-remediation)
    # ============================================================
    try:
        volumes = ec2.describe_volumes()['Volumes']
        for vol in volumes:
            if not vol.get('Encrypted', False):
                findings.append({
                    'type': 'unencrypted_volume',
                    'resource': vol['VolumeId'],
                    'risk_score': 7,
                    'cost_impact': 500.0,
                    'fix_cost': 0.10,
                    'details': f"Volume {vol['VolumeId']} is not encrypted"
                })
    except Exception as e:
        print(f"EBS scan error: {e}")
    
    # ============================================================
    # 3. Priority Scoring (higher = fix first)
    # ============================================================
    for f in findings:
        priority = (f['risk_score'] * 0.5) + (f['cost_impact'] * 0.3) - (f['fix_cost'] * 0.2)
        f['priority_score'] = round(priority, 2)
    
    findings.sort(key=lambda x: x['priority_score'], reverse=True)
    
    # ============================================================
    # 4. Output
    # ============================================================
    print(f"Scan completed at {datetime.utcnow().isoformat()}")
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f" - {f['type']}: {f['resource']} (priority {f['priority_score']})")
    print(f"Auto-remediations applied: {len(remediations)}")
    for r in remediations:
        print(f"   ✓ {r}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'scan_time': datetime.utcnow().isoformat(),
            'findings': findings,
            'remediations': remediations
        })
    }