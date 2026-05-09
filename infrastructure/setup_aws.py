"""
One-time AWS infrastructure setup.
Creates DynamoDB tables, SNS topic, and EventBridge rule.
Run once before first deployment: python infrastructure/setup_aws.py
"""
import boto3
import os
import json
from dotenv import load_dotenv

load_dotenv()

REGION = os.environ.get("AWS_REGION", "ap-southeast-2")
EVENTS_TABLE = os.environ.get("DYNAMO_EVENTS_TABLE", "breach_events")
OAIC_TABLE = os.environ.get("DYNAMO_OAIC_TABLE", "oaic_stats")
VENDORS_TABLE = os.environ.get("DYNAMO_VENDORS_TABLE", "vendor_watchlist")
ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_MINUTES", "15"))


def create_dynamodb_tables():
    db = boto3.resource("dynamodb", region_name=REGION)
    client = boto3.client("dynamodb", region_name=REGION)

    existing = {t["TableName"] for t in client.list_tables()["TableNames"]}

    # breach_events table
    if EVENTS_TABLE not in existing:
        print(f"Creating table: {EVENTS_TABLE}")
        db.create_table(
            TableName=EVENTS_TABLE,
            KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "event_id", "AttributeType": "S"},
                {"AttributeName": "severity", "AttributeType": "S"},
                {"AttributeName": "ingested_at", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "severity-ingested-index",
                    "KeySchema": [
                        {"AttributeName": "severity", "KeyType": "HASH"},
                        {"AttributeName": "ingested_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
            Tags=[
                {"Key": "Project", "Value": "BreachRadarAU"},
                {"Key": "Region", "Value": "Australia"},
            ],
        )
        db.Table(EVENTS_TABLE).wait_until_exists()
        print(f"  ✓ {EVENTS_TABLE} created")

        # TTL: auto-expire events after 90 days
        client.update_time_to_live(
            TableName=EVENTS_TABLE,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
        )
        print(f"  ✓ TTL enabled (90 days)")
    else:
        print(f"  ✓ {EVENTS_TABLE} already exists")

    # oaic_stats table
    if OAIC_TABLE not in existing:
        print(f"Creating table: {OAIC_TABLE}")
        db.create_table(
            TableName=OAIC_TABLE,
            KeySchema=[{"AttributeName": "period", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "period", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": "Project", "Value": "BreachRadarAU"}],
        )
        db.Table(OAIC_TABLE).wait_until_exists()
        print(f"  ✓ {OAIC_TABLE} created")
    else:
        print(f"  ✓ {OAIC_TABLE} already exists")

    # vendor_watchlist table
    if VENDORS_TABLE not in existing:
        print(f"Creating table: {VENDORS_TABLE}")
        db.create_table(
            TableName=VENDORS_TABLE,
            KeySchema=[{"AttributeName": "vendor_name", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "vendor_name", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": "Project", "Value": "BreachRadarAU"}],
        )
        db.Table(VENDORS_TABLE).wait_until_exists()
        print(f"  ✓ {VENDORS_TABLE} created")

        # Seed default vendors
        vendors_table = db.Table(VENDORS_TABLE)
        defaults = ["Canvas", "Salesforce", "Microsoft", "Atlassian", "Okta", "Cisco", "Fortinet", "VMware"]
        from datetime import datetime, timezone
        for v in defaults:
            vendors_table.put_item(Item={"vendor_name": v, "added_at": datetime.now(timezone.utc).isoformat()})
        print(f"  ✓ Seeded {len(defaults)} default vendors")
    else:
        print(f"  ✓ {VENDORS_TABLE} already exists")


def create_sns_topic() -> str:
    sns = boto3.client("sns", region_name=REGION)
    resp = sns.create_topic(
        Name="breach-alerts",
        Attributes={"DisplayName": "BreachRadar AU Alerts"},
        Tags=[{"Key": "Project", "Value": "BreachRadarAU"}],
    )
    topic_arn = resp["TopicArn"]
    print(f"✓ SNS topic: {topic_arn}")

    if ALERT_EMAIL:
        sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=ALERT_EMAIL)
        print(f"  ✓ Subscribed {ALERT_EMAIL} — check inbox to confirm")

    return topic_arn


def create_lambda_role() -> str:
    iam = boto3.client("iam")
    role_name = "BreachRadarAU-Lambda-Role"

    try:
        resp = iam.get_role(RoleName=role_name)
        role_arn = resp["Role"]["Arn"]
        print(f"✓ IAM role exists: {role_arn}")
        return role_arn
    except iam.exceptions.NoSuchEntityException:
        pass

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }

    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="BreachRadar AU Lambda execution role",
        Tags=[{"Key": "Project", "Value": "BreachRadarAU"}],
    )
    role_arn = resp["Role"]["Arn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Scan", "dynamodb:Query",
                           "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
                "Resource": [
                    f"arn:aws:dynamodb:{REGION}:*:table/{EVENTS_TABLE}",
                    f"arn:aws:dynamodb:{REGION}:*:table/{EVENTS_TABLE}/index/*",
                    f"arn:aws:dynamodb:{REGION}:*:table/{OAIC_TABLE}",
                    f"arn:aws:dynamodb:{REGION}:*:table/{VENDORS_TABLE}",
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["sns:Publish"],
                "Resource": f"arn:aws:sns:{REGION}:*:breach-alerts",
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="BreachRadarAU-Policy",
        PolicyDocument=json.dumps(policy),
    )

    # Attach basic Lambda execution managed policy
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    print(f"✓ IAM role created: {role_arn}")
    return role_arn


def create_eventbridge_rule(lambda_arn: str):
    events_client = boto3.client("events", region_name=REGION)
    lambda_client = boto3.client("lambda", region_name=REGION)

    rule_name = "BreachRadarAU-Collector"
    schedule = f"rate({POLL_INTERVAL} minutes)"

    resp = events_client.put_rule(
        Name=rule_name,
        ScheduleExpression=schedule,
        State="ENABLED",
        Description=f"BreachRadar AU — trigger collectors every {POLL_INTERVAL} minutes",
    )
    rule_arn = resp["RuleArn"]

    try:
        lambda_client.add_permission(
            FunctionName=lambda_arn,
            StatementId="EventBridgeInvoke",
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=rule_arn,
        )
    except lambda_client.exceptions.ResourceConflictException:
        pass

    events_client.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "BreachRadarAULambda", "Arn": lambda_arn}],
    )

    print(f"✓ EventBridge rule: {schedule} → {lambda_arn}")


def main():
    print("\n══════════════════════════════════════════")
    print("  BreachRadar AU — AWS Infrastructure Setup")
    print(f"  Region: {REGION}")
    print("══════════════════════════════════════════\n")

    print("1. DynamoDB tables")
    create_dynamodb_tables()

    print("\n2. SNS topic")
    topic_arn = create_sns_topic()

    print("\n3. IAM role")
    role_arn = create_lambda_role()

    print(f"""
══════════════════════════════════════════
  Setup complete. Next steps:

  1. Add to .env:
     SNS_ALERT_TOPIC_ARN={topic_arn}

  2. Deploy Lambda (see README):
     zip -r breach_radar.zip . -x "*.git*" "venv/*"
     aws lambda create-function \\
       --function-name BreachRadarAU \\
       --runtime python3.12 \\
       --handler lambda_handler.handler \\
       --role {role_arn} \\
       --zip-file fileb://breach_radar.zip \\
       --timeout 300 \\
       --memory-size 512 \\
       --region {REGION}

  3. Set EventBridge rule:
     python infrastructure/setup_aws.py --eventbridge <lambda-arn>

  4. Run dashboard:
     streamlit run dashboard/app.py
══════════════════════════════════════════
""")


if __name__ == "__main__":
    import sys
    main()
