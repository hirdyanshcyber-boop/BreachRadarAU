"""
AWS Lambda entry point. Triggered by EventBridge every 15 minutes.
Collects → deduplicates → stores → enriches → alerts.
"""
import json
import os
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime, timezone

from collectors import acsc_rss, hibp, cisa_kev, oaic_scraper
from processors.gemma_enricher import GemmaEnricher
from processors.sns_alerter import SNSAlerter

EVENTS_TABLE = os.environ.get("DYNAMO_EVENTS_TABLE", "breach_events")
OAIC_TABLE = os.environ.get("DYNAMO_OAIC_TABLE", "oaic_stats")
AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-2")

_dynamodb = None
_enricher = None
_alerter = None


def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    return _dynamodb


def _get_enricher():
    global _enricher
    if _enricher is None:
        _enricher = GemmaEnricher()
    return _enricher


def _get_alerter():
    global _alerter
    if _alerter is None:
        _alerter = SNSAlerter()
    return _alerter


def _event_exists(table, event_id: str) -> bool:
    try:
        resp = table.get_item(Key={"event_id": event_id})
        return "Item" in resp
    except ClientError:
        return False


def _store_event(table, event: dict) -> bool:
    try:
        table.put_item(
            Item=event,
            ConditionExpression="attribute_not_exists(event_id)",
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def _store_oaic_stats(oaic_table, stats: dict):
    try:
        oaic_table.put_item(Item=stats)
    except ClientError:
        pass


def _collect_all_events() -> list[dict]:
    events = []

    for event in acsc_rss.fetch():
        events.append(event)

    hibp_key = os.environ.get("HIBP_API_KEY")
    for event in hibp.fetch(api_key=hibp_key):
        events.append(event)

    for event in cisa_kev.fetch():
        events.append(event)

    return events


def handler(event: dict, context) -> dict:
    db = _get_dynamodb()
    events_table = db.Table(EVENTS_TABLE)
    oaic_table = db.Table(OAIC_TABLE)

    try:
        enricher = _get_enricher()
        enricher_available = True
    except Exception:
        enricher_available = False

    try:
        alerter = _get_alerter()
        alerter_available = True
    except Exception:
        alerter_available = False

    # Refresh OAIC stats (idempotent — overwrites same period data)
    for stats in oaic_scraper.fetch_pdf_stats():
        _store_oaic_stats(oaic_table, stats)

    raw_events = _collect_all_events()

    stored = 0
    enriched = 0
    alerted = 0
    skipped = 0

    for raw_event in raw_events:
        event_id = raw_event.get("event_id")
        if not event_id:
            continue

        if _event_exists(events_table, event_id):
            skipped += 1
            continue

        if enricher_available:
            try:
                processed_event = enricher.enrich(raw_event)
                enriched += 1
            except Exception:
                processed_event = {**raw_event, "enriched": False}
        else:
            processed_event = {**raw_event, "enriched": False}

        # Convert lists to DynamoDB-compatible format
        for key, value in processed_event.items():
            if isinstance(value, list) and len(value) == 0:
                processed_event[key] = []

        if _store_event(events_table, processed_event):
            stored += 1

            if alerter_available:
                try:
                    if alerter.send_alert(processed_event):
                        alerted += 1
                except Exception:
                    pass

    result = {
        "statusCode": 200,
        "body": json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_collected": len(raw_events),
            "new_stored": stored,
            "enriched": enriched,
            "alerts_sent": alerted,
            "duplicates_skipped": skipped,
        }),
    }

    print(f"[BreachRadarAU] Run complete: {result['body']}")
    return result


if __name__ == "__main__":
    # Local test run
    from dotenv import load_dotenv
    load_dotenv()
    result = handler({}, None)
    print(result)
