import boto3
import botocore.config
import botocore.exceptions
import os
import json
import copy
import time

# Extract environment variables.
INPUT_CDK_TEMPLATE = os.environ["INPUT_CDK_TEMPLATE"]
OUTPUT_CDK_TEMPLATE = os.environ["OUTPUT_CDK_TEMPLATE"]
DYNAMODB_ENDPOINT = os.environ["DYNAMODB_ENDPOINT"]
LOCAL_LAMBDA_PATH = os.environ["LOCAL_LAMBDA_PATH"]
DEPLOYER_ADDRESS = os.environ["DEPLOYER_ADDRESS"]

# How long to wait for DynamoDB to accept requests, in seconds.
DYNAMODB_READY_TIMEOUT_SECONDS = 30

def main():
    """
    Main function to read a CDK template, create missing DynamoDB tables,
    replace local Lambda paths, and write the modified template.
    """
    ddb_client = create_ddb_client()
    template = read_template(INPUT_CDK_TEMPLATE)
    wait_for_dynamodb(DYNAMODB_READY_TIMEOUT_SECONDS)
    create_missing_tables(template, ddb_client)
    modified_template = replace_local_lambda_path(template, LOCAL_LAMBDA_PATH)
    write_template(modified_template, OUTPUT_CDK_TEMPLATE)

def create_ddb_client(config=None):
    """
    Create a DynamoDB client for the configured endpoint.
    """
    return boto3.client(
        'dynamodb',
        endpoint_url=DYNAMODB_ENDPOINT,
        region_name="us-west-2",
        aws_access_key_id="xxxxxxxx",
        aws_secret_access_key="xxxxxxxx",
        config=config,
    )

def read_template(template_path):
    """
    Read a JSON template from the specified file path.
    """
    with open(template_path) as fp:
        template = json.load(fp)
    print(f"Successfully read template from {template_path}")
    return template

# Write updated CDK template.
def write_template(template, template_path):
    """
    Write a JSON template to the specified file path.
    """
    with open(template_path, "w") as fp:
        json.dump(template, fp, indent=1)
    print(f"Successfully wrote template to {template_path}")

def wait_for_dynamodb(timeout_seconds):
    """
    Wait until DynamoDB accepts requests, exiting if it doesn't within
    the timeout (plus a 5-second buffer).

    The DynamoDB Local container can be running before DynamoDB is
    listening on its port. Requests sent during that window fail with a
    connection error, so we retry those until DynamoDB responds.
    """

    ddb_client = create_ddb_client(botocore.config.Config(
        connect_timeout=5,
        read_timeout=5,
        retries={"total_max_attempts": 1},
    ))
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        try:
            ddb_client.list_tables(Limit=1)
            return
        except (botocore.exceptions.ConnectionClosedError,
                botocore.exceptions.EndpointConnectionError,
                botocore.exceptions.ConnectTimeoutError,
                botocore.exceptions.ReadTimeoutError) as error:

            print(f"Waiting for DynamoDB at {DYNAMODB_ENDPOINT} to accept requests: {error}")
            time.sleep(1)

    print(f"DynamoDB at {DYNAMODB_ENDPOINT} did not accept requests within {timeout_seconds} seconds")
    exit(1)

def get_template_resource_ids_for_resources_type(template, resource_type):
    """
    Get the template resource IDs for a specific resource type in the template.
    """
    return [template_resource_id for template_resource_id, resource_data in template["Resources"].items() \
                if resource_data["Type"] == resource_type]

def get_existing_table_names(ddb_client):
    """
    Get the names of existing DynamoDB tables as a set.
    """
    counter = 0
    existing_tables = set()
    list_tables_response = ddb_client.list_tables(Limit=10)

    def print_discovered_tables(table_names):
        """ Print discovered tables. """
        print(f"Discovered tables:\n\t- {'\n\t- '.join(table_names)}")

    while True:

        if "TableNames" in list_tables_response:
            existing_tables = existing_tables.union(list_tables_response["TableNames"])
        if "LastEvaluatedTableName" not in list_tables_response:
            break

        counter += 1
        if counter > 256:
            print("Either stuck in an infinite loop or you have too many tables.")
            print_discovered_tables(existing_tables)
            exit(1)

        # Get pagination token and use that to make subsequent requests.
        last_evaluated_table_name = list_tables_response["LastEvaluatedTableName"]
        list_tables_response = ddb_client.list_tables(
            Limit=10,
            ExclusiveStartTableName=last_evaluated_table_name,
        )

    print_discovered_tables(existing_tables)
    return existing_tables

def create_missing_tables(template, ddb_client):
    """
    Create missing DynamoDB tables based on the template.
    """
    existing_tables = get_existing_table_names(ddb_client)
    table_template_resource_ids = get_template_resource_ids_for_resources_type(
        template, "AWS::DynamoDB::Table")
    for table_template_resource_id in table_template_resource_ids:
        table_properties = template["Resources"][table_template_resource_id]["Properties"]
        table_name = table_properties["TableName"]
        if table_name not in existing_tables:
            # Make table if it's not present.
            print(f"Creating table {table_name}.")
            ddb_client.create_table(**table_properties)
            print(f"Successfully created table {table_name}.")
        else:
            # Don't make the table if it's already present.
            print(f"Table {table_name} already exists, leaving it alone.")

def replace_local_lambda_path(template, local_lambda_path):
    """
    Replace the local Lambda path in the template.
    """

    # Ensure we don't modify the original template so this function doesn't
    # have unintended side effects.
    modified_template = copy.deepcopy(template)
    lambda_template_resource_ids = get_template_resource_ids_for_resources_type(
        modified_template, "AWS::Lambda::Function")

    # Ensure there's exactly one lambda function in the template.
    if len(lambda_template_resource_ids) == 0:
        print(f"Not making any lambda changes because no Lambda functions were found.")
        return
    if len(lambda_template_resource_ids) != 1:
        print(f"{len(lambda_template_resource_ids)} Lambda functions found, but this script supports at most 1. Failing...")
        print(f"Lambda resource ids: {lambda_template_resource_ids}")
        exit(1)

    # Update lambda local code path.
    lambda_template_resource_id = lambda_template_resource_ids[0]
    print(f"Setting cdk resource with template id {lambda_template_resource_id} to use local code path {local_lambda_path}")
    modified_template["Resources"][lambda_template_resource_id]["Metadata"]["aws:asset:path"] = local_lambda_path
    return modified_template

if __name__ == "__main__":
    main()
