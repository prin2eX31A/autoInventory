# Auto Inventory in AWS Landing Zone
Using AWS Config Aggregator to create an inventory list in CSV format.

## Dependencies:
- Python 3.11.2
- AWS CLI 2.11.13
- AWS SDK / Boto3 1.26.132

## Prerequisites
- Create AWS Config and register to the Organization Unit
- Create AWS Config Aggregator for centralizing the Config Logs
- Install all dependencies above

## Considerations
- Name of Config Aggregator
- AWS Account ID
- IAM User
- Name of AWS CLI Profile
