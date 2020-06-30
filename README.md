# Wake Up EC2 Runners

This github action allows you to find and wake up self-hosted runners on AWS EC2 to meet the concurrency requirements of the workflow.

It will list EC2 instances, grouping them by their status and their CPU Usage to determine which ones are available to take new workflow jobs and then start stopped instances if required (and available).

## Requirements

You will first need to create a new IAM Policy on AWS' dashboard with the following rules:

```
ec2:DescribeInstances
ec2:StartInstances
cloudwatch:GetMetricStatistics
```

Assign that policy to a new user, which should be specific for this action, and create an access key and secret pair.

## Usage

```yaml
# .github/workflows/my-workflow.yml
jobs:
  my_job:
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      - uses: MasterworksIO/action-wake-up-ec2-runners@master
        with:
          aws-region: us-east-2
          concurrency: 4
          tags: { "MyCustomAWSTag": "github-action-runner" }
```
