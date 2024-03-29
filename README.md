# Wake Up EC2 Runners

This github action allows you to find and wake up self-hosted runners on AWS EC2 to meet the concurrency requirements of the workflow.

It will list EC2 instances, grouping them by their status and their CPU Usage to determine which ones are available to take new workflow jobs and then start stopped instances if required (and available).

## Requirements

You will first need to create a new IAM Policy on AWS' dashboard with the following rules:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:StartInstances",
                "ec2:DescribeRegions",
                "cloudwatch:GetMetricStatistics"
            ],
            "Resource": "*"
        }
    ]
}
```

Assign that policy to a new user, which should be specific for this action, and create an access key and secret pair.

For the action to be able to Categorize your instances between idle or busy, you need to [enable Detailed Monitoring](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html) on all of them. If not enabled, all your instance will be considered idle, which might make you under-staffed.

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
          aws-region: us-east-1
      - uses: MasterworksIO/action-wake-up-ec2-runners@master
        with:
          concurrency: 4
          tags: { "MyCustomAWSTag": "github-action-runner" }
```
