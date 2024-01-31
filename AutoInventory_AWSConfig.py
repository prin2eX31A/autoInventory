#!/usr/bin/env python3
import os
import boto3
import botocore.exceptions
import datetime
from datetime import timezone
import re
import logging
import time
import csv
import json

"""
Using BatchGetResourceConfig
"""

def lambda_handler(event, context):

    # Use profile with AWS CLI while run locally:
    session = boto3.session.Session(profile_name='Admin')

    # Use lambda role while run remotely:
    #state the source credential / source session
    # session = boto3.session.Session()

    #region = os.environ['AWS_REGION']    #can only be used on lambda
    region = 'ap-southeast-1'

    awsaccountid = ''

    aggregator = 'dcp-config-aggregator-core-command-center'

    def timestamp():
        return datetime.datetime.now(tz=None).strftime("%d %b %Y - %H:%M")

    def get_resource_list_from_config(resource_type, token, accountID, region):

        # ResourceTaggingAPI is casted as tagapi
        configapi = session.client('config', region_name=region)

        print(f'[{timestamp()}] | session created in {region}')

        print(f'[{timestamp()}] | resource type is {resource_type}')

        try:

            resources_list = configapi.list_aggregate_discovered_resources(
                ConfigurationAggregatorName=aggregator,
                # ResourceType='AWS::ApiGateway::RestApi',
                ResourceType=resource_type,
                Limit=100,
                NextToken=token
            )

            print(f'[{timestamp()}] | config aggregator list resources request sent')
            #print(resources_list)
            '''
                expected output:
                {
                    'ResourceIdentifiers': [
                        {
                            'SourceAccountId': 'string',
                            'SourceRegion': 'string',
                            'ResourceId': 'string',
                            'ResourceType': "ResourceType",
                            'ResourceName': 'string'
                        },
                        ...
                    ],
                    'NextToken': 'string'
                }
            '''
        except botocore.exceptions.ClientError as err:
            logging.error("Couldn't fulfill the request to Config %s. Here's why: %s: %s", resource_type,
                          err.response['Error']['Code'], err.response['Error']['Message'])
            raise


        resourceName_list = []

        for resources in resources_list['ResourceIdentifiers']:

            resource_details = {}

            resource_details['SourceAccountId'] = resources['SourceAccountId']
            resource_details['ResourceId'] = resources['ResourceId']
            resource_details['SourceRegion'] = resources['SourceRegion']
            resource_details['ResourceType'] = resource_type

            resourceName_list.append(resource_details)

        # logging.CRITICAL()

        next_token = resources_list.get('NextToken')

        #print(resourceName_list)
        # print(f'testing: NextToken is {next_token}')

        return [resourceName_list, next_token]

    def search_for_resource_details(resourcelist):

        configapi = session.client('config', region_name=region)
        print(f'[{timestamp()}] | session created in {region}')

        resource_detail = configapi.batch_get_aggregate_resource_config(
            ConfigurationAggregatorName='dcp-config-aggregator-core-command-center',
            ResourceIdentifiers=resourcelist
        )

        print(f'[{timestamp()}] | config aggregator batch get config request sent')
        # print(resource_detail)

        resourceinfo_list = []

        for item in resource_detail['BaseConfigurationItems']:
            resource_details_dict = {}

            resource_details_dict['SourceAccountId'] = f"#{item['accountId']}"
            resource_details_dict['ResourceId'] = item['resourceId']
            resource_details_dict['SourceRegion'] = item['awsRegion']
            resource_details_dict['ResourceType'] = item['resourceType']
            resource_details_dict['ResourceDetails'] = item['configuration'][:30000]  # excel and csv only accept not more than 30000 characters in a cell

            # data = json.loads(item['configuration'])
            # print(data)
            # print(resource_details_dict['ResourceDetails/VolumeType'])
            # # 'configuration': '{"id":"aslakkiwl1","name":"apigw-moments-aps1-dcp-dev-main","endpointConfiguration":{"types":["EDGE"]}}',...}
            # resource_details_dict['EndpointType'] = data["endpointConfiguration"]["types"]
            # resource_details_dict['APIGatewayName'] = data["name"]

            resourceinfo_list.append(resource_details_dict)

        return(resourceinfo_list)


    def inventory_csv(resource_list):

        with open(f'inventory_ebs_dcp_{datetime.datetime.now(tz=None).strftime("%Y%b%d")}.csv', 'w', newline='') as csvfile:
            fieldnames = ['SourceAccountId', 'ResourceId', 'SourceRegion', 'ResourceType', 'ResourceDetails/VolumeType']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()

            reOfInput = "^{'SourceAccountId': '#\d{12}', 'ResourceId':.+}$"

            for item in resource_list:

                # check malform input
                if re.search(reOfInput, str(item)):
                    writer.writerow(item)
                else:
                    print(f'[{timestamp()}] | Error: {str(item)}')

        print(f'[{timestamp()}] | done csv file add content')


    # ******      main function started      ******

    resource_type_string = "AWS::EC2::CustomerGateway'|'AWS::EC2::EIP'|'AWS::EC2::Host'|'AWS::EC2::Instance'|'" \
                           "AWS::EC2::InternetGateway'|'AWS::EC2::NetworkAcl'|'AWS::EC2::NetworkInterface'|'" \
                           "AWS::EC2::RouteTable'|'AWS::EC2::SecurityGroup'|'AWS::EC2::Subnet'|'" \
                           "AWS::CloudTrail::Trail'|'AWS::EC2::Volume'|'AWS::EC2::VPC'|'AWS::EC2::VPNConnection'|'" \
                           "AWS::EC2::VPNGateway'|'AWS::EC2::RegisteredHAInstance'|'AWS::EC2::NatGateway'|'" \
                           "AWS::EC2::EgressOnlyInternetGateway'|'AWS::EC2::VPCEndpoint'|'AWS::EC2::VPCEndpointService'|'" \
                           "AWS::EC2::FlowLog'|'AWS::EC2::VPCPeeringConnection'|'AWS::Elasticsearch::Domain'|'" \
                           "AWS::IAM::Group'|'AWS::IAM::Policy'|'AWS::IAM::Role'|'AWS::IAM::User'|'" \
                           "AWS::ElasticLoadBalancingV2::LoadBalancer'|'AWS::ACM::Certificate'|'AWS::RDS::DBInstance'|'" \
                           "AWS::RDS::DBSubnetGroup'|'AWS::RDS::DBSecurityGroup'|'AWS::RDS::DBSnapshot'|'" \
                           "AWS::RDS::DBCluster'|'AWS::RDS::DBClusterSnapshot'|'AWS::RDS::EventSubscription'|'" \
                           "AWS::S3::Bucket'|'AWS::S3::AccountPublicAccessBlock'|'AWS::Redshift::Cluster'|'" \
                           "AWS::Redshift::ClusterSnapshot'|'AWS::Redshift::ClusterParameterGroup'|'" \
                           "AWS::Redshift::ClusterSecurityGroup'|'AWS::Redshift::ClusterSubnetGroup'|'" \
                           "AWS::Redshift::EventSubscription'|'AWS::SSM::ManagedInstanceInventory'|'" \
                           "AWS::CloudWatch::Alarm'|'AWS::CloudFormation::Stack'|'" \
                           "AWS::ElasticLoadBalancing::LoadBalancer'|'AWS::AutoScaling::AutoScalingGroup'|'" \
                           "AWS::AutoScaling::LaunchConfiguration'|'AWS::AutoScaling::ScalingPolicy'|'" \
                           "AWS::AutoScaling::ScheduledAction'|'AWS::DynamoDB::Table'|'AWS::CodeBuild::Project'|'" \
                           "AWS::WAF::RateBasedRule'|'AWS::WAF::Rule'|'AWS::WAF::RuleGroup'|'AWS::WAF::WebACL'|'" \
                           "AWS::WAFRegional::RateBasedRule'|'AWS::WAFRegional::Rule'|'AWS::WAFRegional::RuleGroup'|'" \
                           "AWS::WAFRegional::WebACL'|'AWS::CloudFront::Distribution'|'" \
                           "AWS::CloudFront::StreamingDistribution'|'AWS::Lambda::Function'|'" \
                           "AWS::NetworkFirewall::Firewall'|'AWS::NetworkFirewall::FirewallPolicy'|'" \
                           "AWS::NetworkFirewall::RuleGroup'|'AWS::ElasticBeanstalk::Application'|'" \
                           "AWS::ElasticBeanstalk::ApplicationVersion'|'AWS::ElasticBeanstalk::Environment'|'" \
                           "AWS::WAFv2::WebACL'|'AWS::WAFv2::RuleGroup'|'AWS::WAFv2::IPSet'|'" \
                           "AWS::WAFv2::RegexPatternSet'|'AWS::WAFv2::ManagedRuleSet'|'AWS::XRay::EncryptionConfig'|'" \
                           "AWS::SSM::AssociationCompliance'|'AWS::SSM::PatchCompliance'|'AWS::Shield::Protection'|'" \
                           "AWS::ShieldRegional::Protection'|'AWS::Config::ConformancePackCompliance'|'" \
                           "AWS::Config::ResourceCompliance'|'AWS::ApiGateway::Stage'|'AWS::ApiGateway::RestApi'|'" \
                           "AWS::ApiGatewayV2::Stage'|'AWS::ApiGatewayV2::Api'|'AWS::CodePipeline::Pipeline'|'" \
                           "AWS::ServiceCatalog::CloudFormationProvisionedProduct'|'" \
                           "AWS::ServiceCatalog::CloudFormationProduct'|'AWS::ServiceCatalog::Portfolio'|'" \
                           "AWS::SQS::Queue'|'AWS::KMS::Key'|'AWS::QLDB::Ledger'|'AWS::SecretsManager::Secret'|'" \
                           "AWS::SNS::Topic'|'AWS::SSM::FileData'|'AWS::Backup::BackupPlan'|'" \
                           "AWS::Backup::BackupSelection'|'AWS::Backup::BackupVault'|'AWS::Backup::RecoveryPoint'|'" \
                           "AWS::ECR::Repository'|'AWS::ECS::Cluster'|'AWS::ECS::Service'|'AWS::ECS::TaskDefinition'|'" \
                           "AWS::EFS::AccessPoint'|'AWS::EFS::FileSystem'|'AWS::EKS::Cluster'|'AWS::OpenSearch::Domain'|'" \
                           "AWS::EC2::TransitGateway'|'AWS::Kinesis::Stream'|'AWS::Kinesis::StreamConsumer'|'" \
                           "AWS::CodeDeploy::Application'|'AWS::CodeDeploy::DeploymentConfig'|'" \
                           "AWS::CodeDeploy::DeploymentGroup'|'AWS::EC2::LaunchTemplate'|'AWS::ECR::PublicRepository'|'" \
                           "AWS::GuardDuty::Detector'|'AWS::EMR::SecurityConfiguration'|'AWS::SageMaker::CodeRepository'|'" \
                           "AWS::Route53Resolver::ResolverEndpoint'|'AWS::Route53Resolver::ResolverRule'|'" \
                           "AWS::Route53Resolver::ResolverRuleAssociation'|'AWS::DMS::ReplicationSubnetGroup'|'" \
                           "AWS::DMS::EventSubscription'|'AWS::MSK::Cluster'|'AWS::StepFunctions::Activity'|'" \
                           "AWS::WorkSpaces::Workspace'|'AWS::WorkSpaces::ConnectionAlias'|'AWS::SageMaker::Model'|'" \
                           "AWS::ElasticLoadBalancingV2::Listener'|'AWS::StepFunctions::StateMachine'|'" \
                           "AWS::Batch::JobQueue'|'AWS::Batch::ComputeEnvironment'|'AWS::AccessAnalyzer::Analyzer'|'" \
                           "AWS::Athena::WorkGroup'|'AWS::Athena::DataCatalog'|'AWS::Detective::Graph'|'" \
                           "AWS::GlobalAccelerator::Accelerator'|'AWS::GlobalAccelerator::EndpointGroup'|'" \
                           "AWS::GlobalAccelerator::Listener'|'AWS::EC2::TransitGatewayAttachment'|'" \
                           "AWS::EC2::TransitGatewayRouteTable'|'AWS::DMS::Certificate'|'AWS::AppConfig::Application'|'" \
                           "AWS::AppSync::GraphQLApi'|'AWS::DataSync::LocationSMB'|'AWS::DataSync::LocationFSxLustre'|'" \
                           "AWS::DataSync::LocationS3'|'AWS::DataSync::LocationEFS'|'AWS::DataSync::Task'|'" \
                           "AWS::DataSync::LocationNFS'|'AWS::EC2::NetworkInsightsAccessScopeAnalysis'|'" \
                           "AWS::EKS::FargateProfile'|'AWS::Glue::Job'|'AWS::GuardDuty::ThreatIntelSet'|'" \
                           "AWS::GuardDuty::IPSet'|'AWS::SageMaker::Workteam'|'AWS::SageMaker::NotebookInstanceLifecycleConfig'|'" \
                           "AWS::ServiceDiscovery::Service'|'AWS::ServiceDiscovery::PublicDnsNamespace'|'AWS::SES::ContactList'|'" \
                           "AWS::SES::ConfigurationSet'|'AWS::Route53::HostedZone'|'AWS::IoTEvents::Input'|'" \
                           "AWS::IoTEvents::DetectorModel'|'AWS::IoTEvents::AlarmModel'|'AWS::ServiceDiscovery::HttpNamespace'|'" \
                           "AWS::Events::EventBus'|'AWS::ImageBuilder::ContainerRecipe'|'AWS::ImageBuilder::DistributionConfiguration'|'" \
                           "AWS::ImageBuilder::InfrastructureConfiguration'|'AWS::DataSync::LocationObjectStorage'|'AWS::DataSync::LocationHDFS'|'" \
                           "AWS::Glue::Classifier'|'AWS::Route53RecoveryReadiness::Cell'|'AWS::Route53RecoveryReadiness::ReadinessCheck'|'" \
                           "AWS::ECR::RegistryPolicy'|'AWS::Backup::ReportPlan'|'AWS::Lightsail::Certificate'|'AWS::RUM::AppMonitor'|'" \
                           "AWS::Events::Endpoint'|'AWS::SES::ReceiptRuleSet'|'AWS::Events::Archive'|'AWS::Events::ApiDestination'|'" \
                           "AWS::Lightsail::Disk'|'AWS::FIS::ExperimentTemplate'|'AWS::DataSync::LocationFSxWindows'|'AWS::SES::ReceiptFilter'|'" \
                           "AWS::GuardDuty::Filter'|'AWS::SES::Template'|'AWS::AmazonMQ::Broker'|'AWS::AppConfig::Environment'|'" \
                           "AWS::AppConfig::ConfigurationProfile'|'AWS::Cloud9::EnvironmentEC2'|'AWS::EventSchemas::Registry'|'" \
                           "AWS::EventSchemas::RegistryPolicy'|'AWS::EventSchemas::Discoverer'|'AWS::FraudDetector::Label'|'" \
                           "AWS::FraudDetector::EntityType'|'AWS::FraudDetector::Variable'|'AWS::FraudDetector::Outcome'|'" \
                           "AWS::IoT::Authorizer'|'AWS::IoT::SecurityProfile'|'AWS::IoT::RoleAlias'|'AWS::IoT::Dimension'|'" \
                           "AWS::IoTAnalytics::Datastore'|'AWS::Lightsail::Bucket'|'AWS::Lightsail::StaticIp'|'AWS::MediaPackage::PackagingGroup'|'" \
                           "AWS::Route53RecoveryReadiness::RecoveryGroup'|'AWS::ResilienceHub::ResiliencyPolicy'|'AWS::Transfer::Workflow'|'" \
                           "AWS::EKS::IdentityProviderConfig'|'AWS::EKS::Addon'|'AWS::Glue::MLTransform'|'AWS::IoT::Policy'|'" \
                           "AWS::IoT::MitigationAction'|'AWS::IoTTwinMaker::Workspace'|'AWS::IoTTwinMaker::Entity'|'AWS::IoTAnalytics::Dataset'|'" \
                           "AWS::IoTAnalytics::Pipeline'|'AWS::IoTAnalytics::Channel'|'AWS::IoTSiteWise::Dashboard'|'AWS::IoTSiteWise::Project'|'" \
                           "AWS::IoTSiteWise::Portal'|'AWS::IoTSiteWise::AssetModel'|'AWS::IVS::Channel'|'AWS::IVS::RecordingConfiguration'|'" \
                           "AWS::IVS::PlaybackKeyPair'|'AWS::KinesisAnalyticsV2::Application'|'AWS::RDS::GlobalCluster'|'" \
                           "AWS::S3::MultiRegionAccessPoint'|'AWS::DeviceFarm::TestGridProject'|'AWS::Budgets::BudgetsAction'|'AWS::Lex::Bot'|'" \
                           "AWS::CodeGuruReviewer::RepositoryAssociation'|'AWS::IoT::CustomMetric'|'AWS::Route53Resolver::FirewallDomainList'|'" \
                           "AWS::RoboMaker::RobotApplicationVersion'|'AWS::EC2::TrafficMirrorSession'|'AWS::IoTSiteWise::Gateway'|'" \
                           "AWS::Lex::BotAlias'|'AWS::LookoutMetrics::Alert'|'AWS::IoT::AccountAuditConfiguration'|'AWS::EC2::TrafficMirrorTarget'|'" \
                           "AWS::S3::StorageLens'|'AWS::IoT::ScheduledAudit'|'AWS::Events::Connection'|'AWS::EventSchemas::Schema'|'" \
                           "AWS::MediaPackage::PackagingConfiguration'|'AWS::KinesisVideo::SignalingChannel'|'AWS::AppStream::DirectoryConfig'|'" \
                           "AWS::LookoutVision::Project'|'AWS::Route53RecoveryControl::Cluster'|'AWS::Route53RecoveryControl::SafetyRule'|'" \
                           "AWS::Route53RecoveryControl::ControlPanel'|'AWS::Route53RecoveryControl::RoutingControl'|'" \
                           "AWS::Route53RecoveryReadiness::ResourceSet'|'AWS::RoboMaker::SimulationApplication'|'AWS::RoboMaker::RobotApplication'|'" \
                           "AWS::HealthLake::FHIRDatastore'|'AWS::Pinpoint::Segment'|'AWS::Pinpoint::ApplicationSettings'|'AWS::Events::Rule'|'" \
                           "AWS::EC2::DHCPOptions'|'AWS::EC2::NetworkInsightsPath'|'AWS::EC2::TrafficMirrorFilter'|'AWS::EC2::IPAM'|'" \
                           "AWS::IoTTwinMaker::Scene'|'AWS::NetworkManager::TransitGatewayRegistration'|'AWS::CustomerProfiles::Domain'|'" \
                           "AWS::AutoScaling::WarmPool'|'AWS::Connect::PhoneNumber'|'AWS::AppConfig::DeploymentStrategy'|'AWS::AppFlow::Flow'|'" \
                           "AWS::AuditManager::Assessment'|'AWS::CloudWatch::MetricStream'|'AWS::DeviceFarm::InstanceProfile'|'" \
                           "AWS::DeviceFarm::Project'|'AWS::EC2::EC2Fleet'|'AWS::EC2::SubnetRouteTableAssociation'|'AWS::ECR::PullThroughCacheRule'|'" \
                           "AWS::GroundStation::Config'|'AWS::ImageBuilder::ImagePipeline'|'AWS::IoT::FleetMetric'|'AWS::IoTWireless::ServiceProfile'|'" \
                           "AWS::NetworkManager::Device'|'AWS::NetworkManager::GlobalNetwork'|'AWS::NetworkManager::Link'|'AWS::NetworkManager::Site'|'" \
                           "AWS::Panorama::Package'|'AWS::Pinpoint::App'|'AWS::Redshift::ScheduledAction'|'" \
                           "AWS::Route53Resolver::FirewallRuleGroupAssociation'|'AWS::SageMaker::AppImageConfig'|'AWS::SageMaker::Image'|'" \
                           "AWS::ECS::TaskSet'|'AWS::Cassandra::Keyspace'|'AWS::Signer::SigningProfile'|'AWS::Amplify::App'|'" \
                           "AWS::AppMesh::VirtualNode'|'AWS::AppMesh::VirtualService'|'AWS::AppRunner::VpcConnector'|'AWS::AppStream::Application'|'" \
                           "AWS::CodeArtifact::Repository'|'AWS::EC2::PrefixList'|'AWS::EC2::SpotFleet'|'AWS::Evidently::Project'|'" \
                           "AWS::Forecast::Dataset'|'AWS::IAM::SAMLProvider'|'AWS::IAM::ServerCertificate'|'AWS::Pinpoint::Campaign'|'" \
                           "AWS::Pinpoint::InAppTemplate'|'AWS::SageMaker::Domain'|'AWS::Transfer::Agreement'|'AWS::Transfer::Connector'|'" \
                           "AWS::KinesisFirehose::DeliveryStream"

    # 1. split the resources types above to get the full list of the inventory
    resource_type_list = resource_type_string.split("'|'")

    # 2. or create the list of resource manually
    # resource_type_list = ["AWS::EC2::Volume"]

    final_resource_list = []

    for resource_type in resource_type_list:
        next_Token = ''
        while next_Token != None:
            resources = []
            resources.clear()
            get_inventory = get_resource_list_from_config(resource_type,next_Token, awsaccountid, region)
            next_Token = get_inventory[1]

            if not get_inventory[0]:
                print(f'[{timestamp()}] | no resource in this type, resource type = {resource_type}')
                print(f'[{timestamp()}] | finish exporting content of {resource_type}')
                continue

            print(f'[{datetime.datetime.now(tz=None).strftime("%d %b %Y - %H:%M")}] | list is not empty')

            if next_Token == None:
                print(f'[{timestamp()}] | next token is empty')
            else:
                print(f'[{timestamp()}] | next token is {next_Token}')

            for resource in get_inventory[0]:
                resources.append(resource)

            resource_list = search_for_resource_details(resources)

            for object in resource_list:
                final_resource_list.append(object)

        print(f'[{timestamp()}] | start exporting content of {resource_type} to CSV')

        inventory_csv(final_resource_list)

        print(f'[{timestamp()}] | finish exporting content of {resource_type}')

if __name__ == "__main__":
    lambda_handler({}, {})
